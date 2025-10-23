use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::{Fr as Scalar, G1Projective as Curve};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use rand::{rngs::StdRng, SeedableRng};
use tokio::time::{interval, MissedTickBehavior};
use tokio::{pin, signal};
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt::time::Uptime, EnvFilter};
use url::Url;

use zk_poker::engine::nl::types::{Chips, HandConfig, SeatId, TableStakes};
use zk_poker::game::coordinator::{
    GameCoordinator, GameCoordinatorConfig, ShufflerSecretConfig, SupabaseRealtimeClientConfig,
};
use zk_poker::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, PlayerSeatSnapshot, RegisterShufflerOutput,
    ShufflerAssignment, ShufflerRecord, ShufflerRegistrationConfig,
};
use zk_poker::ledger::lobby::SeaOrmLobby;
use zk_poker::ledger::snapshot::AnyTableSnapshot;
use zk_poker::ledger::state::LedgerState;
use zk_poker::ledger::store::{EventStore, SeaOrmEventStore, SeaOrmSnapshotStore, SnapshotStore};
use zk_poker::ledger::typestate::MaybeSaved;
use zk_poker::ledger::verifier::{LedgerVerifier, Verifier};
use zk_poker::ledger::HandId;
use zk_poker::ledger::LedgerLobby;
use zk_poker::shuffling::{draw_shuffler_public_key, make_global_public_keys};

const LOG_TARGET: &str = "bin::coordinator_demo";
const DEFAULT_SUPABASE_URL: &str = "http://127.0.0.1:54321";
const DEFAULT_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:54322/postgres";
const PLAYER_COUNT: usize = 4;
const SHUFFLER_COUNT: usize = 3;
const SUBMIT_CHANNEL_CAPACITY: usize = 128;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Parser)]
#[command(name = "coordinator_demo")]
#[command(about = "Seed a lobby and run the coordinator shuffle demo", long_about = None)]
struct Args {
    /// Base Supabase HTTPS endpoint (e.g. https://xyz.supabase.co)
    #[arg(long, env = "SUPABASE_URL")]
    supabase_url: Option<String>,

    /// Supabase anon key for realtime websocket auth
    #[arg(long, env = "SUPABASE_ANON_KEY")]
    supabase_anon_key: Option<String>,

    /// Postgres connection string used by SeaORM
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Comma-separated or JSON array of shuffler secret scalars (hex, optional 0x prefix)
    #[arg(long)]
    shuffler_keys: Option<String>,

    /// Seed the demo RNG to make player/shuffler identities deterministic
    #[arg(long)]
    rng_seed: Option<u64>,

    /// Toggle structured (JSON) tracing output
    #[arg(long)]
    json: bool,
}

struct Config {
    supabase_url: String,
    supabase_key: String,
    database_url: String,
    shuffler_secrets: Vec<Scalar>,
    rng_seed: Option<u64>,
}

struct PlayerSpec {
    name: String,
    seat: SeatId,
    public_key: Vec<u8>,
}

struct ShufflerMaterial {
    secret: Scalar,
    public_key: Curve,
    public_key_bytes: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let manifest_env = env!("CARGO_MANIFEST_DIR");
    let manifest_env_path = PathBuf::from(manifest_env).join(".env");
    dotenv::from_filename(manifest_env_path).ok();
    dotenv::dotenv().ok();
    let args = Args::parse();
    init_tracing(args.json)?;
    let config = build_config(args)?;
    run_demo(config).await
}

async fn run_demo(config: Config) -> Result<()> {
    let realtime_url = build_realtime_url(&config.supabase_url, &config.supabase_key)
        .context("failed to derive Supabase realtime websocket URL")?;
    info!(
        target = LOG_TARGET,
        supabase_rest = %config.supabase_url,
        supabase_realtime = %realtime_url,
        "resolved Supabase endpoints"
    );

    let mut rng = match config.rng_seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };

    // Shuffler key material (use provided secrets or sample new ones)
    let shuffler_secrets = if config.shuffler_secrets.is_empty() {
        info!(
            target = LOG_TARGET,
            count = SHUFFLER_COUNT,
            "generating random shuffler secrets"
        );
        (0..SHUFFLER_COUNT)
            .map(|_| Scalar::rand(&mut rng))
            .collect::<Vec<_>>()
    } else {
        config.shuffler_secrets.clone()
    };
    if shuffler_secrets.len() != SHUFFLER_COUNT {
        bail!(
            "coordinator demo expects exactly {} shuffler secrets (received {})",
            SHUFFLER_COUNT,
            shuffler_secrets.len()
        );
    }

    let shuffler_materials = build_shuffler_materials(&shuffler_secrets)?;
    let aggregated_public_key = make_global_public_keys(
        shuffler_materials
            .iter()
            .map(|material| material.public_key.clone())
            .collect(),
    );
    let aggregated_public_key_bytes = serialize_point(&aggregated_public_key)
        .context("failed to serialize aggregated shuffler public key")?;

    info!(
        target = LOG_TARGET,
        database_url = %config.database_url,
        "connecting to Postgres"
    );
    let conn = sea_orm::Database::connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    let lobby = SeaOrmLobby::new(conn.clone());
    let event_store: Arc<dyn EventStore<Curve>> =
        Arc::new(SeaOrmEventStore::<Curve>::new(conn.clone()));
    let snapshot_store: Arc<dyn SnapshotStore<Curve>> =
        Arc::new(SeaOrmSnapshotStore::<Curve>::new(conn.clone()));
    let state = Arc::new(LedgerState::<Curve>::new());
    let verifier: Arc<dyn Verifier<Curve> + Send + Sync> =
        Arc::new(LedgerVerifier::<Curve>::new(Arc::clone(&state)));

    let player_specs = build_players(&mut rng)?;
    let lobby_config = build_lobby_config();

    info!(target = LOG_TARGET, "hosting game via lobby API");
    let host_registration = PlayerRecord {
        display_name: player_specs[0].name.clone(),
        public_key: player_specs[0].public_key.clone(),
        seat_preference: Some(player_specs[0].seat),
        state: MaybeSaved { id: None },
    };
    let metadata = <SeaOrmLobby as LedgerLobby<Curve>>::host_game(
        &lobby,
        host_registration,
        lobby_config.clone(),
    )
    .await
    .context("failed to host game")?;

    info!(
        target = LOG_TARGET,
        game_id = metadata.record.state.id,
        host_player_id = metadata.host.state.id,
        "game hosted"
    );

    let mut seated_players =
        seat_players(&lobby, &metadata, &player_specs, lobby_config.buy_in).await?;
    let registered_shufflers = register_shufflers(&lobby, &metadata, &shuffler_materials).await?;

    let shuffler_secret_configs = registered_shufflers
        .iter()
        .zip(shuffler_materials.iter())
        .map(|(registration, material)| ShufflerSecretConfig {
            id: registration.shuffler.state.id,
            secret: material.secret.clone(),
        })
        .collect::<Vec<_>>();

    let coordinator_config = GameCoordinatorConfig {
        verifier,
        event_store,
        snapshot_store,
        state: Arc::clone(&state),
        supabase: SupabaseRealtimeClientConfig::new(realtime_url, config.supabase_key.clone()),
        shufflers: shuffler_secret_configs,
        submit_channel_capacity: SUBMIT_CHANNEL_CAPACITY,
        rng_seed: config.rng_seed.map(seed_to_bytes),
    };

    info!(target = LOG_TARGET, "spawning game coordinator");
    let coordinator = GameCoordinator::<Curve>::spawn(coordinator_config)
        .await
        .context("failed to spawn game coordinator")?;
    let state_handle = coordinator.state();
    let operator = coordinator.operator();

    let hand_config = build_hand_config(&player_specs);
    let shuffler_assignments = registered_shufflers
        .iter()
        .zip(shuffler_materials.iter())
        .map(|(registration, material)| {
            ShufflerAssignment::new(
                registration.shuffler.clone(),
                registration.assigned_sequence,
                material.public_key_bytes.clone(),
                aggregated_public_key_bytes.clone(),
            )
        })
        .collect::<Vec<_>>();

    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config,
        players: seated_players.drain(..).collect(),
        shufflers: shuffler_assignments,
        deck_commitment: None,
        buy_in: lobby_config.buy_in,
        min_players: lobby_config.min_players_to_start,
    };

    info!(target = LOG_TARGET, "commencing hand");
    let outcome =
        <SeaOrmLobby as LedgerLobby<Curve>>::commence_game(&lobby, operator.as_ref(), params)
            .await
            .context("failed to commence game")?;

    let hand_id = outcome.hand.state.id;
    let game_id = outcome.hand.game_id;
    let expected_order = outcome.initial_snapshot.shuffling.expected_order.clone();

    coordinator
        .attach_hand(outcome)
        .await
        .context("failed to attach hand to coordinator")?;
    info!(
        target = LOG_TARGET,
        game_id,
        hand_id,
        expected_shufflers = expected_order.len(),
        "hand attached; monitoring shuffle progression"
    );

    monitor_shuffle_progress(state_handle, hand_id, expected_order).await?;

    info!(
        target = LOG_TARGET,
        "hand entered dealing; waiting for CTRL+C to shut down coordinator"
    );
    signal::ctrl_c()
        .await
        .context("failed while awaiting CTRL+C")?;
    info!(
        target = LOG_TARGET,
        "received shutdown signal; shutting down coordinator"
    );
    coordinator
        .shutdown()
        .await
        .context("failed to cleanly shut down coordinator")?;
    info!(target = LOG_TARGET, "demo complete");
    Ok(())
}

async fn seat_players(
    lobby: &SeaOrmLobby,
    metadata: &zk_poker::ledger::lobby::types::GameMetadata,
    specs: &[PlayerSpec],
    starting_stack: Chips,
) -> Result<Vec<PlayerSeatSnapshot<Curve>>> {
    let mut snapshots = Vec::with_capacity(PLAYER_COUNT);

    // Seat the host
    let host = PlayerRecord {
        display_name: metadata.host.display_name.clone(),
        public_key: metadata.host.public_key.clone(),
        seat_preference: Some(specs[0].seat),
        state: MaybeSaved {
            id: Some(metadata.host.state.id),
        },
    };
    let host_join = <SeaOrmLobby as LedgerLobby<Curve>>::join_game(
        lobby,
        &metadata.record,
        host,
        Some(specs[0].seat),
    )
    .await
    .context("failed to seat host player")?;

    snapshots.push(PlayerSeatSnapshot::new(
        host_join.player.clone(),
        specs[0].seat,
        starting_stack,
        specs[0].public_key.clone(),
    ));
    info!(
        target = LOG_TARGET,
        player_id = host_join.player.state.id,
        seat = specs[0].seat,
        "host joined game"
    );

    for spec in specs.iter().skip(1) {
        let record = PlayerRecord {
            display_name: spec.name.clone(),
            public_key: spec.public_key.clone(),
            seat_preference: Some(spec.seat),
            state: MaybeSaved { id: None },
        };
        let join = <SeaOrmLobby as LedgerLobby<Curve>>::join_game(
            lobby,
            &metadata.record,
            record,
            Some(spec.seat),
        )
        .await
        .with_context(|| format!("failed to seat {}", spec.name))?;

        snapshots.push(PlayerSeatSnapshot::new(
            join.player.clone(),
            spec.seat,
            starting_stack,
            spec.public_key.clone(),
        ));
        info!(
            target = LOG_TARGET,
            player_id = join.player.state.id,
            seat = spec.seat,
            "player joined"
        );
    }

    Ok(snapshots)
}

async fn register_shufflers(
    lobby: &SeaOrmLobby,
    metadata: &zk_poker::ledger::lobby::types::GameMetadata,
    materials: &[ShufflerMaterial],
) -> Result<Vec<RegisterShufflerOutput>> {
    let mut outputs = Vec::with_capacity(materials.len());
    for (index, material) in materials.iter().enumerate() {
        let record = ShufflerRecord {
            display_name: format!("demo-shuffler-{}", index + 1),
            public_key: material.public_key_bytes.clone(),
            state: MaybeSaved { id: None },
        };

        let output = <SeaOrmLobby as LedgerLobby<Curve>>::register_shuffler(
            lobby,
            &metadata.record,
            record,
            ShufflerRegistrationConfig {
                sequence: Some(index as u16),
            },
        )
        .await
        .with_context(|| format!("failed to register shuffler {}", index + 1))?;

        info!(
            target = LOG_TARGET,
            shuffler_id = output.shuffler.state.id,
            sequence = output.assigned_sequence,
            "registered shuffler"
        );
        outputs.push(output);
    }
    Ok(outputs)
}

async fn monitor_shuffle_progress(
    state: Arc<LedgerState<Curve>>,
    hand_id: HandId,
    expected_order: Vec<zk_poker::ledger::CanonicalKey<Curve>>,
) -> Result<()> {
    let mut observed = 0usize;
    let total = expected_order.len();
    let start = Instant::now();
    let mut ticker = interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let shutdown = signal::ctrl_c();
    pin!(shutdown);

    info!(
        target = LOG_TARGET,
        hand_id,
        total_turns = total,
        "waiting for shuffle proofs"
    );

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                warn!(target = LOG_TARGET, hand_id, "Ctrl+C received; aborting demo");
                break;
            }
            _ = ticker.tick() => {
                let Some((_, snapshot)) = state.tip_snapshot(hand_id) else {
                    continue;
                };

                match &snapshot {
                    AnyTableSnapshot::Shuffling(table) => {
                        let completed = table.shuffling.steps.len();
                        while observed < completed && observed < total {
                            let shuffler_key = &expected_order[observed];
                            let shuffler_id = table
                                .shufflers
                                .as_ref()
                                .get(shuffler_key)
                                .map(|identity| identity.shuffler_id)
                                .unwrap_or(-1);
                            info!(
                                target = LOG_TARGET,
                                hand_id,
                                turn_index = observed,
                                shuffler_id,
                                "shuffle proof accepted"
                            );
                            observed += 1;
                        }
                    }
                    AnyTableSnapshot::Dealing(_) => {
                        info!(
                            target = LOG_TARGET,
                            hand_id,
                            elapsed_ms = start.elapsed().as_millis(),
                            "hand advanced to dealing phase"
                        );
                        return Ok(());
                    }
                    other => {
                        if observed >= total {
                            info!(
                                target = LOG_TARGET,
                                hand_id,
                                phase = snapshot_phase_name(other),
                                elapsed_ms = start.elapsed().as_millis(),
                                "hand advanced past shuffling"
                            );
                            return Ok(());
                        }
                        debug!(
                            target = LOG_TARGET,
                            hand_id,
                            phase = snapshot_phase_name(other),
                            "waiting for remaining shuffle proofs"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn init_tracing(json: bool) -> Result<()> {
    if json {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("coordinator_demo=info,game::coordinator=info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(true)
            .with_timer(Uptime::default())
            .with_ansi(false)
            .json()
            .try_init()
            .map_err(|err| anyhow!("failed to initialize tracing subscriber: {err}"))?;
    } else {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("coordinator_demo=info,game::coordinator=info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(true)
            .with_timer(Uptime::default())
            .try_init()
            .map_err(|err| anyhow!("failed to initialize tracing subscriber: {err}"))?;
    }
    Ok(())
}

fn build_config(args: Args) -> Result<Config> {
    let supabase_url = args
        .supabase_url
        .or_else(|| std::env::var("SUPABASE_URL").ok())
        .unwrap_or_else(|| DEFAULT_SUPABASE_URL.to_string());
    let supabase_key = args
        .supabase_anon_key
        .or_else(|| std::env::var("SUPABASE_ANON_KEY").ok())
        .ok_or_else(|| anyhow!("Supabase anon key is required (set SUPABASE_ANON_KEY)"))?;
    let database_url = args
        .database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| DEFAULT_DATABASE_URL.to_string());

    let shuffler_secrets = match args.shuffler_keys {
        Some(raw) => parse_shuffler_keys(&raw)
            .context("failed to parse shuffler secrets from CLI/env input")?,
        None => Vec::new(),
    };

    Ok(Config {
        supabase_url,
        supabase_key,
        database_url,
        shuffler_secrets,
        rng_seed: args.rng_seed,
    })
}

fn build_players(rng: &mut StdRng) -> Result<Vec<PlayerSpec>> {
    let mut players = Vec::with_capacity(PLAYER_COUNT);
    for seat in 0..PLAYER_COUNT {
        let (_, public_key) = draw_shuffler_public_key::<Curve, _>(rng);
        let public_key_bytes =
            serialize_point(&public_key).context("failed to serialize player public key")?;
        players.push(PlayerSpec {
            name: format!("demo-player-{}", seat + 1),
            seat: seat as SeatId,
            public_key: public_key_bytes,
        });
    }
    Ok(players)
}

fn build_lobby_config() -> GameLobbyConfig {
    GameLobbyConfig {
        stakes: TableStakes {
            small_blind: 50,
            big_blind: 100,
            ante: 0,
        },
        max_players: 9,
        rake_bps: 0,
        name: "Coordinator Demo Table".into(),
        currency: "chips".into(),
        buy_in: 10_000,
        min_players_to_start: PLAYER_COUNT as i16,
        check_raise_allowed: true,
        action_time_limit: Duration::from_secs(30),
    }
}

fn build_hand_config(players: &[PlayerSpec]) -> HandConfig {
    let button = players[0].seat;
    let small_blind = players.get(1).map(|p| p.seat).unwrap_or(button);
    let big_blind = players.get(2).map(|p| p.seat).unwrap_or(button);
    HandConfig {
        stakes: TableStakes {
            small_blind: 50,
            big_blind: 100,
            ante: 0,
        },
        button,
        small_blind_seat: small_blind,
        big_blind_seat: big_blind,
        check_raise_allowed: true,
    }
}

fn build_shuffler_materials(secrets: &[Scalar]) -> Result<Vec<ShufflerMaterial>> {
    secrets
        .iter()
        .map(|secret| {
            let public_key = Curve::generator() * secret;
            let public_key_bytes =
                serialize_point(&public_key).context("failed to serialize shuffler public key")?;
            Ok(ShufflerMaterial {
                secret: *secret,
                public_key,
                public_key_bytes,
            })
        })
        .collect()
}

fn parse_shuffler_keys(raw: &str) -> Result<Vec<Scalar>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        // JSON array: either ["hex", ...] or [{"secret": "hex"}, ...]
        let value: serde_json::Value =
            serde_json::from_str(trimmed).context("failed to parse JSON for shuffler keys")?;
        let array = value
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array for shuffler keys"))?;
        array
            .iter()
            .map(|entry| match entry {
                serde_json::Value::String(s) => decode_scalar(s),
                serde_json::Value::Object(obj) => obj
                    .get("secret")
                    .and_then(|val| val.as_str())
                    .ok_or_else(|| anyhow!("object entry missing 'secret' field"))
                    .and_then(|s| decode_scalar(s)),
                _ => Err(anyhow!(
                    "expected string or object with 'secret' field in shuffler key array"
                )),
            })
            .collect()
    } else {
        trimmed
            .split(',')
            .map(|part| decode_scalar(part.trim()))
            .collect()
    }
}

fn decode_scalar(hex_scalar: &str) -> Result<Scalar> {
    let cleaned = hex_scalar.trim().trim_start_matches("0x");
    if cleaned.is_empty() {
        bail!("empty scalar value");
    }
    let bytes = hex::decode(cleaned).context("invalid hex in scalar value")?;
    if bytes.is_empty() {
        bail!("scalar value cannot be empty");
    }
    Ok(Scalar::from_le_bytes_mod_order(&bytes))
}

fn serialize_point(point: &Curve) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("failed to serialize curve point: {err}"))?;
    Ok(buf)
}

fn seed_to_bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}

fn build_realtime_url(base: &str, api_key: &str) -> Result<Url> {
    let mut url = Url::parse(base).context("invalid Supabase base URL")?;
    match url.scheme() {
        "http" => url
            .set_scheme("ws")
            .expect("http -> ws conversion should succeed"),
        "https" => url
            .set_scheme("wss")
            .expect("https -> wss conversion should succeed"),
        "ws" | "wss" => {}
        other => bail!("unsupported Supabase URL scheme '{other}'"),
    }

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("Supabase URL cannot be a base URL"))?;
        segments.pop_if_empty();
        segments.extend(&["realtime", "v1", "websocket"]);
    }

    url.set_query(None);
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("apikey", api_key);
        pairs.append_pair("vsn", "1.0.0");
    }
    Ok(url)
}

fn snapshot_phase_name(snapshot: &AnyTableSnapshot<Curve>) -> &'static str {
    match snapshot {
        AnyTableSnapshot::Shuffling(_) => "Shuffling",
        AnyTableSnapshot::Dealing(_) => "Dealing",
        AnyTableSnapshot::Preflop(_) => "Preflop",
        AnyTableSnapshot::Flop(_) => "Flop",
        AnyTableSnapshot::Turn(_) => "Turn",
        AnyTableSnapshot::River(_) => "River",
        AnyTableSnapshot::Showdown(_) => "Showdown",
        AnyTableSnapshot::Complete(_) => "Complete",
    }
}
