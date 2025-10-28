use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{HandConfig, PlayerId, SeatId, TableStakes};
use crate::ledger::hash::LedgerHasherSha256;
use crate::ledger::lobby::service::LobbyServiceFactory;
use crate::ledger::lobby::types::{
    CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::typestate::MaybeSaved;
use crate::server::demo::DemoStreamEvent;
use crate::server::error::ApiError;
use crate::server::routes::ServerContext;
use crate::shuffler::{run_dealing_phase, run_shuffling_phase, ShufflerEngine, ShufflerHandState};

const LOG_TARGET: &str = "legit_poker::server::demo::in_memory_stream";
const NUM_SHUFFLERS: usize = 5;
const NUM_PLAYERS: usize = 7;
const CHANNEL_BUFFER_SIZE: usize = 512;

type Schnorr254<C> = Schnorr<C, Sha256>;

#[derive(Debug, Deserialize)]
pub struct DemoStreamQuery {
    pub public_key: Option<String>,
}

/// Entry point for the in-memory SSE demo stream.
/// Each request runs independently with no database or coordinator dependencies.
pub async fn stream_demo_game_in_memory<C>(
    ctx: Arc<ServerContext<C>>,
    query: DemoStreamQuery,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    if query.public_key.is_some() {
        return Err(ApiError::bad_request(
            "public_key query parameter is not supported for the in-memory demo stream",
        ));
    }

    let (event_tx, event_rx) = mpsc::channel::<DemoStreamEvent<C>>(CHANNEL_BUFFER_SIZE);

    // Run the game flow in a blocking task to avoid blocking the async runtime
    tokio::task::spawn_blocking(move || {
        if let Err(err) = execute_demo_flow(event_tx, ctx) {
            error!(target: LOG_TARGET, ?err, "demo flow failed");
        }
    });

    // Convert events to SSE
    let sse_stream = ReceiverStream::new(event_rx).map(|event| {
        let event_name = event.event_name();
        let data = serde_json::to_string(&event)
            .unwrap_or_else(|err| json!({ "error": err.to_string() }).to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(sse_stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text(":")))
}

/// Main execution flow - runs synchronously in a blocking task.
fn execute_demo_flow<C>(
    event_tx: mpsc::Sender<DemoStreamEvent<C>>,
    _ctx: Arc<ServerContext<C>>,
) -> Result<()>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    info!(target: LOG_TARGET, "🎰 Starting in-memory demo flow");

    // Step 1: Initialize RNG and hasher
    let mut rng = StdRng::from_entropy();
    let hasher = Arc::new(LedgerHasherSha256);

    // Step 2: Set up in-memory lobby service
    let lobby: Arc<dyn crate::ledger::LobbyService<C>> =
        Arc::new(LobbyServiceFactory::<C>::in_memory());

    // Step 3: Generate shuffler identities and keys
    info!(target: LOG_TARGET, num_shufflers = NUM_SHUFFLERS, "🔀 Generating shuffler identities");
    let shuffler_engines = generate_shuffler_engines(&mut rng)?;
    let shuffler_records = create_shuffler_records(&shuffler_engines);
    let aggregated_public_key = compute_aggregated_public_key(&shuffler_engines);

    // Step 4: Generate player identities
    info!(target: LOG_TARGET, num_players = NUM_PLAYERS, "👥 Generating player identities");
    let player_keys = generate_player_keys(&mut rng, NUM_PLAYERS);
    let player_records = create_player_records(&player_keys);

    // Step 5: Host a game (using player 0 as host)
    info!(target: LOG_TARGET, "🎮 Hosting game");
    let host = player_records[0].clone();

    let lobby_config = build_lobby_config();
    let metadata = tokio::runtime::Handle::current()
        .block_on(lobby.host_game(host, lobby_config.clone()))?;

    let game_id: GameId = metadata.record.state.id;

    // Emit PlayerCreated for host (player 0)
    if event_tx
        .try_send(DemoStreamEvent::PlayerCreated {
            game_id,
            seat: 0,
            display_name: metadata.host.display_name.clone(),
            public_key: metadata.host.public_key.clone(),
        })
        .is_err()
    {
        warn!(target: LOG_TARGET, "dropped player_created event");
    }

    // Step 6: Register shufflers
    info!(target: LOG_TARGET, num_shufflers = NUM_SHUFFLERS, "🔀 Registering shufflers");
    for (idx, shuffler_record) in shuffler_records.into_iter().enumerate() {
        let cfg = ShufflerRegistrationConfig {
            sequence: Some(idx as u16),
        };
        let output = tokio::runtime::Handle::current()
            .block_on(lobby.register_shuffler(
                &metadata.record,
                shuffler_record.clone(),
                cfg,
            ))?;
        debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            shuffler_id = ?output.shuffler.state.id,
            "✅ Shuffler registered"
        );
    }

    // Step 7: Join players to the game
    info!(target: LOG_TARGET, num_players = NUM_PLAYERS, "👥 Joining players");
    let mut saved_player_records = Vec::with_capacity(NUM_PLAYERS);
    for (idx, player_record) in player_records.into_iter().enumerate() {
        let seat_id = idx as SeatId;
        let output = tokio::runtime::Handle::current()
            .block_on(lobby.join_game(
                &metadata.record,
                player_record.clone(),
                Some(seat_id),
            ))?;
        saved_player_records.push((output.player, seat_id));
    }

    // Step 8: Commence the game
    info!(target: LOG_TARGET, "🚀 Commencing game");
    let hand_config = build_hand_config();
    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: hand_config.button,
        small_blind_seat: hand_config.small_blind_seat,
        big_blind_seat: hand_config.big_blind_seat,
        deck_commitment: None,
        player_stacks: None,
    };

    let outcome = tokio::runtime::Handle::current()
        .block_on(lobby.commence_game(hasher.as_ref(), params))?;

    let hand_id: HandId = outcome.hand.state.id;
    let initial_snapshot = outcome.initial_snapshot.clone();

    // Emit HandCreated
    if event_tx
        .try_send(DemoStreamEvent::HandCreated {
            game_id,
            hand_id,
            player_count: NUM_PLAYERS,
            shuffler_count: NUM_SHUFFLERS,
            snapshot: initial_snapshot.clone(),
        })
        .is_err()
    {
        warn!(target: LOG_TARGET, "dropped hand_created event");
    }

    // Step 9: Initialize shuffler hand states
    info!(target: LOG_TARGET, "🎲 Step 9: Initializing shuffler states");
    let mut shuffler_states = Vec::with_capacity(NUM_SHUFFLERS);
    for (idx, engine) in shuffler_engines.iter().enumerate() {
        let mut hand_seed = [0u8; 32];
        rng.fill_bytes(&mut hand_seed);

        let state = ShufflerHandState::from_shuffling_snapshot(
            &initial_snapshot,
            &engine.public_key,
            hand_seed,
        )?;
        debug!(
            target: LOG_TARGET,
            shuffler_index = idx,
            "✅ Shuffler state initialized"
        );
        shuffler_states.push(state);
    }

    // Step 10: Execute shuffle phase
    info!(target: LOG_TARGET, "🔄 Step 10: Executing shuffle phase");
    let dealing_snapshot = run_shuffling_phase(
        initial_snapshot,
        &shuffler_engines,
        &mut shuffler_states,
        hasher.as_ref(),
        &event_tx,
    )?;

    // Step 11: Execute dealing phase
    info!(target: LOG_TARGET, "🎴 Step 11: Executing dealing phase");

    let mut dealing_snapshot_mut = dealing_snapshot;
    run_dealing_phase(
        &mut dealing_snapshot_mut,
        &shuffler_engines,
        &saved_player_records,
        &player_keys,
        &aggregated_public_key,
        &mut rng,
        hasher.as_ref(),
        Some(&event_tx),
    )?;

    info!(target: LOG_TARGET, "✅ Demo flow completed successfully");
    Ok(())
}

// Helper functions from game_launch_and_shuffle_flow.rs

fn generate_shuffler_engines<C>(rng: &mut StdRng) -> Result<Vec<ShufflerEngine<C, Schnorr254<C>>>>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    (0..NUM_SHUFFLERS)
        .map(|_| ShufflerEngine::generate(rng))
        .collect()
}

fn create_shuffler_records<C>(
    engines: &[ShufflerEngine<C, Schnorr254<C>>],
) -> Vec<ShufflerRecord<C, MaybeSaved<ShufflerId>>>
where
    C: CurveGroup,
{
    engines
        .iter()
        .enumerate()
        .map(|(idx, engine)| ShufflerRecord {
            display_name: format!("Shuffler-{}", idx),
            public_key: engine.public_key.clone(),
            state: MaybeSaved { id: None },
        })
        .collect()
}

fn compute_aggregated_public_key<C>(engines: &[ShufflerEngine<C, Schnorr254<C>>]) -> C
where
    C: CurveGroup,
{
    engines
        .iter()
        .fold(C::zero(), |acc, engine| acc + engine.public_key)
}

fn generate_player_keys<C>(rng: &mut StdRng, count: usize) -> Vec<(C::ScalarField, C)>
where
    C: CurveGroup,
    C::ScalarField: PrimeField + UniformRand,
{
    (0..count)
        .map(|_| {
            let secret = C::ScalarField::rand(rng);
            let public_key = C::generator() * secret;
            (secret, public_key)
        })
        .collect()
}

fn create_player_records<C>(
    keys: &[(C::ScalarField, C)],
) -> Vec<PlayerRecord<C, MaybeSaved<PlayerId>>>
where
    C: CurveGroup,
{
    keys.iter()
        .enumerate()
        .map(|(idx, (_, public_key))| PlayerRecord {
            display_name: format!("Player-{}", idx),
            public_key: public_key.clone(),
            seat_preference: Some(idx as SeatId),
            state: MaybeSaved { id: None },
        })
        .collect()
}

fn build_lobby_config() -> GameLobbyConfig {
    GameLobbyConfig {
        stakes: TableStakes {
            ante: 10,
            small_blind: 50,
            big_blind: 100,
        },
        max_players: 9,
        rake_bps: 500,
        name: "High Stakes ZK Poker".to_string(),
        currency: "CHIPS".to_string(),
        buy_in: 10_000,
        min_players_to_start: 6,
        check_raise_allowed: true,
        action_time_limit: Duration::from_secs(30),
    }
}

fn build_hand_config() -> HandConfig {
    HandConfig {
        stakes: TableStakes {
            ante: 10,
            small_blind: 50,
            big_blind: 100,
        },
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    }
}
