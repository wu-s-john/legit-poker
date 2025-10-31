// Interactive demo modules
pub mod dto;
pub mod handlers;
pub mod phase_execution;
pub mod session_factory;
pub mod session_store;
pub mod state;
pub mod stream_event;

// Public exports for interactive demo
pub use dto::CreateDemoResponse;
pub use handlers::{create_demo, stream_deal, stream_shuffle};
pub use session_store::DemoSessionStore;
pub use state::{DemoPhase, DemoState};
pub use stream_event::DemoStreamEvent;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{rngs::StdRng, SeedableRng};
use sea_orm::EntityTrait;

use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::hands;
use crate::game::coordinator::{GameCoordinator, ShufflerDescriptor};
use crate::ledger::lobby::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, GameMetadata, HandRecord,
    PlayerRecord, PlayerSeatSnapshot, ShufflerAssignment, ShufflerRecord,
    ShufflerRegistrationConfig,
};
use crate::ledger::serialization::deserialize_curve_hex;
use crate::ledger::snapshot::{rehydrate_snapshot, AnyTableSnapshot};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LobbyService;
use crate::shuffling::draw_shuffler_public_key;

use crate::engine::nl::types::{SeatId, TableStakes};

pub(crate) const DEMO_PLAYER_COUNT: usize = 7;
pub(crate) const NPC_COUNT: usize = DEMO_PLAYER_COUNT - 1;
pub(crate) const NPC_NAMES: [&str; NPC_COUNT] = [
    "demo-npc-1",
    "demo-npc-2",
    "demo-npc-3",
    "demo-npc-4",
    "demo-npc-5",
    "demo-npc-6",
];
pub(crate) const LOBBY_NAME: &str = "Coordinator Demo Table";
pub(crate) const LOBBY_CURRENCY: &str = "chips";
pub(crate) const VIEWER_NAME: &str = "demo-viewer";
pub(crate) const RNG_SEED: u64 = 1337;

pub struct SeedDemoResult<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub player_count: usize,
    pub outcome: CommenceGameOutcome<C>,
}

pub fn parse_viewer_public_key<C>(hex: &str) -> Result<C>
where
    C: CurveGroup + CanonicalDeserialize,
{
    deserialize_curve_hex(hex).context("invalid public_key")
}

pub async fn seed_demo_hand<C>(
    lobby: Arc<dyn LobbyService<C>>,
    coordinator: &GameCoordinator<C>,
    viewer_public_key: C,
) -> Result<SeedDemoResult<C>>
where
    C: CurveGroup
        + CurveAbsorb<C::BaseField>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + CanonicalSerialize + Send + Sync,
    C::Affine: Absorb,
{
    let shufflers = coordinator.shuffler_descriptors();
    if shufflers.is_empty() {
        return Err(anyhow!("coordinator has no shufflers configured"));
    }

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let lobby_config = build_lobby_config();

    let host_registration = PlayerRecord {
        display_name: VIEWER_NAME.into(),
        public_key: viewer_public_key.clone(),
        seat_preference: Some(0),
        state: MaybeSaved { id: None },
    };
    let metadata = lobby
        .host_game(host_registration, lobby_config.clone())
        .await
        .context("failed to host demo game")?;

    let players = seat_players::<C>(
        &lobby,
        &metadata,
        &lobby_config,
        viewer_public_key.clone(),
        &mut rng,
    )
    .await?;
    if players.len() != DEMO_PLAYER_COUNT {
        return Err(anyhow!(
            "expected {} players but prepared {}",
            DEMO_PLAYER_COUNT,
            players.len()
        ));
    }

    let shuffler_assignments = register_shufflers::<C>(&lobby, &metadata, &shufflers).await?;
    if shuffler_assignments.is_empty() {
        return Err(anyhow!("no shufflers registered for demo hand"));
    }

    let hand_config = build_hand_config();
    let player_count = players.len();
    let operator = coordinator.operator();
    let hasher = operator.state().hasher();
    let params = CommenceGameParams {
        game_id: metadata.record.state.id,
        hand_no: 1,
        button_seat: hand_config.button,
        small_blind_seat: hand_config.small_blind_seat,
        big_blind_seat: hand_config.big_blind_seat,
        deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
    };

    let outcome = lobby
        .commence_game(hasher.as_ref(), params)
        .await
        .context("failed to commence demo game")?;

    coordinator.state().upsert_snapshot(
        outcome.hand.state.id,
        AnyTableSnapshot::Shuffling(outcome.initial_snapshot.clone()),
        true,
    );

    Ok(SeedDemoResult {
        game_id: outcome.hand.game_id,
        hand_id: outcome.hand.state.id,
        player_count,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::entity::shufflers;
    use crate::db::{connect_to_postgres_db, postgres_test_url};
    use crate::game::coordinator::{GameCoordinator, GameCoordinatorConfig, ShufflerSecretConfig};
    use crate::ledger::serialization::serialize_curve_bytes;
    use crate::ledger::store::{SeaOrmEventStore, SeaOrmSnapshotStore, SnapshotStore};
    use crate::ledger::verifier::LedgerVerifier;
    use crate::ledger::LobbyService;
    use crate::ledger::{LedgerState, LobbyServiceFactory};
    use anyhow::Result;
    use ark_bn254::G1Projective as TestCurve;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};
    use sea_orm::ActiveModelTrait;
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm::{DbBackend, NotSet, Set, Statement};
    use std::sync::Arc;
    use url::Url;

    #[ignore]
    #[tokio::test]
    async fn seed_demo_hand_seeds_ledger_state() -> Result<()> {
        let url = postgres_test_url();
        let conn = match connect_to_postgres_db(&url).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("skipping demo test: failed to connect to postgres ({err})");
                return Ok(());
            }
        };

        if let Err(err) = conn.ping().await {
            eprintln!("skipping demo test: ping postgres failed ({err})");
            return Ok(());
        }

        if let Err(err) = reset_database(&conn).await {
            eprintln!("skipping demo test: failed to reset database ({err})");
            return Ok(());
        }

        let mut rng = StdRng::seed_from_u64(42);
        let shuffler_secret = <TestCurve as PrimeGroup>::ScalarField::rand(&mut rng);
        let shuffler_public = TestCurve::generator() * shuffler_secret;
        let public_key_bytes = serialize_curve_bytes(&shuffler_public)?;

        let shuffler_active = shufflers::ActiveModel {
            id: NotSet,
            display_name: Set("coordinator-shuffler-temp".to_string()),
            public_key: Set(public_key_bytes),
            created_at: NotSet,
        };
        let inserted = shuffler_active.insert(&conn).await?;
        let mut update_model: shufflers::ActiveModel = inserted.clone().into();
        update_model.display_name = Set(format!("coordinator-shuffler-{}", inserted.id));
        update_model.update(&conn).await?;

        let state = Arc::new(LedgerState::<TestCurve>::new());
        let event_store: Arc<dyn crate::ledger::EventStore<TestCurve>> =
            Arc::new(SeaOrmEventStore::<TestCurve>::new(conn.clone()));
        let snapshot_store: Arc<dyn SnapshotStore<TestCurve>> =
            Arc::new(SeaOrmSnapshotStore::<TestCurve>::new(conn.clone()));
        let verifier: Arc<dyn crate::ledger::Verifier<TestCurve> + Send + Sync> =
            Arc::new(LedgerVerifier::new(Arc::clone(&state)));

        let mut supabase_cfg = crate::game::coordinator::SupabaseRealtimeClientConfig::new(
            Url::parse("ws://localhost:12345/socket").expect("valid url"),
            "test-key",
        );
        supabase_cfg.handshake_timeout = std::time::Duration::from_millis(50);
        supabase_cfg.heartbeat_interval = std::time::Duration::from_secs(3600);
        supabase_cfg.reconnect_delay = std::time::Duration::from_millis(10);

        let shuffler_config = ShufflerSecretConfig::<TestCurve> {
            id: inserted.id,
            secret: shuffler_secret,
        };

        let coordinator_config = GameCoordinatorConfig {
            verifier,
            event_store,
            snapshot_store,
            state: Arc::clone(&state),
            supabase: supabase_cfg,
            shufflers: vec![shuffler_config],
            submit_channel_capacity: 32,
            rng_seed: Some([1u8; 32]),
        };

        let coordinator = match GameCoordinator::spawn(coordinator_config).await {
            Ok(coordinator) => coordinator,
            Err(err) => {
                eprintln!("skipping demo test: failed to spawn coordinator ({err})");
                return Ok(());
            }
        };

        let lobby: Arc<dyn LobbyService<TestCurve>> =
            Arc::new(LobbyServiceFactory::<TestCurve>::from_sea_orm(conn.clone()));

        let viewer_secret = <TestCurve as PrimeGroup>::ScalarField::rand(&mut rng);
        let viewer_public = TestCurve::generator() * viewer_secret;

        let seed_result = seed_demo_hand(Arc::clone(&lobby), &coordinator, viewer_public).await?;

        let tip_snapshot = coordinator
            .state()
            .tip_snapshot(seed_result.hand_id)
            .expect("ledger state should contain initial snapshot");
        let (_, snapshot) = tip_snapshot;
        match snapshot {
            AnyTableSnapshot::Shuffling(_) => {}
            _ => panic!("expected shuffling snapshot in ledger state"),
        }

        coordinator.shutdown().await?;
        Ok(())
    }

    async fn reset_database(conn: &DatabaseConnection) -> Result<()> {
        conn.execute(Statement::from_string(
            DbBackend::Postgres,
            "TRUNCATE TABLE \
                public.table_snapshots, \
                public.phases, \
                public.hand_configs, \
                public.events, \
                public.hand_shufflers, \
                public.hand_player, \
                public.hands, \
                public.game_shufflers, \
                public.game_players, \
                public.games, \
                public.shufflers, \
                public.players \
             RESTART IDENTITY CASCADE",
        ))
        .await?;
        Ok(())
    }
}

async fn seat_players<C>(
    lobby: &Arc<dyn LobbyService<C>>,
    metadata: &GameMetadata<C>,
    lobby_config: &GameLobbyConfig,
    viewer_public_key: C,
    rng: &mut StdRng,
) -> Result<Vec<PlayerSeatSnapshot<C>>>
where
    C: CurveGroup
        + CurveAbsorb<C::BaseField>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + CanonicalSerialize + Send + Sync,
    C::Affine: Absorb,
{
    let mut snapshots = Vec::with_capacity(DEMO_PLAYER_COUNT);

    let host_registration = PlayerRecord {
        display_name: metadata.host.display_name.clone(),
        public_key: metadata.host.public_key.clone(),
        seat_preference: Some(0),
        state: MaybeSaved {
            id: Some(metadata.host.state.id),
        },
    };
    let host_join = lobby
        .join_game(&metadata.record, host_registration, Some(0))
        .await
        .context("failed to seat viewer in demo game")?;

    snapshots.push(PlayerSeatSnapshot::new(
        host_join.player.clone(),
        0,
        lobby_config.buy_in,
        viewer_public_key.clone(),
    ));

    for (idx, spec) in generate_npc_specs::<C>(rng)?.into_iter().enumerate() {
        let seat = (idx + 1) as SeatId;
        let record = PlayerRecord {
            display_name: spec.display_name,
            public_key: spec.public_key.clone(),
            seat_preference: Some(seat),
            state: MaybeSaved { id: None },
        };
        let join = lobby
            .join_game(&metadata.record, record, Some(seat))
            .await
            .with_context(|| format!("failed to seat NPC at seat {}", seat))?;

        snapshots.push(PlayerSeatSnapshot::new(
            join.player.clone(),
            seat,
            lobby_config.buy_in,
            spec.public_key.clone(),
        ));
    }

    Ok(snapshots)
}

pub(crate) async fn register_shufflers<C>(
    lobby: &Arc<dyn LobbyService<C>>,
    metadata: &GameMetadata<C>,
    descriptors: &[ShufflerDescriptor<C>],
) -> Result<Vec<ShufflerAssignment<C>>>
where
    C: CurveGroup
        + CurveAbsorb<C::BaseField>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + CanonicalSerialize + Send + Sync,
    C::Affine: Absorb,
{
    let mut assignments: Vec<ShufflerAssignment<C>> = Vec::with_capacity(descriptors.len());

    for descriptor in descriptors {
        let record = ShufflerRecord {
            display_name: format!("coordinator-shuffler-{}", descriptor.shuffler_id),
            public_key: descriptor.public_key.value().clone(),
            state: MaybeSaved {
                id: Some(descriptor.shuffler_id),
            },
        };

        let registration = lobby
            .register_shuffler(
                &metadata.record,
                record,
                ShufflerRegistrationConfig {
                    sequence: Some(descriptor.turn_index as u16),
                },
            )
            .await
            .with_context(|| format!("failed to register shuffler {}", descriptor.shuffler_id))?;

        assignments.push(ShufflerAssignment::new(
            registration.shuffler.clone(),
            registration.assigned_sequence,
            descriptor.public_key.value().clone(),
            descriptor.aggregated_public_key.clone(),
        ));
    }

    Ok(assignments)
}

pub(crate) struct NpcSpec<C> {
    pub(crate) display_name: String,
    pub(crate) public_key: C,
}

pub(crate) fn generate_npc_specs<C>(rng: &mut StdRng) -> Result<Vec<NpcSpec<C>>>
where
    C: CurveGroup + CanonicalSerialize,
{
    let mut specs = Vec::with_capacity(NPC_COUNT);
    for name in NPC_NAMES {
        let (_, public_key) = draw_shuffler_public_key::<C, _>(rng);
        specs.push(NpcSpec {
            display_name: name.to_string(),
            public_key,
        });
    }
    Ok(specs)
}

pub(crate) fn build_lobby_config() -> GameLobbyConfig {
    GameLobbyConfig {
        stakes: TableStakes {
            small_blind: 50,
            big_blind: 100,
            ante: 0,
        },
        max_players: 9,
        rake_bps: 0,
        name: LOBBY_NAME.into(),
        currency: LOBBY_CURRENCY.into(),
        buy_in: 10_000,
        min_players_to_start: DEMO_PLAYER_COUNT as i16,
        check_raise_allowed: true,
        action_time_limit: Duration::from_secs(30),
    }
}

pub(crate) fn build_hand_config() -> crate::engine::nl::types::HandConfig {
    crate::engine::nl::types::HandConfig {
        stakes: TableStakes {
            small_blind: 50,
            big_blind: 100,
            ante: 0,
        },
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    }
}

pub async fn rehydrate_commence_outcome<C>(
    coordinator: &GameCoordinator<C>,
    game_id: GameId,
    hand_id: HandId,
) -> Result<CommenceGameOutcome<C>>
where
    C: CurveGroup
        + CurveAbsorb<C::BaseField>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync,
    C::BaseField: PrimeField + CanonicalSerialize + Send + Sync,
    C::Affine: Absorb,
{
    let event_store = coordinator.event_store();
    let db = event_store.connection();

    let hand = hands::Entity::find_by_id(hand_id)
        .one(db)
        .await?
        .context("hand not found")?;
    if hand.game_id != game_id {
        return Err(anyhow!(
            "hand {} belongs to game {}, not {}",
            hand_id,
            hand.game_id,
            game_id
        ));
    }

    let desired_hash = hand
        .current_state_hash
        .clone()
        .map(StateHash::from_bytes)
        .transpose()?;
    let snapshot = rehydrate_snapshot::<C>(db, game_id, hand_id, desired_hash).await?;
    let table = match snapshot {
        AnyTableSnapshot::Shuffling(table) => table,
        AnyTableSnapshot::Dealing(_)
        | AnyTableSnapshot::Preflop(_)
        | AnyTableSnapshot::Flop(_)
        | AnyTableSnapshot::Turn(_)
        | AnyTableSnapshot::River(_)
        | AnyTableSnapshot::Showdown(_)
        | AnyTableSnapshot::Complete(_) => {
            return Err(anyhow!(
                "expected shuffling snapshot while rehydrating commence outcome for hand {}",
                hand_id
            ));
        }
    };

    coordinator
        .state()
        .upsert_snapshot(hand_id, AnyTableSnapshot::Shuffling(table.clone()), true);

    let hand_record = HandRecord {
        game_id: hand.game_id,
        hand_no: hand.hand_no,
        status: hand.status,
        state: Saved { id: hand.id },
    };

    Ok(CommenceGameOutcome {
        hand: hand_record,
        nonce_seed: 0,
        initial_snapshot: table,
    })
}
