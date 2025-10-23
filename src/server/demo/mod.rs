pub mod stream_event;

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
use crate::ledger::serialization::{deserialize_curve_hex, serialize_curve_bytes};
use crate::ledger::snapshot::{rehydrate_snapshot, AnyTableSnapshot};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::ledger::LobbyService;
use crate::shuffling::draw_shuffler_public_key;

use crate::engine::nl::types::{SeatId, TableStakes};

const DEMO_PLAYER_COUNT: usize = 8;
const NPC_COUNT: usize = DEMO_PLAYER_COUNT - 1;
const NPC_NAMES: [&str; NPC_COUNT] = [
    "demo-npc-1",
    "demo-npc-2",
    "demo-npc-3",
    "demo-npc-4",
    "demo-npc-5",
    "demo-npc-6",
    "demo-npc-7",
];
const LOBBY_NAME: &str = "Coordinator Demo Table";
const LOBBY_CURRENCY: &str = "chips";
const VIEWER_NAME: &str = "demo-viewer";
const RNG_SEED: u64 = 1337;

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
    let viewer_bytes = serialize_curve_bytes(&viewer_public_key)
        .context("failed to serialize viewer public key")?;

    let shufflers = coordinator.shuffler_descriptors();
    if shufflers.is_empty() {
        return Err(anyhow!("coordinator has no shufflers configured"));
    }

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let lobby_config = build_lobby_config();

    let host_registration = PlayerRecord {
        display_name: VIEWER_NAME.into(),
        public_key: viewer_bytes.clone(),
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
    let params = CommenceGameParams {
        game: metadata.record.clone(),
        hand_no: 1,
        hand_config,
        players,
        shufflers: shuffler_assignments,
        deck_commitment: None,
        buy_in: lobby_config.buy_in,
        min_players: lobby_config.min_players_to_start,
    };

    let outcome = lobby
        .commence_game(operator.as_ref(), params)
        .await
        .context("failed to commence demo game")?;

    Ok(SeedDemoResult {
        game_id: outcome.hand.game_id,
        hand_id: outcome.hand.state.id,
        player_count,
        outcome,
    })
}

async fn seat_players<C>(
    lobby: &Arc<dyn LobbyService<C>>,
    metadata: &GameMetadata,
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
        let public_key_bytes = serialize_curve_bytes(&spec.public_key)
            .context("failed to serialize NPC public key")?;
        let record = PlayerRecord {
            display_name: spec.display_name,
            public_key: public_key_bytes.clone(),
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

async fn register_shufflers<C>(
    lobby: &Arc<dyn LobbyService<C>>,
    metadata: &GameMetadata,
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
        let public_key_bytes = serialize_curve_bytes(descriptor.public_key.value())
            .context("failed to serialize shuffler public key")?;
        let aggregated_bytes = serialize_curve_bytes(&descriptor.aggregated_public_key)
            .context("failed to serialize aggregated shuffler key")?;

        let record = ShufflerRecord {
            display_name: format!("demo-shuffler-{}", descriptor.turn_index.saturating_add(1)),
            public_key: public_key_bytes.clone(),
            state: MaybeSaved { id: None },
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
            public_key_bytes,
            aggregated_bytes,
        ));
    }

    Ok(assignments)
}

struct NpcSpec<C> {
    display_name: String,
    public_key: C,
}

fn generate_npc_specs<C>(rng: &mut StdRng) -> Result<Vec<NpcSpec<C>>>
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

fn build_lobby_config() -> GameLobbyConfig {
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

fn build_hand_config() -> crate::engine::nl::types::HandConfig {
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
