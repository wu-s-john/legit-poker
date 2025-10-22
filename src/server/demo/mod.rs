use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{rngs::StdRng, SeedableRng};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::Value as JsonValue;

use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::{
    hand_configs, hand_player, hand_shufflers, hands, phases, players, shufflers, table_snapshots,
};
use crate::game::coordinator::{GameCoordinator, ShufflerDescriptor};
use crate::ledger::lobby::types::{
    CommenceGameOutcome, CommenceGameParams, GameLobbyConfig, HandRecord, PlayerRecord,
    PlayerSeatSnapshot, ShufflerAssignment, ShufflerRecord, ShufflerRegistrationConfig,
};
use crate::ledger::lobby::LedgerLobby;
use crate::ledger::serialization::{
    canonical_deserialize_hex, deserialize_curve_bytes, deserialize_curve_hex,
    serialize_curve_bytes,
};
use crate::ledger::snapshot::{
    AnyTableSnapshot, PhaseShuffling, PlayerIdentity, PlayerRoster, PlayerStackInfo, PlayerStacks,
    SeatingMap, ShufflerIdentity, ShufflerRoster, ShufflingSnapshot, ShufflingStep, SnapshotStatus,
    TableSnapshot,
};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::ledger::typestate::{MaybeSaved, Saved};
use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
use crate::shuffling::draw_shuffler_public_key;

use crate::engine::nl::types::{PlayerStatus, SeatId, TableStakes};

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
    lobby: Arc<dyn LedgerLobby<C> + Send + Sync>,
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

    let players =
        seat_players::<C>(&lobby, &metadata, &lobby_config, viewer_bytes, &mut rng).await?;
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
    lobby: &Arc<dyn LedgerLobby<C> + Send + Sync>,
    metadata: &crate::ledger::lobby::types::GameMetadata,
    lobby_config: &GameLobbyConfig,
    viewer_bytes: Vec<u8>,
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
        viewer_bytes,
    ));

    for (idx, spec) in generate_npc_specs::<C>(rng)?.into_iter().enumerate() {
        let seat = (idx + 1) as SeatId;
        let record = PlayerRecord {
            display_name: spec.display_name,
            public_key: spec.public_key_bytes.clone(),
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
            spec.public_key_bytes,
        ));
    }

    Ok(snapshots)
}

async fn register_shufflers<C>(
    lobby: &Arc<dyn LedgerLobby<C> + Send + Sync>,
    metadata: &crate::ledger::lobby::types::GameMetadata,
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
    let mut assignments = Vec::with_capacity(descriptors.len());

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

struct NpcSpec {
    display_name: String,
    public_key_bytes: Vec<u8>,
}

fn generate_npc_specs<C>(rng: &mut StdRng) -> Result<Vec<NpcSpec>>
where
    C: CurveGroup,
{
    let mut specs = Vec::with_capacity(NPC_COUNT);
    for name in NPC_NAMES {
        let (_, public_key) = draw_shuffler_public_key::<C, _>(rng);
        let public_key_bytes =
            serialize_curve_bytes(&public_key).context("failed to serialize NPC key")?;
        specs.push(NpcSpec {
            display_name: name.to_string(),
            public_key_bytes,
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

    let hand_config_model = hand_configs::Entity::find_by_id(hand.hand_config_id)
        .one(db)
        .await?
        .context("hand config not found")?;
    let hand_config = hand_config_from_model(&hand_config_model)?;

    let snapshot_model = table_snapshots::Entity::find()
        .filter(table_snapshots::Column::GameId.eq(game_id))
        .filter(table_snapshots::Column::HandId.eq(hand_id))
        .order_by_asc(table_snapshots::Column::Sequence)
        .one(db)
        .await?
        .context("initial snapshot not found")?;

    let shuffling_hash = snapshot_model
        .shuffling_hash
        .clone()
        .context("snapshot missing shuffling phase hash")?;
    let shuffling_phase = phases::Entity::find_by_id(shuffling_hash.clone())
        .one(db)
        .await?
        .context("shuffling phase payload not found")?;

    let player_rows = hand_player::Entity::find()
        .filter(hand_player::Column::HandId.eq(hand_id))
        .order_by_asc(hand_player::Column::Seat)
        .all(db)
        .await?;
    let (player_roster, seating) = build_player_roster::<C>(db, &player_rows).await?;
    let player_stacks = parse_player_stacks::<C>(&snapshot_model.player_stacks)?;

    let shuffler_rows = hand_shufflers::Entity::find()
        .filter(hand_shufflers::Column::HandId.eq(hand_id))
        .order_by_asc(hand_shufflers::Column::Sequence)
        .all(db)
        .await?;
    let shuffler_roster = build_shuffler_roster::<C>(db, &shuffler_rows).await?;

    let shuffling_snapshot = parse_shuffling_snapshot::<C>(&shuffling_phase.payload)?;

    let sequence = u32::try_from(snapshot_model.sequence)
        .map_err(|_| anyhow!("snapshot sequence {} out of range", snapshot_model.sequence))?;
    let state_hash = state_hash_from_vec(snapshot_model.state_hash.clone())?;
    let previous_hash = match snapshot_model.previous_hash.clone() {
        Some(bytes) => Some(state_hash_from_vec(bytes)?),
        None => None,
    };
    let status = match snapshot_model.application_status {
        crate::db::entity::sea_orm_active_enums::ApplicationStatus::Success => {
            SnapshotStatus::Success
        }
        crate::db::entity::sea_orm_active_enums::ApplicationStatus::Failure => {
            SnapshotStatus::Failure(
                snapshot_model
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| "unknown failure".to_string()),
            )
        }
    };

    let table = TableSnapshot::<PhaseShuffling, C> {
        game_id,
        hand_id: Some(hand_id),
        sequence,
        cfg: Arc::new(hand_config),
        shufflers: Arc::new(shuffler_roster),
        players: Arc::new(player_roster),
        seating: Arc::new(seating),
        stacks: Arc::new(player_stacks),
        previous_hash,
        state_hash,
        status,
        shuffling: shuffling_snapshot,
        dealing: (),
        betting: (),
        reveals: (),
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

fn hand_config_from_model(
    model: &hand_configs::Model,
) -> Result<crate::engine::nl::types::HandConfig> {
    Ok(crate::engine::nl::types::HandConfig {
        stakes: TableStakes {
            small_blind: u64::try_from(model.small_blind)
                .map_err(|_| anyhow!("small blind exceeds u64 range"))?,
            big_blind: u64::try_from(model.big_blind)
                .map_err(|_| anyhow!("big blind exceeds u64 range"))?,
            ante: u64::try_from(model.ante).map_err(|_| anyhow!("ante exceeds u64 range"))?,
        },
        button: u8::try_from(model.button_seat)
            .map_err(|_| anyhow!("button seat exceeds u8 range"))?,
        small_blind_seat: u8::try_from(model.small_blind_seat)
            .map_err(|_| anyhow!("small blind seat exceeds u8 range"))?,
        big_blind_seat: u8::try_from(model.big_blind_seat)
            .map_err(|_| anyhow!("big blind seat exceeds u8 range"))?,
        check_raise_allowed: model.check_raise_allowed,
    })
}

fn state_hash_from_vec(bytes: Vec<u8>) -> Result<StateHash> {
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("state hash must be 32 bytes"))?;
    Ok(StateHash::from(array))
}

async fn build_player_roster<C>(
    db: &sea_orm::DatabaseConnection,
    rows: &[hand_player::Model],
) -> Result<(PlayerRoster<C>, SeatingMap<C>)>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let mut roster: PlayerRoster<C> = BTreeMap::new();
    let mut seating: SeatingMap<C> = BTreeMap::new();

    let player_ids: Vec<i64> = rows.iter().map(|row| row.player_id).collect();
    let player_models = players::Entity::find()
        .filter(players::Column::Id.is_in(player_ids.clone()))
        .all(db)
        .await?;

    let player_map: HashMap<i64, players::Model> = player_models
        .into_iter()
        .map(|model| (model.id, model))
        .collect();

    for row in rows {
        let seat =
            u8::try_from(row.seat).map_err(|_| anyhow!("seat {} exceeds u8 range", row.seat))?;
        let player_id = u64::try_from(row.player_id)
            .map_err(|_| anyhow!("player id {} exceeds u64 range", row.player_id))?;
        let nonce = u64::try_from(row.nonce)
            .map_err(|_| anyhow!("nonce {} exceeds u64 range", row.nonce))?;

        let player = player_map
            .get(&row.player_id)
            .context("player row missing public key")?;
        let public_key = deserialize_curve_bytes::<C>(&player.public_key)
            .context("failed to deserialize player public key")?;
        let player_key = crate::ledger::CanonicalKey::new(public_key.clone());

        roster.insert(
            player_key.clone(),
            PlayerIdentity {
                public_key,
                player_key: player_key.clone(),
                player_id,
                nonce,
                seat,
            },
        );
        seating.insert(seat, Some(player_key));
    }

    Ok((roster, seating))
}

fn parse_player_stacks<C>(value: &JsonValue) -> Result<PlayerStacks<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    match serde_json::from_value::<PlayerStacks<C>>(value.clone()) {
        Ok(stacks) => Ok(stacks),
        Err(primary_err) => {
            let entries = value.as_array().ok_or_else(|| {
                anyhow!("player stacks payload not array-compatible: {primary_err}")
            })?;

            let mut stacks: PlayerStacks<C> = BTreeMap::new();
            for entry in entries {
                let seat = entry
                    .get("seat")
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(|| anyhow!("player stack entry missing seat"))?;
                let player_key = entry
                    .get("player_key")
                    .cloned()
                    .map(|value| serde_json::from_value::<crate::ledger::CanonicalKey<C>>(value))
                    .transpose()
                    .context("failed to deserialize player canonical key")?;
                let starting_stack = entry
                    .get("starting_stack")
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(|| anyhow!("player stack entry missing starting_stack"))?;
                let committed_blind = entry
                    .get("committed_blind")
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(|| anyhow!("player stack entry missing committed_blind"))?;
                let status_label = entry
                    .get("status")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| anyhow!("player stack entry missing status"))?;
                let status = parse_player_status(status_label)?;

                stacks.insert(
                    u8::try_from(seat).map_err(|_| anyhow!("seat {} exceeds u8 range", seat))?,
                    PlayerStackInfo {
                        seat: u8::try_from(seat)
                            .map_err(|_| anyhow!("seat {} exceeds u8 range", seat))?,
                        player_key,
                        starting_stack,
                        committed_blind,
                        status,
                    },
                );
            }

            Ok(stacks)
        }
    }
}

async fn build_shuffler_roster<C>(
    db: &sea_orm::DatabaseConnection,
    rows: &[hand_shufflers::Model],
) -> Result<ShufflerRoster<C>>
where
    C: CurveGroup + CanonicalDeserialize + Clone,
{
    let shuffler_ids: Vec<i64> = rows.iter().map(|row| row.shuffler_id).collect();
    let shuffler_models = shufflers::Entity::find()
        .filter(shufflers::Column::Id.is_in(shuffler_ids.clone()))
        .all(db)
        .await?;
    let shuffler_map: HashMap<i64, shufflers::Model> = shuffler_models
        .into_iter()
        .map(|model| (model.id, model))
        .collect();

    let mut points = Vec::with_capacity(rows.len());
    for row in rows {
        let model = shuffler_map
            .get(&row.shuffler_id)
            .context("shuffler row missing public key")?;
        let point = deserialize_curve_bytes::<C>(&model.public_key)
            .context("failed to deserialize shuffler public key")?;
        points.push((row.shuffler_id, point));
    }

    let aggregated = points
        .iter()
        .fold(C::zero(), |acc, (_, pk)| acc + pk.clone());

    let mut roster: ShufflerRoster<C> = BTreeMap::new();
    for (shuffler_id, point) in points {
        let canonical = crate::ledger::CanonicalKey::new(point.clone());
        roster.insert(
            canonical.clone(),
            ShufflerIdentity {
                public_key: point,
                shuffler_key: canonical,
                shuffler_id,
                aggregated_public_key: aggregated.clone(),
            },
        );
    }

    Ok(roster)
}

fn parse_shuffling_snapshot<C>(value: &JsonValue) -> Result<ShufflingSnapshot<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::BaseField: CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    if let Ok(snapshot) = serde_json::from_value::<ShufflingSnapshot<C>>(value.clone()) {
        return Ok(snapshot);
    }

    let initial = value
        .get("initial_deck")
        .context("shuffling payload missing initial_deck")?
        .as_array()
        .context("initial_deck is not an array")?
        .iter()
        .map(parse_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;
    let initial: [ElGamalCiphertext<C>; DECK_SIZE] = initial
        .try_into()
        .map_err(|_| anyhow!("initial deck length mismatch"))?;

    let steps_value = value
        .get("steps")
        .context("shuffling payload missing steps")?
        .as_array()
        .context("steps is not an array")?;
    let mut steps = Vec::with_capacity(steps_value.len());
    for step in steps_value {
        let pk_hex = step
            .get("shuffler_public_key")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("shuffle step missing public key"))?;
        let public_key = deserialize_curve_hex::<C>(pk_hex)
            .context("failed to deserialize shuffle step public key")?;
        let proof_value = step.get("proof").context("shuffle step missing proof")?;
        let proof = parse_shuffle_proof::<C>(proof_value)?;
        steps.push(ShufflingStep {
            shuffler_public_key: public_key,
            proof,
        });
    }

    let final_deck = value
        .get("final_deck")
        .context("shuffling payload missing final_deck")?
        .as_array()
        .context("final_deck is not an array")?
        .iter()
        .map(parse_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;
    let final_deck: [ElGamalCiphertext<C>; DECK_SIZE] = final_deck
        .try_into()
        .map_err(|_| anyhow!("final deck length mismatch"))?;

    let expected_order = value
        .get("expected_order")
        .context("shuffling payload missing expected_order")?
        .as_array()
        .context("expected_order is not an array")?
        .iter()
        .map(|entry| {
            serde_json::from_value::<crate::ledger::CanonicalKey<C>>(entry.clone())
                .context("expected_order entry not a canonical key")
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ShufflingSnapshot {
        initial_deck: initial,
        steps,
        final_deck,
        expected_order,
    })
}

fn parse_ciphertext<C>(value: &JsonValue) -> Result<ElGamalCiphertext<C>>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let c1_hex = value
        .get("c1")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("ciphertext missing c1"))?;
    let c2_hex = value
        .get("c2")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("ciphertext missing c2"))?;
    let c1 = deserialize_curve_hex::<C>(c1_hex).context("failed to deserialize c1")?;
    let c2 = deserialize_curve_hex::<C>(c2_hex).context("failed to deserialize c2")?;
    Ok(ElGamalCiphertext::new(c1, c2))
}

fn parse_shuffle_proof<C>(value: &JsonValue) -> Result<ShuffleProof<C>>
where
    C: CurveGroup + CanonicalDeserialize,
    C::BaseField: CanonicalDeserialize,
    C::ScalarField: CanonicalDeserialize,
{
    if let Ok(proof) = serde_json::from_value::<ShuffleProof<C>>(value.clone()) {
        return Ok(proof);
    }

    let input_deck = value
        .get("input_deck")
        .context("shuffle proof missing input_deck")?
        .as_array()
        .context("input_deck is not an array")?
        .iter()
        .map(parse_ciphertext::<C>)
        .collect::<Result<Vec<_>>>()?;

    let sorted_deck_entries = value
        .get("sorted_deck")
        .context("shuffle proof missing sorted_deck")?
        .as_array()
        .context("sorted_deck is not an array")?;
    let mut sorted_deck = Vec::with_capacity(sorted_deck_entries.len());
    for entry in sorted_deck_entries {
        let cipher_value = entry
            .get("ciphertext")
            .context("sorted deck entry missing ciphertext")?;
        let cipher = parse_ciphertext::<C>(cipher_value)?;
        let randomizer_hex = entry
            .get("randomizer")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("sorted deck entry missing randomizer"))?;
        let randomizer = canonical_deserialize_hex::<C::BaseField>(randomizer_hex)
            .context("failed to deserialize shuffle proof randomizer")?;
        sorted_deck.push((cipher, randomizer));
    }

    let rerand_values = value
        .get("rerandomization_values")
        .context("shuffle proof missing rerandomization_values")?
        .as_array()
        .context("rerandomization_values is not an array")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("rerandomization value not a string"))
                .and_then(|hex| {
                    canonical_deserialize_hex::<C::ScalarField>(hex)
                        .context("failed to deserialize rerandomization value")
                })
        })
        .collect::<Result<Vec<_>>>()?;

    ShuffleProof::new(input_deck, sorted_deck, rerand_values)
        .map_err(|err| anyhow!("invalid shuffle proof: {err}"))
}

fn parse_player_status(label: &str) -> Result<PlayerStatus> {
    match label {
        "active" => Ok(PlayerStatus::Active),
        "folded" => Ok(PlayerStatus::Folded),
        "all_in" => Ok(PlayerStatus::AllIn),
        "sitting_out" => Ok(PlayerStatus::SittingOut),
        other => Err(anyhow!("unknown player status {other}")),
    }
}
