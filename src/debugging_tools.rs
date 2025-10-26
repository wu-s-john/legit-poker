use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context, Result};
use sea_orm::prelude::TimeDateTimeWithTimeZone;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use serde_json::Value as JsonValue;
use time::format_description::well_known::Rfc3339;

use crate::db::entity::sea_orm_active_enums::{
    ApplicationStatus, EventPhase, GameStatus, HandStatus, PhaseKind,
};
use crate::db::entity::{
    events, game_shufflers, games, hand_configs, hand_player, hand_shufflers, hands, phases,
    players, shufflers, table_snapshots,
};

/// Archive payload with pre-formatted values for debugging output.
#[derive(Debug, serde::Serialize)]
pub struct HandArchive {
    pub game: GameRecord,
    pub hand: HandSummary,
    pub players: Vec<HandPlayerEntry>,
    pub shufflers: Vec<HandShufflerEntry>,
    pub events: Option<Vec<EventRecord>>,
    pub snapshots: Option<Vec<TableSnapshotRecord>>,
    pub phases: Option<Vec<PhaseRecord>>,
}

#[derive(Debug, serde::Serialize)]
pub struct GameRecord {
    pub id: i64,
    pub created_at: String,
    pub host_player_id: i64,
    pub name: String,
    pub currency: String,
    pub max_players: i16,
    pub small_blind: i64,
    pub big_blind: i64,
    pub ante: i64,
    pub rake_bps: i16,
    pub status: GameStatus,
    pub current_hand_id: Option<i64>,
    pub current_state_hash: Option<String>,
    pub current_phase: Option<PhaseKind>,
    pub default_hand_config_id: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct HandSummary {
    pub hand: HandRecord,
    pub config: HandConfigRecord,
}

#[derive(Debug, serde::Serialize)]
pub struct HandRecord {
    pub id: i64,
    pub game_id: i64,
    pub created_at: String,
    pub hand_no: i64,
    pub button_seat: i16,
    pub small_blind_seat: i16,
    pub big_blind_seat: i16,
    pub deck_commitment: Option<String>,
    pub status: HandStatus,
    pub current_sequence: i32,
    pub current_state_hash: Option<String>,
    pub current_phase: Option<PhaseKind>,
    pub hand_config_id: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct HandConfigRecord {
    pub id: i64,
    pub game_id: i64,
    pub small_blind: i64,
    pub big_blind: i64,
    pub ante: i64,
    pub button_seat: i16,
    pub small_blind_seat: i16,
    pub big_blind_seat: i16,
    pub check_raise_allowed: bool,
    pub created_at: String,
}

#[derive(Debug, serde::Serialize)]
pub struct HandPlayerEntry {
    pub seat: HandPlayerSeat,
    pub player: PlayerRecord,
}

#[derive(Debug, serde::Serialize)]
pub struct HandPlayerSeat {
    pub id: i64,
    pub game_id: i64,
    pub hand_id: i64,
    pub player_id: i64,
    pub seat: i16,
    pub nonce: i64,
    pub joined_at: String,
}

#[derive(Debug, serde::Serialize)]
pub struct PlayerRecord {
    pub id: i64,
    pub display_name: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Debug, serde::Serialize)]
pub struct HandShufflerEntry {
    pub assignment: HandShufflerAssignment,
    pub shuffler: ShufflerRecord,
    pub game_assignment: Option<GameShufflerRecord>,
}

#[derive(Debug, serde::Serialize)]
pub struct HandShufflerAssignment {
    pub hand_id: i64,
    pub shuffler_id: i64,
    pub sequence: i16,
}

#[derive(Debug, serde::Serialize)]
pub struct ShufflerRecord {
    pub id: i64,
    pub display_name: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GameShufflerRecord {
    pub game_id: i64,
    pub shuffler_id: i64,
    pub sequence: i16,
    pub public_key: String,
    pub joined_at: String,
}

#[derive(Debug, serde::Serialize)]
pub struct EventRecord {
    pub id: i64,
    pub game_id: i64,
    pub hand_id: i64,
    pub entity_kind: i16,
    pub entity_id: i64,
    pub actor_kind: i16,
    pub seat_id: Option<i16>,
    pub shuffler_id: Option<i16>,
    pub public_key: String,
    pub nonce: i64,
    pub phase: EventPhase,
    pub snapshot_number: i32,
    pub is_successful: bool,
    pub failure_message: Option<String>,
    pub resulting_phase: EventPhase,
    pub message_type: String,
    pub payload: JsonValue,
    pub signature: String,
    pub inserted_at: String,
}

#[derive(Debug, serde::Serialize)]
pub struct TableSnapshotRecord {
    pub snapshot_hash: String,
    pub game_id: i64,
    pub hand_id: i64,
    pub sequence: i32,
    pub state_hash: String,
    pub previous_hash: Option<String>,
    pub hand_config_id: i64,
    pub player_stacks: JsonValue,
    pub shuffling_hash: Option<String>,
    pub dealing_hash: Option<String>,
    pub betting_hash: Option<String>,
    pub reveals_hash: Option<String>,
    pub created_at: String,
    pub application_status: ApplicationStatus,
    pub failure_reason: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct PhaseRecord {
    pub hash: String,
    pub phase_type: PhaseKind,
    pub payload: JsonValue,
    pub message_id: Option<i64>,
    pub created_at: String,
}

/// Load the complete hand archive for debugging purposes.
pub async fn fetch_hand_archive(
    conn: &DatabaseConnection,
    game_id: i64,
    hand_id: i64,
    include_events: bool,
    include_snapshots: bool,
) -> Result<HandArchive> {
    let game = games::Entity::find_by_id(game_id)
        .one(conn)
        .await?
        .context(format!("game {game_id} not found"))?;

    let hand = hands::Entity::find()
        .filter(hands::Column::Id.eq(hand_id))
        .filter(hands::Column::GameId.eq(game_id))
        .one(conn)
        .await?
        .context(format!("hand {hand_id} not found in game {game_id}"))?;

    let config = hand_configs::Entity::find_by_id(hand.hand_config_id)
        .one(conn)
        .await?
        .context(format!(
            "hand_config {} referenced by hand {hand_id} not found",
            hand.hand_config_id
        ))?;

    let players = load_players(conn, game_id, hand_id).await?;
    let shufflers = load_shufflers(conn, game_id, hand_id).await?;

    let events = if include_events {
        Some(
            events::Entity::find()
                .filter(events::Column::GameId.eq(game_id))
                .filter(events::Column::HandId.eq(hand_id))
                .order_by_asc(events::Column::SnapshotNumber)
                .order_by_asc(events::Column::Id)
                .all(conn)
                .await?
                .into_iter()
                .map(EventRecord::from)
                .collect(),
        )
    } else {
        None
    };

    let (snapshots, phases) = if include_snapshots {
        let snapshot_models = table_snapshots::Entity::find()
            .filter(table_snapshots::Column::GameId.eq(game_id))
            .filter(table_snapshots::Column::HandId.eq(hand_id))
            .order_by_asc(table_snapshots::Column::Sequence)
            .all(conn)
            .await?;

        let phase_hashes: HashSet<Vec<u8>> = snapshot_models
            .iter()
            .flat_map(|row| {
                [
                    row.shuffling_hash.clone(),
                    row.dealing_hash.clone(),
                    row.betting_hash.clone(),
                    row.reveals_hash.clone(),
                ]
                .into_iter()
                .flatten()
            })
            .collect();

        let phases = if phase_hashes.is_empty() {
            Vec::new()
        } else {
            phases::Entity::find()
                .filter(phases::Column::Hash.is_in(phase_hashes.into_iter().collect::<Vec<_>>()))
                .order_by_asc(phases::Column::CreatedAt)
                .all(conn)
                .await?
        };

        let snapshot_records = snapshot_models
            .into_iter()
            .map(TableSnapshotRecord::from)
            .collect();
        let phase_records = phases.into_iter().map(PhaseRecord::from).collect();

        (Some(snapshot_records), Some(phase_records))
    } else {
        (None, None)
    };

    Ok(HandArchive {
        game: GameRecord::from(game),
        hand: HandSummary {
            hand: HandRecord::from(hand),
            config: HandConfigRecord::from(config),
        },
        players,
        shufflers,
        events,
        snapshots,
        phases,
    })
}

impl From<games::Model> for GameRecord {
    fn from(model: games::Model) -> Self {
        let games::Model {
            id,
            created_at,
            host_player_id,
            name,
            currency,
            max_players,
            small_blind,
            big_blind,
            ante,
            rake_bps,
            status,
            buy_in: _,
            min_players_to_start: _,
            check_raise_allowed: _,
            action_time_limit_secs: _,
            current_hand_id,
            current_state_hash,
            current_phase,
            default_hand_config_id,
        } = model;

        Self {
            id,
            created_at: format_timestamp(created_at),
            host_player_id,
            name,
            currency,
            max_players,
            small_blind,
            big_blind,
            ante,
            rake_bps,
            status,
            current_hand_id,
            current_state_hash: current_state_hash.map(bytes_to_hex),
            current_phase,
            default_hand_config_id,
        }
    }
}

impl From<hands::Model> for HandRecord {
    fn from(model: hands::Model) -> Self {
        let hands::Model {
            id,
            game_id,
            created_at,
            hand_no,
            button_seat,
            small_blind_seat,
            big_blind_seat,
            deck_commitment,
            status,
            current_sequence,
            current_state_hash,
            current_phase,
            hand_config_id,
        } = model;

        Self {
            id,
            game_id,
            created_at: format_timestamp(created_at),
            hand_no,
            button_seat,
            small_blind_seat,
            big_blind_seat,
            deck_commitment: deck_commitment.map(bytes_to_hex),
            status,
            current_sequence,
            current_state_hash: current_state_hash.map(bytes_to_hex),
            current_phase,
            hand_config_id,
        }
    }
}

impl From<hand_configs::Model> for HandConfigRecord {
    fn from(model: hand_configs::Model) -> Self {
        let hand_configs::Model {
            id,
            game_id,
            small_blind,
            big_blind,
            ante,
            button_seat,
            small_blind_seat,
            big_blind_seat,
            check_raise_allowed,
            created_at,
        } = model;

        Self {
            id,
            game_id,
            small_blind,
            big_blind,
            ante,
            button_seat,
            small_blind_seat,
            big_blind_seat,
            check_raise_allowed,
            created_at: format_timestamp(created_at),
        }
    }
}

impl From<hand_player::Model> for HandPlayerSeat {
    fn from(model: hand_player::Model) -> Self {
        let hand_player::Model {
            id,
            game_id,
            hand_id,
            player_id,
            seat,
            nonce,
            starting_stack: _,
            joined_at,
        } = model;

        Self {
            id,
            game_id,
            hand_id,
            player_id,
            seat,
            nonce,
            joined_at: format_timestamp(joined_at),
        }
    }
}

impl From<players::Model> for PlayerRecord {
    fn from(model: players::Model) -> Self {
        let players::Model {
            id,
            display_name,
            public_key,
            created_at,
        } = model;

        Self {
            id,
            display_name,
            public_key: bytes_to_hex(public_key),
            created_at: format_timestamp(created_at),
        }
    }
}

impl From<hand_shufflers::Model> for HandShufflerAssignment {
    fn from(model: hand_shufflers::Model) -> Self {
        let hand_shufflers::Model {
            hand_id,
            shuffler_id,
            sequence,
        } = model;

        Self {
            hand_id,
            shuffler_id,
            sequence,
        }
    }
}

impl From<shufflers::Model> for ShufflerRecord {
    fn from(model: shufflers::Model) -> Self {
        let shufflers::Model {
            id,
            display_name,
            public_key,
            created_at,
        } = model;

        Self {
            id,
            display_name,
            public_key: bytes_to_hex(public_key),
            created_at: format_timestamp(created_at),
        }
    }
}

impl From<game_shufflers::Model> for GameShufflerRecord {
    fn from(model: game_shufflers::Model) -> Self {
        let game_shufflers::Model {
            game_id,
            shuffler_id,
            sequence,
            public_key,
            joined_at,
        } = model;

        Self {
            game_id,
            shuffler_id,
            sequence,
            public_key: bytes_to_hex(public_key),
            joined_at: format_timestamp(joined_at),
        }
    }
}

impl From<events::Model> for EventRecord {
    fn from(model: events::Model) -> Self {
        let events::Model {
            id,
            game_id,
            hand_id,
            entity_kind,
            entity_id,
            actor_kind,
            seat_id,
            shuffler_id,
            public_key,
            nonce,
            phase,
            snapshot_number,
            is_successful,
            failure_message,
            resulting_phase,
            message_type,
            payload,
            signature,
            inserted_at,
        } = model;

        Self {
            id,
            game_id,
            hand_id,
            entity_kind,
            entity_id,
            actor_kind,
            seat_id,
            shuffler_id,
            public_key: bytes_to_hex(public_key),
            nonce,
            phase,
            snapshot_number,
            is_successful,
            failure_message,
            resulting_phase,
            message_type,
            payload,
            signature: bytes_to_hex(signature),
            inserted_at: format_timestamp(inserted_at),
        }
    }
}

impl From<table_snapshots::Model> for TableSnapshotRecord {
    fn from(model: table_snapshots::Model) -> Self {
        let table_snapshots::Model {
            snapshot_hash,
            game_id,
            hand_id,
            sequence,
            state_hash,
            previous_hash,
            hand_config_id,
            player_stacks,
            shuffling_hash,
            dealing_hash,
            betting_hash,
            reveals_hash,
            created_at,
            application_status,
            failure_reason,
        } = model;

        Self {
            snapshot_hash: bytes_to_hex(snapshot_hash),
            game_id,
            hand_id,
            sequence,
            state_hash: bytes_to_hex(state_hash),
            previous_hash: previous_hash.map(bytes_to_hex),
            hand_config_id,
            player_stacks,
            shuffling_hash: shuffling_hash.map(bytes_to_hex),
            dealing_hash: dealing_hash.map(bytes_to_hex),
            betting_hash: betting_hash.map(bytes_to_hex),
            reveals_hash: reveals_hash.map(bytes_to_hex),
            created_at: format_timestamp(created_at),
            application_status,
            failure_reason,
        }
    }
}

impl From<phases::Model> for PhaseRecord {
    fn from(model: phases::Model) -> Self {
        let phases::Model {
            hash,
            phase_type,
            payload,
            message_id,
            created_at,
        } = model;

        Self {
            hash: bytes_to_hex(hash),
            phase_type,
            payload,
            message_id,
            created_at: format_timestamp(created_at),
        }
    }
}

async fn load_players(
    conn: &DatabaseConnection,
    game_id: i64,
    hand_id: i64,
) -> Result<Vec<HandPlayerEntry>> {
    let rows = hand_player::Entity::find()
        .filter(hand_player::Column::GameId.eq(game_id))
        .filter(hand_player::Column::HandId.eq(hand_id))
        .order_by_asc(hand_player::Column::Seat)
        .find_also_related(players::Entity)
        .all(conn)
        .await?;

    rows.into_iter()
        .map(|(seat, player)| {
            let player = player.ok_or_else(|| {
                anyhow!(
                    "player {} referenced by hand_player row {} missing",
                    seat.player_id,
                    seat.id
                )
            })?;
            Ok(HandPlayerEntry {
                seat: HandPlayerSeat::from(seat),
                player: PlayerRecord::from(player),
            })
        })
        .collect()
}

async fn load_shufflers(
    conn: &DatabaseConnection,
    game_id: i64,
    hand_id: i64,
) -> Result<Vec<HandShufflerEntry>> {
    let assignments = hand_shufflers::Entity::find()
        .filter(hand_shufflers::Column::HandId.eq(hand_id))
        .order_by_asc(hand_shufflers::Column::Sequence)
        .find_also_related(shufflers::Entity)
        .all(conn)
        .await?;

    let mut shuffler_ids = Vec::with_capacity(assignments.len());
    for (assignment, _) in &assignments {
        shuffler_ids.push(assignment.shuffler_id);
    }

    let game_shuffler_map: HashMap<i64, GameShufflerRecord> = if shuffler_ids.is_empty() {
        HashMap::new()
    } else {
        game_shufflers::Entity::find()
            .filter(game_shufflers::Column::GameId.eq(game_id))
            .filter(game_shufflers::Column::ShufflerId.is_in(shuffler_ids.clone()))
            .all(conn)
            .await?
            .into_iter()
            .map(|row| (row.shuffler_id, GameShufflerRecord::from(row)))
            .collect()
    };

    assignments
        .into_iter()
        .map(|(assignment, shuffler)| {
            let shuffler = shuffler.ok_or_else(|| {
                anyhow!(
                    "shuffler {} referenced by hand_shufflers row ({}, {}) missing",
                    assignment.shuffler_id,
                    assignment.hand_id,
                    assignment.sequence
                )
            })?;

            let game_assignment = game_shuffler_map.get(&assignment.shuffler_id).cloned();

            Ok(HandShufflerEntry {
                assignment: HandShufflerAssignment::from(assignment),
                shuffler: ShufflerRecord::from(shuffler),
                game_assignment,
            })
        })
        .collect()
}

fn format_timestamp(ts: TimeDateTimeWithTimeZone) -> String {
    ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string())
}

fn bytes_to_hex(bytes: Vec<u8>) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&hex::encode(bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_hex_prefix() {
        assert_eq!(bytes_to_hex(vec![0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
    }

    #[test]
    fn format_timestamp_rfc3339() {
        let ts =
            TimeDateTimeWithTimeZone::from_unix_timestamp_nanos(1_697_000_000_000_000_000).unwrap();
        let formatted = format_timestamp(ts);
        assert!(formatted.contains('T'));
        assert!(formatted.contains('Z') || formatted.contains('+'));
    }
}
