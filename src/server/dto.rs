use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::Serialize;

use crate::engine::nl::types::{PlayerId, SeatId};
use crate::ledger::actor::AnyActor;
use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::query::LatestSnapshot;
use crate::ledger::serialization::{encode_state_hash, serialize_curve_hex};
use crate::ledger::snapshot::{SnapshotSeq, SnapshotStatus};
use crate::ledger::store::event::StoredGameMessage;
use crate::ledger::types::{EventPhase, GameId, HandId, ShufflerId};

#[derive(Serialize)]
pub struct LatestSnapshotResponse {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub sequence: SnapshotSeq,
    pub state_hash: String,
    pub previous_hash: Option<String>,
    pub phase: SnapshotPhaseResponse,
    pub status: SnapshotStatusResponse,
    pub snapshot_debug: String,
}

impl LatestSnapshotResponse {
    pub fn from_domain(snapshot: LatestSnapshot) -> Self {
        Self {
            game_id: snapshot.game_id,
            hand_id: snapshot.hand_id,
            sequence: snapshot.sequence,
            state_hash: encode_state_hash(snapshot.state_hash),
            previous_hash: snapshot.previous_hash.map(encode_state_hash),
            phase: SnapshotPhaseResponse::from(snapshot.phase),
            status: SnapshotStatusResponse::from(snapshot.status),
            snapshot_debug: snapshot.snapshot_debug,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPhaseResponse {
    Pending,
    Shuffling,
    Dealing,
    Betting,
    Reveals,
    Showdown,
    Complete,
    Cancelled,
}

impl From<EventPhase> for SnapshotPhaseResponse {
    fn from(phase: EventPhase) -> Self {
        match phase {
            EventPhase::Pending => SnapshotPhaseResponse::Pending,
            EventPhase::Shuffling => SnapshotPhaseResponse::Shuffling,
            EventPhase::Dealing => SnapshotPhaseResponse::Dealing,
            EventPhase::Betting => SnapshotPhaseResponse::Betting,
            EventPhase::Reveals => SnapshotPhaseResponse::Reveals,
            EventPhase::Showdown => SnapshotPhaseResponse::Showdown,
            EventPhase::Complete => SnapshotPhaseResponse::Complete,
            EventPhase::Cancelled => SnapshotPhaseResponse::Cancelled,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatusResponse {
    Success,
    Failure { reason: String },
}

impl From<SnapshotStatus> for SnapshotStatusResponse {
    fn from(value: SnapshotStatus) -> Self {
        match value {
            SnapshotStatus::Success => SnapshotStatusResponse::Success,
            SnapshotStatus::Failure(reason) => SnapshotStatusResponse::Failure { reason },
        }
    }
}

#[derive(Serialize)]
pub struct HandMessagesResponse {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub messages: Vec<HandMessageResponse>,
}

impl HandMessagesResponse {
    pub fn try_from_events<C>(
        game_id: GameId,
        hand_id: HandId,
        events: Vec<FinalizedAnyMessageEnvelope<C>>,
    ) -> Result<Self>
    where
        C: CurveGroup + CanonicalSerialize,
    {
        let mut messages = Vec::with_capacity(events.len());
        for event in events {
            if event.envelope.hand_id != hand_id {
                return Err(anyhow!(
                    "event hand id {} does not match requested {hand_id}",
                    event.envelope.hand_id
                ));
            }
            if event.envelope.game_id != game_id {
                return Err(anyhow!(
                    "event game id {} does not match requested {game_id}",
                    event.envelope.game_id
                ));
            }
            messages.push(HandMessageResponse::try_from_event(event)?);
        }

        Ok(Self {
            game_id,
            hand_id,
            messages,
        })
    }
}

#[derive(Serialize)]
pub struct HandMessageResponse {
    pub sequence: SnapshotSeq,
    pub nonce: u64,
    pub status: SnapshotStatusResponse,
    pub phase: SnapshotPhaseResponse,
    pub message_type: MessageTypeResponse,
    pub actor: ActorResponse,
    pub public_key: String,
    pub signature: String,
    pub payload: serde_json::Value,
}

impl HandMessageResponse {
    fn try_from_event<C>(event: FinalizedAnyMessageEnvelope<C>) -> Result<Self>
    where
        C: CurveGroup + CanonicalSerialize,
    {
        let stored = StoredGameMessage::from_any(&event.envelope.message.value)?;
        let message_type = MessageTypeResponse::from(&stored);
        let payload = serde_json::to_value(&stored)?;

        let status = SnapshotStatusResponse::from(event.snapshot_status.clone());
        let phase = SnapshotPhaseResponse::from(event.applied_phase);
        let actor = ActorResponse::from(&event.envelope.actor);
        let public_key = serialize_curve_hex(&event.envelope.public_key)?;
        let signature = hex::encode(&event.envelope.message.signature);

        Ok(Self {
            sequence: event.snapshot_sequence_id,
            nonce: event.envelope.nonce,
            status,
            phase,
            message_type,
            actor,
            public_key,
            signature,
            payload,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageTypeResponse {
    Shuffle,
    Blinding,
    PartialUnblinding,
    PlayerPreflop,
    PlayerFlop,
    PlayerTurn,
    PlayerRiver,
    Showdown,
}

impl From<&StoredGameMessage> for MessageTypeResponse {
    fn from(message: &StoredGameMessage) -> Self {
        match message {
            StoredGameMessage::Shuffle { .. } => MessageTypeResponse::Shuffle,
            StoredGameMessage::Blinding { .. } => MessageTypeResponse::Blinding,
            StoredGameMessage::PartialUnblinding { .. } => MessageTypeResponse::PartialUnblinding,
            StoredGameMessage::PlayerPreflop { .. } => MessageTypeResponse::PlayerPreflop,
            StoredGameMessage::PlayerFlop { .. } => MessageTypeResponse::PlayerFlop,
            StoredGameMessage::PlayerTurn { .. } => MessageTypeResponse::PlayerTurn,
            StoredGameMessage::PlayerRiver { .. } => MessageTypeResponse::PlayerRiver,
            StoredGameMessage::Showdown { .. } => MessageTypeResponse::Showdown,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorResponse {
    None,
    Player {
        seat_id: SeatId,
        player_id: PlayerId,
    },
    Shuffler {
        shuffler_id: ShufflerId,
    },
}

impl ActorResponse {
    fn from(actor: &AnyActor) -> Self {
        match actor {
            AnyActor::None => ActorResponse::None,
            AnyActor::Player { seat_id, player_id } => ActorResponse::Player {
                seat_id: *seat_id,
                player_id: *player_id,
            },
            AnyActor::Shuffler { shuffler_id } => ActorResponse::Shuffler {
                shuffler_id: *shuffler_id,
            },
        }
    }
}
