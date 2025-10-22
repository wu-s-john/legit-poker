use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::query::LatestSnapshot;
use crate::ledger::serialization::encode_state_hash;
use crate::ledger::snapshot::{SnapshotSeq, SnapshotStatus};
use crate::ledger::types::{EventPhase, GameId, HandId};

#[derive(Deserialize)]
pub struct DemoCreateRequest {
    pub public_key: String,
}

#[derive(Serialize)]
pub struct DemoCreateResponse {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub player_count: usize,
}

#[derive(Serialize)]
pub struct DemoStartResponse {
    pub status: &'static str,
}

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
#[serde(bound(serialize = "C: CanonicalSerialize"))]
pub struct HandMessagesResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub game_id: GameId,
    pub hand_id: HandId,
    pub messages: Vec<FinalizedAnyMessageEnvelope<C>>,
}

impl<C> HandMessagesResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub fn try_from_events(
        game_id: GameId,
        hand_id: HandId,
        events: Vec<FinalizedAnyMessageEnvelope<C>>,
    ) -> Result<Self> {
        // Validate that all events match the requested game_id and hand_id
        for event in &events {
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
        }

        Ok(Self {
            game_id,
            hand_id,
            messages: events,
        })
    }
}



