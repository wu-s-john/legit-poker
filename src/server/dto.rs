use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::types::{GameId, HandId};

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
#[serde(bound(serialize = "C: CanonicalSerialize"))]
pub struct LatestSnapshotResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub snapshot: AnyTableSnapshot<C>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<FinalizedAnyMessageEnvelope<C>>>,
}

impl<C> LatestSnapshotResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub fn from_domain(snapshot: AnyTableSnapshot<C>) -> Self {
        Self {
            snapshot,
            messages: None,
        }
    }

    pub fn from_domain_with_messages(
        snapshot: AnyTableSnapshot<C>,
        messages: Option<Vec<FinalizedAnyMessageEnvelope<C>>>,
    ) -> Self {
        Self { snapshot, messages }
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
