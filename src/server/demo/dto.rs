use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::Serialize;
use uuid::Uuid;

use crate::ledger::snapshot::TableAtShuffling;
use crate::ledger::types::{GameId, HandId};

/// Response payload for POST /games/demo endpoint.
#[derive(Serialize)]
#[serde(bound(serialize = "TableAtShuffling<C>: Serialize"))]
pub struct CreateDemoResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    /// Unique identifier for the demo session
    pub demo_id: Uuid,

    /// Game ID for this demo
    pub game_id: GameId,

    /// Hand ID for this demo
    pub hand_id: HandId,

    /// Viewer's public key (player 0)
    #[serde(with = "crate::crypto_serde::curve")]
    pub viewer_public_key: C,

    /// Initial table snapshot at shuffling phase
    pub initial_snapshot: TableAtShuffling<C>,
}

impl<C> CreateDemoResponse<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub fn new(
        demo_id: Uuid,
        game_id: GameId,
        hand_id: HandId,
        viewer_public_key: C,
        initial_snapshot: TableAtShuffling<C>,
    ) -> Self {
        Self {
            demo_id,
            game_id,
            hand_id,
            viewer_public_key,
            initial_snapshot,
        }
    }
}
