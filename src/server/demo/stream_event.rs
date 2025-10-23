use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::Serialize;

use crate::engine::nl::types::SeatId;
use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::snapshot::TableAtShuffling;
use crate::ledger::types::{GameId, HandId};
use crate::showdown::Index as CardIndex;

/// Events emitted over the demo streaming endpoint.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DemoStreamEvent<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    /// Viewer player registration (NPCs are not emitted).
    PlayerCreated {
        game_id: GameId,
        seat: SeatId,
        display_name: String,
        #[serde(with = "crate::crypto_serde::curve")]
        public_key: C,
    },

    /// Hand has been commenced and the initial shuffling snapshot is ready.
    HandCreated {
        game_id: GameId,
        hand_id: HandId,
        player_count: usize,
        snapshot: TableAtShuffling<C>,
    },

    /// Raw ledger activity (shuffle proofs, dealing messages, etc.).
    #[serde(bound(serialize = "FinalizedAnyMessageEnvelope<C>: Serialize"))]
    GameEvent {
        #[serde(flatten)]
        envelope: FinalizedAnyMessageEnvelope<C>,
    },

    /// Community board decrypted on the backend (0-based card indices).
    CommunityDecrypted {
        game_id: GameId,
        hand_id: HandId,
        cards: Vec<CardIndex>,
    },

    /// Viewer hole cards decrypted (0-based card indices).
    HoleCardsDecrypted {
        game_id: GameId,
        hand_id: HandId,
        seat: SeatId,
        cards: [CardIndex; 2],
    },
}
