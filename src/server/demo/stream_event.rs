use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use serde::Serialize;

use crate::engine::nl::types::SeatId;
use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::snapshot::TableAtShuffling;
use crate::ledger::types::{GameId, HandId};
use crate::showdown::Card;

/// Events emitted over the demo streaming endpoint.
#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    bound(serialize = "TableAtShuffling<C>: Serialize, FinalizedAnyMessageEnvelope<C>: Serialize")
)]
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
        shuffler_count: usize,
        snapshot: TableAtShuffling<C>,
    },

    /// Raw ledger activity (shuffle proofs, dealing messages, etc.).
    #[serde(bound(serialize = "FinalizedAnyMessageEnvelope<C>: Serialize"))]
    GameEvent {
        #[serde(flatten)]
        envelope: FinalizedAnyMessageEnvelope<C>,
    },

    /// Community board decrypted on the backend (revealed cards).
    CommunityDecrypted {
        game_id: GameId,
        hand_id: HandId,
        cards: Vec<Card>,
    },

    /// A player can now decrypt their card (has all unblinding shares).
    CardDecryptable {
        game_id: GameId,
        hand_id: HandId,
        seat: SeatId,
        card_position: usize,
    },

    /// Single hole card decrypted (revealed card value).
    /// Emitted once per card for real-time reveals.
    HoleCardsDecrypted {
        game_id: GameId,
        hand_id: HandId,
        seat: SeatId,
        card_position: usize,
        card: Card,
    },

    /// Hand considered complete for demo purposes.
    HandCompleted { game_id: GameId, hand_id: HandId },
}

impl<C> DemoStreamEvent<C>
where
    C: CurveGroup + CanonicalSerialize,
{
    pub fn event_name(&self) -> &'static str {
        match self {
            DemoStreamEvent::PlayerCreated { .. } => "player_created",
            DemoStreamEvent::HandCreated { .. } => "hand_created",
            DemoStreamEvent::GameEvent { .. } => "game_event",
            DemoStreamEvent::CommunityDecrypted { .. } => "community_decrypted",
            DemoStreamEvent::CardDecryptable { .. } => "card_decryptable",
            DemoStreamEvent::HoleCardsDecrypted { .. } => "hole_cards_decrypted",
            DemoStreamEvent::HandCompleted { .. } => "hand_completed",
        }
    }
}
