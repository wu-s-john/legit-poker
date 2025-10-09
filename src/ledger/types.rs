use crate::engine::nl::types::{PlayerId, SeatId};
use serde::Serialize;

pub type GameId = i64;
pub type HandId = i64;
pub type ShufflerId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum EntityKind {
    Player,
    Shuffler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum HandStatus {
    Pending,
    Shuffling,
    Dealing,
    Betting,
    Showdown,
    Complete,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ActorKind {
    Player {
        seat_id: SeatId,
        player_id: PlayerId,
    },
    Shuffler {
        shuffler_id: ShufflerId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct NonceKey {
    pub hand_id: HandId,
    pub entity_kind: EntityKind,
    pub entity_id: i64,
}

pub type SignatureBytes = Vec<u8>;
pub type PublicKeyBytes = Vec<u8>;
