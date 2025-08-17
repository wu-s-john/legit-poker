//! Core domain types for ZK Poker backend

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod game_state;
pub mod transcript;

pub use game_state::*;
pub use transcript::*;

/// ---------- Common type aliases ----------
pub type RoomId = i32;
pub type UserId = String;
pub type ShufflerId = String;
pub type CorrelationId = String;
pub type HashHex = String;
pub type PublicKey = String;
pub type Base64 = String;

/// ---------- Enums ----------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomStatus {
    Waiting,
    Playing,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    Player,
    Shuffler,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Command,
    Event,
    Proof,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Player,
    Spectator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Street {
    Preflop,
    Flop,
    Turn,
    River,
    Showdown,
}

/// Actor identity (type + id string)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub r#type: ActorType,
    pub id: String,
}

/// A reference to a logical card instance
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CardRef(pub String);

/// Encrypted card under ElGamal scheme
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardCiphertext {
    pub alpha: Base64,
    pub beta: Base64,
}

/// Plaintext card representation (1..52)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct CardPlain(pub u8);

/// ---------- Shuffler ----------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShufflerPublic {
    pub id: ShufflerId,
    pub pk_shuffle: PublicKey,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShufflerSecret {
    pub sk_shuffle: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Shuffler {
    pub public: ShufflerPublic,
    pub secret: Option<ShufflerSecret>,
}

/// ---------- Player ----------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerPublic {
    pub id: UserId,
    pub role: MemberRole,
    pub seat: Option<u8>,
    pub pk_player: Option<PublicKey>,
    pub stack: Option<i64>,
    pub last_proof_ms: Option<u32>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlayerSecret {
    pub sk_player: Vec<u8>,
    pub hole_cards: Option<[CardPlain; 2]>,
}

#[derive(Debug, Clone)]
pub struct Player {
    pub public: PlayerPublic,
    pub secret: Option<PlayerSecret>,
}
