use serde::{Deserialize, Serialize};

pub type GameId = i64;
pub type HandId = i64;
pub type ShufflerId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    Player,
    Shuffler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandStatus {
    Pending,
    Shuffling,
    Dealing,
    Betting,
    Showdown,
    Complete,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventPhase {
    Pending,
    Shuffling,
    Dealing,
    Betting,
    Reveals,
    Showdown,
    Complete,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NonceKey {
    pub hand_id: HandId,
    pub entity_kind: EntityKind,
    pub entity_id: i64,
}

pub type SignatureBytes = Vec<u8>;
pub type PublicKeyBytes = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateHash([u8; 32]);

impl StateHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Default for StateHash {
    fn default() -> Self {
        Self::zero()
    }
}

impl AsRef<[u8; 32]> for StateHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for StateHash {
    fn from(bytes: [u8; 32]) -> Self {
        StateHash::new(bytes)
    }
}

impl From<StateHash> for [u8; 32] {
    fn from(hash: StateHash) -> Self {
        hash.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::serde::assert_round_trip_eq;

    #[test]
    fn ledger_enums_round_trip_with_serde() {
        assert_round_trip_eq(&EntityKind::Shuffler);
        assert_round_trip_eq(&HandStatus::Showdown);
        assert_round_trip_eq(&EventPhase::Reveals);
    }

    #[test]
    fn nonce_key_round_trips_with_serde() {
        let key = NonceKey {
            hand_id: 12,
            entity_kind: EntityKind::Player,
            entity_id: 44,
        };
        assert_round_trip_eq(&key);
    }
}
