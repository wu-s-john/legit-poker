use std::sync::Arc;

use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

use crate::ledger::messages::{EnvelopedMessage, GameMessage};
use crate::ledger::snapshot::{HandPhase, TableSnapshot};
use crate::ledger::types::StateHash;
use crate::poseidon_config;
use crate::signing::DomainSeparated;

/// Trait abstracting over the hashing backend used by the ledger.
pub trait LedgerHasher: Send + Sync {
    fn hash(&self, message: &[u8]) -> StateHash;
}

impl<T> LedgerHasher for Arc<T>
where
    T: LedgerHasher + ?Sized,
{
    fn hash(&self, message: &[u8]) -> StateHash {
        (**self).hash(message)
    }
}

/// Poseidon-based hasher suitable for SNARK-friendly usage.
pub struct LedgerHasherPoseidon<F: PrimeField> {
    params: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>,
}

impl<F: PrimeField> LedgerHasherPoseidon<F> {
    pub fn new(params: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>) -> Self {
        Self { params }
    }
}

impl<F: PrimeField> LedgerHasher for LedgerHasherPoseidon<F> {
    fn hash(&self, message: &[u8]) -> StateHash {
        let mut sponge = PoseidonSponge::<F>::new(&self.params);
        sponge.absorb(&message);
        let output = sponge.squeeze_bytes(32);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&output[..32]);
        StateHash::from(bytes)
    }
}

/// SHA-256 fallback hasher, useful for tests or tooling.
pub struct LedgerHasherSha256;

impl LedgerHasher for LedgerHasherSha256 {
    fn hash(&self, message: &[u8]) -> StateHash {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        StateHash::from(bytes)
    }
}

pub fn default_poseidon_hasher<F: PrimeField>() -> Arc<dyn LedgerHasher + Send + Sync> {
    Arc::new(LedgerHasherPoseidon::new(poseidon_config::<F>()))
}

pub fn initial_snapshot_hash<P, C>(
    snapshot: &TableSnapshot<P, C>,
    hasher: &dyn LedgerHasher,
) -> StateHash
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    let mut bytes = Vec::new();
    // Domain separation
    bytes.extend_from_slice(b"ledger/state/init\0");

    // Serialize snapshot metadata
    snapshot
        .game_id
        .serialize_compressed(&mut bytes)
        .expect("game_id serialization should not fail");

    // Serialize optional hand_id
    if let Some(hand_id) = snapshot.hand_id {
        1u8.serialize_compressed(&mut bytes)
            .expect("u8 serialization should not fail");
        hand_id
            .serialize_compressed(&mut bytes)
            .expect("hand_id serialization should not fail");
    } else {
        0u8.serialize_compressed(&mut bytes)
            .expect("u8 serialization should not fail");
    }

    // Version byte
    1u8.serialize_compressed(&mut bytes)
        .expect("u8 serialization should not fail");

    // Serialize snapshot state
    // Dereference Arc to get HandConfig
    snapshot
        .cfg
        .as_ref()
        .serialize_compressed(&mut bytes)
        .expect("cfg serialization should not fail");

    // Serialize BTreeMaps by serializing their entries
    let shufflers_count = snapshot.shufflers.len() as u64;
    shufflers_count
        .serialize_compressed(&mut bytes)
        .expect("shufflers count serialization should not fail");
    for (key, value) in snapshot.shufflers.as_ref().iter() {
        key.serialize_compressed(&mut bytes)
            .expect("shuffler key serialization should not fail");
        value
            .serialize_compressed(&mut bytes)
            .expect("shuffler value serialization should not fail");
    }

    let players_count = snapshot.players.len() as u64;
    players_count
        .serialize_compressed(&mut bytes)
        .expect("players count serialization should not fail");
    for (key, value) in snapshot.players.as_ref().iter() {
        key.serialize_compressed(&mut bytes)
            .expect("player key serialization should not fail");
        value
            .serialize_compressed(&mut bytes)
            .expect("player value serialization should not fail");
    }

    snapshot
        .seating
        .as_ref()
        .serialize_compressed(&mut bytes)
        .expect("seating serialization should not fail");

    let stacks_count = snapshot.stacks.len() as u64;
    stacks_count
        .serialize_compressed(&mut bytes)
        .expect("stacks count serialization should not fail");
    for (seat, stack_info) in snapshot.stacks.as_ref().iter() {
        seat.serialize_compressed(&mut bytes)
            .expect("seat serialization should not fail");
        stack_info
            .serialize_compressed(&mut bytes)
            .expect("stack info serialization should not fail");
    }

    hasher.hash(&bytes)
}

pub fn message_hash<C, M>(envelope: &EnvelopedMessage<C, M>, hasher: &dyn LedgerHasher) -> StateHash
where
    C: CurveGroup,
    M: GameMessage<C> + CanonicalSerialize + DomainSeparated,
    M::Actor: CanonicalSerialize,
{
    let mut bytes = Vec::new();
    // Domain separation
    bytes.extend_from_slice(b"ledger/state/msg\0");

    // Serialize envelope metadata
    envelope
        .game_id
        .serialize_compressed(&mut bytes)
        .expect("game_id serialization should not fail");
    envelope
        .hand_id
        .serialize_compressed(&mut bytes)
        .expect("hand_id serialization should not fail");
    envelope
        .nonce
        .serialize_compressed(&mut bytes)
        .expect("nonce serialization should not fail");
    envelope
        .actor
        .serialize_compressed(&mut bytes)
        .expect("actor serialization should not fail");
    envelope
        .public_key
        .serialize_compressed(&mut bytes)
        .expect("public_key serialization should not fail");

    // Serialize message payload using signing_bytes (which includes message's domain tag)
    let signing_bytes = crate::signing::signing_bytes(&envelope.message.value)
        .expect("canonical serialization should not fail for valid messages");
    bytes.extend_from_slice(&signing_bytes);

    hasher.hash(&bytes)
}

pub fn chain_hash(previous: StateHash, message: StateHash, hasher: &dyn LedgerHasher) -> StateHash {
    let mut bytes = Vec::new();
    // Domain separation
    bytes.extend_from_slice(b"ledger/state/chain\0");
    // Serialize previous and message state hashes
    bytes.extend_from_slice(previous.as_bytes());
    bytes.extend_from_slice(message.as_bytes());
    hasher.hash(&bytes)
}
