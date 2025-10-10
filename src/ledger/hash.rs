use std::sync::Arc;

use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::ledger::messages::{EnvelopedMessage, GameMessage};
use crate::ledger::snapshot::{HandPhase, TableSnapshot};
use crate::ledger::types::{GameId, HandId, StateHash};
use crate::poseidon_config;
use crate::signing::{Signable, TranscriptBuilder};

use crate::shuffling::data_structures::append_curve_point;

/// Trait abstracting over the hashing backend used by the ledger.
pub trait LedgerHasher: Send + Sync {
    fn hash(&self, message: &[u8]) -> StateHash;
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

fn append_ids(builder: &mut TranscriptBuilder, game_id: GameId, hand_id: Option<HandId>) {
    builder.append_i64(game_id);
    match hand_id {
        Some(id) => {
            builder.append_u8(1);
            builder.append_i64(id);
        }
        None => builder.append_u8(0),
    }
}

pub fn initial_snapshot_hash<P, C>(
    snapshot: &TableSnapshot<P, C>,
    hasher: &dyn LedgerHasher,
) -> StateHash
where
    P: HandPhase<C>,
    C: CurveGroup,
{
    let mut builder = TranscriptBuilder::new("ledger/state/init");
    append_ids(&mut builder, snapshot.game_id, snapshot.hand_id);

    match snapshot.cfg.as_ref() {
        Some(cfg) => {
            builder.append_u8(1);
            cfg.write_transcript(&mut builder);
        }
        None => builder.append_u8(0),
    }

    snapshot.shufflers.as_ref().write_transcript(&mut builder);
    snapshot.players.as_ref().write_transcript(&mut builder);
    snapshot.seating.as_ref().write_transcript(&mut builder);
    snapshot.stacks.as_ref().write_transcript(&mut builder);

    hasher.hash(&builder.finish())
}

pub fn message_hash<C, M>(envelope: &EnvelopedMessage<C, M>, hasher: &dyn LedgerHasher) -> StateHash
where
    C: CurveGroup,
    M: GameMessage<C> + Signable,
    M::Actor: Signable,
{
    let mut builder = TranscriptBuilder::new("ledger/state/msg");
    append_ids(&mut builder, envelope.game_id, Some(envelope.hand_id));
    builder.append_u64(envelope.nonce);
    envelope.actor.write_transcript(&mut builder);

    append_curve_point(&mut builder, &envelope.public_key);
    builder.append_bytes(&envelope.message.transcript);

    hasher.hash(&builder.finish())
}

pub fn chain_hash(previous: StateHash, message: StateHash, hasher: &dyn LedgerHasher) -> StateHash {
    let mut builder = TranscriptBuilder::new("ledger/state/chain");
    builder.append_bytes(previous.as_bytes());
    builder.append_bytes(message.as_bytes());
    hasher.hash(&builder.finish())
}
