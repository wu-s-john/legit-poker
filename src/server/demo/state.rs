use std::sync::Arc;
use std::time::Instant;

use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::{PlayerId, SeatId};
use crate::ledger::lobby::types::PlayerRecord;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::types::{GameId, HandId};
use crate::ledger::typestate::Saved;
use crate::shuffler::{ShufflerEngine, ShufflerHandState};

type Schnorr254<C> = Schnorr<C, Sha256>;

/// Phase of the interactive demo session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemoPhase {
    /// Session created, waiting for shuffle to start
    Initialized,
    /// Shuffle in progress
    Shuffling,
    /// Shuffle complete, waiting for deal to start
    ShuffleComplete,
    /// Dealing in progress
    Dealing,
    /// All phases complete
    Complete,
}

impl DemoPhase {
    /// Check if transition from current phase to target phase is valid.
    pub fn can_transition_to(&self, target: DemoPhase) -> bool {
        use DemoPhase::*;
        matches!(
            (self, target),
            (Initialized, Shuffling)
                | (Shuffling, ShuffleComplete)
                | (ShuffleComplete, Dealing)
                | (Dealing, Complete)
        )
    }
}

/// State for an interactive demo session.
pub struct DemoState<C>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    /// Unique identifier for this demo session
    pub id: Uuid,

    /// Game ID associated with this demo
    pub game_id: GameId,

    /// Hand ID associated with this demo
    pub hand_id: HandId,

    /// Current phase of the demo
    pub phase: DemoPhase,

    /// Nonce seed for the hand
    pub nonce_seed: u64,

    /// Table snapshot that transitions through phases (Shuffling → Dealing)
    pub snapshot: AnyTableSnapshot<C>,

    /// Shuffler engines for cryptographic operations
    pub shuffler_engines: Vec<ShufflerEngine<C, Schnorr254<C>>>,

    /// Shuffler hand states for each shuffler
    pub shuffler_states: Vec<ShufflerHandState<C>>,

    /// Player records with seat assignments
    pub player_records: Vec<(PlayerRecord<C, Saved<PlayerId>>, SeatId)>,

    /// Player keys (secret, public) for each player
    pub player_keys: Vec<(C::ScalarField, C)>,

    /// Aggregated public key from all shufflers
    pub aggregated_public_key: C,

    /// Random number generator for this session
    pub rng: StdRng,

    /// Notification for shuffle phase completion
    pub shuffle_complete_notify: Arc<Notify>,

    /// Timestamp when session was created
    pub created_at: Instant,

    /// Timestamp of last access (for TTL)
    pub last_accessed: Instant,
}

impl<C> DemoState<C>
where
    C: CurveGroup
        + CanonicalSerialize
        + CanonicalDeserialize
        + CurveAbsorb<C::BaseField>
        + Send
        + Sync
        + 'static,
    C::ScalarField: PrimeField + UniformRand + Absorb + CanonicalSerialize + Send + Sync + Clone,
    C::BaseField: PrimeField + Send + Sync,
    C::Affine: Absorb + CanonicalSerialize,
{
    /// Create a new demo state in Initialized phase.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        game_id: GameId,
        hand_id: HandId,
        nonce_seed: u64,
        snapshot: AnyTableSnapshot<C>,
        shuffler_engines: Vec<ShufflerEngine<C, Schnorr254<C>>>,
        shuffler_states: Vec<ShufflerHandState<C>>,
        player_records: Vec<(PlayerRecord<C, Saved<PlayerId>>, SeatId)>,
        player_keys: Vec<(C::ScalarField, C)>,
        aggregated_public_key: C,
        rng: StdRng,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            game_id,
            hand_id,
            phase: DemoPhase::Initialized,
            nonce_seed,
            snapshot,
            shuffler_engines,
            shuffler_states,
            player_records,
            player_keys,
            aggregated_public_key,
            rng,
            shuffle_complete_notify: Arc::new(Notify::new()),
            created_at: now,
            last_accessed: now,
        }
    }

    /// Update last accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    /// Transition to a new phase if valid.
    pub fn transition_to(&mut self, target: DemoPhase) -> Result<(), String> {
        if !self.phase.can_transition_to(target) {
            return Err(format!(
                "Invalid phase transition from {:?} to {:?}",
                self.phase, target
            ));
        }
        self.phase = target;
        self.touch();
        Ok(())
    }

    /// Check if session has expired based on TTL.
    pub fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.last_accessed.elapsed() > ttl
    }
}
