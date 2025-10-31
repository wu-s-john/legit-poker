use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info};
use uuid::Uuid;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::types::{GameId, HandId};

use super::state::{DemoPhase, DemoState};

const LOG_TARGET: &str = "legit_poker::server::demo::session_store";
const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60); // 1 minute

/// In-memory store for demo sessions with TTL-based cleanup.
pub struct DemoSessionStore<C>
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
    sessions: Arc<RwLock<HashMap<Uuid, DemoState<C>>>>,
    ttl: Duration,
    cleanup_handle: Option<JoinHandle<()>>,
}

impl<C> DemoSessionStore<C>
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
    /// Create a new session store with default TTL.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    /// Create a new session store with custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let cleanup_handle = Self::start_cleanup_task(Arc::clone(&sessions), ttl);

        info!(
            target: LOG_TARGET,
            ttl_secs = ttl.as_secs(),
            cleanup_interval_secs = CLEANUP_INTERVAL.as_secs(),
            "Demo session store initialized"
        );

        Self {
            sessions,
            ttl,
            cleanup_handle: Some(cleanup_handle),
        }
    }

    /// Start background cleanup task that runs every CLEANUP_INTERVAL.
    fn start_cleanup_task(
        sessions: Arc<RwLock<HashMap<Uuid, DemoState<C>>>>,
        ttl: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;

                let mut sessions_lock = sessions.write().await;
                let initial_count = sessions_lock.len();

                sessions_lock.retain(|id, state| {
                    let expired = state.is_expired(ttl);
                    if expired {
                        debug!(
                            target: LOG_TARGET,
                            demo_id = %id,
                            phase = ?state.phase,
                            age_secs = state.created_at.elapsed().as_secs(),
                            "Evicting expired demo session"
                        );
                    }
                    !expired
                });

                let evicted_count = initial_count - sessions_lock.len();
                if evicted_count > 0 {
                    info!(
                        target: LOG_TARGET,
                        evicted_count,
                        remaining_count = sessions_lock.len(),
                        "Cleaned up expired demo sessions"
                    );
                }
            }
        })
    }

    /// Insert a new demo session.
    pub async fn create_session(&self, state: DemoState<C>) -> Uuid {
        let id = state.id;
        let mut sessions = self.sessions.write().await;
        sessions.insert(id, state);

        debug!(
            target: LOG_TARGET,
            demo_id = %id,
            total_sessions = sessions.len(),
            "Created new demo session"
        );

        id
    }

    /// Get a mutable reference to a demo session by ID and update its last_accessed timestamp.
    /// The closure receives a mutable reference to the state for in-place updates.
    pub async fn with_session<F, R>(&self, id: Uuid, f: F) -> Option<R>
    where
        F: FnOnce(&mut DemoState<C>) -> R,
    {
        let mut sessions = self.sessions.write().await;
        if let Some(state) = sessions.get_mut(&id) {
            state.touch();
            Some(f(state))
        } else {
            debug!(
                target: LOG_TARGET,
                demo_id = %id,
                "Demo session not found"
            );
            None
        }
    }

    /// Get a copy of session data for read-only access.
    /// Note: This clones the entire state, use sparingly.
    pub async fn get_session_data(&self, id: Uuid) -> Option<(GameId, HandId, DemoPhase)> {
        let mut sessions = self.sessions.write().await;
        if let Some(state) = sessions.get_mut(&id) {
            state.touch();
            Some((state.game_id, state.hand_id, state.phase))
        } else {
            debug!(
                target: LOG_TARGET,
                demo_id = %id,
                "Demo session not found"
            );
            None
        }
    }

    /// Update an existing demo session.
    pub async fn update_session(&self, state: DemoState<C>) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let id = state.id;

        if sessions.contains_key(&id) {
            sessions.insert(id, state);
            debug!(
                target: LOG_TARGET,
                demo_id = %id,
                "Updated demo session"
            );
            Ok(())
        } else {
            Err(format!("Demo session {} not found", id))
        }
    }

    /// Remove and return a demo session by ID (for taking ownership).
    pub async fn take_session(&self, id: Uuid) -> Option<DemoState<C>> {
        let mut sessions = self.sessions.write().await;
        let removed = sessions.remove(&id);

        if removed.is_some() {
            info!(
                target: LOG_TARGET,
                demo_id = %id,
                remaining_sessions = sessions.len(),
                "Took demo session from store"
            );
        }

        removed
    }

    /// Remove a demo session by ID without returning it (for eviction after completion).
    pub async fn remove_session(&self, id: Uuid) -> bool {
        let mut sessions = self.sessions.write().await;
        let removed = sessions.remove(&id).is_some();

        if removed {
            info!(
                target: LOG_TARGET,
                demo_id = %id,
                remaining_sessions = sessions.len(),
                "Removed demo session"
            );
        }

        removed
    }

    /// Get current number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

impl<C> Drop for DemoSessionStore<C>
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
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
            info!(target: LOG_TARGET, "Demo session store cleanup task aborted");
        }
    }
}

impl<C> Default for DemoSessionStore<C>
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
    fn default() -> Self {
        Self::new()
    }
}

