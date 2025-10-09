use std::sync::Arc;

use ark_ec::CurveGroup;

use super::messages::{ActionEnvelope, VerifiedEnvelope};
use super::queue::LedgerQueue;
use super::state::LedgerState;
use super::store::EventStore;
use super::types::HandId;
use super::verifier::{Verifier, VerifyError};
use super::worker::LedgerWorker;

/// Facade that wires together verifier, queue, worker, event store, and state.
pub struct LedgerOperator<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    verifier: Arc<dyn Verifier<C> + Send + Sync>,
    queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
    event_store: Arc<dyn EventStore<C>>,
    state: Arc<LedgerState<C>>,
    worker: LedgerWorker<C>,
}

impl<C> LedgerOperator<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(
        verifier: Arc<dyn Verifier<C> + Send + Sync>,
        queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
        event_store: Arc<dyn EventStore<C>>,
        state: Arc<LedgerState<C>>,
    ) -> Self {
        let worker = LedgerWorker::new(queue.clone(), event_store.clone(), state.clone());
        Self {
            verifier,
            queue,
            event_store,
            state,
            worker,
        }
    }

    /// Called on startup to replay state and spawn the worker loop.
    pub async fn start(&self) -> anyhow::Result<()> {
        let events = self.event_store.load_all_events()?;
        self.state.replay(events)?;
        let _ = &self.worker;
        todo!("ledger operator start not implemented")
    }

    /// Entry point for API submissions: verify and enqueue an action envelope.
    pub async fn submit(
        &self,
        hand_id: HandId,
        envelope: ActionEnvelope<C>,
    ) -> Result<(), VerifyError> {
        let verified: VerifiedEnvelope<C> = self.verifier.verify(hand_id, envelope)?;
        self.queue
            .push(verified)
            .map_err(|_| VerifyError::InvalidMessage)?;
        Ok(())
    }

    pub fn state(&self) -> Arc<LedgerState<C>> {
        self.state.clone()
    }
}
