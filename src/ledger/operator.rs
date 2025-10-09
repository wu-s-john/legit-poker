use std::sync::Arc;

use ark_ec::CurveGroup;

use super::messages::ActionEnvelope;
use super::queue::LedgerQueue;
use super::types::HandId;
use super::verifier::{Verifier, VerifyError};
use super::worker::LedgerWorker;

/// Facade that wires together verifier, queue, worker, and shared state.
pub struct LedgerOperator<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    verifier: Arc<dyn Verifier<C> + Send + Sync>,
    queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
    worker: LedgerWorker<C>,
}

impl<C> LedgerOperator<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(
        verifier: Arc<dyn Verifier<C> + Send + Sync>,
        queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
        worker: LedgerWorker<C>,
    ) -> Self {
        let _ = (&verifier, &queue, &worker);
        todo!("ledger operator constructor not implemented")
    }

    /// Called on startup to replay state and spawn the worker loop.
    pub async fn start(&self) -> anyhow::Result<()> {
        todo!("ledger operator start not implemented")
    }

    /// Entry point for API submissions: verify and enqueue an action envelope.
    pub async fn submit(
        &self,
        hand_id: HandId,
        envelope: ActionEnvelope<C>,
    ) -> Result<(), VerifyError> {
        let _ = (hand_id, envelope);
        todo!("ledger operator submit not implemented")
    }
}
