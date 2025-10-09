use std::sync::Arc;

use ark_ec::CurveGroup;
use thiserror::Error;

use super::messages::VerifiedEnvelope;
use super::queue::LedgerQueue;
use super::state::LedgerState;
use super::store::EventStore;

pub struct LedgerWorker<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
    event_store: Arc<dyn EventStore<C>>,
    state: Arc<LedgerState<C>>,
    _marker: std::marker::PhantomData<C>,
}

impl<C> LedgerWorker<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(
        queue: Arc<dyn LedgerQueue<C> + Send + Sync>,
        event_store: Arc<dyn EventStore<C>>,
        state: Arc<LedgerState<C>>,
    ) -> Self {
        Self {
            queue,
            event_store,
            state,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn run(&self) -> Result<(), WorkerError> {
        let _ = (&self.queue, &self.event_store, &self.state);
        todo!("worker loop not implemented")
    }

    pub async fn handle_event(&self, event: VerifiedEnvelope<C>) -> Result<(), WorkerError> {
        let _ = (&self.event_store, &self.state, event);
        todo!("handle_event not implemented")
    }
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("queue error")]
    Queue,
    #[error("database error")]
    Database,
    #[error("apply error")]
    Apply,
}
