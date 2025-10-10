use std::sync::Arc;

use ark_ec::CurveGroup;
use thiserror::Error;

use super::messages::AnyMessageEnvelope;
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

    pub async fn handle_event(&self, event: AnyMessageEnvelope<C>) -> Result<(), WorkerError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::queue::QueueError;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
        use crate::engine::nl::actions::PlayerBetAction;
        use crate::ledger::actor::AnyActor;
        use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};
        use crate::signing::WithSignature;

        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage {
            street: PreflopStreet,
            action: PlayerBetAction::Call,
            _curve: std::marker::PhantomData,
        });

        AnyMessageEnvelope {
            hand_id: 0,
            game_id: 0,
            actor: AnyActor::None,
            nonce,
            public_key: Curve::zero(),
            message: WithSignature {
                value: message,
                signature: Vec::new(),
                transcript: Vec::new(),
            },
        }
    }

    struct MemoryQueue<C: CurveGroup> {
        inner: Arc<Mutex<VecDeque<AnyMessageEnvelope<C>>>>,
    }

    impl<C: CurveGroup> MemoryQueue<C> {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl<C: CurveGroup> LedgerQueue<C> for MemoryQueue<C> {
        fn push(&self, item: AnyMessageEnvelope<C>) -> Result<(), QueueError> {
            self.inner.lock().unwrap().push_back(item);
            Ok(())
        }

        fn pop(&self) -> tokio::sync::oneshot::Receiver<AnyMessageEnvelope<C>> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Some(item) = self.inner.lock().unwrap().pop_front() {
                let _ = tx.send(item);
            }
            rx
        }

        fn len(&self) -> usize {
            self.inner.lock().unwrap().len()
        }
    }

    struct MemoryStore<C: CurveGroup> {
        events: Arc<Mutex<Vec<AnyMessageEnvelope<C>>>>,
    }

    impl<C: CurveGroup> MemoryStore<C> {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn len(&self) -> usize {
            self.events.lock().unwrap().len()
        }
    }

    impl<C: CurveGroup> EventStore<C> for MemoryStore<C> {
        fn persist_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }

        fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
            Ok(self.events.lock().unwrap().clone())
        }

        fn load_hand_events(
            &self,
            hand_id: crate::ledger::types::HandId,
        ) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
            let events = self.events.lock().unwrap();
            Ok(events
                .iter()
                .cloned()
                .filter(|event| event.hand_id == hand_id)
                .collect())
        }
    }

    #[test]
    fn worker_can_be_constructed() {
        let queue = Arc::new(MemoryQueue::<Curve>::new());
        let store = Arc::new(MemoryStore::<Curve>::new());
        let state = Arc::new(LedgerState::<Curve>::new());
        let worker = LedgerWorker::new(queue.clone(), store.clone(), state.clone());
        assert_eq!(queue.len(), 0);
        assert_eq!(store.len(), 0);
        let _ = worker;
    }

    #[test]
    #[should_panic]
    fn handle_event_is_not_implemented() {
        let queue = Arc::new(MemoryQueue::<Curve>::new());
        let store = Arc::new(MemoryStore::<Curve>::new());
        let state = Arc::new(LedgerState::<Curve>::new());
        let worker = LedgerWorker::new(queue, store, state);
        let env = sample_verified_envelope(1);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(worker.handle_event(env)).unwrap();
    }
}
