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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective as Curve;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn sample_verified_envelope(nonce: u64) -> VerifiedEnvelope<Curve> {
        use crate::engine::nl::actions::PlayerBetAction;
        use crate::ledger::messages::{
            ActionEnvelope, GamePlayerMessage, LedgerMessage, PreflopStreet,
        };
        use crate::ledger::types::{ActorKind, EntityKind, HandStatus, NonceKey};
        use crate::player::signing::WithSignature;

        let message = LedgerMessage::PlayerPreflop(GamePlayerMessage {
            street: PreflopStreet,
            action: PlayerBetAction::Call,
            _curve: std::marker::PhantomData,
        });

        let envelope = ActionEnvelope {
            public_key: Vec::new(),
            actor: ActorKind::Player {
                seat_id: 0,
                player_id: 0,
            },
            nonce,
            signed_message: WithSignature {
                value: message.clone(),
                signature: Vec::new(),
                transcript: Vec::new(),
            },
        };

        VerifiedEnvelope {
            key: NonceKey {
                hand_id: 0,
                entity_kind: EntityKind::Player,
                entity_id: 0,
            },
            nonce,
            phase: HandStatus::Betting,
            message,
            raw: envelope,
        }
    }

    struct MemoryQueue<C: CurveGroup> {
        inner: Arc<Mutex<VecDeque<VerifiedEnvelope<C>>>>,
    }

    impl<C: CurveGroup> MemoryQueue<C> {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl<C: CurveGroup> LedgerQueue<C> for MemoryQueue<C> {
        fn push(&self, item: VerifiedEnvelope<C>) -> Result<(), QueueError> {
            self.inner.lock().unwrap().push_back(item);
            Ok(())
        }

        fn pop(&self) -> tokio::sync::oneshot::Receiver<VerifiedEnvelope<C>> {
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
        events: Arc<Mutex<Vec<VerifiedEnvelope<C>>>>,
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
        fn persist_event(&self, event: &VerifiedEnvelope<C>) -> anyhow::Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }

        fn load_all_events(&self) -> anyhow::Result<Vec<VerifiedEnvelope<C>>> {
            Ok(self.events.lock().unwrap().clone())
        }

        fn load_hand_events(
            &self,
            _hand_id: crate::ledger::types::HandId,
        ) -> anyhow::Result<Vec<VerifiedEnvelope<C>>> {
            Ok(self.events.lock().unwrap().clone())
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
