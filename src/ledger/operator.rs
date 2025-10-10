use std::sync::Arc;

use ark_ec::CurveGroup;

use super::messages::AnyMessageEnvelope;
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
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<(), VerifyError> {
        let verified = self.verifier.verify(hand_id, envelope)?;
        self.queue
            .push(verified)
            .map_err(|_| VerifyError::InvalidMessage)?;
        Ok(())
    }

    pub fn state(&self) -> Arc<LedgerState<C>> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::ledger::{LedgerVerifier, QueueError};

    use super::*;
    use crate::ledger::actor::AnyActor;
    use crate::ledger::{GameId, HandId};
    use crate::signing::WithSignature;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
        use crate::engine::nl::actions::PlayerBetAction;
        use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};

        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage {
            street: PreflopStreet,
            action: PlayerBetAction::Check,
            _curve: std::marker::PhantomData,
        });

        AnyMessageEnvelope {
            hand_id: HandId::default(),
            game_id: GameId::default(),
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
            _hand_id: crate::ledger::types::HandId,
        ) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
            Ok(self.events.lock().unwrap().clone())
        }
    }

    struct NoopVerifier {
        _state: Arc<LedgerState<Curve>>,
    }

    impl Verifier<Curve> for NoopVerifier {
        fn verify(
            &self,
            _hand_id: HandId,
            _envelope: AnyMessageEnvelope<Curve>,
        ) -> Result<AnyMessageEnvelope<Curve>, VerifyError> {
            Ok(sample_verified_envelope(0))
        }
    }

    #[test]
    fn operator_can_be_constructed() {
        let queue = Arc::new(MemoryQueue::<Curve>::new());
        let store = Arc::new(MemoryStore::<Curve>::new());
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let operator = LedgerOperator::new(verifier, queue.clone(), store.clone(), state.clone());
        assert_eq!(queue.len(), 0);
        assert_eq!(store.len(), 0);
        let _ = operator;
    }

    #[test]
    #[should_panic]
    fn start_is_not_implemented() {
        let queue = Arc::new(MemoryQueue::<Curve>::new());
        let store = Arc::new(MemoryStore::<Curve>::new());
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let operator = LedgerOperator::new(verifier, queue, store, state);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(operator.start()).unwrap();
    }

    #[test]
    #[should_panic]
    fn submit_is_not_implemented() {
        let queue = Arc::new(MemoryQueue::<Curve>::new());
        let store = Arc::new(MemoryStore::<Curve>::new());
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(LedgerVerifier::new(Arc::clone(&state)));
        let operator = LedgerOperator::new(verifier, queue, store, state);
        let envelope = sample_verified_envelope(10);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(operator.submit(0, envelope)).unwrap();
    }
}
