use ark_ec::CurveGroup;
use tokio::sync::oneshot::Receiver;

use super::messages::VerifiedEnvelope;

pub trait LedgerQueue<C>
where
    C: CurveGroup,
{
    fn push(&self, item: VerifiedEnvelope<C>) -> Result<(), QueueError>;
    fn pop(&self) -> Receiver<VerifiedEnvelope<C>>;
    fn len(&self) -> usize;
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
}

#[derive(Debug)]
pub struct FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    _marker: std::marker::PhantomData<C>,
}

impl<C> FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    pub fn new(_capacity: usize) -> Self {
        todo!("queue not implemented")
    }
}

impl<C> LedgerQueue<C> for FifoLedgerQueue<C>
where
    C: CurveGroup + 'static,
{
    fn push(&self, _item: VerifiedEnvelope<C>) -> Result<(), QueueError> {
        todo!("queue push not implemented")
    }

    fn pop(&self) -> Receiver<VerifiedEnvelope<C>> {
        todo!("queue pop not implemented")
    }

    fn len(&self) -> usize {
        todo!("queue len not implemented")
    }
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
            action: PlayerBetAction::Fold,
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

    struct InMemoryQueue<C: CurveGroup> {
        inner: Arc<Mutex<VecDeque<VerifiedEnvelope<C>>>>,
    }

    impl<C: CurveGroup> InMemoryQueue<C> {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl<C: CurveGroup> LedgerQueue<C> for InMemoryQueue<C> {
        fn push(&self, item: VerifiedEnvelope<C>) -> Result<(), QueueError> {
            self.inner.lock().unwrap().push_back(item);
            Ok(())
        }

        fn pop(&self) -> Receiver<VerifiedEnvelope<C>> {
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

    #[test]
    fn fifo_ordering_is_preserved() {
        let queue = InMemoryQueue::<Curve>::new();
        queue.push(sample_verified_envelope(1)).unwrap();
        queue.push(sample_verified_envelope(2)).unwrap();
        queue.push(sample_verified_envelope(3)).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(queue.pop()).unwrap();
        let b = rt.block_on(queue.pop()).unwrap();
        let c = rt.block_on(queue.pop()).unwrap();

        assert_eq!(a.nonce, 1);
        assert_eq!(b.nonce, 2);
        assert_eq!(c.nonce, 3);
    }

    struct ClosedQueue<C: CurveGroup>(std::marker::PhantomData<C>);

    impl<C: CurveGroup> LedgerQueue<C> for ClosedQueue<C> {
        fn push(&self, _item: VerifiedEnvelope<C>) -> Result<(), QueueError> {
            Err(QueueError::Closed)
        }

        fn pop(&self) -> Receiver<VerifiedEnvelope<C>> {
            let (_tx, rx) = tokio::sync::oneshot::channel();
            rx
        }

        fn len(&self) -> usize {
            0
        }
    }

    #[test]
    fn push_after_close_returns_error() {
        let queue = ClosedQueue::<Curve>(std::marker::PhantomData);
        let result = queue.push(sample_verified_envelope(0));
        assert!(matches!(result, Err(QueueError::Closed)));
    }

    #[test]
    fn pop_receiver_resolves_after_push() {
        let queue = InMemoryQueue::<Curve>::new();
        queue.push(sample_verified_envelope(42)).unwrap();
        let rx = queue.pop();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let value = rt.block_on(rx).unwrap();
        assert_eq!(value.nonce, 42);
    }
}
