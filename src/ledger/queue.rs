use crate::ledger::messages::AnyMessageEnvelope;
use ark_ec::CurveGroup;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use tokio::sync::oneshot::{Receiver, Sender};

// We should accept a message Envelop of any type
pub trait LedgerQueue<C>
where
    C: CurveGroup,
{
    fn push(&self, item: AnyMessageEnvelope<C>) -> Result<(), QueueError>;
    fn pop(&self) -> Receiver<AnyMessageEnvelope<C>>;
    fn len(&self) -> usize;
    fn close(&self);
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
}

pub struct FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    state: Mutex<QueueState<C>>,
}

struct QueueState<C: CurveGroup> {
    items: VecDeque<AnyMessageEnvelope<C>>,
    waiters: VecDeque<Sender<AnyMessageEnvelope<C>>>,
    closed: bool,
}

impl<C> FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(capacity),
                waiters: VecDeque::new(),
                closed: false,
            }),
        }
    }

    fn close_inner(&self) {
        let mut state = self.state.lock().expect("ledger queue poisoned");
        if state.closed {
            return;
        }
        state.closed = true;
        state.waiters.clear();
        state.items.clear();
    }
}

impl<C> LedgerQueue<C> for FifoLedgerQueue<C>
where
    C: CurveGroup + 'static,
{
    fn push(&self, item: AnyMessageEnvelope<C>) -> Result<(), QueueError> {
        let mut pending = Some(item);

        loop {
            let waiter = {
                let mut state = self.state.lock().expect("ledger queue poisoned");
                if state.closed {
                    return Err(QueueError::Closed);
                }
                state.waiters.pop_front()
            };

            if let Some(waiter) = waiter {
                let value = pending.take().expect("item must remain available");
                match waiter.send(value) {
                    Ok(()) => return Ok(()),
                    Err(value) => {
                        pending = Some(value);
                        continue;
                    }
                }
            } else {
                let mut state = self.state.lock().expect("ledger queue poisoned");
                if state.closed {
                    return Err(QueueError::Closed);
                }
                state
                    .items
                    .push_back(pending.take().expect("item must remain available"));
                return Ok(());
            }
        }
    }

    fn pop(&self) -> Receiver<AnyMessageEnvelope<C>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        let mut state = self.state.lock().expect("ledger queue poisoned");
        if state.closed {
            drop(tx);
            return rx;
        }

        if let Some(item) = state.items.pop_front() {
            drop(state);
            if let Err(item) = tx.send(item) {
                let mut state = self.state.lock().expect("ledger queue poisoned");
                state.items.push_front(item);
            }
        } else {
            state.waiters.push_back(tx);
        }

        rx
    }

    fn len(&self) -> usize {
        let state = self.state.lock().expect("ledger queue poisoned");
        state.items.len()
    }

    fn close(&self) {
        self.close_inner();
    }
}

impl<C> Drop for FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    fn drop(&mut self) {
        self.close_inner();
    }
}

impl<C> fmt::Debug for FifoLedgerQueue<C>
where
    C: CurveGroup,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.state.lock() {
            Ok(state) => f
                .debug_struct("FifoLedgerQueue")
                .field("pending_items", &state.items.len())
                .field("waiting_receivers", &state.waiters.len())
                .finish(),
            Err(_) => f
                .debug_struct("FifoLedgerQueue")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective as Curve;
    use tokio::runtime::Runtime;

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
        use crate::engine::nl::actions::PlayerBetAction;
        use crate::ledger::actor::AnyActor;
        use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};
        use crate::signing::WithSignature;
        use ark_ff::Zero;

        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage {
            street: PreflopStreet,
            action: PlayerBetAction::Fold,
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

    #[test]
    fn fifo_ordering_is_preserved() {
        let queue = FifoLedgerQueue::<Curve>::new(8);
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

    #[test]
    fn pop_receiver_resolves_after_push() {
        let queue = FifoLedgerQueue::<Curve>::new(4);
        let rx = queue.pop();
        queue.push(sample_verified_envelope(42)).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let value = rt.block_on(rx).unwrap();
        assert_eq!(value.nonce, 42);
    }

    #[test]
    fn pop_before_push_completes_when_item_arrives() {
        let queue = FifoLedgerQueue::<Curve>::new(2);
        let rx = queue.pop();
        queue.push(sample_verified_envelope(7)).unwrap();
        let rt = Runtime::new().unwrap();
        let value = rt.block_on(rx).unwrap();
        assert_eq!(value.nonce, 7);
    }

    #[test]
    fn len_reflects_enqueued_items() {
        let queue = FifoLedgerQueue::<Curve>::new(2);
        assert_eq!(queue.len(), 0);
        queue.push(sample_verified_envelope(5)).unwrap();
        assert_eq!(queue.len(), 1);
        let rt = Runtime::new().unwrap();
        let _ = rt.block_on(queue.pop()).unwrap();
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn push_after_close_returns_error() {
        let queue = FifoLedgerQueue::<Curve>::new(2);
        queue.close();
        let result = queue.push(sample_verified_envelope(0));
        assert!(matches!(result, Err(QueueError::Closed)));
    }

    #[test]
    fn pop_after_close_returns_err() {
        let queue = FifoLedgerQueue::<Curve>::new(2);
        queue.close();
        let rt = Runtime::new().unwrap();
        let result = rt.block_on(queue.pop());
        assert!(result.is_err());
    }

    #[test]
    fn outstanding_waiters_receive_error_when_closed() {
        let queue = FifoLedgerQueue::<Curve>::new(2);
        let rx = queue.pop();
        queue.close();
        let rt = Runtime::new().unwrap();
        assert!(rt.block_on(rx).is_err());
    }
}
