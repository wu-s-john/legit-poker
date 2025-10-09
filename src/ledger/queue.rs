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
