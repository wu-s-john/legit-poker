use std::sync::Arc;

use ark_ec::CurveGroup;

use super::messages::VerifiedEnvelope;

pub trait EventStore<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    fn persist_event(&self, event: &VerifiedEnvelope<C>) -> anyhow::Result<()>;
    fn load_all_events(&self) -> anyhow::Result<Vec<VerifiedEnvelope<C>>>;
    fn load_hand_events(
        &self,
        hand_id: crate::ledger::types::HandId,
    ) -> anyhow::Result<Vec<VerifiedEnvelope<C>>>;
}

pub type SharedEventStore<C> = Arc<dyn EventStore<C>>;
