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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "EventStore trait lacks concrete in-memory implementation"]
    fn load_all_events_returns_ordered_history() {
        todo!(
            "Persist events out of order and assert load_all_events returns them chronologically"
        );
    }

    #[test]
    #[ignore = "EventStore trait lacks concrete in-memory implementation"]
    fn load_hand_events_filters_correctly() {
        todo!("Persist events for multiple hands and ensure load_hand_events returns only the requested hand");
    }
}
