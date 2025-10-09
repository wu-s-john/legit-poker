use std::sync::Arc;

use ark_ec::CurveGroup;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

use super::messages::AnyMessageEnvelope;

pub trait EventStore<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    fn persist_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<()>;
    fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
    fn load_hand_events(
        &self,
        hand_id: crate::ledger::types::HandId,
    ) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
}

pub type SharedEventStore<C> = Arc<dyn EventStore<C>>;

pub struct SeaOrmEventStore<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub connection: DatabaseConnection,
    _marker: std::marker::PhantomData<C>,
}

impl<C> SeaOrmEventStore<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(connection: DatabaseConnection) -> Self {
        Self {
            connection,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C> EventStore<C> for SeaOrmEventStore<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    fn persist_event(&self, _event: &AnyMessageEnvelope<C>) -> anyhow::Result<()> {
        // TODO: Use sea-orm ActiveModel to insert into the `events` table
        todo!("SeaOrmEventStore::persist_event is not implemented yet")
    }

    fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
        // TODO: Query all events ordered by hand_id then nonce using sea-orm
        let _ = events::Entity::find()
            .order_by_asc(events::Column::HandId)
            .order_by_asc(events::Column::Nonce);
        todo!("SeaOrmEventStore::load_all_events is not implemented yet")
    }

    fn load_hand_events(
        &self,
        hand_id: crate::ledger::types::HandId,
    ) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
        // TODO: Query events filtered by hand_id using sea-orm
        let _ = events::Entity::find()
            .filter(events::Column::HandId.eq(hand_id))
            .order_by_asc(events::Column::Nonce);
        todo!("SeaOrmEventStore::load_hand_events is not implemented yet")
    }
}

use crate::db::entity::events;

#[cfg(test)]
mod tests {

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
