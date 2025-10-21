use std::sync::Arc;

use anyhow::{bail, Result};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::ledger::{
    messages::FinalizedAnyMessageEnvelope, snapshot::SnapshotSeq, store::EventStore, types::HandId,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct SequenceBounds {
    pub from: Option<SnapshotSeq>,
    pub to: Option<SnapshotSeq>,
}

impl SequenceBounds {
    pub fn new(from: Option<SnapshotSeq>, to: Option<SnapshotSeq>) -> Result<Self> {
        if let (Some(start), Some(end)) = (from, to) {
            if start > end {
                bail!("invalid sequence range: from {start} exceeds to {end}");
            }
        }
        Ok(Self { from, to })
    }
}

pub struct HandMessagesQuery<C>
where
    C: CurveGroup,
{
    store: Arc<dyn EventStore<C>>,
}

impl<C> HandMessagesQuery<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    pub fn new(store: Arc<dyn EventStore<C>>) -> Self {
        Self { store }
    }

    pub async fn execute(
        &self,
        hand_id: HandId,
        bounds: &SequenceBounds,
    ) -> Result<Vec<FinalizedAnyMessageEnvelope<C>>> {
        let mut events = self
            .store
            .load_hand_events_in_sequence_range(hand_id, bounds.from, bounds.to)
            .await?;
        events.sort_by_key(|event| (event.snapshot_sequence_id, event.envelope.nonce));
        Ok(events)
    }
}
