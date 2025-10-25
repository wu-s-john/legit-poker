mod serialization;

use std::marker::PhantomData;
use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, TransactionTrait};
use tracing::info;

use crate::curve_absorb::CurveAbsorb;
use crate::db::entity::table_snapshots;
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::AnyTableSnapshot;
use crate::ledger::types::HandId;

use self::serialization::{prepare_snapshot_data, reconstruct_snapshot_from_db, SNAPSHOT_LOG_TARGET};

pub use self::serialization::{compute_dealing_hash, persist_prepared_snapshot, PreparedSnapshot};

pub type SharedSnapshotStore<C> = Arc<dyn SnapshotStore<C>>;

pub fn prepare_snapshot<C>(
    snapshot: &AnyTableSnapshot<C>,
    hasher: &dyn LedgerHasher,
) -> anyhow::Result<PreparedSnapshot>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    prepare_snapshot_data(snapshot, hasher)
}

#[async_trait]
pub trait SnapshotStore<C>: Send + Sync
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn persist_snapshot(
        &self,
        snapshot: &AnyTableSnapshot<C>,
        hasher: &Arc<dyn LedgerHasher + Send + Sync>,
    ) -> anyhow::Result<()>;
    async fn persist_snapshot_in_txn(
        &self,
        txn: &DatabaseTransaction,
        prepared: &PreparedSnapshot,
    ) -> anyhow::Result<()>;

    /// Loads the latest snapshot for a given hand from the database.
    /// Returns None if no snapshots exist for the hand.
    async fn load_latest_snapshot(
        &self,
        hand_id: HandId,
    ) -> anyhow::Result<Option<AnyTableSnapshot<C>>>;
}

pub struct SeaOrmSnapshotStore<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    pub connection: DatabaseConnection,
    _marker: PhantomData<C>,
}

impl<C> SeaOrmSnapshotStore<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    pub fn new(connection: DatabaseConnection) -> Self {
        Self {
            connection,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<C> SnapshotStore<C> for SeaOrmSnapshotStore<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    async fn persist_snapshot(
        &self,
        snapshot: &AnyTableSnapshot<C>,
        hasher: &Arc<dyn LedgerHasher + Send + Sync>,
    ) -> anyhow::Result<()> {
        let prepared = prepare_snapshot_data(snapshot, hasher.as_ref())?;
        let txn = self.connection.begin().await?;
        self.persist_snapshot_in_txn(&txn, &prepared).await?;
        txn.commit().await?;
        Ok(())
    }

    async fn persist_snapshot_in_txn(
        &self,
        txn: &DatabaseTransaction,
        prepared: &PreparedSnapshot,
    ) -> anyhow::Result<()> {
        info!(
            target = SNAPSHOT_LOG_TARGET,
            game_id = prepared.game_id,
            hand_id = prepared.hand_id,
            sequence = prepared.sequence,
            status = ?prepared.application_status,
            "persisting snapshot"
        );
        persist_prepared_snapshot(txn, prepared).await?;
        info!(
            target = SNAPSHOT_LOG_TARGET,
            game_id = prepared.game_id,
            hand_id = prepared.hand_id,
            sequence = prepared.sequence,
            status = ?prepared.application_status,
            "snapshot persisted"
        );
        Ok(())
    }

    async fn load_latest_snapshot(
        &self,
        hand_id: HandId,
    ) -> anyhow::Result<Option<AnyTableSnapshot<C>>> {
        info!(
            target = SNAPSHOT_LOG_TARGET,
            hand_id = hand_id,
            "loading latest snapshot from database"
        );

        // Query for the latest snapshot by hand_id, ordered by sequence DESC
        let snapshot_row = table_snapshots::Entity::find()
            .filter(table_snapshots::Column::HandId.eq(hand_id))
            .order_by_desc(table_snapshots::Column::Sequence)
            .one(&self.connection)
            .await?;

        match snapshot_row {
            Some(row) => {
                info!(
                    target = SNAPSHOT_LOG_TARGET,
                    hand_id = hand_id,
                    sequence = row.sequence,
                    "found latest snapshot"
                );
                let snapshot = reconstruct_snapshot_from_db(row, &self.connection).await?;
                Ok(Some(snapshot))
            }
            None => {
                info!(
                    target = SNAPSHOT_LOG_TARGET,
                    hand_id = hand_id,
                    "no snapshots found for hand"
                );
                Ok(None)
            }
        }
    }
}
