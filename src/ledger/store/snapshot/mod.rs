mod serialization;

use std::marker::PhantomData;
use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use async_trait::async_trait;
use sea_orm::{DatabaseConnection, TransactionTrait};
use tracing::info;

use crate::curve_absorb::CurveAbsorb;
use crate::ledger::hash::LedgerHasher;
use crate::ledger::snapshot::AnyTableSnapshot;

use self::serialization::{persist_prepared_snapshot, prepare_snapshot_data, SNAPSHOT_LOG_TARGET};

pub type SharedSnapshotStore<C> = Arc<dyn SnapshotStore<C>>;

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
        info!(
            target = SNAPSHOT_LOG_TARGET,
            game_id = prepared.game_id,
            hand_id = prepared.hand_id,
            sequence = prepared.sequence,
            "persisting snapshot"
        );
        let txn = self.connection.begin().await?;
        persist_prepared_snapshot(&txn, &prepared).await?;
        txn.commit().await?;
        info!(
            target = SNAPSHOT_LOG_TARGET,
            game_id = prepared.game_id,
            hand_id = prepared.hand_id,
            sequence = prepared.sequence,
            "snapshot persisted"
        );
        Ok(())
    }
}
