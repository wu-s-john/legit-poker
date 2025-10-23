use std::future::Future;
use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::messages::{AnyMessageEnvelope, FinalizedAnyMessageEnvelope};
use super::snapshot::{AnyTableSnapshot, Shared};
use super::state::LedgerState;
use super::store::EventStore;
use super::types::HandId;
use super::verifier::{Verifier, VerifyError};
use super::worker::StagingLedgerUpdate;
use super::worker::{LedgerWorker, WorkerError};
use crate::curve_absorb::CurveAbsorb;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, instrument, Span};

const LOG_TARGET: &str = "legit_poker::ledger::operator";

fn spawn_named_task<F, S>(name: S, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
    S: Into<String>,
{
    let name_owned = name.into();
    #[cfg(tokio_unstable)]
    {
        tokio::task::Builder::new().name(&name_owned).spawn(future)
    }
    #[cfg(not(tokio_unstable))]
    {
        use tracing::Instrument;
        let span = tracing::info_span!("task", task_name = %name_owned);
        tokio::spawn(future.instrument(span))
    }
}

/// Facade that wires together verifier, queue, worker, event store, and state.
pub struct LedgerOperator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    verifier: Arc<dyn Verifier<C> + Send + Sync>,
    sender: mpsc::Sender<AnyMessageEnvelope<C>>,
    event_store: Arc<dyn EventStore<C>>,
    state: Arc<LedgerState<C>>,
    events_tx: broadcast::Sender<FinalizedAnyMessageEnvelope<C>>,
    snapshots_tx: broadcast::Sender<Shared<AnyTableSnapshot<C>>>,
    staging_tx: broadcast::Sender<StagingLedgerUpdate<C>>,
}

impl<C> LedgerOperator<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    pub fn new(
        verifier: Arc<dyn Verifier<C> + Send + Sync>,
        sender: mpsc::Sender<AnyMessageEnvelope<C>>,
        event_store: Arc<dyn EventStore<C>>,
        state: Arc<LedgerState<C>>,
        events_tx: broadcast::Sender<FinalizedAnyMessageEnvelope<C>>,
        snapshots_tx: broadcast::Sender<Shared<AnyTableSnapshot<C>>>,
        staging_tx: broadcast::Sender<StagingLedgerUpdate<C>>,
    ) -> Self {
        Self {
            verifier,
            sender,
            event_store,
            state,
            events_tx,
            snapshots_tx,
            staging_tx,
        }
    }

    /// Called on startup to replay state and spawn the worker loop.
    pub async fn start(
        &self,
        worker: LedgerWorker<C>,
    ) -> anyhow::Result<JoinHandle<Result<(), WorkerError>>> {
        // let events = self.event_store.load_all_events().await?;
        // self.state.replay(events)?;
        let handle = spawn_named_task("ledger-worker", async move {
            let result = worker.run().await;
            if let Err(err) = &result {
                error!("ledger worker exited with error: {err}");
            }
            result
        });
        Ok(handle)
    }

    /// Entry point for API submissions: verify and enqueue an action envelope.
    #[instrument(
        skip(self, envelope),
        level = "info",
        target = LOG_TARGET,
        fields(hand_id = %hand_id, nonce = tracing::field::Empty)
    )]
    pub async fn submit(
        &self,
        hand_id: HandId,
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<(), VerifyError> {
        let nonce = envelope.nonce;
        Span::current().record("nonce", &nonce);
        info!(target: LOG_TARGET, "verifying envelope");
        let verified = self.verifier.verify(hand_id, envelope)?;
        info!(target: LOG_TARGET, "enqueueing verified envelope");
        self.sender.send(verified).await.map_err(|_| {
            error!(target: LOG_TARGET, "failed to enqueue verified envelope");
            VerifyError::InvalidMessage
        })?;
        info!(target: LOG_TARGET, "enqueued verified envelope");
        Ok(())
    }

    pub fn state(&self) -> Arc<LedgerState<C>> {
        self.state.clone()
    }

    pub fn event_updates(&self) -> broadcast::Receiver<FinalizedAnyMessageEnvelope<C>> {
        self.events_tx.subscribe()
    }

    pub fn snapshot_updates(&self) -> broadcast::Receiver<Shared<AnyTableSnapshot<C>>> {
        self.snapshots_tx.subscribe()
    }

    pub fn staging_updates(&self) -> broadcast::Receiver<StagingLedgerUpdate<C>> {
        self.staging_tx.subscribe()
    }

    pub fn event_sender(&self) -> broadcast::Sender<FinalizedAnyMessageEnvelope<C>> {
        self.events_tx.clone()
    }

    pub fn snapshot_sender(&self) -> broadcast::Sender<Shared<AnyTableSnapshot<C>>> {
        self.snapshots_tx.clone()
    }

    pub fn staging_sender(&self) -> broadcast::Sender<StagingLedgerUpdate<C>> {
        self.staging_tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{connect_to_postgres_db, postgres_test_url};
    use crate::engine::nl::actions::PlayerBetAction;
    use crate::ledger::actor::AnyActor;
    use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};
    use crate::ledger::store::{SeaOrmEventStore, SeaOrmSnapshotStore, SnapshotStore};
    use crate::ledger::{GameId, HandId};
    use crate::signing::WithSignature;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
        let message = AnyGameMessage::PlayerPreflop(
            GamePlayerMessage::<PreflopStreet, Curve>::new(PlayerBetAction::Check),
        );

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

    async fn setup_event_store() -> Option<Arc<SeaOrmEventStore<Curve>>> {
        let url = postgres_test_url();
        let conn = match connect_to_postgres_db(&url).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("operator test: failed to connect to postgres ({err})");
                return None;
            }
        };

        if let Err(err) = conn.ping().await {
            eprintln!("operator test: ping postgres failed ({err})");
            return None;
        }

        let truncate = Statement::from_string(
            DbBackend::Postgres,
            "TRUNCATE TABLE public.events RESTART IDENTITY CASCADE",
        );
        if let Err(err) = conn.execute(truncate).await {
            eprintln!("operator test: failed to truncate events table ({err})");
            return None;
        }

        Some(Arc::new(SeaOrmEventStore::new(conn)))
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

    #[tokio::test]
    async fn operator_can_be_constructed() {
        let (tx, _rx) = mpsc::channel(4);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let (events_tx, _) = broadcast::channel(16);
        let (snapshots_tx, _) = broadcast::channel(16);
        let (staging_tx, _) = broadcast::channel(16);
        let operator = LedgerOperator::new(
            verifier,
            tx,
            Arc::clone(&store) as Arc<dyn EventStore<Curve>>,
            Arc::clone(&state),
            events_tx,
            snapshots_tx,
            staging_tx,
        );
        assert!(state.hands().is_empty());
        let _ = operator;
    }

    #[tokio::test]
    async fn start_replays_and_starts_worker() {
        let (tx, rx) = mpsc::channel(4);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let snapshot_store: Arc<dyn SnapshotStore<Curve>> =
            Arc::new(SeaOrmSnapshotStore::new(store.connection.clone()));
        let event_store_trait: Arc<dyn EventStore<Curve>> =
            Arc::clone(&store) as Arc<dyn EventStore<Curve>>;
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let (events_tx, _) = broadcast::channel(16);
        let (snapshots_tx, _) = broadcast::channel(16);
        let (staging_tx, _) = broadcast::channel(16);
        let operator = LedgerOperator::new(
            verifier,
            tx,
            Arc::clone(&event_store_trait),
            Arc::clone(&state),
            events_tx.clone(),
            snapshots_tx.clone(),
            staging_tx.clone(),
        );
        let worker = LedgerWorker::new(
            rx,
            Arc::clone(&event_store_trait),
            Arc::clone(&snapshot_store),
            Arc::clone(&state),
            events_tx,
            snapshots_tx,
            staging_tx,
        );
        let handle = operator.start(worker).await.unwrap();
        handle.abort();
    }

    #[tokio::test]
    async fn submit_enqueues_messages() {
        let (tx, mut rx) = mpsc::channel(4);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let event_store_trait: Arc<dyn EventStore<Curve>> =
            Arc::clone(&store) as Arc<dyn EventStore<Curve>>;
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let (events_tx, _) = broadcast::channel(16);
        let (snapshots_tx, _) = broadcast::channel(16);
        let (staging_tx, _) = broadcast::channel(16);
        let operator = LedgerOperator::new(
            verifier,
            tx,
            event_store_trait,
            Arc::clone(&state),
            events_tx,
            snapshots_tx,
            staging_tx,
        );
        let envelope = sample_verified_envelope(10);
        operator.submit(0, envelope).await.unwrap();
        let received = rx.recv().await.expect("message enqueued");
        assert_eq!(received.nonce, 0);
    }
}
