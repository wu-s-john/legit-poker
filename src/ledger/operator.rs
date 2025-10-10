use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::messages::AnyMessageEnvelope;
use super::state::LedgerState;
use super::store::EventStore;
use super::types::HandId;
use super::verifier::{Verifier, VerifyError};
use super::worker::LedgerWorker;
use crate::curve_absorb::CurveAbsorb;
use tokio::sync::mpsc;
use tracing::error;

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
    ) -> Self {
        Self {
            verifier,
            sender,
            event_store,
            state,
        }
    }

    /// Called on startup to replay state and spawn the worker loop.
    pub async fn start(&self, worker: LedgerWorker<C>) -> anyhow::Result<()> {
        let events = self.event_store.load_all_events().await?;
        self.state.replay(events)?;
        tokio::spawn(async move {
            if let Err(err) = worker.run().await {
                error!("ledger worker exited with error: {err}");
            }
        });
        Ok(())
    }

    /// Entry point for API submissions: verify and enqueue an action envelope.
    pub async fn submit(
        &self,
        hand_id: HandId,
        envelope: AnyMessageEnvelope<C>,
    ) -> Result<(), VerifyError> {
        let verified = self.verifier.verify(hand_id, envelope)?;
        self.sender
            .send(verified)
            .await
            .map_err(|_| VerifyError::InvalidMessage)?;
        Ok(())
    }

    pub fn state(&self) -> Arc<LedgerState<C>> {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::actor::AnyActor;
    use crate::ledger::{GameId, HandId};
    use crate::signing::WithSignature;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
        use crate::engine::nl::actions::PlayerBetAction;
        use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};

        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage {
            street: PreflopStreet,
            action: PlayerBetAction::Check,
            _curve: std::marker::PhantomData,
        });

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

    use crate::ledger::store::SeaOrmEventStore;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use std::env;
    use std::time::Duration as StdDuration;

    async fn setup_event_store() -> Option<Arc<SeaOrmEventStore<Curve>>> {
        let url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgresql://postgres:postgres@127.0.0.1:54322/postgres".into());

        let mut opt = ConnectOptions::new(url);
        opt.max_connections(5)
            .min_connections(1)
            .connect_timeout(StdDuration::from_secs(5))
            .sqlx_logging(true);

        let conn = match Database::connect(opt).await {
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
        let event_store: Arc<dyn EventStore<Curve>> = store.clone();
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let operator =
            LedgerOperator::new(verifier, tx, Arc::clone(&event_store), Arc::clone(&state));
        assert!(state.hands().is_empty());
        let _ = operator;
    }

    #[tokio::test]
    async fn start_replays_and_starts_worker() {
        let (tx, rx) = mpsc::channel(4);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let event_store: Arc<dyn EventStore<Curve>> = store.clone();
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let operator =
            LedgerOperator::new(verifier, tx, Arc::clone(&event_store), Arc::clone(&state));
        let worker = LedgerWorker::new(rx, Arc::clone(&event_store), Arc::clone(&state));
        operator.start(worker).await.unwrap();
    }

    #[tokio::test]
    async fn submit_enqueues_messages() {
        let (tx, mut rx) = mpsc::channel(4);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let event_store: Arc<dyn EventStore<Curve>> = store.clone();
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(NoopVerifier {
            _state: Arc::clone(&state),
        });
        let operator = LedgerOperator::new(verifier, tx, event_store, Arc::clone(&state));
        let envelope = sample_verified_envelope(10);
        operator.submit(0, envelope).await.unwrap();
        let received = rx.recv().await.expect("message enqueued");
        assert_eq!(received.nonce, 0);
    }
}
