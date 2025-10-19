use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use thiserror::Error;

use super::messages::{AnyMessageEnvelope, FinalizedAnyMessageEnvelope};
use super::shuffler_signals::ShufflerDealSignalDispatcher;
use super::state::LedgerState;
use super::store::{EventStore, SnapshotStore};
use crate::curve_absorb::CurveAbsorb;
use crate::ledger::snapshot::{clone_snapshot_for_failure, SnapshotStatus};
use crate::ledger::store::snapshot::prepare_snapshot;
use sea_orm::TransactionTrait;
use tokio::sync::mpsc;
use tracing::{error, info, instrument, warn};

const LOG_TARGET: &str = "legit_poker::ledger::worker";

pub struct LedgerWorker<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    receiver: mpsc::Receiver<AnyMessageEnvelope<C>>,
    event_store: Arc<dyn EventStore<C>>,
    snapshot_store: Arc<dyn SnapshotStore<C>>,
    state: Arc<LedgerState<C>>,
    signal_dispatcher: Option<Arc<ShufflerDealSignalDispatcher<C>>>,
    _marker: std::marker::PhantomData<C>,
}

impl<C> LedgerWorker<C>
where
    C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    pub fn new(
        receiver: mpsc::Receiver<AnyMessageEnvelope<C>>,
        event_store: Arc<dyn EventStore<C>>,
        snapshot_store: Arc<dyn SnapshotStore<C>>,
        state: Arc<LedgerState<C>>,
        signal_dispatcher: Option<Arc<ShufflerDealSignalDispatcher<C>>>,
    ) -> Self {
        Self {
            receiver,
            event_store,
            snapshot_store,
            state,
            signal_dispatcher,
            _marker: std::marker::PhantomData,
        }
    }

    #[instrument(skip(self), level = "info", target = LOG_TARGET)]
    pub async fn run(mut self) -> Result<(), WorkerError> {
        while let Some(event) = self.receiver.recv().await {
            let hand_id = event.hand_id;
            let nonce = event.nonce;
            info!(
                target: LOG_TARGET,
                hand_id,
                nonce,
                "received event from channel"
            );
            if let Err(err) = self.handle_event(event).await {
                match err {
                    WorkerError::Apply => {
                        warn!(
                            target: LOG_TARGET,
                            hand_id,
                            nonce,
                            "dropping event after apply failure"
                        );
                        continue;
                    }
                    WorkerError::Database => return Err(WorkerError::Database),
                }
            } else {
                info!(
                    target: LOG_TARGET,
                    hand_id,
                    nonce,
                    "finished processing event"
                );
            }
        }

        info!(target: LOG_TARGET, "receiver closed; worker exiting");

        Ok(())
    }

    #[instrument(
        skip(self, event),
        target = LOG_TARGET,
        fields(hand_id = %event.hand_id, nonce = %event.nonce)
    )]
    pub async fn handle_event(&self, event: AnyMessageEnvelope<C>) -> Result<(), WorkerError> {
        let hand_id = event.hand_id;
        let nonce = event.nonce;

        let tip_before = match self.state.tip_snapshot(hand_id) {
            Some((_, snapshot)) => snapshot,
            None => {
                warn!(
                    target: LOG_TARGET,
                    hand_id,
                    nonce,
                    "no snapshot tip available before applying event"
                );
                return Err(WorkerError::Apply);
            }
        };

        let hasher = self.state.hasher();

        let preview = self.state.preview_event(&event);

        let (snapshot, finalized_event, apply_error) = match preview {
            Ok(snapshot) => {
                let finalized = FinalizedAnyMessageEnvelope {
                    envelope: event.clone(),
                    snapshot_status: SnapshotStatus::Success,
                    applied_phase: snapshot.event_phase(),
                    snapshot_sequence_id: snapshot.sequence(),
                };
                (snapshot, finalized, None)
            }
            Err(apply_err) => {
                warn!(
                    target: LOG_TARGET,
                    error = ?apply_err,
                    hand_id,
                    nonce,
                    "state apply error"
                );
                let reason = apply_err.to_string();
                let failure_snapshot =
                    clone_snapshot_for_failure(&tip_before, hasher.as_ref(), reason.clone());
                let finalized = FinalizedAnyMessageEnvelope {
                    envelope: event.clone(),
                    snapshot_status: SnapshotStatus::Failure(reason.clone()),
                    applied_phase: failure_snapshot.event_phase(),
                    snapshot_sequence_id: failure_snapshot.sequence(),
                };
                (failure_snapshot, finalized, Some(reason))
            }
        };

        let prepared = match prepare_snapshot(&snapshot, hasher.as_ref()) {
            Ok(prepared) => prepared,
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    error = ?err,
                    hand_id,
                    nonce,
                    "failed to prepare snapshot"
                );
                return Err(WorkerError::Database);
            }
        };

        let txn = match self.event_store.connection().begin().await {
            Ok(txn) => txn,
            Err(err) => {
                error!(
                    target: LOG_TARGET,
                    error = ?err,
                    hand_id,
                    nonce,
                    "failed to begin transaction"
                );
                return Err(WorkerError::Database);
            }
        };

        if let Err(err) = self
            .event_store
            .persist_event_in_txn(&txn, &finalized_event)
            .await
        {
            error!(
                target: LOG_TARGET,
                error = ?err,
                hand_id,
                nonce,
                "failed to persist event"
            );
            let _ = txn.rollback().await;
            return Err(WorkerError::Database);
        }

        info!(
            target: LOG_TARGET,
            hand_id,
            nonce,
            "persisted event"
        );

        if let Err(err) = self
            .snapshot_store
            .persist_snapshot_in_txn(&txn, &prepared)
            .await
        {
            error!(
                target: LOG_TARGET,
                error = ?err,
                hand_id,
                nonce,
                "failed to persist snapshot"
            );
            let _ = txn.rollback().await;
            return Err(WorkerError::Database);
        }

        if let Err(err) = txn.commit().await {
            error!(
                target: LOG_TARGET,
                error = ?err,
                hand_id,
                nonce,
                "failed to commit transaction"
            );
            return Err(WorkerError::Database);
        }

        self.state.upsert_snapshot(hand_id, snapshot.clone(), true);

        match apply_error {
            None => {
                if let Some(dispatcher) = &self.signal_dispatcher {
                    if let Err(err) = dispatcher.observe_snapshot(&snapshot).await {
                        warn!(
                            target: LOG_TARGET,
                            error = ?err,
                            hand_id,
                            nonce,
                            "failed to dispatch shuffler signals"
                        );
                    }
                }

                info!(
                    target: LOG_TARGET,
                    hand_id,
                    nonce,
                    "state applied successfully"
                );
                info!(
                    target: LOG_TARGET,
                    hand_id,
                    nonce,
                    "persisted snapshot"
                );
                Ok(())
            }
            Some(reason) => {
                warn!(
                    target: LOG_TARGET,
                    hand_id,
                    nonce,
                    failure_reason = reason,
                    "recorded failure snapshot"
                );
                Err(WorkerError::Apply)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("database error")]
    Database,
    #[error("apply error")]
    Apply,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::actor::AnyActor;
    use crate::ledger::types::HandId;
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use anyhow::{Context, Result};
    use ark_bn254::{Fq, Fr, G1Projective as Curve};
    use ark_ff::Zero;
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
        DbBackend, Statement, Value,
    };
    use std::{env, sync::Arc, time::Duration as StdDuration};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, timeout, Duration};
    use tracing::{info, Level};
    use tracing_subscriber::{filter, fmt, prelude::*};

    use crate::engine::nl::types::{HandConfig, TableStakes};
    use crate::ledger::hash::LedgerHasher;
    use crate::ledger::messages::{AnyGameMessage, GameShuffleMessage};
    use crate::ledger::snapshot::{
        AnyTableSnapshot, PhaseShuffling, ShufflerIdentity, ShufflerRoster, ShufflingSnapshot,
        SnapshotStatus, TableSnapshot,
    };
    use crate::ledger::store::snapshot::PreparedSnapshot;
    use crate::ledger::store::SeaOrmEventStore;
    use crate::ledger::types::StateHash;
    use crate::ledger::worker::WorkerError;
    use crate::signing::WithSignature;
    use async_trait::async_trait;

    #[derive(Default)]
    struct NoopSnapshotStore<C> {
        _marker: std::marker::PhantomData<C>,
    }

    #[async_trait]
    impl<C> SnapshotStore<C> for NoopSnapshotStore<C>
    where
        C: CurveGroup + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
        C::BaseField: PrimeField,
        C::ScalarField: PrimeField + Absorb,
        C::Affine: Absorb,
    {
        async fn persist_snapshot(
            &self,
            _snapshot: &AnyTableSnapshot<C>,
            _hasher: &Arc<dyn LedgerHasher + Send + Sync>,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn persist_snapshot_in_txn(
            &self,
            _txn: &DatabaseTransaction,
            _prepared: &PreparedSnapshot,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn sample_cipher() -> ElGamalCiphertext<Curve> {
        ElGamalCiphertext::new(Curve::zero(), Curve::zero())
    }

    fn shuffle_proof() -> ShuffleProof<Curve> {
        let input = vec![sample_cipher(); DECK_SIZE];
        let sorted = vec![(sample_cipher(), Fq::zero()); DECK_SIZE];
        let rerand = vec![Fr::zero(); DECK_SIZE];
        ShuffleProof::new(input, sorted, rerand).expect("valid shuffle proof")
    }

    fn prepare_shuffle_event(
        state: &LedgerState<Curve>,
        hand_id: HandId,
        nonce: u64,
    ) -> AnyMessageEnvelope<Curve> {
        let deck_vec: Vec<_> = (0..DECK_SIZE).map(|_| sample_cipher()).collect();
        let deck_in: [ElGamalCiphertext<Curve>; DECK_SIZE] =
            deck_vec.clone().try_into().expect("deck length");
        let deck_out = deck_in.clone();

        let shuffling = ShufflingSnapshot {
            initial_deck: deck_in.clone(),
            steps: Vec::new(),
            final_deck: deck_out.clone(),
            expected_order: vec![0],
        };

        let mut roster = ShufflerRoster::new();
        roster.insert(
            0,
            ShufflerIdentity {
                public_key: Curve::zero(),
                aggregated_public_key: Curve::zero(),
            },
        );

        let hand_cfg = HandConfig {
            stakes: TableStakes {
                small_blind: 0,
                big_blind: 0,
                ante: 0,
            },
            button: 0,
            small_blind_seat: 0,
            big_blind_seat: 0,
            check_raise_allowed: true,
        };

        let mut snapshot: TableSnapshot<PhaseShuffling, Curve> = TableSnapshot {
            game_id: TEST_GAME_ID,
            hand_id: Some(hand_id),
            sequence: 0,
            cfg: Arc::new(hand_cfg),
            shufflers: Arc::new(roster),
            players: Arc::new(Default::default()),
            seating: Arc::new(Default::default()),
            stacks: Arc::new(Default::default()),
            previous_hash: None,
            state_hash: StateHash::default(),
            status: SnapshotStatus::Success,
            shuffling,
            dealing: (),
            betting: (),
            reveals: (),
        };

        let hasher = state.hasher();
        snapshot.initialize_hash(&*hasher);
        state.upsert_snapshot(hand_id, AnyTableSnapshot::Shuffling(snapshot), true);

        let message = AnyGameMessage::Shuffle(GameShuffleMessage::new(
            deck_in,
            deck_out,
            shuffle_proof(),
            0,
        ));

        AnyMessageEnvelope {
            hand_id,
            game_id: TEST_GAME_ID,
            actor: AnyActor::Shuffler { shuffler_id: 0 },
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
                eprintln!("skipping worker test: failed to connect to postgres ({err})");
                return None;
            }
        };

        if let Err(err) = conn.ping().await {
            eprintln!("skipping worker test: ping postgres failed ({err})");
            return None;
        }

        let truncate = Statement::from_string(
            DbBackend::Postgres,
            "TRUNCATE TABLE public.events RESTART IDENTITY CASCADE",
        );
        if let Err(err) = conn.execute(truncate).await {
            eprintln!("skipping worker test: failed to truncate events table ({err})");
            return None;
        }

        Some(Arc::new(SeaOrmEventStore::new(conn)))
    }

    const TEST_PLAYER_ID: i64 = 9_001;
    const TEST_GAME_ID: i64 = 4_200_001;

    async fn seed_hand_rows(
        conn: &DatabaseConnection,
        hand_ids: impl IntoIterator<Item = HandId>,
    ) -> Result<()> {
        let hand_ids: Vec<HandId> = hand_ids.into_iter().collect();
        if hand_ids.is_empty() {
            return Ok(());
        }

        let insert_player = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO public.players (id, display_name, public_key, created_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (id) DO NOTHING",
            vec![
                Value::from(TEST_PLAYER_ID),
                Value::from("ledger-worker-test-player"),
                Value::from(vec![0u8]),
            ],
        );
        conn.execute(insert_player)
            .await
            .context("failed to upsert test player")?;

        let insert_game = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO public.games (
                 id,
                 created_at,
                 host_player_id,
                 name,
                 currency,
                 max_players,
                 small_blind,
                 big_blind,
                 ante,
                 rake_bps,
                 status
             )
             VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8, $9, $10::game_status)
             ON CONFLICT (id) DO NOTHING",
            vec![
                Value::from(TEST_GAME_ID),
                Value::from(TEST_PLAYER_ID),
                Value::from("ledger-worker-test-game"),
                Value::from("test"),
                Value::from(6i16),
                Value::from(1i64),
                Value::from(2i64),
                Value::from(0i64),
                Value::from(0i16),
                Value::from("active"),
            ],
        );
        conn.execute(insert_game)
            .await
            .context("failed to upsert test game")?;

        for hand_id in hand_ids {
            let insert_hand = Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO public.hands (
                     id,
                     game_id,
                     created_at,
                     hand_no,
                     button_seat,
                     small_blind_seat,
                     big_blind_seat,
                     deck_commitment,
                     status
                 )
                 VALUES ($1, $2, NOW(), $3, $4, $5, $6, NULL, $7::hand_status)
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    Value::from(hand_id),
                    Value::from(TEST_GAME_ID),
                    Value::from(hand_id),
                    Value::from(0i16),
                    Value::from(1i16),
                    Value::from(2i16),
                    Value::from("shuffling"),
                ],
            );
            conn.execute(insert_hand)
                .await
                .with_context(|| format!("failed to upsert test hand {}", hand_id))?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn worker_can_be_constructed() {
        let _guard = setup_test_tracing();
        let (_tx, rx) = mpsc::channel(16);
        let Some(store) = setup_event_store().await else {
            return;
        };
        seed_hand_rows(&store.connection, [0])
            .await
            .expect("seed worker hand");
        let state = Arc::new(LedgerState::<Curve>::new());
        let worker = LedgerWorker::new(
            rx,
            store.clone(),
            Arc::new(NoopSnapshotStore::<Curve>::default()),
            state.clone(),
            None,
        );
        assert!(state.hands().is_empty());
        let _ = worker;
    }

    #[tokio::test]
    async fn persist_before_apply() {
        let _guard = setup_test_tracing();
        let (_tx, rx) = mpsc::channel(16);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let hand_id: HandId = 1;
        seed_hand_rows(&store.connection, [hand_id])
            .await
            .expect("seed worker hand");
        let state = Arc::new(LedgerState::<Curve>::new());
        let worker = LedgerWorker::new(
            rx,
            store.clone(),
            Arc::new(NoopSnapshotStore::<Curve>::default()),
            state.clone(),
            None,
        );

        let event = prepare_shuffle_event(&state, hand_id, 0);
        let before_tip = state.tip_hash(hand_id);

        worker.handle_event(event.clone()).await.unwrap();

        let persisted = store.load_all_events().await.unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].envelope.nonce, event.nonce);

        let after_tip = state.tip_hash(hand_id);
        assert!(after_tip.is_some());
        assert_ne!(before_tip, after_tip);
    }

    #[tokio::test]
    async fn rollback_on_state_failure() {
        let _guard = setup_test_tracing();
        let (_tx, rx) = mpsc::channel(16);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let hand_id: HandId = 7;
        seed_hand_rows(&store.connection, [hand_id])
            .await
            .expect("seed worker hand");
        let state = Arc::new(LedgerState::<Curve>::new());
        let worker = LedgerWorker::new(
            rx,
            store.clone(),
            Arc::new(NoopSnapshotStore::<Curve>::default()),
            state.clone(),
            None,
        );

        let event = prepare_shuffle_event(&state, hand_id, 0);
        state.remove_hand(hand_id);
        let before_tip = state.tip_hash(hand_id);

        let result = worker.handle_event(event).await;
        assert!(matches!(result, Err(WorkerError::Apply)));

        let persisted = store.load_all_events().await.unwrap();
        assert!(persisted.is_empty());
        assert_eq!(state.tip_hash(hand_id), before_tip);
    }

    #[tokio::test]
    async fn run_loop_drains_queue() {
        let _guard = setup_test_tracing();
        let (tx, rx) = mpsc::channel(16);
        let Some(store) = setup_event_store().await else {
            return;
        };
        let hand_ids: Vec<HandId> = (0..3).map(|id| id as HandId).collect();
        seed_hand_rows(&store.connection, hand_ids.iter().copied())
            .await
            .expect("seed worker hands");
        let state = Arc::new(LedgerState::<Curve>::new());

        let worker = LedgerWorker::new(
            rx,
            store.clone(),
            Arc::new(NoopSnapshotStore::<Curve>::default()),
            state.clone(),
            None,
        );
        let runner = tokio::spawn(async move { worker.run().await.unwrap() });

        for (idx, hand_id) in hand_ids.iter().enumerate() {
            let env = prepare_shuffle_event(&state, *hand_id, idx as u64);
            info!(
                target: TEST_LOG_TARGET,
                ?hand_id,
                nonce = idx,
                "sending event to worker"
            );
            tx.send(env).await.unwrap();
        }
        drop(tx);
        info!(target: TEST_LOG_TARGET, "sender dropped; waiting for worker to drain");

        let mut poll_count: u32 = 0;
        timeout(Duration::from_secs(5), async {
            loop {
                let persisted = store.load_all_events().await.unwrap().len();
                info!(
                    target: TEST_LOG_TARGET,
                    poll = poll_count,
                    persisted,
                    expected = hand_ids.len(),
                    "checking event store"
                );
                poll_count = poll_count.saturating_add(1);
                if persisted == hand_ids.len() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("worker drained queue");

        runner.await.unwrap();

        for hand_id in hand_ids {
            assert!(state.tip_hash(hand_id).is_some());
        }
    }

    const TEST_LOG_TARGET: &str = "legit_poker";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_LOG_TARGET, Level::DEBUG)
            .with_target(LOG_TARGET, Level::DEBUG);

        let timer = fmt::time::uptime();
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::ENTER)
                    .with_file(true)
                    .with_line_number(true)
                    .with_timer(timer)
                    .with_writer(tracing_subscriber::fmt::TestWriter::default()),
            )
            .with(filter)
            .set_default()
    }
}
