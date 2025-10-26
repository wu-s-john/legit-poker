mod serialization;

use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde_json::Value as JsonValue;
use tracing::{debug, Level};

use crate::db::entity::events;
use crate::ledger::messages::FinalizedAnyMessageEnvelope;
use crate::ledger::snapshot::{SnapshotSeq, SnapshotStatus};
use crate::ledger::types::HandId;

pub use self::serialization::model_to_envelope;

use self::serialization::{encode_actor, message_type, to_db_event_phase};

pub type SharedEventStore<C> = Arc<dyn EventStore<C>>;

const LOG_TARGET: &str = "legit_poker::ledger::event_store";

pub fn serialize_curve<C>(value: &C) -> anyhow::Result<Vec<u8>>
where
    C: CanonicalSerialize,
{
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("curve serialization failed: {err}"))?;
    Ok(buf)
}

fn status_columns(status: &SnapshotStatus) -> (bool, Option<String>) {
    match status {
        SnapshotStatus::Success => (true, None),
        SnapshotStatus::Failure(reason) => (false, Some(reason.clone())),
    }
}

fn log_event_payload<C>(
    event: &FinalizedAnyMessageEnvelope<C>,
    payload_value: &JsonValue,
    message: &str,
) -> anyhow::Result<()>
where
    C: CurveGroup,
{
    if tracing::enabled!(Level::DEBUG) {
        let payload_json = serde_json::to_string_pretty(payload_value)?;
        debug!(
            target = LOG_TARGET,
            hand_id = event.envelope.hand_id,
            nonce = event.envelope.nonce,
            %payload_json,
            message = message
        );
    }
    Ok(())
}

fn active_model_for_event<C>(
    event: &FinalizedAnyMessageEnvelope<C>,
    message_type: &str,
    payload_value: &JsonValue,
) -> anyhow::Result<events::ActiveModel>
where
    C: CurveGroup + CanonicalSerialize,
{
    let actor_cols = encode_actor(&event.envelope.actor)?;
    let public_key = serialize_curve(&event.envelope.public_key)?;
    let nonce = i64::try_from(event.envelope.nonce)
        .map_err(|_| anyhow!("nonce {} exceeds i64::MAX", event.envelope.nonce))?;
    let (is_successful, failure_message) = status_columns(&event.snapshot_status);
    let snapshot_number = i32::try_from(event.snapshot_sequence_id).map_err(|_| {
        anyhow!(
            "snapshot sequence {} exceeds i32::MAX",
            event.snapshot_sequence_id
        )
    })?;

    Ok(events::ActiveModel {
        game_id: Set(event.envelope.game_id),
        hand_id: Set(event.envelope.hand_id),
        entity_kind: Set(actor_cols.entity_kind),
        entity_id: Set(actor_cols.entity_id),
        actor_kind: Set(actor_cols.actor_kind),
        seat_id: Set(actor_cols.seat_id),
        shuffler_id: Set(actor_cols.shuffler_id),
        public_key: Set(public_key),
        nonce: Set(nonce),
        phase: Set(to_db_event_phase(event.envelope.message.value.phase())),
        snapshot_number: Set(snapshot_number),
        is_successful: Set(is_successful),
        failure_message: Set(failure_message),
        resulting_phase: Set(to_db_event_phase(event.applied_phase)),
        message_type: Set(message_type.to_string()),
        payload: Set(payload_value.clone()),
        signature: Set(event.envelope.message.signature.clone()),
        ..Default::default()
    })
}

#[async_trait]
pub trait EventStore<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    async fn persist_event(&self, event: &FinalizedAnyMessageEnvelope<C>) -> anyhow::Result<()>;
    async fn persist_event_in_txn(
        &self,
        txn: &DatabaseTransaction,
        event: &FinalizedAnyMessageEnvelope<C>,
    ) -> anyhow::Result<()>;
    async fn remove_event(&self, hand_id: HandId, nonce: u64) -> anyhow::Result<()>;
    async fn load_all_events(&self) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>>;
    async fn load_hand_events(
        &self,
        hand_id: HandId,
    ) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>>;
    async fn load_hand_events_in_sequence_range(
        &self,
        hand_id: HandId,
        from: Option<SnapshotSeq>,
        to: Option<SnapshotSeq>,
    ) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>>;
    fn connection(&self) -> &DatabaseConnection;
}

pub struct SeaOrmEventStore<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub connection: DatabaseConnection,
    _marker: PhantomData<C>,
}

impl<C> SeaOrmEventStore<C>
where
    C: CurveGroup + Send + Sync + 'static,
{
    pub fn new(connection: DatabaseConnection) -> Self {
        Self {
            connection,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<C> EventStore<C> for SeaOrmEventStore<C>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize + Send + Sync + 'static,
{
    async fn persist_event(&self, event: &FinalizedAnyMessageEnvelope<C>) -> anyhow::Result<()> {
        let message_json = serde_json::to_value(&event.envelope.message.value)?;
        let payload_value = message_json;
        log_event_payload(event, &payload_value, "persisting event payload")?;

        let active = active_model_for_event(
            event,
            message_type(&event.envelope.message.value),
            &payload_value,
        )?;

        events::Entity::insert(active)
            .exec(&self.connection)
            .await
            .context("failed to persist ledger event")?;

        Ok(())
    }

    async fn persist_event_in_txn(
        &self,
        txn: &DatabaseTransaction,
        event: &FinalizedAnyMessageEnvelope<C>,
    ) -> anyhow::Result<()> {
        let message_json = serde_json::to_value(&event.envelope.message.value)?;
        let payload_value = message_json;
        log_event_payload(event, &payload_value, "persisting event payload (txn)")?;

        let active = active_model_for_event(
            event,
            message_type(&event.envelope.message.value),
            &payload_value,
        )?;

        events::Entity::insert(active)
            .exec(txn)
            .await
            .context("failed to persist ledger event")?;

        Ok(())
    }

    async fn remove_event(&self, hand_id: HandId, nonce: u64) -> anyhow::Result<()> {
        let nonce =
            i64::try_from(nonce).map_err(|_| anyhow!("nonce {} exceeds i64::MAX", nonce))?;

        events::Entity::delete_many()
            .filter(events::Column::HandId.eq(hand_id))
            .filter(events::Column::Nonce.eq(nonce))
            .exec(&self.connection)
            .await
            .context("failed to rollback persisted event")?;

        Ok(())
    }

    async fn load_all_events(&self) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>> {
        let rows = events::Entity::find()
            .order_by_asc(events::Column::HandId)
            .order_by_asc(events::Column::Nonce)
            .all(&self.connection)
            .await
            .context("failed to load events from database")?;

        rows.into_iter().map(model_to_envelope).collect()
    }

    async fn load_hand_events(
        &self,
        hand_id: HandId,
    ) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>> {
        let rows = events::Entity::find()
            .filter(events::Column::HandId.eq(hand_id))
            .order_by_asc(events::Column::Nonce)
            .all(&self.connection)
            .await
            .context("failed to load events for hand")?;

        rows.into_iter().map(model_to_envelope).collect()
    }

    async fn load_hand_events_in_sequence_range(
        &self,
        hand_id: HandId,
        from: Option<SnapshotSeq>,
        to: Option<SnapshotSeq>,
    ) -> anyhow::Result<Vec<FinalizedAnyMessageEnvelope<C>>> {
        let mut query = events::Entity::find().filter(events::Column::HandId.eq(hand_id));

        if let Some(start) = from {
            let snapshot_start = i32::try_from(start).map_err(|_| {
                anyhow!("snapshot sequence {start} exceeds i32::MAX and cannot be queried")
            })?;
            query = query.filter(events::Column::SnapshotNumber.gte(snapshot_start));
        }

        if let Some(end) = to {
            let snapshot_end = i32::try_from(end).map_err(|_| {
                anyhow!("snapshot sequence {end} exceeds i32::MAX and cannot be queried")
            })?;
            query = query.filter(events::Column::SnapshotNumber.lte(snapshot_end));
        }

        let rows = query
            .order_by_asc(events::Column::SnapshotNumber)
            .order_by_asc(events::Column::Nonce)
            .all(&self.connection)
            .await
            .context("failed to load events for hand in sequence range")?;

        rows.into_iter().map(model_to_envelope).collect()
    }

    fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{connect_to_postgres_db, postgres_test_url};
    use crate::engine::nl::actions::PlayerBetAction;
    use crate::engine::nl::types::{HandConfig, TableStakes};
    use crate::ledger::actor::AnyActor;
    use crate::ledger::lobby::types::{
        CommenceGameParams, GameLobbyConfig, PlayerRecord, ShufflerRecord, ShufflerRegistrationConfig,
    };
    use crate::ledger::messages::{
        AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope, GamePlayerMessage,
        GameShuffleMessage, PreflopStreet,
    };
    use crate::ledger::operator::LedgerOperator;
    use crate::ledger::snapshot::SnapshotStatus;
    use crate::ledger::state::LedgerState;
    use crate::ledger::store::SeaOrmEventStore;
    use crate::ledger::types::EventPhase;
    use crate::ledger::typestate::MaybeSaved;
    use crate::ledger::verifier::LedgerVerifier;
    use crate::ledger::{GameId, HandId, LobbyService, LobbyServiceFactory};
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use crate::signing::WithSignature;
    use ark_bn254::{Fr as TestScalar, G1Projective as Curve};
    use ark_ec::PrimeGroup;
    use ark_ff::{UniformRand, Zero};
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};

    static NEXT_KEY_SEED: AtomicU64 = AtomicU64::new(0);
    type BaseField = <Curve as ark_ec::CurveGroup>::BaseField;
    type ScalarField = <Curve as PrimeGroup>::ScalarField;

    #[derive(Clone)]
    struct TestKeys {
        host: GeneratedKey,
        player: GeneratedKey,
        shuffler: GeneratedKey,
        aggregated: Vec<u8>,
    }

    impl TestKeys {
        fn new() -> Self {
            Self::from_seed(NEXT_KEY_SEED.fetch_add(1, Ordering::Relaxed) + 1)
        }

        fn from_seed(seed: u64) -> Self {
            let mut rng = StdRng::seed_from_u64(seed);
            let host = sample_key(&mut rng);
            let player = sample_key(&mut rng);
            let shuffler = sample_key(&mut rng);
            Self {
                host,
                player,
                shuffler: shuffler.clone(),
                aggregated: serialize_point(&shuffler.point),
            }
        }
    }

    #[derive(Clone)]
    struct GeneratedKey {
        point: Curve,
        bytes: Vec<u8>,
    }

    fn sample_key(rng: &mut StdRng) -> GeneratedKey {
        let scalar = TestScalar::rand(rng);
        let point = Curve::generator() * scalar;
        let bytes = serialize_point(&point);
        GeneratedKey { point, bytes }
    }

    fn serialize_point(point: &Curve) -> Vec<u8> {
        let mut buf = Vec::new();
        point
            .serialize_compressed(&mut buf)
            .expect("compress curve point");
        buf
    }

    fn shuffle_proof() -> ShuffleProof<Curve> {
        let input = vec![ElGamalCiphertext::new(Curve::zero(), Curve::zero()); DECK_SIZE];
        let sorted = vec![
            (
                ElGamalCiphertext::new(Curve::zero(), Curve::zero()),
                BaseField::zero(),
            );
            DECK_SIZE
        ];
        let rerand = vec![ScalarField::zero(); DECK_SIZE];
        ShuffleProof::new(input, sorted, rerand).expect("valid shuffle proof")
    }

    async fn reset_database(conn: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
        conn.execute(Statement::from_string(
            DbBackend::Postgres,
            "TRUNCATE TABLE \
                public.table_snapshots, \
                public.phases, \
                public.hand_configs, \
                public.events, \
                public.hand_shufflers, \
                public.hand_player, \
                public.hands, \
                public.game_shufflers, \
                public.game_players, \
                public.games, \
                public.shufflers, \
                public.players \
             RESTART IDENTITY CASCADE",
        ))
        .await?;
        Ok(())
    }

    async fn prepare_environment() -> Option<(Arc<SeaOrmEventStore<Curve>>, HandId, GameId)> {
        let url = postgres_test_url();
        let conn = match connect_to_postgres_db(&url).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("skipping event store test: failed to connect to postgres ({err})");
                return None;
            }
        };

        if let Err(err) = conn.ping().await {
            eprintln!("skipping event store test: ping postgres failed ({err})");
            return None;
        }

        if let Err(err) = reset_database(&conn).await {
            eprintln!("skipping event store test: failed to reset database ({err})");
            return None;
        }

        let lobby: Arc<dyn LobbyService<Curve>> =
            Arc::new(LobbyServiceFactory::<Curve>::from_sea_orm(conn.clone()));
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(LedgerVerifier::new(state.clone()));
        let event_store = Arc::new(SeaOrmEventStore::new(conn.clone()));

        let (tx, _rx) = mpsc::channel(4);
        let (events_tx, _) = broadcast::channel(16);
        let (snapshots_tx, _) = broadcast::channel(16);
        let (staging_tx, _) = broadcast::channel(16);
        let operator = LedgerOperator::new(
            verifier,
            tx,
            Arc::clone(&event_store) as Arc<dyn EventStore<Curve>>,
            Arc::clone(&state),
            events_tx,
            snapshots_tx,
            staging_tx,
        );

        let host_keys = TestKeys::new();
        let lobby_cfg = GameLobbyConfig {
            name: "event-test".into(),
            currency: "chips".into(),
            stakes: TableStakes {
                small_blind: 1,
                big_blind: 2,
                ante: 0,
            },
            max_players: 6,
            rake_bps: 0,
            buy_in: 100,
            min_players_to_start: 3,
            check_raise_allowed: true,
            action_time_limit: std::time::Duration::from_secs(30),
        };

        let host = PlayerRecord {
            display_name: "Host".into(),
            public_key: host_keys.host.point,
            seat_preference: Some(0),
            state: MaybeSaved { id: None },
        };
        let metadata = lobby
            .host_game(host, lobby_cfg.clone())
            .await
            .expect("host_game should succeed in prepare_environment");

        let host_registered = lobby
            .join_game(
                &metadata.record,
                PlayerRecord {
                    display_name: metadata.host.display_name.clone(),
                    public_key: metadata.host.public_key.clone(),
                    seat_preference: Some(0),
                    state: MaybeSaved {
                        id: Some(metadata.host.state.id),
                    },
                },
                Some(0),
            )
            .await
            .expect("join_game (host) should succeed in prepare_environment")
            .player;

        let guest_keys = TestKeys::new();
        let guest = PlayerRecord {
            display_name: "Guest".into(),
            public_key: guest_keys.player.point,
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        };

        let guest_saved = lobby
            .join_game(&metadata.record, guest, Some(1))
            .await
            .expect("join_game (guest) should succeed in prepare_environment")
            .player;

        let third_keys = TestKeys::new();
        let third_player = PlayerRecord {
            display_name: "Third".into(),
            public_key: third_keys.player.point,
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        };

        let third_saved = lobby
            .join_game(&metadata.record, third_player, Some(2))
            .await
            .expect("join_game (third) should succeed in prepare_environment")
            .player;

        let shuffler = ShufflerRecord {
            display_name: "Primary Shuffler".into(),
            public_key: host_keys.shuffler.point,
            state: MaybeSaved { id: None },
        };
        let shuffler_output = lobby
            .register_shuffler(
                &metadata.record,
                shuffler,
                ShufflerRegistrationConfig { sequence: Some(0) },
            )
            .await
            .expect("register_shuffler should succeed in prepare_environment");

        let params = CommenceGameParams {
            game_id: metadata.record.state.id,
            hand_no: 0,
            button_seat: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            deck_commitment: None,
        player_stacks: None, // First hand - use buy-in
        };

        let hand = lobby
            .commence_game(&operator.state().hasher(), params)
            .await
            .expect("commence_game should succeed in prepare_environment")
            .hand
            .state
            .id;

        Some((event_store, hand, metadata.record.state.id))
    }

    fn sample_shuffle_envelope(
        hand_id: HandId,
        game_id: GameId,
        nonce: u64,
    ) -> AnyMessageEnvelope<Curve> {
        let deck = std::array::from_fn(|_| ElGamalCiphertext::new(Curve::zero(), Curve::zero()));
        let message = AnyGameMessage::Shuffle(GameShuffleMessage::new(
            deck.clone(),
            deck,
            shuffle_proof(),
            0,
        ));

        AnyMessageEnvelope {
            hand_id,
            game_id,
            actor: AnyActor::Shuffler {
                shuffler_id: 0,
                shuffler_key: crate::ledger::CanonicalKey::new(Curve::zero()),
            },
            nonce,
            public_key: Curve::zero(),
            message: WithSignature {
                value: message,
                signature: Vec::new(),
            },
        }
    }

    fn finalized(envelope: AnyMessageEnvelope<Curve>) -> FinalizedAnyMessageEnvelope<Curve> {
        FinalizedAnyMessageEnvelope::new(
            envelope,
            SnapshotStatus::Success,
            EventPhase::Shuffling,
            1,
        )
    }

    #[tokio::test]
    async fn stored_message_roundtrip_player_action() {
        let message = AnyGameMessage::PlayerPreflop(
            GamePlayerMessage::<PreflopStreet, Curve>::new(PlayerBetAction::Call),
        );

        let json = serde_json::to_value(&message).unwrap();
        let restored: AnyGameMessage<Curve> = serde_json::from_value(json).unwrap();
        match restored {
            AnyGameMessage::PlayerPreflop(inner) => {
                assert!(matches!(inner.action, PlayerBetAction::Call));
            }
            _ => panic!("restored wrong variant"),
        }
    }

    #[tokio::test]
    async fn persist_and_load_events() {
        let Some((store, hand_id, game_id)) = prepare_environment().await else {
            return;
        };

        let envelope = sample_shuffle_envelope(hand_id, game_id, 10);
        store
            .persist_event(&finalized(envelope.clone()))
            .await
            .unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].envelope.nonce, envelope.nonce);
        assert_eq!(loaded[0].envelope.hand_id, hand_id);
    }

    #[tokio::test]
    async fn remove_event_clears_rows() {
        let Some((store, hand_id, game_id)) = prepare_environment().await else {
            return;
        };

        let envelope = sample_shuffle_envelope(hand_id, game_id, 22);
        store
            .persist_event(&finalized(envelope.clone()))
            .await
            .unwrap();
        store
            .remove_event(envelope.hand_id, envelope.nonce)
            .await
            .unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert!(loaded.is_empty());
    }
}
