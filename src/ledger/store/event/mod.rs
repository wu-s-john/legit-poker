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
use crate::ledger::messages::AnyMessageEnvelope;
use crate::ledger::types::HandId;

pub use self::serialization::model_to_envelope;

use self::serialization::{
    encode_actor, to_db_hand_status, StoredEnvelopePayload, StoredGameMessage,
};

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

#[async_trait]
pub trait EventStore<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    async fn persist_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<()>;
    async fn persist_event_in_txn(
        &self,
        txn: &DatabaseTransaction,
        event: &AnyMessageEnvelope<C>,
    ) -> anyhow::Result<()>;
    async fn remove_event(&self, hand_id: HandId, nonce: u64) -> anyhow::Result<()>;
    async fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
    async fn load_hand_events(&self, hand_id: HandId)
        -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
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
    async fn persist_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<()> {
        let stored = StoredGameMessage::from_any(&event.message.value)?;
        let payload_value = serde_json::to_value(StoredEnvelopePayload {
            game_id: event.game_id,
            message: stored.clone(),
        })?;
        if tracing::enabled!(Level::DEBUG) {
            let payload_json = serde_json::to_string_pretty(&payload_value)?;
            debug!(
                target: LOG_TARGET,
                hand_id = event.hand_id,
                nonce = event.nonce,
                %payload_json,
                "persisting event payload"
            );
        }

        let actor_cols = encode_actor(&event.actor)?;
        let public_key = serialize_curve(&event.public_key)?;
        let nonce = i64::try_from(event.nonce)
            .map_err(|_| anyhow!("nonce {} exceeds i64::MAX", event.nonce))?;

        let active = events::ActiveModel {
            hand_id: Set(event.hand_id),
            entity_kind: Set(actor_cols.entity_kind),
            entity_id: Set(actor_cols.entity_id),
            actor_kind: Set(actor_cols.actor_kind),
            seat_id: Set(actor_cols.seat_id),
            shuffler_id: Set(actor_cols.shuffler_id),
            public_key: Set(public_key),
            nonce: Set(nonce),
            phase: Set(to_db_hand_status(event.message.value.phase())),
            message_type: Set(stored.message_type().to_string()),
            payload: Set(JsonValue::from(payload_value.clone())),
            signature: Set(event.message.signature.clone()),
            ..Default::default()
        };

        events::Entity::insert(active)
            .exec(&self.connection)
            .await
            .context("failed to persist ledger event")?;

        Ok(())
    }

    async fn persist_event_in_txn(
        &self,
        txn: &DatabaseTransaction,
        event: &AnyMessageEnvelope<C>,
    ) -> anyhow::Result<()> {
        let stored = StoredGameMessage::from_any(&event.message.value)?;
        let payload_value = serde_json::to_value(StoredEnvelopePayload {
            game_id: event.game_id,
            message: stored.clone(),
        })?;
        if tracing::enabled!(Level::DEBUG) {
            let payload_json = serde_json::to_string_pretty(&payload_value)?;
            debug!(
                target: LOG_TARGET,
                hand_id = event.hand_id,
                nonce = event.nonce,
                %payload_json,
                "persisting event payload (txn)"
            );
        }

        let actor_cols = encode_actor(&event.actor)?;
        let public_key = serialize_curve(&event.public_key)?;
        let nonce = i64::try_from(event.nonce)
            .map_err(|_| anyhow!("nonce {} exceeds i64::MAX", event.nonce))?;

        let active = events::ActiveModel {
            hand_id: Set(event.hand_id),
            entity_kind: Set(actor_cols.entity_kind),
            entity_id: Set(actor_cols.entity_id),
            actor_kind: Set(actor_cols.actor_kind),
            seat_id: Set(actor_cols.seat_id),
            shuffler_id: Set(actor_cols.shuffler_id),
            public_key: Set(public_key),
            nonce: Set(nonce),
            phase: Set(to_db_hand_status(event.message.value.phase())),
            message_type: Set(stored.message_type().to_string()),
            payload: Set(JsonValue::from(payload_value.clone())),
            signature: Set(event.message.signature.clone()),
            ..Default::default()
        };

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

    async fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
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
    ) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>> {
        let rows = events::Entity::find()
            .filter(events::Column::HandId.eq(hand_id))
            .order_by_asc(events::Column::Nonce)
            .all(&self.connection)
            .await
            .context("failed to load events for hand")?;

        rows.into_iter().map(model_to_envelope).collect()
    }

    fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::serialization::StoredGameMessage;
    use super::*;
    use crate::engine::nl::actions::PlayerBetAction;
    use crate::engine::nl::types::{HandConfig, TableStakes};
    use crate::ledger::actor::AnyActor;
    use crate::ledger::lobby::sea_orm::SeaOrmLobby;
    use crate::ledger::lobby::service::LedgerLobby;
    use crate::ledger::lobby::types::{
        CommenceGameParams, GameLobbyConfig, PlayerRecord, PlayerSeatSnapshot, ShufflerAssignment,
        ShufflerRecord, ShufflerRegistrationConfig,
    };
    use crate::ledger::messages::{
        AnyGameMessage, GamePlayerMessage, GameShuffleMessage, PreflopStreet,
    };
    use crate::ledger::operator::LedgerOperator;
    use crate::ledger::state::LedgerState;
    use crate::ledger::store::SeaOrmEventStore;
    use crate::ledger::typestate::MaybeSaved;
    use crate::ledger::verifier::LedgerVerifier;
    use crate::ledger::{GameId, HandId};
    use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
    use crate::signing::WithSignature;
    use ark_bn254::{Fr as TestScalar, G1Projective as Curve};
    use ark_ec::PrimeGroup;
    use ark_ff::{UniformRand, Zero};
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    };
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration as StdDuration;
    use tokio::sync::mpsc;

    static NEXT_KEY_SEED: AtomicU64 = AtomicU64::new(0);
    type BaseField = <Curve as ark_ec::CurveGroup>::BaseField;
    type ScalarField = <Curve as PrimeGroup>::ScalarField;

    #[derive(Clone)]
    struct TestKeys {
        host: Vec<u8>,
        player: Vec<u8>,
        shuffler: Vec<u8>,
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
                host: host.bytes,
                player: player.bytes,
                shuffler: shuffler.bytes.clone(),
                aggregated: serialize_point(&shuffler.point),
            }
        }
    }

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

        let lobby = SeaOrmLobby::new(conn.clone());
        let state = Arc::new(LedgerState::<Curve>::new());
        let verifier = Arc::new(LedgerVerifier::new(state.clone()));
        let event_store = Arc::new(SeaOrmEventStore::new(conn.clone()));

        let (tx, _rx) = mpsc::channel(4);
        let operator = LedgerOperator::new(
            verifier,
            tx,
            Arc::clone(&event_store) as Arc<dyn EventStore<Curve>>,
            Arc::clone(&state),
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
            public_key: host_keys.host.clone(),
            seat_preference: Some(0),
            state: MaybeSaved { id: None },
        };
        let metadata =
            <SeaOrmLobby as LedgerLobby<Curve>>::host_game(&lobby, host, lobby_cfg.clone())
                .await
                .expect("host_game should succeed in prepare_environment");

        let host_registered = <SeaOrmLobby as LedgerLobby<Curve>>::join_game(
            &lobby,
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
            public_key: guest_keys.player.clone(),
            seat_preference: Some(1),
            state: MaybeSaved { id: None },
        };

        let guest_saved = <SeaOrmLobby as LedgerLobby<Curve>>::join_game(
            &lobby,
            &metadata.record,
            guest,
            Some(1),
        )
        .await
        .expect("join_game (guest) should succeed in prepare_environment")
        .player;

        let third_keys = TestKeys::new();
        let third_player = PlayerRecord {
            display_name: "Third".into(),
            public_key: third_keys.player.clone(),
            seat_preference: Some(2),
            state: MaybeSaved { id: None },
        };

        let third_saved = <SeaOrmLobby as LedgerLobby<Curve>>::join_game(
            &lobby,
            &metadata.record,
            third_player,
            Some(2),
        )
        .await
        .expect("join_game (third) should succeed in prepare_environment")
        .player;

        let shuffler = ShufflerRecord {
            display_name: "Primary Shuffler".into(),
            public_key: host_keys.shuffler.clone(),
            state: MaybeSaved { id: None },
        };
        let shuffler_output = <SeaOrmLobby as LedgerLobby<Curve>>::register_shuffler(
            &lobby,
            &metadata.record,
            shuffler,
            ShufflerRegistrationConfig { sequence: Some(0) },
        )
        .await
        .expect("register_shuffler should succeed in prepare_environment");

        let params = CommenceGameParams {
            game: metadata.record.clone(),
            hand_no: 0,
            hand_config: HandConfig {
                stakes: lobby_cfg.stakes,
                button: 0,
                small_blind_seat: 0,
                big_blind_seat: 1,
                check_raise_allowed: lobby_cfg.check_raise_allowed,
            },
            players: vec![
                PlayerSeatSnapshot::new(
                    host_registered,
                    0,
                    lobby_cfg.buy_in,
                    metadata.host.public_key.clone(),
                ),
                PlayerSeatSnapshot::new(
                    guest_saved.clone(),
                    1,
                    lobby_cfg.buy_in,
                    guest_saved.public_key.clone(),
                ),
                PlayerSeatSnapshot::new(
                    third_saved.clone(),
                    2,
                    lobby_cfg.buy_in,
                    third_saved.public_key.clone(),
                ),
            ],
            shufflers: vec![ShufflerAssignment::new(
                shuffler_output.shuffler,
                shuffler_output.assigned_sequence,
                host_keys.shuffler.clone(),
                host_keys.aggregated.clone(),
            )],
            deck_commitment: None,
            buy_in: lobby_cfg.buy_in,
            min_players: lobby_cfg.min_players_to_start,
        };

        let hand = <SeaOrmLobby as LedgerLobby<Curve>>::commence_game(&lobby, &operator, params)
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

    #[tokio::test]
    async fn stored_message_roundtrip_player_action() {
        let message = AnyGameMessage::PlayerPreflop(
            GamePlayerMessage::<PreflopStreet, Curve>::new(PlayerBetAction::Call),
        );

        let stored = StoredGameMessage::from_any(&message).unwrap();
        let restored: AnyGameMessage<Curve> = stored.into_any().unwrap();
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
        store.persist_event(&envelope).await.unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].nonce, envelope.nonce);
        assert_eq!(loaded[0].hand_id, hand_id);
    }

    #[tokio::test]
    async fn remove_event_clears_rows() {
        let Some((store, hand_id, game_id)) = prepare_environment().await else {
            return;
        };

        let envelope = sample_shuffle_envelope(hand_id, game_id, 22);
        store.persist_event(&envelope).await.unwrap();
        store
            .remove_event(envelope.hand_id, envelope.nonce)
            .await
            .unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert!(loaded.is_empty());
    }
}
