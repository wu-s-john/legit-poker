mod serialization;

use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set};
use serde_json::Value as JsonValue;

use crate::db::entity::events;
use crate::ledger::messages::AnyMessageEnvelope;
use crate::ledger::types::HandId;

use self::serialization::{
    encode_actor, model_to_envelope, serialize_curve, to_db_hand_status, StoredEnvelopePayload,
    StoredGameMessage,
};

pub type SharedEventStore<C> = Arc<dyn EventStore<C>>;

#[async_trait]
pub trait EventStore<C>: Send + Sync
where
    C: CurveGroup + Send + Sync + 'static,
{
    async fn persist_event(&self, event: &AnyMessageEnvelope<C>) -> anyhow::Result<()>;
    async fn remove_event(&self, hand_id: HandId, nonce: u64) -> anyhow::Result<()>;
    async fn load_all_events(&self) -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
    async fn load_hand_events(&self, hand_id: HandId)
        -> anyhow::Result<Vec<AnyMessageEnvelope<C>>>;
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
        let payload = serde_json::to_value(StoredEnvelopePayload {
            game_id: event.game_id,
            message: stored.clone(),
        })?;

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
            payload: Set(JsonValue::from(payload)),
            signature: Set(event.message.signature.clone()),
            ..Default::default()
        };

        events::Entity::insert(active)
            .exec(&self.connection)
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
}

#[cfg(test)]
mod tests {
    use super::serialization::StoredGameMessage;
    use super::*;
    use crate::engine::nl::actions::PlayerBetAction;
    use crate::ledger::actor::AnyActor;
    use crate::ledger::messages::{AnyGameMessage, GamePlayerMessage, PreflopStreet};
    use crate::ledger::store::SeaOrmEventStore;
    use crate::ledger::{GameId, HandId};
    use crate::signing::WithSignature;
    use ark_bn254::G1Projective as Curve;
    use ark_ff::Zero;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use std::env;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    fn sample_verified_envelope(nonce: u64) -> AnyMessageEnvelope<Curve> {
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
                eprintln!("skipping event store test: failed to connect to postgres ({err})");
                return None;
            }
        };

        if let Err(err) = conn.ping().await {
            eprintln!("skipping event store test: ping postgres failed ({err})");
            return None;
        }

        let truncate = Statement::from_string(
            DbBackend::Postgres,
            "TRUNCATE TABLE public.events RESTART IDENTITY CASCADE",
        );
        if let Err(err) = conn.execute(truncate).await {
            eprintln!("skipping event store test: failed to truncate events table ({err})");
            return None;
        }

        Some(Arc::new(SeaOrmEventStore::new(conn)))
    }

    #[tokio::test]
    async fn stored_message_roundtrip_player_action() {
        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage::<PreflopStreet, Curve> {
            street: PreflopStreet,
            action: PlayerBetAction::Call,
            _curve: std::marker::PhantomData,
        });

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
        let Some(store) = setup_event_store().await else {
            return;
        };

        let envelope = sample_verified_envelope(10);
        store.persist_event(&envelope).await.unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].nonce, envelope.nonce);
    }

    #[tokio::test]
    async fn remove_event_clears_rows() {
        let Some(store) = setup_event_store().await else {
            return;
        };

        let envelope = sample_verified_envelope(22);
        store.persist_event(&envelope).await.unwrap();
        store
            .remove_event(envelope.hand_id, envelope.nonce)
            .await
            .unwrap();

        let loaded = store.load_all_events().await.unwrap();
        assert!(loaded.is_empty());
    }
}
