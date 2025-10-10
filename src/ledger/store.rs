use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::chaum_pedersen::ChaumPedersenProof;
use crate::engine::nl::actions::PlayerBetAction;
use crate::ledger::actor::AnyActor;
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, FlopStreet, GameBlindingDecryptionMessage,
    GamePartialUnblindingShareMessage, GamePlayerMessage, GameShowdownMessage, GameShuffleMessage,
    PreflopStreet, RiverStreet, TurnStreet,
};
use crate::ledger::types::{GameId, HandId, HandStatus};
use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
use crate::shuffling::player_decryption::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::{Signable, WithSignature};

use crate::db::entity::events;
use crate::db::entity::sea_orm_active_enums as db_enums;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEnvelopePayload {
    game_id: GameId,
    message: StoredGameMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredGameMessage {
    Shuffle {
        deck_in: Vec<String>,
        deck_out: Vec<String>,
        proof: String,
    },
    Blinding {
        card_in_deck_position: u8,
        share: String,
    },
    PartialUnblinding {
        card_in_deck_position: u8,
        share: String,
    },
    PlayerPreflop {
        action: PlayerBetAction,
    },
    PlayerFlop {
        action: PlayerBetAction,
    },
    PlayerTurn {
        action: PlayerBetAction,
    },
    PlayerRiver {
        action: PlayerBetAction,
    },
    Showdown {
        chaum_pedersen_proofs: Vec<String>,
        card_in_deck_position: [u8; 2],
        hole_ciphertexts: Vec<String>,
    },
}

impl StoredGameMessage {
    fn message_type(&self) -> &'static str {
        match self {
            StoredGameMessage::Shuffle { .. } => "shuffle",
            StoredGameMessage::Blinding { .. } => "blinding",
            StoredGameMessage::PartialUnblinding { .. } => "partial_unblinding",
            StoredGameMessage::PlayerPreflop { .. } => "player_preflop",
            StoredGameMessage::PlayerFlop { .. } => "player_flop",
            StoredGameMessage::PlayerTurn { .. } => "player_turn",
            StoredGameMessage::PlayerRiver { .. } => "player_river",
            StoredGameMessage::Showdown { .. } => "showdown",
        }
    }

    fn from_any<C>(message: &AnyGameMessage<C>) -> anyhow::Result<Self>
    where
        C: CurveGroup + CanonicalSerialize,
    {
        match message {
            AnyGameMessage::Shuffle(inner) => Ok(StoredGameMessage::Shuffle {
                deck_in: encode_ciphertexts(&inner.deck_in)?,
                deck_out: encode_ciphertexts(&inner.deck_out)?,
                proof: encode_hex(&inner.proof)?,
            }),
            AnyGameMessage::Blinding(inner) => Ok(StoredGameMessage::Blinding {
                card_in_deck_position: inner.card_in_deck_position,
                share: encode_hex(&inner.share)?,
            }),
            AnyGameMessage::PartialUnblinding(inner) => Ok(StoredGameMessage::PartialUnblinding {
                card_in_deck_position: inner.card_in_deck_position,
                share: encode_hex(&inner.share)?,
            }),
            AnyGameMessage::PlayerPreflop(inner) => Ok(StoredGameMessage::PlayerPreflop {
                action: inner.action.clone(),
            }),
            AnyGameMessage::PlayerFlop(inner) => Ok(StoredGameMessage::PlayerFlop {
                action: inner.action.clone(),
            }),
            AnyGameMessage::PlayerTurn(inner) => Ok(StoredGameMessage::PlayerTurn {
                action: inner.action.clone(),
            }),
            AnyGameMessage::PlayerRiver(inner) => Ok(StoredGameMessage::PlayerRiver {
                action: inner.action.clone(),
            }),
            AnyGameMessage::Showdown(inner) => Ok(StoredGameMessage::Showdown {
                chaum_pedersen_proofs: encode_many(&inner.chaum_pedersen_proofs)?,
                card_in_deck_position: inner.card_in_deck_position,
                hole_ciphertexts: encode_many(&inner.hole_ciphertexts)?,
            }),
        }
    }

    fn into_any<C>(self) -> anyhow::Result<AnyGameMessage<C>>
    where
        C: CurveGroup + CanonicalDeserialize,
    {
        Ok(match self {
            StoredGameMessage::Shuffle {
                deck_in,
                deck_out,
                proof,
            } => {
                let deck_in = decode_ciphertexts::<C>(&deck_in)?;
                let deck_out = decode_ciphertexts::<C>(&deck_out)?;
                let proof = decode_hex::<ShuffleProof<C>>(&proof)?;
                AnyGameMessage::Shuffle(GameShuffleMessage {
                    deck_in,
                    deck_out,
                    proof,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::Blinding {
                card_in_deck_position,
                share,
            } => {
                let share = decode_hex::<PlayerTargetedBlindingContribution<C>>(&share)?;
                AnyGameMessage::Blinding(GameBlindingDecryptionMessage {
                    card_in_deck_position,
                    share,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::PartialUnblinding {
                card_in_deck_position,
                share,
            } => {
                let share = decode_hex::<PartialUnblindingShare<C>>(&share)?;
                AnyGameMessage::PartialUnblinding(GamePartialUnblindingShareMessage {
                    card_in_deck_position,
                    share,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::PlayerPreflop { action } => {
                AnyGameMessage::PlayerPreflop(GamePlayerMessage::<PreflopStreet, C> {
                    street: PreflopStreet::default(),
                    action,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::PlayerFlop { action } => {
                AnyGameMessage::PlayerFlop(GamePlayerMessage::<FlopStreet, C> {
                    street: FlopStreet::default(),
                    action,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::PlayerTurn { action } => {
                AnyGameMessage::PlayerTurn(GamePlayerMessage::<TurnStreet, C> {
                    street: TurnStreet::default(),
                    action,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::PlayerRiver { action } => {
                AnyGameMessage::PlayerRiver(GamePlayerMessage::<RiverStreet, C> {
                    street: RiverStreet::default(),
                    action,
                    _curve: PhantomData,
                })
            }
            StoredGameMessage::Showdown {
                chaum_pedersen_proofs,
                card_in_deck_position,
                hole_ciphertexts,
            } => {
                let proofs_vec = decode_many::<ChaumPedersenProof<C>>(&chaum_pedersen_proofs)?;
                let proofs = vec_to_array::<_, 2>(proofs_vec, "chaum_pedersen_proofs")?;
                let ciphertexts_vec =
                    decode_many::<PlayerAccessibleCiphertext<C>>(&hole_ciphertexts)?;
                let ciphertexts = vec_to_array::<_, 2>(ciphertexts_vec, "hole_ciphertexts")?;

                AnyGameMessage::Showdown(GameShowdownMessage {
                    chaum_pedersen_proofs: proofs,
                    card_in_deck_position,
                    hole_ciphertexts: ciphertexts,
                    _curve: PhantomData,
                })
            }
        })
    }
}

fn model_to_envelope<C>(row: events::Model) -> anyhow::Result<AnyMessageEnvelope<C>>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    let actor = decode_actor(&row)?;
    let public_key = deserialize_curve::<C>(&row.public_key)?;
    let nonce =
        u64::try_from(row.nonce).map_err(|_| anyhow!("stored nonce {} is negative", row.nonce))?;

    let payload: StoredEnvelopePayload =
        serde_json::from_value(row.payload).context("failed to deserialize event payload")?;
    let message = payload.message.into_any::<C>()?;

    let with_signature = WithSignature {
        value: message.clone(),
        signature: row.signature.clone(),
        transcript: message.to_signing_bytes(),
    };

    Ok(AnyMessageEnvelope {
        hand_id: row.hand_id,
        game_id: payload.game_id,
        actor,
        nonce,
        public_key,
        message: with_signature,
    })
}

fn encode_ciphertexts<C>(deck: &[ElGamalCiphertext<C>]) -> anyhow::Result<Vec<String>>
where
    C: CurveGroup + CanonicalSerialize,
{
    encode_many(deck)
}

fn decode_ciphertexts<C>(encoded: &[String]) -> anyhow::Result<[ElGamalCiphertext<C>; DECK_SIZE]>
where
    C: CurveGroup + CanonicalDeserialize,
{
    let decoded = encoded
        .iter()
        .map(|value| decode_hex::<ElGamalCiphertext<C>>(value))
        .collect::<anyhow::Result<Vec<_>>>()?;
    vec_to_array::<_, DECK_SIZE>(decoded, "deck")
}

fn encode_many<T>(items: &[T]) -> anyhow::Result<Vec<String>>
where
    T: CanonicalSerialize,
{
    items.iter().map(|item| encode_hex(item)).collect()
}

fn decode_many<T>(items: &[String]) -> anyhow::Result<Vec<T>>
where
    T: CanonicalDeserialize,
{
    items.iter().map(|value| decode_hex::<T>(value)).collect()
}

fn encode_hex<T>(value: &T) -> anyhow::Result<String>
where
    T: CanonicalSerialize,
{
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("canonical serialize failed: {err}"))?;
    Ok(hex::encode(buf))
}

fn decode_hex<T>(value: &str) -> anyhow::Result<T>
where
    T: CanonicalDeserialize,
{
    let bytes = hex::decode(value).context("failed to decode hex payload stored in event")?;
    T::deserialize_compressed(&mut &bytes[..])
        .map_err(|err| anyhow!("canonical deserialize failed: {err}"))
}

fn serialize_curve<C>(value: &C) -> anyhow::Result<Vec<u8>>
where
    C: CanonicalSerialize,
{
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|err| anyhow!("curve serialization failed: {err}"))?;
    Ok(buf)
}

fn deserialize_curve<C>(bytes: &[u8]) -> anyhow::Result<C>
where
    C: CanonicalDeserialize,
{
    C::deserialize_compressed(&mut &bytes[..])
        .map_err(|err| anyhow!("curve deserialization failed: {err}"))
}

fn vec_to_array<T, const N: usize>(vec: Vec<T>, label: &str) -> anyhow::Result<[T; N]> {
    vec.try_into().map_err(|_: Vec<T>| {
        anyhow!(
            "expected {} elements while decoding {} but lengths mismatched",
            N,
            label
        )
    })
}

struct ActorColumns {
    entity_kind: i16,
    entity_id: i64,
    actor_kind: i16,
    seat_id: Option<i16>,
    shuffler_id: Option<i16>,
}

const ENTITY_PLAYER: i16 = 0;
const ENTITY_SHUFFLER: i16 = 1;
const ACTOR_NONE: i16 = 0;
const ACTOR_PLAYER: i16 = 1;
const ACTOR_SHUFFLER: i16 = 2;

fn encode_actor(actor: &AnyActor) -> anyhow::Result<ActorColumns> {
    match actor {
        AnyActor::None => Ok(ActorColumns {
            entity_kind: ENTITY_PLAYER,
            entity_id: 0,
            actor_kind: ACTOR_NONE,
            seat_id: None,
            shuffler_id: None,
        }),
        AnyActor::Player { seat_id, player_id } => {
            let entity_id = i64::try_from(*player_id)
                .map_err(|_| anyhow!("player_id {} cannot be represented as i64", player_id))?;
            Ok(ActorColumns {
                entity_kind: ENTITY_PLAYER,
                entity_id,
                actor_kind: ACTOR_PLAYER,
                seat_id: Some(i16::from(*seat_id)),
                shuffler_id: None,
            })
        }
        AnyActor::Shuffler { shuffler_id } => {
            let shuffler_small = i16::try_from(*shuffler_id)
                .map_err(|_| anyhow!("shuffler_id {} cannot be represented as i16", shuffler_id))?;
            Ok(ActorColumns {
                entity_kind: ENTITY_SHUFFLER,
                entity_id: *shuffler_id,
                actor_kind: ACTOR_SHUFFLER,
                seat_id: None,
                shuffler_id: Some(shuffler_small),
            })
        }
    }
}

fn decode_actor(row: &events::Model) -> anyhow::Result<AnyActor> {
    match row.actor_kind {
        ACTOR_NONE => Ok(AnyActor::None),
        ACTOR_PLAYER => {
            let seat = row
                .seat_id
                .ok_or_else(|| anyhow!("player actor missing seat_id"))?;
            if row.entity_kind != ENTITY_PLAYER {
                return Err(anyhow!(
                    "player actor stored with mismatched entity_kind {}",
                    row.entity_kind
                ));
            }
            let player_id = u64::try_from(row.entity_id)
                .map_err(|_| anyhow!("player entity_id {} invalid", row.entity_id))?;
            let seat_id =
                u8::try_from(seat).map_err(|_| anyhow!("seat_id {} cannot fit in u8", seat))?;
            Ok(AnyActor::Player { seat_id, player_id })
        }
        ACTOR_SHUFFLER => {
            let id = row
                .shuffler_id
                .map(|value| i64::from(value))
                .unwrap_or(row.entity_id);
            if row.entity_kind != ENTITY_SHUFFLER {
                return Err(anyhow!(
                    "shuffler actor stored with mismatched entity_kind {}",
                    row.entity_kind
                ));
            }
            Ok(AnyActor::Shuffler { shuffler_id: id })
        }
        other => Err(anyhow!("unknown actor_kind value {}", other)),
    }
}

fn to_db_hand_status(status: HandStatus) -> db_enums::HandStatus {
    match status {
        HandStatus::Pending => db_enums::HandStatus::Pending,
        HandStatus::Shuffling => db_enums::HandStatus::Shuffling,
        HandStatus::Dealing => db_enums::HandStatus::Dealing,
        HandStatus::Betting => db_enums::HandStatus::Betting,
        HandStatus::Showdown => db_enums::HandStatus::Showdown,
        HandStatus::Complete => db_enums::HandStatus::Complete,
        HandStatus::Cancelled => db_enums::HandStatus::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective as Curve;

    #[test]
    fn stored_message_roundtrip_player_action() {
        let message = AnyGameMessage::PlayerPreflop(GamePlayerMessage::<PreflopStreet, Curve> {
            street: PreflopStreet,
            action: PlayerBetAction::Call,
            _curve: PhantomData,
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
}
