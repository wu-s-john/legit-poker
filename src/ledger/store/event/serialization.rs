use anyhow::{anyhow, Context};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use crate::chaum_pedersen::ChaumPedersenProof;
use crate::db::entity::events;
use crate::db::entity::sea_orm_active_enums as db_enums;
use crate::engine::nl::actions::PlayerBetAction;
use crate::ledger::actor::AnyActor;
use crate::ledger::messages::{
    AnyGameMessage, AnyMessageEnvelope, FlopStreet, GameBlindingDecryptionMessage,
    GamePartialUnblindingShareMessage, GamePlayerMessage, GameShowdownMessage, GameShuffleMessage,
    PreflopStreet, RiverStreet, TurnStreet,
};
use crate::ledger::types::{GameId, HandStatus};
use crate::shuffling::data_structures::{ElGamalCiphertext, ShuffleProof, DECK_SIZE};
use crate::shuffling::player_decryption::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::signing::{Signable, WithSignature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredEnvelopePayload {
    pub(super) game_id: GameId,
    pub(super) message: StoredGameMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum StoredGameMessage {
    Shuffle {
        turn_index: u16,
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
    pub(super) fn message_type(&self) -> &'static str {
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

    pub(super) fn from_any<C>(message: &AnyGameMessage<C>) -> anyhow::Result<Self>
    where
        C: CurveGroup + CanonicalSerialize,
    {
        match message {
            AnyGameMessage::Shuffle(inner) => Ok(StoredGameMessage::Shuffle {
                turn_index: inner.turn_index,
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

    pub(super) fn into_any<C>(self) -> anyhow::Result<AnyGameMessage<C>>
    where
        C: CurveGroup + CanonicalDeserialize,
    {
        Ok(match self {
            StoredGameMessage::Shuffle {
                turn_index,
                deck_in,
                deck_out,
                proof,
            } => {
                let deck_in = decode_ciphertexts::<C>(&deck_in)?;
                let deck_out = decode_ciphertexts::<C>(&deck_out)?;
                let proof = decode_hex::<ShuffleProof<C>>(&proof)?;
                AnyGameMessage::Shuffle(GameShuffleMessage::new(
                    deck_in, deck_out, proof, turn_index,
                ))
            }
            StoredGameMessage::Blinding {
                card_in_deck_position,
                share,
            } => {
                let share = decode_hex::<PlayerTargetedBlindingContribution<C>>(&share)?;
                AnyGameMessage::Blinding(GameBlindingDecryptionMessage::new(
                    card_in_deck_position,
                    share,
                ))
            }
            StoredGameMessage::PartialUnblinding {
                card_in_deck_position,
                share,
            } => {
                let share = decode_hex::<PartialUnblindingShare<C>>(&share)?;
                AnyGameMessage::PartialUnblinding(GamePartialUnblindingShareMessage::new(
                    card_in_deck_position,
                    share,
                ))
            }
            StoredGameMessage::PlayerPreflop { action } => {
                AnyGameMessage::PlayerPreflop(GamePlayerMessage::<PreflopStreet, C>::new(action))
            }
            StoredGameMessage::PlayerFlop { action } => {
                AnyGameMessage::PlayerFlop(GamePlayerMessage::<FlopStreet, C>::new(action))
            }
            StoredGameMessage::PlayerTurn { action } => {
                AnyGameMessage::PlayerTurn(GamePlayerMessage::<TurnStreet, C>::new(action))
            }
            StoredGameMessage::PlayerRiver { action } => {
                AnyGameMessage::PlayerRiver(GamePlayerMessage::<RiverStreet, C>::new(action))
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

                AnyGameMessage::Showdown(GameShowdownMessage::new(
                    proofs,
                    card_in_deck_position,
                    ciphertexts,
                ))
            }
        })
    }
}

pub fn model_to_envelope<C>(row: events::Model) -> anyhow::Result<AnyMessageEnvelope<C>>
where
    C: CurveGroup + CanonicalSerialize + CanonicalDeserialize,
{
    tracing::debug!(
        target: "ledger::store::event",
        hand_id = row.hand_id,
        entity_kind = row.entity_kind,
        actor_kind = row.actor_kind,
        message_type = %row.message_type,
        nonce = row.nonce,
        "attempting to decode ledger event row"
    );
    let actor = decode_actor(&row)?;
    let public_key = deserialize_curve::<C>(&row.public_key)?;
    let nonce =
        u64::try_from(row.nonce).map_err(|_| anyhow!("stored nonce {} is negative", row.nonce))?;

    let payload: StoredEnvelopePayload =
        serde_json::from_value(row.payload).context("failed to deserialize event payload")?;
    tracing::trace!(
        target: "ledger::store::event",
        hand_id = row.hand_id,
        game_id = payload.game_id,
        "decoded event payload"
    );
    let message = match payload.message.into_any::<C>() {
        Ok(msg) => msg,
        Err(err) => {
            tracing::error!(
                target: "ledger::store::event",
                hand_id = row.hand_id,
                message_type = %row.message_type,
                error = %err,
                "failed to deserialize stored message"
            );
            return Err(err);
        }
    };

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

pub(super) fn encode_actor(actor: &AnyActor) -> anyhow::Result<ActorColumns> {
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

pub(super) fn to_db_hand_status(status: HandStatus) -> db_enums::HandStatus {
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

    vec_to_array(decoded, "deck")
}

fn encode_many<T>(items: &[T]) -> anyhow::Result<Vec<String>>
where
    T: CanonicalSerialize,
{
    items.iter().map(|item| encode_hex(item)).collect()
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

fn decode_many<T>(encoded: &[String]) -> anyhow::Result<Vec<T>>
where
    T: CanonicalDeserialize,
{
    encoded.iter().map(|value| decode_hex(value)).collect()
}

fn decode_hex<T>(value: &str) -> anyhow::Result<T>
where
    T: CanonicalDeserialize,
{
    let trimmed = value.trim();
    let mut owned = String::new();
    let input = if trimmed.len() % 2 == 1 {
        owned.reserve(trimmed.len() + 1);
        owned.push('0');
        owned.push_str(trimmed);
        tracing::warn!(
            target: "ledger::store::event",
            len = trimmed.len(),
            "hex payload had odd length; prefixed leading zero"
        );
        owned.as_str()
    } else {
        trimmed
    };
    let bytes = hex::decode(input).context("failed to decode hex payload stored in event")?;
    match T::deserialize_compressed(&mut &bytes[..]) {
        Ok(value) => Ok(value),
        Err(err) => {
            tracing::error!(
                target: "ledger::store::event",
                error = %err,
                byte_len = bytes.len(),
                first_byte = bytes.first().copied(),
                "canonical deserialize failed for hex payload"
            );
            Err(anyhow!("canonical deserialize failed: {err}"))
        }
    }
}

fn deserialize_curve<C>(bytes: &[u8]) -> anyhow::Result<C>
where
    C: CanonicalDeserialize,
{
    tracing::trace!(
        target: "ledger::store::event",
        byte_len = bytes.len(),
        tail = bytes.last().copied().unwrap_or_default(),
        "deserializing curve point"
    );
    match C::deserialize_compressed(&mut &bytes[..]) {
        Ok(curve) => Ok(curve),
        Err(ark_serialize::SerializationError::UnexpectedFlags) => {
            if let Some(normalized) = normalize_sw_compressed(bytes) {
                match C::deserialize_compressed(&mut &normalized[..]) {
                    Ok(curve) => {
                        tracing::warn!(
                            target: "ledger::store::event",
                            "normalized unexpected short Weierstrass flags in compressed point"
                        );
                        Ok(curve)
                    }
                    Err(err) => Err(anyhow!(
                        "curve deserialization failed after normalization: {err}"
                    )),
                }
            } else {
                tracing::error!(
                    target: "ledger::store::event",
                    byte_len = bytes.len(),
                    tail = bytes.last().copied().unwrap_or_default(),
                    "cannot normalize compressed point with unexpected flags"
                );
                Err(anyhow!(
                    "curve deserialization failed: unexpected compression flags"
                ))
            }
        }
        Err(err) => Err(anyhow!("curve deserialization failed: {err}")),
    }
}

fn normalize_sw_compressed(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut normalized = bytes.to_vec();
    let last = normalized.last_mut().expect("vec not empty");
    const SW_NEGATIVE: u8 = 1 << 7;
    const SW_INFINITY: u8 = 1 << 6;
    if (*last & (SW_NEGATIVE | SW_INFINITY)) == (SW_NEGATIVE | SW_INFINITY) {
        *last &= !SW_INFINITY;
        return Some(normalized);
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective as Curve;
    use ark_ec::PrimeGroup;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

    #[test]
    fn deserialize_curve_handles_negative_infinity_flags() {
        let point = -Curve::generator();
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .expect("compress curve point");
        assert_eq!(bytes.last().unwrap() & 0x80, 0x80);

        let mut invalid = bytes.clone();
        *invalid.last_mut().unwrap() |= 0x40;

        let err = Curve::deserialize_compressed(&mut &invalid[..])
            .expect_err("invalid flags should fail");
        assert!(matches!(err, SerializationError::UnexpectedFlags));

        let recovered = deserialize_curve::<Curve>(&invalid).expect("fallback normalizes flags");
        assert_eq!(recovered.into_affine(), point.into_affine());
    }
}

pub(super) struct ActorColumns {
    pub(super) entity_kind: i16,
    pub(super) entity_id: i64,
    pub(super) actor_kind: i16,
    pub(super) seat_id: Option<i16>,
    pub(super) shuffler_id: Option<i16>,
}

const ENTITY_PLAYER: i16 = 0;
const ENTITY_SHUFFLER: i16 = 1;
const ACTOR_NONE: i16 = 0;
const ACTOR_PLAYER: i16 = 1;
const ACTOR_SHUFFLER: i16 = 2;
