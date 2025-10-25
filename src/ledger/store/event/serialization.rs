use crate::db::entity::events;
use crate::db::entity::sea_orm_active_enums as db_enums;
use crate::ledger::actor::AnyActor;
use crate::ledger::messages::{AnyGameMessage, AnyMessageEnvelope, FinalizedAnyMessageEnvelope};
use crate::ledger::serialization::deserialize_curve_bytes;
use crate::ledger::snapshot::SnapshotStatus;
use crate::ledger::types::EventPhase;
use crate::signing::WithSignature;
use anyhow::{anyhow, Context};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chrono::{DateTime, Utc};

pub(super) fn message_type<C>(message: &AnyGameMessage<C>) -> &'static str
where
    C: CurveGroup,
{
    match message {
        AnyGameMessage::Shuffle(_) => "shuffle",
        AnyGameMessage::Blinding(_) => "blinding",
        AnyGameMessage::PartialUnblinding(_) => "partial_unblinding",
        AnyGameMessage::PlayerPreflop(_) => "player_preflop",
        AnyGameMessage::PlayerFlop(_) => "player_flop",
        AnyGameMessage::PlayerTurn(_) => "player_turn",
        AnyGameMessage::PlayerRiver(_) => "player_river",
        AnyGameMessage::Showdown(_) => "showdown",
    }
}

pub fn model_to_envelope<C>(row: events::Model) -> anyhow::Result<FinalizedAnyMessageEnvelope<C>>
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
    let public_key = deserialize_curve_bytes::<C>(&row.public_key)
        .context("failed to deserialize stored public key")?;
    let canonical_key = crate::ledger::CanonicalKey::new(public_key);
    let actor = decode_actor(&row, canonical_key)?;
    let nonce =
        u64::try_from(row.nonce).map_err(|_| anyhow!("stored nonce {} is negative", row.nonce))?;

    let message: AnyGameMessage<C> = serde_json::from_value(row.payload)
        .context("failed to deserialize stored message payload")?;

    let with_signature = WithSignature {
        value: message.clone(),
        signature: row.signature.clone(),
    };

    let envelope = AnyMessageEnvelope {
        hand_id: row.hand_id,
        game_id: row.game_id,
        actor,
        nonce,
        public_key,
        message: with_signature,
    };

    let snapshot_sequence_id = u32::try_from(row.snapshot_number)
        .map_err(|_| anyhow!("stored snapshot_number {} is negative", row.snapshot_number))?;
    let snapshot_status = if row.is_successful {
        SnapshotStatus::Success
    } else {
        SnapshotStatus::Failure(
            row.failure_message
                .unwrap_or_else(|| "unknown failure".to_string()),
        )
    };

    // Convert SeaORM TimeDateTimeWithTimeZone (time::OffsetDateTime) to chrono::DateTime<Utc>
    let timestamp_nanos = row
        .inserted_at
        .unix_timestamp_nanos()
        .try_into()
        .context("timestamp overflow converting to i64")?;
    let created_timestamp = DateTime::<Utc>::from_timestamp_nanos(timestamp_nanos);

    Ok(FinalizedAnyMessageEnvelope::with_timestamp(
        envelope,
        snapshot_status,
        from_db_event_phase(row.resulting_phase),
        snapshot_sequence_id,
        created_timestamp,
    ))
}

pub(super) fn encode_actor<C>(actor: &AnyActor<C>) -> anyhow::Result<ActorColumns>
where
    C: ark_ec::CurveGroup,
{
    match actor {
        AnyActor::None => Ok(ActorColumns {
            entity_kind: ENTITY_PLAYER,
            entity_id: 0,
            actor_kind: ACTOR_NONE,
            seat_id: None,
            shuffler_id: None,
        }),
        AnyActor::Player {
            seat_id, player_id, ..
        } => {
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
        AnyActor::Shuffler { shuffler_id, .. } => {
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

pub(super) fn to_db_event_phase(phase: EventPhase) -> db_enums::EventPhase {
    match phase {
        EventPhase::Pending => db_enums::EventPhase::Pending,
        EventPhase::Shuffling => db_enums::EventPhase::Shuffling,
        EventPhase::Dealing => db_enums::EventPhase::Dealing,
        EventPhase::Betting => db_enums::EventPhase::Betting,
        EventPhase::Reveals => db_enums::EventPhase::Reveals,
        EventPhase::Showdown => db_enums::EventPhase::Showdown,
        EventPhase::Complete => db_enums::EventPhase::Complete,
        EventPhase::Cancelled => db_enums::EventPhase::Cancelled,
    }
}

pub(super) fn from_db_event_phase(phase: db_enums::EventPhase) -> EventPhase {
    match phase {
        db_enums::EventPhase::Pending => EventPhase::Pending,
        db_enums::EventPhase::Shuffling => EventPhase::Shuffling,
        db_enums::EventPhase::Dealing => EventPhase::Dealing,
        db_enums::EventPhase::Betting => EventPhase::Betting,
        db_enums::EventPhase::Reveals => EventPhase::Reveals,
        db_enums::EventPhase::Showdown => EventPhase::Showdown,
        db_enums::EventPhase::Complete => EventPhase::Complete,
        db_enums::EventPhase::Cancelled => EventPhase::Cancelled,
    }
}

fn decode_actor<C>(
    row: &events::Model,
    canonical_key: crate::ledger::CanonicalKey<C>,
) -> anyhow::Result<AnyActor<C>>
where
    C: ark_ec::CurveGroup,
{
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
            Ok(AnyActor::Player {
                seat_id,
                player_id,
                player_key: canonical_key,
            })
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
            Ok(AnyActor::Shuffler {
                shuffler_id: id,
                shuffler_key: canonical_key,
            })
        }
        other => Err(anyhow!("unknown actor_kind value {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::serialization::deserialize_curve_bytes;
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

        let recovered =
            deserialize_curve_bytes::<Curve>(&invalid).expect("fallback normalizes flags");
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
