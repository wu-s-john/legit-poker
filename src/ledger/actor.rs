use ark_ec::CurveGroup;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    engine::nl::{PlayerId, SeatId},
    ledger::{CanonicalKey, ShufflerId},
    signing::DomainSeparated,
};

pub trait GameActor {}

#[derive(Debug, Serialize, Deserialize, Clone, CanonicalSerialize, CanonicalDeserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct PlayerActor<C: CurveGroup> {
    pub seat_id: SeatId,
    pub player_id: PlayerId,
    pub player_key: CanonicalKey<C>,
}

impl<C: CurveGroup> GameActor for PlayerActor<C> {}

impl<C: CurveGroup> DomainSeparated for PlayerActor<C> {
    fn domain_string() -> &'static str {
        "ledger/player_actor_v1"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, CanonicalSerialize, CanonicalDeserialize)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
pub struct ShufflerActor<C: CurveGroup> {
    pub shuffler_id: ShufflerId,
    pub shuffler_key: CanonicalKey<C>,
}

impl<C: CurveGroup> GameActor for ShufflerActor<C> {}

impl<C: CurveGroup> DomainSeparated for ShufflerActor<C> {
    fn domain_string() -> &'static str {
        "ledger/shuffler_actor_v1"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(bound(
    serialize = "C: CanonicalSerialize",
    deserialize = "C: CanonicalDeserialize"
))]
#[serde(rename_all = "snake_case")]
pub enum AnyActor<C: CurveGroup> {
    None,
    Player {
        seat_id: SeatId,
        player_id: PlayerId,
        player_key: CanonicalKey<C>,
    },
    Shuffler {
        shuffler_id: ShufflerId,
        shuffler_key: CanonicalKey<C>,
    },
}

impl<C: CurveGroup> Default for AnyActor<C> {
    fn default() -> Self {
        AnyActor::None
    }
}

impl<C: CurveGroup> GameActor for AnyActor<C> {}

impl<C: CurveGroup> DomainSeparated for AnyActor<C> {
    fn domain_string() -> &'static str {
        "ledger/any_actor_v1"
    }
}

impl<C: CurveGroup> CanonicalSerialize for AnyActor<C> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            AnyActor::None => {
                0u8.serialize_with_mode(&mut writer, compress)?;
            }
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                seat_id.serialize_with_mode(&mut writer, compress)?;
                player_id.serialize_with_mode(&mut writer, compress)?;
                player_key.serialize_with_mode(&mut writer, compress)?;
            }
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => {
                2u8.serialize_with_mode(&mut writer, compress)?;
                shuffler_id.serialize_with_mode(&mut writer, compress)?;
                shuffler_key.serialize_with_mode(&mut writer, compress)?;
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        1 + match self {
            AnyActor::None => 0,
            AnyActor::Player {
                seat_id,
                player_id,
                player_key,
            } => {
                seat_id.serialized_size(compress)
                    + player_id.serialized_size(compress)
                    + player_key.serialized_size(compress)
            }
            AnyActor::Shuffler {
                shuffler_id,
                shuffler_key,
            } => shuffler_id.serialized_size(compress) + shuffler_key.serialized_size(compress),
        }
    }
}

impl<C: CurveGroup> CanonicalDeserialize for AnyActor<C> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let discriminant = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match discriminant {
            0 => Ok(AnyActor::None),
            1 => {
                let seat_id = SeatId::deserialize_with_mode(&mut reader, compress, validate)?;
                let player_id = PlayerId::deserialize_with_mode(&mut reader, compress, validate)?;
                let player_key =
                    CanonicalKey::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(AnyActor::Player {
                    seat_id,
                    player_id,
                    player_key,
                })
            }
            2 => {
                let shuffler_id =
                    ShufflerId::deserialize_with_mode(&mut reader, compress, validate)?;
                let shuffler_key =
                    CanonicalKey::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(AnyActor::Shuffler {
                    shuffler_id,
                    shuffler_key,
                })
            }
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

impl<C: CurveGroup> ark_serialize::Valid for AnyActor<C> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}
