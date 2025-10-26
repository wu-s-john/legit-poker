use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use super::types::Chips;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayerBetAction {
    Fold,
    Check,               // only when price_to_call == 0
    Call,                // match current price (or go short all-in)
    BetTo { to: Chips }, // first bet this round (unopened pot)
    RaiseTo { to: Chips },
    AllIn, // engine normalizes to bet/raise/call
}

impl CanonicalSerialize for PlayerBetAction {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            PlayerBetAction::Fold => {
                0u8.serialize_with_mode(&mut writer, compress)?;
            }
            PlayerBetAction::Check => {
                1u8.serialize_with_mode(&mut writer, compress)?;
            }
            PlayerBetAction::Call => {
                2u8.serialize_with_mode(&mut writer, compress)?;
            }
            PlayerBetAction::BetTo { to } => {
                3u8.serialize_with_mode(&mut writer, compress)?;
                to.serialize_with_mode(&mut writer, compress)?;
            }
            PlayerBetAction::RaiseTo { to } => {
                4u8.serialize_with_mode(&mut writer, compress)?;
                to.serialize_with_mode(&mut writer, compress)?;
            }
            PlayerBetAction::AllIn => {
                5u8.serialize_with_mode(&mut writer, compress)?;
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        1 + match self {
            PlayerBetAction::Fold
            | PlayerBetAction::Check
            | PlayerBetAction::Call
            | PlayerBetAction::AllIn => 0,
            PlayerBetAction::BetTo { to } | PlayerBetAction::RaiseTo { to } => {
                to.serialized_size(compress)
            }
        }
    }
}

impl CanonicalDeserialize for PlayerBetAction {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let discriminant = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match discriminant {
            0 => Ok(PlayerBetAction::Fold),
            1 => Ok(PlayerBetAction::Check),
            2 => Ok(PlayerBetAction::Call),
            3 => {
                let to = Chips::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(PlayerBetAction::BetTo { to })
            }
            4 => {
                let to = Chips::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(PlayerBetAction::RaiseTo { to })
            }
            5 => Ok(PlayerBetAction::AllIn),
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

impl ark_serialize::Valid for PlayerBetAction {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}
