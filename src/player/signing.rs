/// Minimal payload for betting action attestation.
/// Extend as needed with table/hand identifiers, nonces, etc.
use serde::{Deserialize, Serialize};

use crate::engine::nl::actions::PlayerBetAction;
use crate::signing::{Signable, TranscriptBuilder};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlayerActionBet {
    pub seat: crate::engine::nl::types::SeatId,
    pub action: PlayerBetAction,
    /// Optional anti-replay field (caller managed). 0 if unused.
    pub nonce: u64,
}

impl Signable for PlayerActionBet {
    fn domain_kind(&self) -> &'static str {
        "player_action_bet_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u8(self.seat);
        append_player_bet_action(builder, &self.action);
        builder.append_u64(self.nonce);
    }
}

pub(crate) fn append_player_bet_action(builder: &mut TranscriptBuilder, action: &PlayerBetAction) {
    match action {
        PlayerBetAction::Fold => builder.append_u8(0),
        PlayerBetAction::Check => builder.append_u8(1),
        PlayerBetAction::Call => builder.append_u8(2),
        PlayerBetAction::BetTo { to } => {
            builder.append_u8(3);
            builder.append_u64(*to);
        }
        PlayerBetAction::RaiseTo { to } => {
            builder.append_u8(4);
            builder.append_u64(*to);
        }
        PlayerBetAction::AllIn => builder.append_u8(5),
    }
}
