use super::events::NormalizedAction;
use crate::signing::{Signable, TranscriptBuilder};
use serde::{Deserialize, Serialize};

pub type Chips = u64;
pub type SeatId = u8; // 0..=9
pub type PlayerId = u64; // optional stable identity

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Street {
    Preflop,
    Flop,
    Turn,
    River,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayerStatus {
    Active,     // can act this round
    Folded,     // out of hand
    AllIn,      // cannot act; still eligible for pots
    SittingOut, // not dealt in
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerState {
    pub seat: SeatId,
    pub player_id: Option<PlayerId>,

    // Stack & contributions:
    pub stack: Chips,                // uncommitted chips behind
    pub committed_this_round: Chips, // on the current street
    pub committed_total: Chips,      // across all streets

    pub status: PlayerStatus,
    pub has_acted_this_round: bool, // for flow (check/raise cycles)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pot {
    pub amount: Chips,
    pub eligible: Vec<SeatId>, // seats that can win this pot
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pots {
    pub main: Pot,
    pub sides: Vec<Pot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableStakes {
    pub small_blind: Chips,
    pub big_blind: Chips,
    pub ante: Chips, // 0 if none
}

/// Fixed for the hand (No-Limit only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandConfig {
    pub stakes: TableStakes,
    pub button: SeatId,
    pub small_blind_seat: SeatId,
    pub big_blind_seat: SeatId,
    pub check_raise_allowed: bool, // default true in standard NLH
}

impl HandConfig {
    pub fn append_to_transcript(&self, builder: &mut TranscriptBuilder) {
        builder.append_u64(self.stakes.small_blind);
        builder.append_u64(self.stakes.big_blind);
        builder.append_u64(self.stakes.ante);
        builder.append_u8(self.button);
        builder.append_u8(self.small_blind_seat);
        builder.append_u8(self.big_blind_seat);
        builder.append_u8(self.check_raise_allowed as u8);
    }
}

impl Signable for HandConfig {
    fn domain_kind(&self) -> &'static str {
        "engine/nl/hand_config_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        self.append_to_transcript(builder);
    }
}

impl PlayerStatus {
    pub fn as_byte(self) -> u8 {
        match self {
            PlayerStatus::Active => 0,
            PlayerStatus::Folded => 1,
            PlayerStatus::AllIn => 2,
            PlayerStatus::SittingOut => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionLogEntry {
    pub street: Street,
    pub seat: SeatId,
    pub action: NormalizedAction,
    pub price_to_call_before: Chips,
    pub current_bet_to_match_after: Chips,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionLog(pub Vec<ActionLogEntry>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::serde::assert_round_trip_eq;

    #[test]
    fn enums_round_trip_with_serde() {
        assert_round_trip_eq(&Street::Turn);
        assert_round_trip_eq(&PlayerStatus::AllIn);
    }

    #[test]
    fn structs_round_trip_with_serde() {
        let stakes = TableStakes {
            small_blind: 1,
            big_blind: 2,
            ante: 0,
        };
        assert_round_trip_eq(&stakes);

        let cfg = HandConfig {
            stakes: stakes.clone(),
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };
        assert_round_trip_eq(&cfg);

        let pot = Pot {
            amount: 120,
            eligible: vec![0, 1],
        };
        assert_round_trip_eq(&pot);

        let pots = Pots {
            main: pot.clone(),
            sides: vec![pot.clone()],
        };
        assert_round_trip_eq(&pots);

        let player_state = PlayerState {
            seat: 3,
            player_id: Some(99),
            stack: 450,
            committed_this_round: 10,
            committed_total: 20,
            status: PlayerStatus::Active,
            has_acted_this_round: false,
        };
        assert_round_trip_eq(&player_state);

        let entry = ActionLogEntry {
            street: Street::Flop,
            seat: 1,
            action: NormalizedAction::Call {
                call_amount: 40,
                full_call: true,
            },
            price_to_call_before: 30,
            current_bet_to_match_after: 40,
        };
        assert_round_trip_eq(&entry);

        let log = ActionLog(vec![entry]);
        assert_round_trip_eq(&log);
    }
}
