use super::events::NormalizedAction;

pub type Chips = u64;
pub type SeatId = u8; // 0..=9
pub type PlayerId = u64; // optional stable identity

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Street {
    Preflop,
    Flop,
    Turn,
    River,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlayerStatus {
    Active,     // can act this round
    Folded,     // out of hand
    AllIn,      // cannot act; still eligible for pots
    SittingOut, // not dealt in
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pot {
    pub amount: Chips,
    pub eligible: Vec<SeatId>, // seats that can win this pot
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pots {
    pub main: Pot,
    pub sides: Vec<Pot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableStakes {
    pub small_blind: Chips,
    pub big_blind: Chips,
    pub ante: Chips, // 0 if none
}

/// Fixed for the hand (No-Limit only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandConfig {
    pub stakes: TableStakes,
    pub button: SeatId,
    pub small_blind_seat: SeatId,
    pub big_blind_seat: SeatId,
    pub check_raise_allowed: bool, // default true in standard NLH
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionLogEntry {
    pub street: Street,
    pub seat: SeatId,
    pub action: NormalizedAction,
    pub price_to_call_before: Chips,
    pub current_bet_to_match_after: Chips,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionLog(pub Vec<ActionLogEntry>);
