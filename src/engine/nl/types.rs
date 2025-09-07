

pub type Chips = u64;
pub type SeatId = u8;    // 0..=9
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

    pub stack: Chips,                // uncommitted chips behind
    pub committed_this_round: Chips, // on the current street
    pub committed_total: Chips,      // across all streets

    pub status: PlayerStatus,
    pub has_acted_this_round: bool,
}

impl PlayerState {
    pub fn new(seat: SeatId, stack: Chips) -> Self {
        Self {
            seat,
            player_id: None,
            stack,
            committed_this_round: 0,
            committed_total: 0,
            status: PlayerStatus::Active,
            has_acted_this_round: false,
        }
    }
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

impl Default for Pots {
    fn default() -> Self {
        Self {
            main: Pot { amount: 0, eligible: vec![] },
            sides: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableStakes {
    pub small_blind: Chips,
    pub big_blind: Chips,
    pub ante: Chips,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandConfig {
    pub stakes: TableStakes,
    pub button: SeatId,
    pub small_blind_seat: SeatId,
    pub big_blind_seat: SeatId,
    pub check_raise_allowed: bool,
}


