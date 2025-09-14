use super::types::{Chips, SeatId, Street};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizedAction {
    Fold,
    Check,
    Call {
        call_amount: Chips,
        full_call: bool,
    }, // full_call=false => short
    Bet {
        to: Chips,
    }, // first open
    Raise {
        to: Chips,
        raise_amount: Chips,
        full_raise: bool,
    },
    AllInAsCall {
        call_amount: Chips,
        full_call: bool,
    },
    AllInAsBet {
        to: Chips,
    },
    AllInAsRaise {
        to: Chips,
        raise_amount: Chips,
        full_raise: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GameEvent {
    ActionApplied {
        seat: SeatId,
        action: NormalizedAction,
    },
    PotUpdated,
    StreetEnded {
        street: Street,
    },
    AllPlayersAllIn,
    HandEndedByFolds {
        winner: SeatId,
        pots: super::types::Pots,
    },
}
