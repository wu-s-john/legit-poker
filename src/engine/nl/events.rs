use super::types::{Chips, SeatId, Street};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::serde::assert_round_trip_eq;

    #[test]
    fn normalized_action_round_trips_with_serde() {
        let action = NormalizedAction::Raise {
            to: 42,
            raise_amount: 17,
            full_raise: true,
        };

        assert_round_trip_eq(&action);
    }
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
