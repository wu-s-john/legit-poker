use super::rules::NoLimitRules;
use super::state::BettingState;
use super::types::{Chips, SeatId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalActions {
    pub may_fold: bool,
    pub may_check: bool,
    pub call_amount: Option<Chips>,
    pub bet_to_range: Option<std::ops::RangeInclusive<Chips>>, // when unopened
    pub raise_to_range: Option<std::ops::RangeInclusive<Chips>>, // when opened
}

impl LegalActions {
    pub fn none() -> Self {
        Self {
            may_fold: false,
            may_check: false,
            call_amount: None,
            bet_to_range: None,
            raise_to_range: None,
        }
    }
}

pub fn legal_actions_for(state: &BettingState, seat: SeatId) -> LegalActions {
    use super::types::PlayerStatus::*;
    let Some(p) = state.players.iter().find(|p| p.seat == seat) else {
        return LegalActions::none();
    };
    if p.status != Active {
        return LegalActions::none();
    }

    // Only generate legals for current actor
    if seat != state.to_act {
        return LegalActions::none();
    }

    let price = <BettingState as NoLimitRules>::price_to_call(state, seat);
    let mut legals = LegalActions {
        may_fold: price > 0,
        may_check: price == 0,
        call_amount: Some(price),
        bet_to_range: None,
        raise_to_range: None,
    };

    if !state.voluntary_bet_opened {
        // Preflop BB special case: may check or raise (not bet) when unopened
        let is_bb_preflop =
            state.street == super::types::Street::Preflop && seat == state.cfg.big_blind_seat;
        if is_bb_preflop {
            legals.raise_to_range =
                <BettingState as NoLimitRules>::raise_to_bounds_opened(state, seat);
        } else {
            legals.bet_to_range =
                <BettingState as NoLimitRules>::bet_to_bounds_unopened(state, seat);
        }
    } else {
        legals.raise_to_range = <BettingState as NoLimitRules>::raise_to_bounds_opened(state, seat);
    }

    legals
}
