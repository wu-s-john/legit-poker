use super::state::BettingState;
use super::types::*;

pub struct RaiseBounds {
    pub min_raise_to: Chips,
    pub max_raise_to: Chips,
}

pub trait NoLimitRules {
    fn price_to_call(state: &BettingState, seat: SeatId) -> Chips;
    fn bet_to_bounds_unopened(state: &BettingState, seat: SeatId) -> Option<std::ops::RangeInclusive<Chips>>;
    fn raise_to_bounds_opened(state: &BettingState, seat: SeatId) -> Option<std::ops::RangeInclusive<Chips>>;
    fn is_full_raise(state: &BettingState, raise_amount: Chips) -> bool;
}

pub struct NoLimit;

impl NoLimitRules for NoLimit {
    fn price_to_call(state: &BettingState, seat: SeatId) -> Chips {
        let player = state.player(seat);
        if state.current_bet_to_match > player.committed_this_round {
            state.current_bet_to_match - player.committed_this_round
        } else {
            0
        }
    }

    fn bet_to_bounds_unopened(state: &BettingState, seat: SeatId) -> Option<std::ops::RangeInclusive<Chips>> {
        if state.current_bet_to_match != 0 { return None; }
        let player = state.player(seat);
        if player.stack == 0 { return None; }
        let min = state.cfg.stakes.big_blind;
        let max = player.stack + player.committed_this_round;
        if max < min { None } else { Some(min..=max) }
    }

    fn raise_to_bounds_opened(state: &BettingState, seat: SeatId) -> Option<std::ops::RangeInclusive<Chips>> {
        if state.current_bet_to_match == 0 { return None; }
        let player = state.player(seat);
        if player.stack == 0 { return None; }
        // allow raise only if player may raise (reopened logic handled by engine)
        let min = state.current_bet_to_match + state.last_full_raise_amount;
        let max = player.stack + player.committed_this_round;
        if max < min { None } else { Some(min..=max) }
    }

    fn is_full_raise(state: &BettingState, raise_amount: Chips) -> bool {
        raise_amount >= state.last_full_raise_amount
    }
}
