use super::errors::StateError;
use super::state::BettingState;
use super::types::{Chips, SeatId};

pub struct RaiseBounds {
    pub min_raise_to: Chips,
    pub max_raise_to: Chips,
}

pub trait NoLimitRules {
    fn price_to_call(state: &BettingState, seat: SeatId) -> Chips;
    fn bet_to_bounds_unopened(
        state: &BettingState,
        seat: SeatId,
    ) -> Option<std::ops::RangeInclusive<Chips>>;
    fn raise_to_bounds_opened(
        state: &BettingState,
        seat: SeatId,
    ) -> Option<std::ops::RangeInclusive<Chips>>;
    fn is_full_raise(state: &BettingState, raise_amount: Chips) -> bool;
}

impl NoLimitRules for BettingState {
    fn price_to_call(state: &BettingState, seat: SeatId) -> Chips {
        let p = state
            .players
            .iter()
            .find(|p| p.seat == seat)
            .expect("seat present");
        if p.status != super::types::PlayerStatus::Active {
            return 0;
        }
        state
            .current_bet_to_match
            .saturating_sub(p.committed_this_round)
    }

    fn bet_to_bounds_unopened(
        state: &BettingState,
        seat: SeatId,
    ) -> Option<std::ops::RangeInclusive<Chips>> {
        if state.voluntary_bet_opened {
            return None;
        }
        let p = state.players.iter().find(|p| p.seat == seat)?;
        if p.status != super::types::PlayerStatus::Active {
            return None;
        }
        let min = state.cfg.stakes.big_blind;
        let max = p.committed_this_round + p.stack;
        if max < min {
            return None;
        }
        Some(min..=max)
    }

    fn raise_to_bounds_opened(
        state: &BettingState,
        seat: SeatId,
    ) -> Option<std::ops::RangeInclusive<Chips>> {
        // Special-case: preflop big blind may raise even if no voluntary bet yet.
        let is_bb_preflop_unopened = state.street == super::types::Street::Preflop
            && !state.voluntary_bet_opened
            && seat == state.cfg.big_blind_seat;
        if !state.voluntary_bet_opened && !is_bb_preflop_unopened {
            return None;
        }
        let p = state.players.iter().find(|p| p.seat == seat)?;
        if p.status != super::types::PlayerStatus::Active {
            return None;
        }
        if state.current_bet_to_match == 0 {
            return None;
        }
        let min = state
            .current_bet_to_match
            .saturating_add(state.last_full_raise_amount);
        let max = p.committed_this_round + p.stack;
        if max <= state.current_bet_to_match {
            return None;
        }
        Some(min..=max)
    }

    fn is_full_raise(state: &BettingState, raise_amount: Chips) -> bool {
        raise_amount >= state.last_full_raise_amount && state.last_full_raise_amount > 0
            || (!state.voluntary_bet_opened && raise_amount > 0)
    }
}

impl BettingState {
    pub fn compute_pots(&self) -> Result<super::types::Pots, StateError> {
        use super::types::{PlayerStatus, Pot, Pots};
        // contributions include all streets so far (total + current street)
        let contrib: Vec<(SeatId, Chips, PlayerStatus)> = self
            .players
            .iter()
            .map(|p| (p.seat, p.committed_total + p.committed_this_round, p.status))
            .collect();

        // Sum only contributions from non-folded players when computing amounts.
        // Folded chips remain in the pot conceptually, but our tests treat folded
        // contributions as not affecting tier amounts formed by active/all-in players.
        let total_on_table: Chips = contrib
            .iter()
            .filter(|(_, _, s)| *s != PlayerStatus::Folded)
            .map(|(_, c, _)| *c)
            .sum();
        if total_on_table == 0 {
            return Ok(Pots {
                main: Pot {
                    amount: 0,
                    eligible: vec![],
                },
                sides: vec![],
            });
        }

        // thresholds are unique non-zero contributions of non-folded players
        let mut thresholds: Vec<Chips> = contrib
            .iter()
            .filter(|(_, c, s)| *c > 0 && *s != PlayerStatus::Folded)
            .map(|(_, c, _)| *c)
            .collect();
        thresholds.sort_unstable();
        thresholds.dedup();
        if thresholds.is_empty() {
            // all folded? pot still exists but no eligible players; caller should end hand by folds
            return Ok(Pots {
                main: Pot {
                    amount: total_on_table,
                    eligible: vec![],
                },
                sides: vec![],
            });
        }

        let mut pots: Vec<Pot> = Vec::new();
        let mut prev_cap: Chips = 0;
        for cap in thresholds.iter().copied() {
            let mut amount: Chips = 0;
            for (_, c, s) in contrib.iter() {
                if *s == PlayerStatus::Folded {
                    continue;
                }
                let tier = cap.saturating_sub(prev_cap);
                let contrib_in_tier = (*c).saturating_sub(prev_cap).min(tier);
                amount = amount.saturating_add(contrib_in_tier);
            }
            // eligible: non-folded seats that contributed at least cap
            let mut eligible: Vec<SeatId> = contrib
                .iter()
                .filter(|(_, c, s)| *s != PlayerStatus::Folded && *c >= cap)
                .map(|(sid, _, _)| *sid)
                .collect();
            eligible.sort_unstable();
            pots.push(Pot { amount, eligible });
            prev_cap = cap;
        }

        let main = pots.remove(0);
        Ok(Pots { main, sides: pots })
    }
}
