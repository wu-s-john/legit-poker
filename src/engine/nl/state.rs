use super::errors::{InvariantCheck, StateError};
use super::events::GameEvent;
use super::seating::Seating;
use super::types::{ActionLog, Chips, HandConfig, PlayerState, PlayerStatus, Pots, SeatId, Street};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BettingState {
    // Street and turn order:
    pub street: Street,
    pub button: SeatId,
    pub first_to_act: SeatId,
    pub to_act: SeatId,

    // Open/raise accounting:
    pub current_bet_to_match: Chips, // highest committed_this_round among active seats
    pub last_full_raise_amount: Chips, // NL min-raise size for this round
    pub last_aggressor: Option<SeatId>,
    pub voluntary_bet_opened: bool, // whether a voluntary bet has occurred this street

    // Players & pots:
    pub players: Vec<PlayerState>,
    pub pots: Pots,

    // Rules for this hand:
    pub cfg: HandConfig,

    // Flow helpers:
    pub pending_to_match: Vec<SeatId>, // active, non-all-in seats that still owe
    pub betting_locked_all_in: bool,

    // Optional deterministic log
    pub action_log: ActionLog,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::nl::{events::NormalizedAction, types};
    use crate::test_utils::serde::assert_round_trip_json;

    #[test]
    fn betting_state_round_trips_with_serde() {
        let stakes = types::TableStakes {
            small_blind: 1,
            big_blind: 2,
            ante: 0,
        };
        let cfg = HandConfig {
            stakes: stakes.clone(),
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };
        let players = vec![
            PlayerState {
                seat: 0,
                player_id: Some(1),
                stack: 900,
                committed_this_round: 50,
                committed_total: 150,
                status: PlayerStatus::Active,
                has_acted_this_round: true,
            },
            PlayerState {
                seat: 1,
                player_id: Some(2),
                stack: 750,
                committed_this_round: 40,
                committed_total: 120,
                status: PlayerStatus::AllIn,
                has_acted_this_round: true,
            },
        ];
        let main_pot = types::Pot {
            amount: 200,
            eligible: vec![0, 1],
        };
        let pots = Pots {
            main: main_pot.clone(),
            sides: vec![types::Pot {
                amount: 40,
                eligible: vec![0],
            }],
        };
        let action_log = ActionLog(vec![types::ActionLogEntry {
            street: Street::Turn,
            seat: 0,
            action: NormalizedAction::Raise {
                to: 90,
                raise_amount: 40,
                full_raise: true,
            },
            price_to_call_before: 50,
            current_bet_to_match_after: 90,
        }]);

        let state = BettingState {
            street: Street::Turn,
            button: 0,
            first_to_act: 0,
            to_act: 0,
            current_bet_to_match: 90,
            last_full_raise_amount: 40,
            last_aggressor: Some(0),
            voluntary_bet_opened: true,
            players,
            pots,
            cfg,
            pending_to_match: vec![0],
            betting_locked_all_in: false,
            action_log,
        };

        assert_round_trip_json(&state);
    }
}

impl BettingState {
    pub fn active_non_allin_seats(&self) -> Vec<SeatId> {
        self.players
            .iter()
            .filter(|p| p.status == PlayerStatus::Active)
            .map(|p| p.seat)
            .collect()
    }

    pub fn seats_still_in(&self) -> Vec<SeatId> {
        self.players
            .iter()
            .filter(|p| p.status != PlayerStatus::Folded && p.status != PlayerStatus::SittingOut)
            .map(|p| p.seat)
            .collect()
    }

    pub fn seat_index(&self, seat: SeatId) -> usize {
        self.players
            .iter()
            .position(|p| p.seat == seat)
            .expect("seat must exist")
    }

    pub fn recompute_lock_if_all_in(&mut self) -> Option<GameEvent> {
        let any_active = self.players.iter().any(|p| {
            let excluded_preflop_button =
                self.street == Street::Preflop && p.seat == self.cfg.button;
            p.status == PlayerStatus::Active && p.stack > 0 && !excluded_preflop_button
        });
        if !any_active {
            self.betting_locked_all_in = true;
            Some(GameEvent::AllPlayersAllIn)
        } else {
            None
        }
    }

    pub fn refresh_pots(&mut self) {
        if let Ok(p) = self.compute_pots() {
            self.pots = p;
        }
    }

    pub fn reset_per_street(&mut self, street: Street) {
        for p in &mut self.players {
            p.committed_total = p.committed_total.saturating_add(p.committed_this_round);
            p.committed_this_round = 0;
            if p.status == PlayerStatus::Active {
                p.has_acted_this_round = false;
            }
        }
        self.street = street;
        self.current_bet_to_match = 0;
        self.last_full_raise_amount = 0;
        self.last_aggressor = None;
        self.voluntary_bet_opened = false;

        self.first_to_act = self.compute_first_to_act(street);
        self.to_act = self.first_to_act;
        self.pending_to_match = self
            .players
            .iter()
            .filter(|p| p.status == PlayerStatus::Active)
            .map(|p| p.seat)
            .collect();

        self.refresh_pots();
    }
}

impl InvariantCheck for BettingState {
    fn validate_invariants(&self) -> Result<(), StateError> {
        // Stacks non-negative (u64 always ok)
        // Money conservation at street granularity cannot be fully checked without initial buy-ins,
        // but we can ensure no one is over-committed beyond stack+committed.
        for p in &self.players {
            // cannot have negative (u64) and committed_this_round should not exceed total chips used so far
            let _ = p; // placeholder for extensible rules
        }

        // Folded players must not appear in eligibility sets
        let folded: std::collections::HashSet<_> = self
            .players
            .iter()
            .filter(|p| p.status == PlayerStatus::Folded)
            .map(|p| p.seat)
            .collect();
        for sid in &self.pots.main.eligible {
            if folded.contains(sid) {
                return Err(StateError::InvariantViolation(
                    "Folded seat in main pot eligibility",
                ));
            }
        }
        for pot in &self.pots.sides {
            for sid in &pot.eligible {
                if folded.contains(sid) {
                    return Err(StateError::InvariantViolation(
                        "Folded seat in side pot eligibility",
                    ));
                }
            }
        }
        Ok(())
    }
}
