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
