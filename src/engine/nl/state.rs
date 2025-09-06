use super::types::*;
use super::errors::*;

#[derive(Clone, Debug)]
pub struct BettingState {
    pub street: Street,
    pub button: SeatId,
    pub first_to_act: SeatId,
    pub to_act: SeatId,

    pub current_bet_to_match: Chips,
    pub last_full_raise_amount: Chips,
    pub last_aggressor: Option<SeatId>,

    pub players: Vec<PlayerState>,
    pub pots: Pots,
    pub cfg: HandConfig,

    pub pending_to_match: Vec<SeatId>,
    pub betting_locked_all_in: bool,
}

impl BettingState {
    pub fn player(&self, seat: SeatId) -> &PlayerState {
        self.players.iter().find(|p| p.seat == seat).unwrap()
    }
    pub fn player_mut(&mut self, seat: SeatId) -> &mut PlayerState {
        self.players.iter_mut().find(|p| p.seat == seat).unwrap()
    }

    pub fn active_non_all_in_seats(&self) -> Vec<SeatId> {
        self.players
            .iter()
            .filter(|p| p.status == PlayerStatus::Active)
            .map(|p| p.seat)
            .collect()
    }

    pub fn non_folded_seats(&self) -> Vec<SeatId> {
        self.players
            .iter()
            .filter(|p| p.status != PlayerStatus::Folded)
            .map(|p| p.seat)
            .collect()
    }
}

impl InvariantCheck for BettingState {
    fn validate_invariants(&self) -> Result<(), StateError> {
        for p in &self.players {
            if p.committed_this_round > p.committed_total {
                return Err(StateError::InvariantViolation("commit mismatch"));
            }
        }
        let mut total_committed = 0;
        for p in &self.players { total_committed += p.committed_total; }
        let mut pot_total = self.pots.main.amount;
        for s in &self.pots.sides { pot_total += s.amount; }
        if total_committed != pot_total {
            return Err(StateError::InvariantViolation("pot mismatch"));
        }
        Ok(())
    }
}
