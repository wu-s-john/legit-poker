use super::types::*;
use super::state::BettingState;

pub trait Seating {
    fn next_actor(&self, from: SeatId) -> SeatId;
    fn compute_first_to_act(&self, street: Street) -> SeatId;
}

impl Seating for BettingState {
    fn next_actor(&self, from: SeatId) -> SeatId {
        let mut seat = from;
        for _ in 0..10 {
            seat = (seat + 1) % 10;
            if let Some(p) = self.players.iter().find(|p| p.seat == seat) {
                if p.status == PlayerStatus::Active {
                    return seat;
                }
            }
        }
        from
    }

    fn compute_first_to_act(&self, street: Street) -> SeatId {
        match street {
            Street::Preflop => self.next_actor(self.cfg.big_blind_seat),
            _ => self.next_actor(self.cfg.button),
        }
    }
}
