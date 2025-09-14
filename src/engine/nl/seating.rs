use super::types::{SeatId, Street};

pub trait Seating {
    /// Next seat clockwise that is eligible to act (Active and not AllIn).
    fn next_actor(&self, from: SeatId) -> SeatId;

    /// Compute first to act for the street:
    /// - Preflop: left of big blind
    /// - Postflop: left of button
    fn compute_first_to_act(&self, street: Street) -> SeatId;
}

impl Seating for super::state::BettingState {
    fn next_actor(&self, from: SeatId) -> SeatId {
        use super::types::PlayerStatus::{Active, AllIn};
        let n = self.players.len() as u8;
        let mut i = (from + 1) % n;
        for _ in 0..n {
            if let Some(p) = self.players.iter().find(|p| p.seat == i) {
                if p.status == Active && p.status != AllIn {
                    return i;
                }
            }
            i = (i + 1) % n;
        }
        from
    }

    fn compute_first_to_act(&self, street: Street) -> SeatId {
        match street {
            Street::Preflop => (self.cfg.big_blind_seat() + 1) % (self.players.len() as u8),
            Street::Flop | Street::Turn | Street::River => {
                (self.cfg.button + 1) % (self.players.len() as u8)
            }
        }
    }
}

// Small helper on cfg for preflop convenience.
trait SeatsExt {
    fn big_blind_seat(&self) -> SeatId;
}

impl SeatsExt for super::types::HandConfig {
    fn big_blind_seat(&self) -> SeatId {
        self.big_blind_seat
    }
}
