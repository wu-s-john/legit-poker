use super::types::Chips;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlayerAction {
    Fold,
    Check,               // only when price_to_call == 0
    Call,                // match current price (or go short all-in)
    BetTo { to: Chips }, // first bet this round (unopened pot)
    RaiseTo { to: Chips },
    AllIn, // engine normalizes to bet/raise/call
}

