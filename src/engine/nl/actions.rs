use super::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlayerAction {
    Fold,
    Check,
    Call,
    BetTo { to: Chips },
    RaiseTo { to: Chips },
    AllIn,
}
