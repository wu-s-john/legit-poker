
#[derive(Debug, PartialEq, Eq)]
pub enum ActionError {
    NotPlayersTurn,
    ActorCannotAct,
    IllegalAction,
    CannotCheckFacingBet,
    CannotBetWhenOpened,
    BadCallAmount,
    RaiseBelowMinimum,
    InsufficientChips,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidTransition,
    InvariantViolation(&'static str),
}

pub trait InvariantCheck {
    fn validate_invariants(&self) -> Result<(), StateError>;
}
