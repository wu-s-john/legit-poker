//! Game phase definitions and transitions

use serde::{Deserialize, Serialize};

/// Game phases for the simplified card game
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GamePhase {
    /// Initial setup - creating game, spawning participants
    Setup,
    /// Players place initial bets to join
    InitialBetting,
    /// 7 shufflers shuffle the deck
    Shuffling,
    /// Deal 2 hole cards to each player
    DealingHoleCards,
    /// Reveal 3 community cards
    RevealCommunity,
    /// Players make final betting decisions
    FinalBetting,
    /// All remaining players reveal hands
    Showdown,
    /// Determine winner and distribute pot
    Settlement,
    /// Game complete
    Complete,
}

impl GamePhase {
    /// Check if the game is in an active playing state
    pub fn is_active(&self) -> bool {
        !matches!(self, GamePhase::Setup | GamePhase::Complete)
    }

    /// Get the next phase in the sequence
    pub fn next(&self) -> Option<GamePhase> {
        match self {
            GamePhase::Setup => Some(GamePhase::InitialBetting),
            GamePhase::InitialBetting => Some(GamePhase::Shuffling),
            GamePhase::Shuffling => Some(GamePhase::DealingHoleCards),
            GamePhase::DealingHoleCards => Some(GamePhase::RevealCommunity),
            GamePhase::RevealCommunity => Some(GamePhase::FinalBetting),
            GamePhase::FinalBetting => Some(GamePhase::Showdown),
            GamePhase::Showdown => Some(GamePhase::Settlement),
            GamePhase::Settlement => Some(GamePhase::Complete),
            GamePhase::Complete => None,
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &str {
        match self {
            GamePhase::Setup => "Setting up game",
            GamePhase::InitialBetting => "Players placing initial bets",
            GamePhase::Shuffling => "Shufflers shuffling deck",
            GamePhase::DealingHoleCards => "Dealing hole cards",
            GamePhase::RevealCommunity => "Revealing community cards",
            GamePhase::FinalBetting => "Final betting round",
            GamePhase::Showdown => "Players revealing hands",
            GamePhase::Settlement => "Settling bets",
            GamePhase::Complete => "Game complete",
        }
    }
}