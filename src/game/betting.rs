//! Betting system for the card game

use crate::player_service::PlayerAction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A betting round manages the betting state for one phase of the game
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BettingRound {
    pub pot: u64,
    pub current_bets: HashMap<String, u64>,
    pub min_bet: u64,
    pub active_players: Vec<String>,
    pub folded_players: Vec<String>,
    pub round_complete: bool,
}

impl BettingRound {
    /// Create a new betting round
    pub fn new(min_bet: u64, player_ids: Vec<String>) -> Self {
        Self {
            pot: 0,
            current_bets: HashMap::new(),
            min_bet,
            active_players: player_ids,
            folded_players: Vec::new(),
            round_complete: false,
        }
    }

    /// Process a player's action
    pub fn process_action(
        &mut self,
        player_id: &str,
        action: PlayerAction,
    ) -> Result<(), String> {
        if !self.active_players.contains(&player_id.to_string()) {
            return Err("Player not active in this round".to_string());
        }

        match action {
            PlayerAction::Fold => {
                self.active_players.retain(|id| id != player_id);
                self.folded_players.push(player_id.to_string());
            }
            PlayerAction::Call => {
                let bet_amount = self.min_bet;
                self.current_bets.insert(player_id.to_string(), bet_amount);
                self.pot += bet_amount;
            }
            PlayerAction::Raise(amount) => {
                if amount < self.min_bet {
                    return Err(format!("Raise amount {} is less than minimum bet {}", amount, self.min_bet));
                }
                self.current_bets.insert(player_id.to_string(), amount);
                self.pot += amount;
                self.min_bet = amount; // Update minimum for others to call
            }
        }

        // Check if round is complete (only one player left or all have acted)
        if self.active_players.len() <= 1 {
            self.round_complete = true;
        }

        Ok(())
    }

    /// Check if the betting round is complete
    pub fn is_complete(&self) -> bool {
        self.round_complete || self.active_players.len() <= 1
    }

    /// Get the current pot size
    pub fn get_pot(&self) -> u64 {
        self.pot
    }

    /// Get remaining active players
    pub fn get_active_players(&self) -> &[String] {
        &self.active_players
    }

    /// Check if a player has folded
    pub fn has_folded(&self, player_id: &str) -> bool {
        self.folded_players.contains(&player_id.to_string())
    }

    /// Calculate side pots if needed (for all-in situations)
    /// For simplicity, this implementation just returns the main pot
    pub fn calculate_pots(&self) -> Vec<Pot> {
        vec![Pot {
            amount: self.pot,
            eligible_players: self.active_players.clone(),
        }]
    }
}

/// Represents a pot (main or side pot)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pot {
    pub amount: u64,
    pub eligible_players: Vec<String>,
}

/// Betting configuration for a game
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BettingConfig {
    pub initial_bet: u64,
    pub min_raise: u64,
    pub max_bet: Option<u64>,
}

impl Default for BettingConfig {
    fn default() -> Self {
        Self {
            initial_bet: 10,
            min_raise: 5,
            max_bet: None, // No limit by default
        }
    }
}

/// Result of a betting round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BettingResult {
    pub total_pot: u64,
    pub active_players: Vec<String>,
    pub folded_players: Vec<String>,
    pub player_contributions: HashMap<String, u64>,
}

impl From<&BettingRound> for BettingResult {
    fn from(round: &BettingRound) -> Self {
        Self {
            total_pot: round.pot,
            active_players: round.active_players.clone(),
            folded_players: round.folded_players.clone(),
            player_contributions: round.current_bets.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_betting_round() {
        let players = vec![
            "player1".to_string(),
            "player2".to_string(),
            "player3".to_string(),
        ];
        
        let mut round = BettingRound::new(10, players);

        // Player 1 calls
        round.process_action("player1", PlayerAction::Call).unwrap();
        assert_eq!(round.pot, 10);

        // Player 2 raises
        round.process_action("player2", PlayerAction::Raise(20)).unwrap();
        assert_eq!(round.pot, 30);
        assert_eq!(round.min_bet, 20);

        // Player 3 folds
        round.process_action("player3", PlayerAction::Fold).unwrap();
        assert_eq!(round.active_players.len(), 2);
        assert!(round.has_folded("player3"));
    }

    #[test]
    fn test_pot_calculation() {
        let mut round = BettingRound::new(10, vec!["p1".to_string(), "p2".to_string()]);
        
        round.process_action("p1", PlayerAction::Call).unwrap();
        round.process_action("p2", PlayerAction::Call).unwrap();
        
        let pots = round.calculate_pots();
        assert_eq!(pots.len(), 1);
        assert_eq!(pots[0].amount, 20);
    }
}