//! Card ranking and winner determination logic

use serde::{Deserialize, Serialize};

/// Card value (0-51 representing standard deck)
/// 0-12: Hearts (A-K)
/// 13-25: Diamonds (A-K)
/// 26-38: Clubs (A-K)
/// 39-51: Spades (A-K)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card(pub u8);

impl Card {
    /// Get the rank of the card (0-12, where 0 is Ace, 12 is King)
    pub fn rank(&self) -> u8 {
        self.0 % 13
    }

    /// Get the suit of the card (0-3: Hearts, Diamonds, Clubs, Spades)
    pub fn suit(&self) -> u8 {
        self.0 / 13
    }

    /// Get the value for comparison (Ace is high)
    pub fn value(&self) -> u8 {
        let rank = self.rank();
        if rank == 0 {
            14 // Ace is highest
        } else {
            rank + 1
        }
    }

    /// Get a human-readable string representation
    pub fn to_string(&self) -> String {
        let ranks = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"];
        let suits = ["♥", "♦", "♣", "♠"];
        format!("{}{}", ranks[self.rank() as usize], suits[self.suit() as usize])
    }
}

/// Simple hand evaluation - just finds the highest card
/// For the simplified game, we only care about the highest card value
pub fn evaluate_hand(hole_cards: &[u8], community_cards: &[u8]) -> u8 {
    let all_cards: Vec<Card> = hole_cards
        .iter()
        .chain(community_cards.iter())
        .map(|&c| Card(c))
        .collect();

    all_cards
        .iter()
        .map(|c| c.value())
        .max()
        .unwrap_or(0)
}

/// Determine the winner from a list of players and their cards
/// Returns the player ID of the winner
pub fn determine_winner(
    players: &[(String, Vec<u8>)],
    community_cards: &[u8],
) -> Option<String> {
    players
        .iter()
        .filter(|(_, cards)| !cards.is_empty()) // Only consider players with cards
        .max_by_key(|(_, cards)| evaluate_hand(cards, community_cards))
        .map(|(id, _)| id.clone())
}

/// Result of a showdown
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShowdownResult {
    pub winner_id: String,
    pub winning_hand_value: u8,
    pub winning_cards: Vec<Card>,
    pub all_hands: Vec<PlayerHand>,
}

/// A player's hand in the showdown
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlayerHand {
    pub player_id: String,
    pub hole_cards: Vec<Card>,
    pub best_card_value: u8,
    pub folded: bool,
}

/// Perform a complete showdown evaluation
pub fn evaluate_showdown(
    players: Vec<(String, Vec<u8>, bool)>, // (id, cards, folded)
    community_cards: &[u8],
) -> ShowdownResult {
    let mut all_hands = Vec::new();
    let mut best_player = None;
    let mut best_value = 0;

    for (player_id, hole_cards, folded) in players {
        if !folded && !hole_cards.is_empty() {
            let hand_value = evaluate_hand(&hole_cards, community_cards);
            
            if hand_value > best_value {
                best_value = hand_value;
                best_player = Some((player_id.clone(), hole_cards.clone()));
            }

            all_hands.push(PlayerHand {
                player_id,
                hole_cards: hole_cards.iter().map(|&c| Card(c)).collect(),
                best_card_value: hand_value,
                folded,
            });
        } else {
            all_hands.push(PlayerHand {
                player_id,
                hole_cards: vec![],
                best_card_value: 0,
                folded,
            });
        }
    }

    let (winner_id, winning_cards_raw) = best_player.unwrap_or((String::new(), vec![]));
    let winning_cards: Vec<Card> = winning_cards_raw.iter().map(|&c| Card(c)).collect();

    ShowdownResult {
        winner_id,
        winning_hand_value: best_value,
        winning_cards,
        all_hands,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_ranking() {
        let ace_hearts = Card(0);
        assert_eq!(ace_hearts.rank(), 0);
        assert_eq!(ace_hearts.suit(), 0);
        assert_eq!(ace_hearts.value(), 14); // Ace is high

        let king_spades = Card(51);
        assert_eq!(king_spades.rank(), 12);
        assert_eq!(king_spades.suit(), 3);
        assert_eq!(king_spades.value(), 13);

        let two_diamonds = Card(14);
        assert_eq!(two_diamonds.rank(), 1);
        assert_eq!(two_diamonds.suit(), 1);
        assert_eq!(two_diamonds.value(), 2);
    }

    #[test]
    fn test_hand_evaluation() {
        // Player has Ace of Hearts (0) and King of Spades (51)
        let hole_cards = vec![0, 51];
        // Community has 2 of Diamonds (14), 7 of Clubs (32), Jack of Hearts (10)
        let community_cards = vec![14, 32, 10];

        let value = evaluate_hand(&hole_cards, &community_cards);
        assert_eq!(value, 14); // Ace is highest
    }

    #[test]
    fn test_winner_determination() {
        let community_cards = vec![14, 32, 10]; // 2♦, 7♣, J♥

        let players = vec![
            ("player1".to_string(), vec![0, 51]),  // A♥, K♠ - has Ace (14)
            ("player2".to_string(), vec![12, 25]), // K♥, K♦ - has King (13)
            ("player3".to_string(), vec![1, 2]),   // 2♥, 3♥ - has 3 (3)
        ];

        let winner = determine_winner(&players, &community_cards);
        assert_eq!(winner, Some("player1".to_string()));
    }
}