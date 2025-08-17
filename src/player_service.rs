//! Player service for managing player operations in the card game

use crate::domain::{ActorType, AppendParams, RoomId};
use crate::shuffling::{
    game_events::CardsRevealedEvent,
    player_decryption::{recover_card_value, PartialUnblindingShare, PlayerAccessibleCiphertext},
};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Player action during betting
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PlayerAction {
    Fold,
    Call,
    Raise(u64),
}

/// CPU player behavior types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CpuBehavior {
    Random,       // Completely random actions
    Aggressive,   // Higher bet tendency
    Conservative, // Lower bet tendency
}

/// Database client trait for writing events
#[async_trait::async_trait]
pub trait DatabaseClient: Send + Sync {
    async fn append_to_transcript(
        &self,
        params: AppendParams,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Player service that manages player operations
pub struct PlayerService {
    pub id: String,
    pub game_id: [u8; 32],
    pub secret_key: Fr,
    pub public_key: G1Affine,
    pub hole_cards: Option<Vec<u8>>, // Plaintext after decryption
    pub escrow_balance: u64,
    pub current_bet: u64,
    pub folded: bool,
    pub is_cpu: bool,
    pub cpu_behavior: Option<CpuBehavior>,
    db_client: Arc<dyn DatabaseClient>,
}

impl PlayerService {
    /// Create a new player (human or CPU)
    pub fn new(
        player_id: String,
        game_id: [u8; 32],
        initial_escrow: u64,
        is_cpu: bool,
        db_client: Arc<dyn DatabaseClient>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use ark_std::rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        let secret_key = Fr::rand(&mut rng);
        let public_key = (G1Affine::generator() * secret_key).into_affine();

        let cpu_behavior = if is_cpu {
            Some(match rng.gen::<u8>() % 3 {
                0 => CpuBehavior::Random,
                1 => CpuBehavior::Aggressive,
                _ => CpuBehavior::Conservative,
            })
        } else {
            None
        };

        Ok(Self {
            id: player_id,
            game_id,
            secret_key,
            public_key,
            hole_cards: None,
            escrow_balance: initial_escrow,
            current_bet: 0,
            folded: false,
            is_cpu,
            cpu_behavior,
            db_client,
        })
    }

    /// Get the public key of this player
    pub fn public_key(&self) -> G1Affine {
        self.public_key
    }

    /// Make a betting decision (human input or CPU logic)
    pub async fn make_betting_decision(
        &mut self,
        pot: u64,
        min_bet: u64,
        room_id: RoomId,
    ) -> Result<PlayerAction, Box<dyn std::error::Error>> {
        let action = if self.is_cpu {
            self.cpu_decide_action(pot, min_bet)
        } else {
            // For human player, get real user input
            self.get_human_betting_decision(pot, min_bet)?
        };

        // Update internal state
        match &action {
            PlayerAction::Fold => self.folded = true,
            PlayerAction::Call => {
                let bet_amount = min_bet.min(self.escrow_balance);
                self.current_bet = bet_amount;
                self.escrow_balance = self.escrow_balance.saturating_sub(bet_amount);
            }
            PlayerAction::Raise(amount) => {
                let bet_amount = (*amount).min(self.escrow_balance);
                self.current_bet = bet_amount;
                self.escrow_balance = self.escrow_balance.saturating_sub(bet_amount);
            }
        }

        // Log to database
        self.log_action(room_id, "betting_decision", &action)
            .await?;

        Ok(action)
    }
    
    /// Get betting decision from human player via stdin
    fn get_human_betting_decision(
        &self,
        pot: u64,
        min_bet: u64,
    ) -> Result<PlayerAction, Box<dyn std::error::Error>> {
        use crate::game::user_interface::prompt_for_betting_action;
        
        // Determine phase based on game state
        let phase = if self.hole_cards.is_none() {
            "INITIAL BETTING"
        } else {
            "FINAL BETTING"
        };
        
        prompt_for_betting_action(pot, min_bet, self.escrow_balance, phase)
    }

    /// CPU decision logic (random, no ZK)
    fn cpu_decide_action(&self, _pot: u64, min_bet: u64) -> PlayerAction {
        use ark_std::rand::{thread_rng, Rng};
        let mut rng = thread_rng();

        if self.escrow_balance < min_bet {
            return PlayerAction::Fold;
        }

        match self.cpu_behavior {
            Some(CpuBehavior::Random) => {
                let r: f32 = rng.gen();
                if r < 0.3 {
                    PlayerAction::Fold
                } else if r < 0.7 {
                    PlayerAction::Call
                } else {
                    let max_raise = self.escrow_balance.saturating_sub(min_bet);
                    if max_raise > 0 {
                        let raise = min_bet + (rng.gen::<u64>() % max_raise);
                        PlayerAction::Raise(raise)
                    } else {
                        PlayerAction::Call
                    }
                }
            }
            Some(CpuBehavior::Aggressive) => {
                let r: f32 = rng.gen();
                if r < 0.1 {
                    PlayerAction::Fold
                } else if r < 0.4 {
                    PlayerAction::Call
                } else {
                    let raise = min_bet + (self.escrow_balance - min_bet) / 2;
                    PlayerAction::Raise(raise)
                }
            }
            Some(CpuBehavior::Conservative) => {
                let r: f32 = rng.gen();
                if r < 0.5 {
                    PlayerAction::Fold
                } else {
                    PlayerAction::Call
                }
            }
            None => PlayerAction::Call,
        }
    }

    /// Decrypt hole cards using unblinding shares
    pub async fn decrypt_hole_cards(
        &mut self,
        player_ciphertexts: Vec<PlayerAccessibleCiphertext<G1Projective>>,
        unblinding_shares: Vec<Vec<PartialUnblindingShare<G1Projective>>>,
        room_id: RoomId,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut card_values = Vec::new();

        for (ciphertext, shares) in player_ciphertexts.iter().zip(unblinding_shares.iter()) {
            let card_value = recover_card_value(ciphertext, self.secret_key, shares.clone(), 7)?;
            card_values.push(card_value);
        }

        self.hole_cards = Some(card_values.clone());

        // Log card reveal event
        let event = CardsRevealedEvent {
            game_id: self.game_id,
            player_id: self.id.as_bytes()[..32.min(self.id.len())]
                .try_into()
                .unwrap_or([0u8; 32]),
            card_values: card_values.clone(),
            card_indices: vec![], // Will be filled by coordinator
            num_unblinding_shares: 7,
            timestamp: Utc::now().timestamp() as u64,
        };

        self.log_event(room_id, "cards_revealed", event).await?;

        Ok(card_values)
    }

    /// Simple reveal for showdown (no ZK)
    pub async fn reveal_hand_plaintext(
        &self,
        room_id: RoomId,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cards = self.hole_cards.clone().unwrap_or_default();

        // Log the reveal
        self.log_action(room_id, "hand_revealed", &cards).await?;

        Ok(cards)
    }

    /// Add winnings to escrow
    pub fn add_winnings(&mut self, amount: u64) {
        self.escrow_balance += amount;
    }

    /// Reset for new round
    pub fn reset_for_new_round(&mut self) {
        self.hole_cards = None;
        self.current_bet = 0;
        self.folded = false;
    }

    // Database logging helpers
    async fn log_action<T: Serialize>(
        &self,
        room_id: RoomId,
        action: &str,
        data: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = AppendParams {
            room_id,
            actor_type: ActorType::Player,
            actor_id: self.id.clone(),
            kind: action.to_string(),
            payload: serde_json::to_value(data)?,
            correlation_id: Some(hex::encode(self.game_id)),
            idempotency_key: None,
        };

        self.db_client.append_to_transcript(params).await?;
        Ok(())
    }

    async fn log_event<T: Serialize>(
        &self,
        room_id: RoomId,
        event_type: &str,
        event: T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = AppendParams {
            room_id,
            actor_type: ActorType::Player,
            actor_id: self.id.clone(),
            kind: event_type.to_string(),
            payload: serde_json::to_value(event)?,
            correlation_id: Some(hex::encode(self.game_id)),
            idempotency_key: None,
        };

        self.db_client.append_to_transcript(params).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDatabaseClient;

    #[async_trait::async_trait]
    impl DatabaseClient for MockDatabaseClient {
        async fn append_to_transcript(
            &self,
            _params: AppendParams,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn test_player_creation() {
        let db_client = Arc::new(MockDatabaseClient);
        let game_id = [0u8; 32];

        let player = PlayerService::new(
            "test_player".to_string(),
            game_id,
            1000,
            false,
            db_client.clone(),
        )
        .unwrap();

        assert_eq!(player.id, "test_player");
        assert_eq!(player.escrow_balance, 1000);
        assert!(!player.is_cpu);
        assert!(!player.folded);
    }

    #[test]
    fn test_cpu_player_creation() {
        let db_client = Arc::new(MockDatabaseClient);
        let game_id = [0u8; 32];

        let cpu_player = PlayerService::new(
            "cpu_player_1".to_string(),
            game_id,
            1000,
            true,
            db_client.clone(),
        )
        .unwrap();

        assert!(cpu_player.is_cpu);
        assert!(cpu_player.cpu_behavior.is_some());
    }
}