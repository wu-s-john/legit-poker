//! Game manager for coordinating the card game

use crate::domain::{ActorType, AppendParams, RoomId};
use crate::game::{
    betting::BettingRound,
    card_ranking::evaluate_showdown,
    game_phases::GamePhase,
};
use crate::player_service::{DatabaseClient, PlayerService};
use crate::shuffler_service::ShufflerService;
use crate::shuffling::{
    data_structures::ElGamalCiphertext,
    game_events::GameEventLog,
    unified_shuffler::{self, UnifiedShufflerSetup},
};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Game result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GameResult {
    pub winner: String,
    pub pot: u64,
    pub final_standings: Vec<(String, u64)>, // Player ID and final balance
}

/// Simple card game instance
pub struct SimpleCardGame {
    pub game_id: [u8; 32],
    pub room_id: RoomId,

    // Participants
    pub shufflers: Vec<ShufflerService>,
    pub players: Vec<PlayerService>,

    // Crypto components
    pub aggregated_public_key: G1Projective,
    pub setup: Arc<UnifiedShufflerSetup>,

    // Game state
    pub phase: GamePhase,
    pub deck: Vec<ElGamalCiphertext<G1Projective>>,
    pub community_cards: Vec<u8>,
    pub pot: u64,
    pub betting_round: Option<BettingRound>,

    // Event tracking
    pub event_log: GameEventLog<G1Projective>,
}

/// Main game manager
pub struct GameManager {
    pub unified_setup: Arc<UnifiedShufflerSetup>,
    pub games: HashMap<[u8; 32], SimpleCardGame>,
    pub db_client: Arc<dyn DatabaseClient>,
}

impl GameManager {
    /// Initialize the game manager with unified setup
    pub async fn new<R: ark_std::rand::Rng + ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        rng: &mut R,
        db_client: Arc<dyn DatabaseClient>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate unified setup once (expensive operation)
        let unified_setup = Arc::new(unified_shuffler::setup_unified_shuffler(rng)?);

        Ok(Self {
            unified_setup,
            games: HashMap::new(),
            db_client,
        })
    }

    /// Create a new game with 7 shufflers and 5 players
    pub async fn create_game(
        &mut self,
        human_player_id: String,
        initial_bet: u64,
        room_id: RoomId,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        use ark_std::rand::thread_rng;

        let game_id = generate_game_id();

        // Create 7 shufflers with database connections
        let mut shufflers = Vec::new();
        for i in 0..7 {
            let shuffler = ShufflerService::new_with_db(
                &mut thread_rng(),
                format!("shuffler_{}", i),
                game_id,
                self.unified_setup.clone(),
                self.db_client.clone(),
                None,
            )?;
            shufflers.push(shuffler);
        }

        // Compute aggregated public key
        let aggregated_public_key = shufflers
            .iter()
            .map(|s| s.public_key().into())
            .fold(G1Projective::zero(), |acc, pk: G1Projective| acc + pk);

        // Create players (1 human + 4 CPU)
        let mut players = Vec::new();

        // Human player
        players.push(PlayerService::new(
            human_player_id,
            game_id,
            initial_bet * 10, // Starting balance
            false,             // not CPU
            self.db_client.clone(),
        )?);

        // CPU players
        for i in 0..4 {
            players.push(PlayerService::new(
                format!("cpu_player_{}", i),
                game_id,
                initial_bet * 10, // Starting balance
                true,             // is CPU
                self.db_client.clone(),
            )?);
        }

        let game = SimpleCardGame {
            game_id,
            room_id,
            shufflers,
            players,
            aggregated_public_key,
            setup: self.unified_setup.clone(),
            phase: GamePhase::Setup,
            deck: Vec::new(),
            community_cards: Vec::new(),
            pot: 0,
            betting_round: None,
            event_log: GameEventLog::new(game_id, 5, 7),
        };

        self.games.insert(game_id, game);

        // Log game creation
        self.log_game_event(room_id, "game_created", &game_id)
            .await?;

        Ok(game_id)
    }

    /// Run a complete game
    pub async fn run_game(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<GameResult, Box<dyn std::error::Error>> {
        // Phase 1: Initial betting
        self.execute_initial_betting(game_id).await?;

        // Phase 2: Shuffle with 7 shufflers
        self.execute_shuffle_phase(game_id).await?;

        // Phase 3: Deal hole cards
        self.deal_hole_cards(game_id).await?;

        // Phase 4: Reveal 3 community cards
        self.reveal_community_cards(game_id).await?;

        // Phase 5: Final betting
        self.execute_final_betting(game_id).await?;

        // Phase 6: Showdown (no ZK)
        let winner = self.execute_showdown(game_id).await?;

        // Phase 7: Settlement
        let result = self.settle_game(game_id, winner).await?;

        Ok(result)
    }

    /// Execute the initial betting round
    async fn execute_initial_betting(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        game.phase = GamePhase::InitialBetting;

        let player_ids: Vec<String> = game.players.iter().map(|p| p.id.clone()).collect();
        let room_id = game.room_id;
        let mut betting_round = BettingRound::new(10, player_ids); // Min bet of 10

        for player in game.players.iter_mut() {
            let action = player
                .make_betting_decision(betting_round.pot, betting_round.min_bet, room_id)
                .await?;

            betting_round.process_action(&player.id, action)?;
        }

        game.pot = betting_round.pot;
        game.betting_round = Some(betting_round);

        Ok(())
    }

    /// Coordinate shuffle phase using ShufflerService
    async fn execute_shuffle_phase(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use ark_std::rand::thread_rng;

        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        game.phase = GamePhase::Shuffling;

        // Create initial deck (52 cards)
        let mut current_deck = create_initial_deck(&game.aggregated_public_key);

        // Each shuffler performs their shuffle
        for (idx, shuffler) in game.shufflers.iter_mut().enumerate() {
            tracing::info!(target: "game_manager", "Shuffler {} starting shuffle", idx);

            let (shuffled_deck, _proof) = shuffler
                .shuffle_and_encrypt_with_logging(
                    &mut thread_rng(),
                    current_deck.clone(),
                    idx,
                    game.room_id,
                )
                .await?;

            current_deck = shuffled_deck;
        }

        game.deck = current_deck;
        game.phase = GamePhase::DealingHoleCards;

        Ok(())
    }

    /// Deal hole cards using two-phase decryption
    async fn deal_hole_cards(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        let room_id = game.room_id;
        let aggregated_public_key = game.aggregated_public_key;
        let deck = game.deck.clone();

        // Deal 2 cards to each player
        let num_players = game.players.len();
        for player_idx in 0..num_players {
            let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
            
            if game.players[player_idx].folded {
                continue;
            }

            let card_indices = vec![player_idx * 2, player_idx * 2 + 1];
            let player_id = game.players[player_idx].id.clone();
            let player_public_key = game.players[player_idx].public_key();

            // Phase 1: Collect blinding contributions from all shufflers
            let mut contributions = Vec::new();
            for (shuffler_idx, shuffler) in game.shufflers.iter().enumerate() {
                let contribution = shuffler
                    .generate_blinding_with_logging(
                        aggregated_public_key,
                        player_public_key.into(),
                        player_id.clone(),
                        card_indices.clone(),
                        shuffler_idx,
                        room_id,
                    )
                    .await?;
                contributions.push(contribution);
            }

            // Combine contributions for each card
            let mut player_ciphertexts = Vec::new();
            for &idx in &card_indices {
                let ciphertext = ShufflerService::combine_blinding_contributions(
                    &deck[idx],
                    &contributions,
                    aggregated_public_key,
                    player_public_key.into(),
                )?;
                player_ciphertexts.push(ciphertext);
            }

            // Phase 2: Collect unblinding shares from all shufflers
            let mut all_unblinding_shares = Vec::new();
            for ciphertext in &player_ciphertexts {
                let mut shares = Vec::new();
                for (shuffler_idx, shuffler) in game.shufflers.iter().enumerate() {
                    let share = shuffler
                        .generate_unblinding_with_logging(
                            ciphertext,
                            shuffler_idx,
                            player_id.clone(),
                            card_indices.clone(),
                            room_id,
                        )
                        .await?;
                    shares.push(share);
                }
                all_unblinding_shares.push(shares);
            }

            // Player decrypts their cards
            game.players[player_idx]
                .decrypt_hole_cards(player_ciphertexts, all_unblinding_shares, room_id)
                .await?;
        }

        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        game.phase = GamePhase::RevealCommunity;
        Ok(())
    }

    /// Reveal community cards (simplified - just pick from deck)
    async fn reveal_community_cards(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        let room_id = game.room_id;

        // For simplicity, just use indices 20, 21, 22 as community cards
        // In a real implementation, these would be properly decrypted
        game.community_cards = vec![20, 21, 22];
        let community_cards = game.community_cards.clone();

        self.log_game_event(room_id, "community_cards_revealed", &community_cards)
            .await?;

        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        game.phase = GamePhase::FinalBetting;
        Ok(())
    }

    /// Execute final betting round
    async fn execute_final_betting(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;

        let active_players: Vec<String> = game
            .players
            .iter()
            .filter(|p| !p.folded)
            .map(|p| p.id.clone())
            .collect();

        let room_id = game.room_id;
        let current_pot = game.pot;
        let mut betting_round = BettingRound::new(20, active_players); // Higher min bet

        for player in game.players.iter_mut() {
            if !player.folded {
                let action = player
                    .make_betting_decision(current_pot + betting_round.pot, betting_round.min_bet, room_id)
                    .await?;

                betting_round.process_action(&player.id, action)?;
            }
        }

        game.pot += betting_round.pot;
        game.phase = GamePhase::Showdown;

        Ok(())
    }

    /// Simple showdown without ZK
    async fn execute_showdown(
        &mut self,
        game_id: [u8; 32],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        let room_id = game.room_id;
        let community_cards = game.community_cards.clone();

        // Collect all non-folded players' hands
        let mut player_hands = Vec::new();
        for player in game.players.iter() {
            let hand = player.reveal_hand_plaintext(room_id).await?;
            player_hands.push((player.id.clone(), hand, player.folded));
        }

        // Evaluate showdown
        let showdown_result = evaluate_showdown(player_hands, &community_cards);

        // Log showdown result
        self.log_game_event(room_id, "showdown_complete", &showdown_result)
            .await?;

        let winner_id = showdown_result.winner_id.clone();
        
        // Update game phase
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;
        game.phase = GamePhase::Settlement;
        
        Ok(winner_id)
    }

    /// Settle the game and distribute winnings
    async fn settle_game(
        &mut self,
        game_id: [u8; 32],
        winner_id: String,
    ) -> Result<GameResult, Box<dyn std::error::Error>> {
        // Extract room_id before mutable borrow
        let room_id = self.games.get(&game_id)
            .ok_or("Game not found")?
            .room_id;
            
        let game = self.games.get_mut(&game_id).ok_or("Game not found")?;

        // Find winner and give them the pot
        if let Some(winner) = game.players.iter_mut().find(|p| p.id == winner_id) {
            winner.add_winnings(game.pot);
        }

        // Collect final standings
        let final_standings: Vec<(String, u64)> = game
            .players
            .iter()
            .map(|p| (p.id.clone(), p.escrow_balance))
            .collect();

        let result = GameResult {
            winner: winner_id,
            pot: game.pot,
            final_standings,
        };

        game.phase = GamePhase::Complete;
        
        // Log game completion after releasing mutable borrow
        self.log_game_event(room_id, "game_complete", &result)
            .await?;

        Ok(result)
    }

    // Helper functions
    async fn log_game_event<T: Serialize>(
        &self,
        room_id: RoomId,
        event_type: &str,
        data: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = AppendParams {
            room_id,
            actor_type: ActorType::System,
            actor_id: "game_manager".to_string(),
            kind: event_type.to_string(),
            payload: serde_json::to_value(data)?,
            correlation_id: None,
            idempotency_key: None,
        };

        self.db_client.append_to_transcript(params).await?;
        Ok(())
    }
}

/// Generate a unique game ID
fn generate_game_id() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(timestamp.to_le_bytes());
    hasher.update(b"game");
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Create initial encrypted deck
fn create_initial_deck(
    aggregated_public_key: &G1Projective,
) -> Vec<ElGamalCiphertext<G1Projective>> {
    use ark_std::rand::thread_rng;
    let mut rng = thread_rng();
    let mut deck = Vec::new();

    for i in 0..52 {
        // Card value as field element
        let card_value = Fr::from(i as u64);
        let msg = G1Affine::generator() * card_value;

        // Initial encryption with randomness 0 (will be re-encrypted by shufflers)
        let r = Fr::rand(&mut rng);
        let c1 = (G1Affine::generator() * r).into();
        let c2 = (msg + (*aggregated_public_key * r).into_affine()).into();

        deck.push(ElGamalCiphertext::<G1Projective> { c1, c2 });
    }

    deck
}