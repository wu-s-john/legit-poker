//! Game events for shuffler operations in the poker protocol
//!
//! This module defines all the events that shufflers generate during the game,
//! including shuffle operations, encryption, and decryption phases.

use ark_ec::CurveGroup;
use serde::{Deserialize, Serialize};

use super::{
    chaum_pedersen::ChaumPedersenProof,
    data_structures::ElGamalCiphertext,
    player_decryption::{
        PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
    },
    unified_shuffler::UnifiedShuffleProof,
};

/// Main event enum encompassing all shuffler-related game events
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ShufflerGameEvent<C: CurveGroup> {
    /// Initial deck preparation by the dealer
    DeckInitialized(DeckInitializedEvent<C>),

    /// Shuffler performs shuffle and re-encryption
    ShuffleAndEncrypt(ShuffleAndEncryptEvent<C>),

    /// Shuffler contributes blinding for player-targeted decryption (Phase 1)
    PlayerBlindingContribution(PlayerBlindingContributionEvent<C>),

    /// Combined blinding result posted on-chain
    PlayerBlindingCombined(PlayerBlindingCombinedEvent<C>),

    /// Shuffler provides unblinding share for card revelation (Phase 2)
    UnblindingShareSubmitted(UnblindingShareEvent<C>),

    /// Player successfully decrypts their cards
    CardsRevealed(CardsRevealedEvent),

    /// Community cards (flop/turn/river) blinding contribution
    CommunityBlindingContribution(CommunityBlindingContributionEvent<C>),
}

/// Event: Initial deck created by dealer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeckInitializedEvent<C: CurveGroup> {
    /// Unique identifier for this game round
    pub game_id: [u8; 32],

    /// The initial encrypted deck (52 cards)
    #[serde(skip)]
    pub encrypted_deck: Vec<ElGamalCiphertext<C>>,

    /// Public key of the dealer who initialized the deck
    #[serde(skip)]
    pub dealer_public_key: C,

    /// Timestamp of deck creation
    pub timestamp: u64,
}

/// Event: Shuffler performs shuffle and re-encryption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShuffleAndEncryptEvent<C: CurveGroup> {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Index of this shuffler in the shuffling sequence
    pub shuffler_index: usize,

    /// Public key of the shuffler
    #[serde(skip)]
    pub shuffler_public_key: C,

    /// The shuffled and re-encrypted deck
    #[serde(skip)]
    pub output_deck: Vec<ElGamalCiphertext<C>>,

    /// Zero-knowledge proof of correct shuffle (stored as bytes for serialization)
    #[serde(skip)]
    pub shuffle_proof: Option<UnifiedShuffleProof>,

    /// Hash of the input deck for verification
    pub input_deck_hash: [u8; 32],

    /// Timestamp of shuffle operation
    pub timestamp: u64,
}

/// Event: Shuffler submits blinding contribution for player-targeted decryption (Phase 1)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlayerBlindingContributionEvent<C: CurveGroup> {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Target player's identifier
    pub player_id: [u8; 32],

    /// Card indices being blinded for this player
    pub card_indices: Vec<usize>,

    /// Shuffler's index in the committee
    pub shuffler_index: usize,

    /// The blinding contribution with proof
    #[serde(skip, default = "default_blinding_contribution")]
    pub blinding_contribution: PlayerTargetedBlindingContribution<C>,

    /// Aggregated public key used
    #[serde(skip)]
    pub aggregated_public_key: C,

    /// Target player's public key
    #[serde(skip)]
    pub player_public_key: C,

    /// Timestamp
    pub timestamp: u64,
}

/// Event: Combined blinding result posted on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlayerBlindingCombinedEvent<C: CurveGroup> {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Target player's identifier
    pub player_id: [u8; 32],

    /// Card indices that were blinded
    pub card_indices: Vec<usize>,

    /// The complete player-accessible ciphertext with all proofs
    #[serde(skip, default = "default_player_ciphertext")]
    pub player_ciphertext: PlayerAccessibleCiphertext<C>,

    /// List of shuffler indices who contributed
    pub contributing_shufflers: Vec<usize>,

    /// Timestamp
    pub timestamp: u64,
}

/// Event: Shuffler provides unblinding share for card revelation (Phase 2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnblindingShareEvent<C: CurveGroup> {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Target player's identifier
    pub player_id: [u8; 32],

    /// Card indices being unblinded
    pub card_indices: Vec<usize>,

    /// The partial unblinding share
    #[serde(skip, default = "default_unblinding_share")]
    pub unblinding_share: PartialUnblindingShare<C>,

    /// Optional Chaum-Pedersen proof for the unblinding share
    /// (can be added for additional verification)
    #[serde(skip)]
    pub unblinding_proof: Option<ChaumPedersenProof<C>>,

    /// Timestamp
    pub timestamp: u64,
}

/// Event: Player successfully decrypts their cards
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CardsRevealedEvent {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Player who revealed cards
    pub player_id: [u8; 32],

    /// The revealed card values (0-51)
    pub card_values: Vec<u8>,

    /// Card indices that were revealed
    pub card_indices: Vec<usize>,

    /// Number of unblinding shares that were combined
    pub num_unblinding_shares: usize,

    /// Timestamp
    pub timestamp: u64,
}

/// Event: Community cards blinding contribution
/// Used for flop, turn, and river cards that are revealed to all players
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommunityBlindingContributionEvent<C: CurveGroup> {
    /// Game round identifier
    pub game_id: [u8; 32],

    /// Stage of community cards (flop=0, turn=1, river=2)
    pub community_stage: u8,

    /// Card indices being blinded
    pub card_indices: Vec<usize>,

    /// Shuffler's index in the committee
    pub shuffler_index: usize,

    /// The blinding contributions (one per card)
    /// For community cards, all players get the same blinding
    #[serde(skip)]
    pub blinding_contributions: Vec<PlayerTargetedBlindingContribution<C>>,

    /// Aggregated public key used
    #[serde(skip)]
    pub aggregated_public_key: C,

    /// Timestamp
    pub timestamp: u64,
}

/// Event verification status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventVerificationResult {
    /// The event ID being verified
    pub event_id: [u8; 32],

    /// Whether the verification passed
    pub is_valid: bool,

    /// Optional error message if verification failed
    pub error_message: Option<String>,

    /// Timestamp of verification
    pub timestamp: u64,
}

/// Helper functions for event handling
impl<C: CurveGroup> ShufflerGameEvent<C> {
    /// Get the game ID from any event
    pub fn game_id(&self) -> [u8; 32] {
        match self {
            Self::DeckInitialized(e) => e.game_id,
            Self::ShuffleAndEncrypt(e) => e.game_id,
            Self::PlayerBlindingContribution(e) => e.game_id,
            Self::PlayerBlindingCombined(e) => e.game_id,
            Self::UnblindingShareSubmitted(e) => e.game_id,
            Self::CardsRevealed(e) => e.game_id,
            Self::CommunityBlindingContribution(e) => e.game_id,
        }
    }

    /// Get the timestamp from any event
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::DeckInitialized(e) => e.timestamp,
            Self::ShuffleAndEncrypt(e) => e.timestamp,
            Self::PlayerBlindingContribution(e) => e.timestamp,
            Self::PlayerBlindingCombined(e) => e.timestamp,
            Self::UnblindingShareSubmitted(e) => e.timestamp,
            Self::CardsRevealed(e) => e.timestamp,
            Self::CommunityBlindingContribution(e) => e.timestamp,
        }
    }

    /// Get a human-readable event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::DeckInitialized(_) => "DeckInitialized",
            Self::ShuffleAndEncrypt(_) => "ShuffleAndEncrypt",
            Self::PlayerBlindingContribution(_) => "PlayerBlindingContribution",
            Self::PlayerBlindingCombined(_) => "PlayerBlindingCombined",
            Self::UnblindingShareSubmitted(_) => "UnblindingShareSubmitted",
            Self::CardsRevealed(_) => "CardsRevealed",
            Self::CommunityBlindingContribution(_) => "CommunityBlindingContribution",
        }
    }
}

/// Game phase tracking
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GamePhase {
    /// Initial setup
    Setup,
    /// Shuffling phase
    Shuffling,
    /// Player card distribution
    PlayerCardDistribution,
    /// Pre-flop betting
    PreFlop,
    /// Flop cards revealed
    Flop,
    /// Turn card revealed
    Turn,
    /// River card revealed
    River,
    /// Showdown
    Showdown,
    /// Game complete
    Complete,
}

/// Complete game state tracker
#[derive(Clone, Debug)]
pub struct GameEventLog<C: CurveGroup> {
    /// Game identifier
    pub game_id: [u8; 32],

    /// Current game phase
    pub current_phase: GamePhase,

    /// All events in chronological order
    pub events: Vec<ShufflerGameEvent<C>>,

    /// Number of players
    pub num_players: usize,

    /// Number of shufflers
    pub num_shufflers: usize,

    /// Game start time
    pub start_time: u64,
}

impl<C: CurveGroup> GameEventLog<C> {
    /// Create a new game event log
    pub fn new(game_id: [u8; 32], num_players: usize, num_shufflers: usize) -> Self {
        Self {
            game_id,
            current_phase: GamePhase::Setup,
            events: Vec::new(),
            num_players,
            num_shufflers,
            start_time: 0, // Set when game starts
        }
    }

    /// Add an event to the log
    pub fn add_event(&mut self, event: ShufflerGameEvent<C>) {
        self.events.push(event);
    }

    /// Transition to the next game phase
    pub fn advance_phase(&mut self) {
        self.current_phase = match self.current_phase {
            GamePhase::Setup => GamePhase::Shuffling,
            GamePhase::Shuffling => GamePhase::PlayerCardDistribution,
            GamePhase::PlayerCardDistribution => GamePhase::PreFlop,
            GamePhase::PreFlop => GamePhase::Flop,
            GamePhase::Flop => GamePhase::Turn,
            GamePhase::Turn => GamePhase::River,
            GamePhase::River => GamePhase::Showdown,
            GamePhase::Showdown => GamePhase::Complete,
            GamePhase::Complete => GamePhase::Complete,
        };
    }

    /// Get events for a specific phase
    pub fn events_for_phase(&self, _phase: GamePhase) -> Vec<&ShufflerGameEvent<C>> {
        // This would filter events based on the phase timing
        // For now, returns all events
        self.events.iter().collect()
    }

    /// Check if all shufflers have submitted their contributions
    pub fn all_shufflers_contributed(&self, player_id: [u8; 32]) -> bool {
        let contributions: Vec<_> = self
            .events
            .iter()
            .filter_map(|e| match e {
                ShufflerGameEvent::PlayerBlindingContribution(contrib)
                    if contrib.player_id == player_id =>
                {
                    Some(contrib.shuffler_index)
                }
                _ => None,
            })
            .collect();

        contributions.len() == self.num_shufflers
    }
}

// Default functions for skipped serde fields
fn default_blinding_contribution<C: CurveGroup>() -> PlayerTargetedBlindingContribution<C> {
    use super::chaum_pedersen::ChaumPedersenProof;

    PlayerTargetedBlindingContribution {
        blinding_base_contribution: C::generator(),
        blinding_combined_contribution: C::generator(),
        proof: ChaumPedersenProof {
            t_g: C::generator(),
            t_h: C::generator(),
            z: C::ScalarField::from(0u64),
        },
    }
}

fn default_player_ciphertext<C: CurveGroup>() -> PlayerAccessibleCiphertext<C> {
    PlayerAccessibleCiphertext {
        blinded_base: C::generator(),
        blinded_message_with_player_key: C::generator(),
        player_unblinding_helper: C::generator(),
        shuffler_proofs: vec![],
    }
}

fn default_unblinding_share<C: CurveGroup>() -> PartialUnblindingShare<C> {
    PartialUnblindingShare {
        share: C::generator(),
        member_index: 0,
    }
}
