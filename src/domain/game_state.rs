//! Game state types and reduction logic

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Board state (community cards)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardState {
    pub street: Street,
    pub revealed: Vec<CardPlain>,
    pub pending_refs: Vec<CardRef>,
    pub shares_received: HashMap<CardRef, BTreeSet<ShufflerId>>,
}

impl Default for BoardState {
    fn default() -> Self {
        Self {
            street: Street::Preflop,
            revealed: Vec::new(),
            pending_refs: Vec::new(),
            shares_received: HashMap::new(),
        }
    }
}

/// Deck state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeckState {
    pub ciphertexts: Vec<CardCiphertext>,
    pub consumed: BTreeSet<usize>,
    pub ref_to_index: HashMap<CardRef, usize>,
}

impl Default for DeckState {
    fn default() -> Self {
        Self {
            ciphertexts: Vec::new(),
            consumed: BTreeSet::new(),
            ref_to_index: HashMap::new(),
        }
    }
}

/// Seating arrangement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seating {
    pub seats: BTreeMap<u8, UserId>,
    pub by_user: HashMap<UserId, u8>,
}

impl Default for Seating {
    fn default() -> Self {
        Self {
            seats: BTreeMap::new(),
            by_user: HashMap::new(),
        }
    }
}

/// Card visibility tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Visibility {
    pub player_cards: HashMap<UserId, Vec<CardRef>>,
    #[serde(skip)]
    pub local_hole_cards: HashMap<UserId, [CardPlain; 2]>,
}

impl Default for Visibility {
    fn default() -> Self {
        Self {
            player_cards: HashMap::new(),
            local_hole_cards: HashMap::new(),
        }
    }
}

/// Complete game state (reduced from transcript)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameState {
    // Room metadata
    pub room_id: RoomId,
    pub status: RoomStatus,
    pub nonce: Option<String>,
    
    // Actors
    pub shufflers: HashMap<ShufflerId, ShufflerPublic>,
    pub pk_shuffle_agg: Option<PublicKey>,
    pub players: HashMap<UserId, PlayerPublic>,
    pub seating: Seating,
    
    // Cards
    pub deck: DeckState,
    pub board: BoardState,
    pub visibility: Visibility,
    
    // Betting state
    pub pot: i64,
    pub to_act: Option<UserId>,
    
    // Bookkeeping
    pub last_seq: i64,
}

impl GameState {
    pub fn new(room_id: RoomId) -> Self {
        Self {
            room_id,
            status: RoomStatus::Waiting,
            nonce: None,
            shufflers: HashMap::new(),
            pk_shuffle_agg: None,
            players: HashMap::new(),
            seating: Seating::default(),
            deck: DeckState::default(),
            board: BoardState::default(),
            visibility: Visibility::default(),
            pot: 0,
            to_act: None,
            last_seq: 0,
        }
    }
    
    /// Apply a transcript row to update state
    pub fn apply_row(&mut self, row: &TranscriptRow) {
        self.last_seq = self.last_seq.max(row.seq);
        
        match (row.category, row.kind.as_str()) {
            (Category::Event, "event.room.created") => {
                self.status = RoomStatus::Waiting;
            }
            
            (Category::Event, "event.room.status_changed") => {
                #[derive(Deserialize)]
                struct Payload {
                    to: RoomStatus,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.status = p.to;
                }
            }
            
            (Category::Event, "event.shuffler.registered") => {
                #[derive(Deserialize)]
                struct Payload {
                    shuffler_id: String,
                    pk_shuffle: PublicKey,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.shufflers.insert(
                        p.shuffler_id.clone(),
                        ShufflerPublic {
                            id: p.shuffler_id,
                            pk_shuffle: p.pk_shuffle,
                        },
                    );
                }
            }
            
            (Category::Event, "event.shufflers.aggregated") => {
                #[derive(Deserialize)]
                struct Payload {
                    pk_shuffle_agg: PublicKey,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.pk_shuffle_agg = Some(p.pk_shuffle_agg);
                }
            }
            
            (Category::Event, "event.player.joined") => {
                #[derive(Deserialize)]
                struct Payload {
                    user: UserId,
                    role: MemberRole,
                    seat: Option<u8>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    let player = self.players.entry(p.user.clone()).or_insert(PlayerPublic {
                        id: p.user.clone(),
                        role: p.role,
                        seat: p.seat,
                        pk_player: None,
                        stack: None,
                        last_proof_ms: None,
                    });
                    player.role = p.role;
                    player.seat = p.seat;
                    
                    if let Some(seat) = p.seat {
                        self.seating.seats.insert(seat, p.user.clone());
                        self.seating.by_user.insert(p.user, seat);
                    }
                }
            }
            
            (Category::Event, "event.player.key_registered") => {
                #[derive(Deserialize)]
                struct Payload {
                    user: UserId,
                    pk_player: PublicKey,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    if let Some(player) = self.players.get_mut(&p.user) {
                        player.pk_player = Some(p.pk_player);
                    }
                }
            }
            
            (Category::Event, "event.nonce.generated") => {
                #[derive(Deserialize)]
                struct Payload {
                    nonce: String,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.nonce = Some(p.nonce);
                }
            }
            
            (Category::Event, "event.deck.initialized") => {
                #[derive(Deserialize)]
                struct Payload {
                    ciphertexts: Vec<CardCiphertext>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.deck.ciphertexts = p.ciphertexts;
                    self.deck.consumed.clear();
                    self.deck.ref_to_index.clear();
                    self.board = BoardState::default();
                }
            }
            
            (Category::Event, "event.deck.shuffled") => {
                #[derive(Deserialize)]
                struct Payload {
                    ciphertexts: Vec<CardCiphertext>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.deck.ciphertexts = p.ciphertexts;
                }
            }
            
            (Category::Event, "event.deal.assigned") => {
                #[derive(Deserialize)]
                struct Payload {
                    to: UserId,
                    card_ref: String,
                    index: Option<usize>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.visibility
                        .player_cards
                        .entry(p.to)
                        .or_default()
                        .push(CardRef(p.card_ref.clone()));
                    
                    if let Some(idx) = p.index {
                        self.deck.consumed.insert(idx);
                        self.deck.ref_to_index.insert(CardRef(p.card_ref), idx);
                    }
                }
            }
            
            (Category::Event, "event.community.pick") => {
                #[derive(Deserialize)]
                struct Payload {
                    street: Street,
                    card_refs: Vec<String>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.board.street = p.street;
                    self.board.pending_refs = p.card_refs.into_iter().map(CardRef).collect();
                }
            }
            
            (Category::Proof, "proof.cp_dleq") => {
                #[derive(Deserialize)]
                struct Payload {
                    card_ref: String,
                    by: String,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.board
                        .shares_received
                        .entry(CardRef(p.card_ref))
                        .or_default()
                        .insert(p.by);
                }
            }
            
            (Category::Event, "event.board.reveal") => {
                #[derive(Deserialize)]
                struct Payload {
                    street: Street,
                    cards: Vec<u8>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    self.board.street = p.street;
                    self.board.revealed.extend(p.cards.into_iter().map(CardPlain));
                    self.board.pending_refs.clear();
                }
            }
            
            (Category::Event, "event.action.verified") => {
                #[derive(Deserialize)]
                struct Payload {
                    action_id: String,
                    verified: bool,
                    prover_ms: u32,
                    actor: Option<UserId>,
                }
                if let Ok(p) = serde_json::from_value::<Payload>(row.payload.clone()) {
                    if let Some(actor) = p.actor {
                        if let Some(player) = self.players.get_mut(&actor) {
                            player.last_proof_ms = Some(p.prover_ms);
                        }
                    }
                }
            }
            
            _ => {
                // Ignore unknown events or add more handlers as needed
            }
        }
    }
    
    /// Reduce an entire transcript into a game state
    pub fn from_transcript(transcript: &GameTranscript) -> Self {
        let mut state = Self::new(transcript.room_id);
        for row in &transcript.items {
            state.apply_row(row);
        }
        state
    }
}