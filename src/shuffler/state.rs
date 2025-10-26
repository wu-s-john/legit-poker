use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::SeatId;
use crate::ledger::actor::ShufflerActor;
use crate::ledger::hash::default_poseidon_hasher;
use crate::ledger::messages::{
    AnyMessageEnvelope, EnvelopedMessage, GameShuffleMessage, MetadataEnvelope,
};
use crate::ledger::snapshot::{
    CardDestination, CardPlan, DealingSnapshot, DealtCard, PlayerRoster, SeatingMap, Shared,
    ShufflerRoster, SnapshotSeq, TableAtDealing, TableAtPreflop, TableAtShuffling,
};
use crate::ledger::store::snapshot::compute_dealing_hash;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;
use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;
use crate::shuffling::{ElGamalCiphertext, DECK_SIZE};
use crate::signing::SignatureBytes;
use tracing::{debug, field::display, info, warn};

use super::api::{ShufflerApi, ShufflerSigningSecret};

const LOG_TARGET: &str = "legit_poker::game::shuffler::deal";

// ============================================================================
// Shuffler Hand State (Top-Level)
// ============================================================================

/// Top-level pure state for a single hand from a shuffler's perspective.
/// Contains no async coordination primitives - just pure state and RNGs.
#[derive(Debug)]
pub struct ShufflerHandState<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub shuffler_id: ShufflerId,
    pub shuffler_index: usize,
    pub shuffler_key: CanonicalKey<C>,

    /// Next nonce for message signing (moved from ShufflingHandState)
    pub next_nonce: u64,

    /// Aggregated public key for encryption (moved from ShufflingHandState)
    pub aggregated_public_key: C,

    /// Separate RNG for shuffling phase
    pub shuffling_rng: StdRng,

    /// Separate RNG for dealing phase
    pub dealing_rng: StdRng,

    /// Shuffling phase state
    pub shuffling: ShufflingHandState<C>,

    /// Dealing phase state
    pub dealing: DealingHandState<C>,
}

impl<C: CurveGroup> ShufflerHandState<C> {
    /// Record an incoming shuffle message and return whether shuffling is complete.
    pub fn record_incoming_shuffle(
        &mut self,
        envelope: &EnvelopedMessage<C, GameShuffleMessage<C>>,
        history_cap: usize,
    ) -> bool {
        self.shuffling.buffered.push(envelope.clone());
        if self.shuffling.buffered.len() > history_cap {
            self.shuffling.buffered.remove(0);
        }
        self.shuffling.is_complete()
    }

    /// Attempt to emit a shuffle message if it's this shuffler's turn.
    /// Returns None if already acted or not our turn.
    pub fn try_emit_shuffle<S, A>(
        &mut self,
        shuffler: &A,
        actor: &ShufflerActor<C>,
    ) -> Result<Option<AnyMessageEnvelope<C>>>
    where
        C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
        S::Signature: SignatureBytes,
        S::SecretKey: ShufflerSigningSecret<C>,
        A: ShufflerApi<C, S>,
    {
        if self.shuffling.is_complete() || self.shuffling.acted {
            return Ok(None);
        }

        let position = self.shuffling.buffered.len();
        if let Some(expected) = self.shuffling.expected_order.get(position) {
            if *expected != actor.shuffler_key {
                warn!(
                    target = LOG_TARGET,
                    game_id = self.game_id,
                    hand_id = self.hand_id,
                    expected = ?expected,
                    actual = ?actor.shuffler_key,
                    "attempted to emit shuffle out of turn"
                );
                return Ok(None);
            }
        }

        let deck_in = self.shuffling.latest_deck.clone();
        let turn_index = u16::try_from(self.shuffler_index)
            .map_err(|_| anyhow!("turn index overflow for shuffle message"))?;

        let ctx = MetadataEnvelope {
            hand_id: self.hand_id,
            game_id: self.game_id,
            actor: actor.clone(),
            nonce: self.next_nonce,
            public_key: self.shuffler_key.value().clone(),
        };

        let (typed, any) = shuffler.shuffle_and_sign(
            &self.aggregated_public_key,
            &ctx,
            &deck_in,
            turn_index,
            &mut self.shuffling_rng,
        )?;

        // Update state
        self.shuffling.latest_deck = typed.message.value.deck_out.clone();
        self.shuffling.acted = true;
        self.next_nonce = self.next_nonce.saturating_add(1);

        info!(
            target = LOG_TARGET,
            game_id = self.game_id,
            hand_id = self.hand_id,
            shuffler_id = actor.shuffler_id,
            "prepared shuffle message"
        );

        Ok(Some(any))
    }

    /// Prepare a player blinding share for a specific hole card.
    pub fn try_prepare_player_blinding<S, A>(
        &mut self,
        request: &PlayerBlindingRequest<C>,
        shuffler: &A,
        actor: &ShufflerActor<C>,
    ) -> Result<Option<AnyMessageEnvelope<C>>>
    where
        C: CurveAbsorb<C::BaseField>,
        C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Absorb,
        C::BaseField: PrimeField,
        C::Affine: Absorb,
        S: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
        S::Signature: SignatureBytes,
        S::SecretKey: ShufflerSigningSecret<C>,
        A: ShufflerApi<C, S>,
    {
        if request.game_id != self.game_id || request.hand_id != self.hand_id {
            warn!(
                target = LOG_TARGET,
                expected_game = self.game_id,
                expected_hand = self.hand_id,
                request_game = request.game_id,
                request_hand = request.hand_id,
                "received player blinding request for mismatched hand"
            );
            return Ok(None);
        }

        let ctx = MetadataEnvelope {
            hand_id: self.hand_id,
            game_id: self.game_id,
            actor: actor.clone(),
            nonce: self.next_nonce,
            public_key: self.shuffler_key.value().clone(),
        };

        let (_, any) = shuffler.player_blinding_and_sign(
            &self.aggregated_public_key,
            &ctx,
            request.deal_index,
            &request.player_public_key,
            &mut self.dealing_rng,
        )?;

        self.next_nonce = self.next_nonce.saturating_add(1);

        info!(
            target = LOG_TARGET,
            game_id = self.game_id,
            hand_id = self.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            seat = request.seat,
            hole_index = request.hole_index,
            "prepared player blinding share"
        );

        Ok(Some(any))
    }

    /// Prepare a player unblinding share for a specific hole card.
    pub fn try_prepare_player_unblinding<S, A>(
        &mut self,
        request: &PlayerUnblindingRequest<C>,
        shuffler: &A,
        actor: &ShufflerActor<C>,
    ) -> Result<Option<AnyMessageEnvelope<C>>>
    where
        C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand + Absorb,
        C::BaseField: PrimeField,
        C::Affine: Absorb,
        S: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
        S::Signature: SignatureBytes,
        S::SecretKey: ShufflerSigningSecret<C>,
        A: ShufflerApi<C, S>,
    {
        if request.game_id != self.game_id || request.hand_id != self.hand_id {
            warn!(
                target = LOG_TARGET,
                expected_game = self.game_id,
                expected_hand = self.hand_id,
                request_game = request.game_id,
                request_hand = request.hand_id,
                "received player unblinding request for mismatched hand"
            );
            return Ok(None);
        }

        let ctx = MetadataEnvelope {
            hand_id: self.hand_id,
            game_id: self.game_id,
            actor: actor.clone(),
            nonce: self.next_nonce,
            public_key: self.shuffler_key.value().clone(),
        };

        let (_, any) = shuffler.player_unblinding_and_sign(
            &ctx,
            request.deal_index,
            &request.player_public_key,
            &request.ciphertext,
            &mut self.dealing_rng,
        )?;

        self.next_nonce = self.next_nonce.saturating_add(1);

        info!(
            target = LOG_TARGET,
            game_id = self.game_id,
            hand_id = self.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            seat = request.seat,
            hole_index = request.hole_index,
            "prepared player unblinding share"
        );

        Ok(Some(any))
    }

    /// Prepare a board card decryption request (placeholder - not yet implemented).
    pub fn try_prepare_board_request<S>(
        &mut self,
        request: &BoardCardShufflerRequest<C>,
        actor: &ShufflerActor<C>,
    ) -> Result<Option<AnyMessageEnvelope<C>>>
    where
        C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
        C::ScalarField: CanonicalSerialize + PrimeField + UniformRand,
        C::BaseField: PrimeField,
        S: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
        S::Signature: SignatureBytes,
    {
        if request.game_id != self.game_id || request.hand_id != self.hand_id {
            warn!(
                target = LOG_TARGET,
                expected_game = self.game_id,
                expected_hand = self.hand_id,
                request_game = request.game_id,
                request_hand = request.hand_id,
                "received board deal request for mismatched hand"
            );
            return Ok(None);
        }

        // TODO: emit community decryption share once ledger message type is defined.
        debug!(
            target = LOG_TARGET,
            game_id = self.game_id,
            hand_id = self.hand_id,
            shuffler_id = actor.shuffler_id,
            deal_index = request.deal_index,
            ?request.slot,
            "board deal requests are not yet supported"
        );
        Ok(None)
    }

    /// Create a new ShufflerHandState from a shuffling snapshot using the shuffler's public key.
    ///
    /// # Arguments
    /// * `snapshot` - The table snapshot at shuffling phase
    /// * `shuffler_public_key` - This shuffler's public key (used to find identity)
    /// * `rng_seed` - Seed for both shuffling and dealing RNGs
    pub fn from_shuffling_snapshot(
        snapshot: &TableAtShuffling<C>,
        shuffler_public_key: &C,
        rng_seed: [u8; 32],
    ) -> Result<Self>
    where
        C: CanonicalSerialize + CurveAbsorb<C::BaseField>,
        C::BaseField: PrimeField + CanonicalSerialize,
        C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
        C::Affine: Absorb,
    {
        let shuffler_key = CanonicalKey::new(shuffler_public_key.clone());

        // Find this shuffler in the roster
        let identity = snapshot
            .shufflers
            .values()
            .find(|id| id.shuffler_key == shuffler_key)
            .ok_or_else(|| anyhow!("shuffler public key not found in roster"))?;

        let shuffler_id = identity.shuffler_id;

        // Use the expected order from the snapshot (which is the authoritative order
        // enforced by the coordinator and ledger), rather than rebuilding it from
        // the roster BTreeMap iteration (which uses canonical key sorting)
        let expected_order = snapshot.shuffling.expected_order.clone();

        let shuffler_index = expected_order
            .iter()
            .position(|key| key == &shuffler_key)
            .ok_or_else(|| anyhow!("shuffler not found in expected order"))?;

        let hand_id = snapshot
            .hand_id
            .ok_or_else(|| anyhow!("hand_id missing from shuffling snapshot"))?;

        // Initialize decks from snapshot
        let initial_deck = snapshot.shuffling.initial_deck.clone();
        let latest_deck = snapshot.shuffling.final_deck.clone();

        // Compute aggregated public key from all shuffler public keys
        let shuffler_public_keys: Vec<C> = snapshot
            .shufflers
            .values()
            .map(|id| id.shuffler_key.value().clone())
            .collect();
        let aggregated_public_key = crate::shuffling::make_global_public_keys(shuffler_public_keys);

        // Derive separate RNG seeds for shuffling and dealing
        let shuffling_rng = StdRng::from_seed(rng_seed);
        let mut dealing_seed = rng_seed;
        dealing_seed[0] = dealing_seed[0].wrapping_add(1); // Perturb seed for isolation
        let dealing_rng = StdRng::from_seed(dealing_seed);

        // Create shuffling state (fields moved to parent)
        let shuffling = ShufflingHandState {
            expected_order,
            buffered: Vec::new(),
            initial_deck,
            latest_deck,
            acted: false,
        };

        Ok(Self {
            game_id: snapshot.game_id,
            hand_id,
            shuffler_id,
            shuffler_index,
            shuffler_key,
            next_nonce: 0,
            aggregated_public_key,
            shuffling_rng,
            dealing_rng,
            shuffling,
            dealing: DealingHandState::new(),
        })
    }

    /// Basic constructor for compatibility during transition.
    /// This will be removed once all callsites are updated.
    pub fn new(
        game_id: GameId,
        hand_id: HandId,
        shuffler_id: ShufflerId,
        shuffler_index: usize,
        shuffler_key: CanonicalKey<C>,
        shuffling_state: ShufflingHandState<C>,
        next_nonce: u64,
        aggregated_public_key: C,
        rng_seed: [u8; 32],
    ) -> Self {
        let shuffling_rng = StdRng::from_seed(rng_seed);
        let mut dealing_seed = rng_seed;
        dealing_seed[0] = dealing_seed[0].wrapping_add(1);
        let dealing_rng = StdRng::from_seed(dealing_seed);

        Self {
            game_id,
            hand_id,
            shuffler_id,
            shuffler_index,
            shuffler_key,
            next_nonce,
            aggregated_public_key,
            shuffling_rng,
            dealing_rng,
            shuffling: shuffling_state,
            dealing: DealingHandState::new(),
        }
    }

    /// Check if a board card should be emitted based on game progress.
    fn should_emit_board(
        &self,
        board_index: u8,
        card_plan: &CardPlan,
        dealing: &DealingSnapshot<C>,
    ) -> bool {
        if !self.all_hole_cards_served(card_plan) {
            return false;
        }

        match board_index {
            0 | 1 | 2 => true,
            3 => self.flop_revealed(card_plan, dealing),
            4 => self.turn_revealed(card_plan, dealing),
            _ => false,
        }
    }

    /// Check if all hole cards have been served (unblinding requests sent).
    fn all_hole_cards_served(&self, card_plan: &CardPlan) -> bool {
        card_plan
            .iter()
            .filter_map(|(&deal_index, destination)| match destination {
                CardDestination::Hole { .. } => Some(deal_index),
                _ => None,
            })
            .all(|deal_index| self.dealing.unblinding_sent.contains(&deal_index))
    }

    /// Check if the flop (first 3 board cards) has been revealed.
    fn flop_revealed(&self, card_plan: &CardPlan, dealing: &DealingSnapshot<C>) -> bool {
        card_plan
            .iter()
            .filter_map(|(&deal_index, destination)| match destination {
                CardDestination::Board { board_index } if *board_index < 3 => Some(deal_index),
                _ => None,
            })
            .all(|deal_index| dealing.community_cards.contains_key(&deal_index))
    }

    /// Check if the turn (4th board card) has been revealed.
    fn turn_revealed(&self, card_plan: &CardPlan, dealing: &DealingSnapshot<C>) -> bool {
        if !self.flop_revealed(card_plan, dealing) {
            return false;
        }

        card_plan
            .iter()
            .find_map(|(&deal_index, destination)| match destination {
                CardDestination::Board { board_index } if *board_index == 3 => Some(deal_index),
                _ => None,
            })
            .map(|deal_index| dealing.community_cards.contains_key(&deal_index))
            .unwrap_or(false)
    }

    /// Process a dealing snapshot and generate appropriate shuffler requests.
    ///
    /// This method examines the current dealing state and determines which dealing-phase
    /// requests (blinding, unblinding, board cards) this shuffler should emit.
    #[tracing::instrument(
        skip(self, table),
        fields(
            game_id = table.game_id(),
            hand_id = ?table.hand_id(),
            shuffler_id = self.shuffler_id,
            sequence = table.sequence(),
            dealing_hash = tracing::field::Empty
        )
    )]
    pub fn process_snapshot_and_make_responses<T>(
        &mut self,
        table: &T,
    ) -> Result<Vec<DealShufflerRequest<C>>>
    where
        T: DealingTableView<C>,
        C: CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
        C::BaseField: PrimeField + CanonicalSerialize,
        C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
        C::Affine: Absorb,
    {
        if self.dealing.card_plan.is_none() {
            self.dealing.card_plan = Some(table.dealing().card_plan.clone());
        }
        self.dealing.shuffler_keys = table
            .shufflers()
            .values()
            .map(|identity| identity.shuffler_key.clone())
            .collect();

        let card_plan = self
            .dealing
            .card_plan
            .as_ref()
            .ok_or_else(|| anyhow!("card plan unavailable for dealing snapshot"))?;

        let hand_id_opt = table.hand_id();
        let sequence = table.sequence();
        let dealing_snapshot = table.dealing();
        let hasher = default_poseidon_hasher::<C::BaseField>();
        let dealing_hash_hex = compute_dealing_hash(dealing_snapshot, hasher.as_ref())
            .map(|hash| format!("0x{}", hex::encode(hash.as_bytes())))
            .unwrap_or_else(|err| {
                warn!(
                    target = LOG_TARGET,
                    game_id = table.game_id(),
                    hand_id = ?hand_id_opt,
                    shuffler_id = self.shuffler_id,
                    sequence,
                    error = %err,
                    "failed to compute dealing hash"
                );
                "hash-error".to_string()
            });

        tracing::Span::current().record("dealing_hash", &display(&dealing_hash_hex));

        let mut hole_card_sources: BTreeMap<(SeatId, u8), u8> = BTreeMap::new();
        for (&card_ref, destination) in dealing_snapshot.card_plan.iter() {
            if let CardDestination::Hole { seat, hole_index } = destination {
                hole_card_sources.insert((*seat, *hole_index), card_ref);
            }
        }

        let ready_positions: Vec<(SeatId, u8, Option<u8>)> = dealing_snapshot
            .player_ciphertexts
            .iter()
            .map(|(&(seat, hole_index), _)| {
                let source_index = hole_card_sources
                    .get(&(seat, hole_index))
                    .and_then(|card_ref| dealing_snapshot.assignments.get(card_ref))
                    .and_then(|dealt| dealt.source_index);
                (seat, hole_index, source_index)
            })
            .collect();

        debug!(
            target = LOG_TARGET,
            game_id = table.game_id(),
            hand_id = ?hand_id_opt,
            shuffler_id = self.shuffler_id,
            sequence,
            dealing_hash = dealing_hash_hex.as_str(),
            ciphertext_count = ready_positions.len(),
            ready_cipher_positions = ?ready_positions,
            "evaluated dealing snapshot"
        );

        let hand_id =
            hand_id_opt.expect("hand id for dealing snapshot when processing dealing state");

        let mut requests = Vec::new();

        for (&deal_index, destination) in card_plan.iter() {
            match destination {
                CardDestination::Hole { seat, hole_index } => {
                    let player_public_key = player_public_key_for_seat(table, *seat)?;
                    let already_blinded = dealing_snapshot
                        .player_blinding_contribs
                        .contains_key(&(self.shuffler_key.clone(), *seat, *hole_index));
                    if already_blinded {
                        self.dealing.blinding_sent.insert(deal_index);
                    } else if self.dealing.blinding_sent.insert(deal_index) {
                        let expected_contribs = self.dealing.shuffler_keys.len();
                        let contribution_count = dealing_snapshot
                            .player_blinding_contribs
                            .keys()
                            .filter(|(_, s, h)| *s == *seat && *h == *hole_index)
                            .count();
                        let ciphertext_ready = dealing_snapshot
                            .player_ciphertexts
                            .contains_key(&(*seat, *hole_index));
                        debug!(
                            target = LOG_TARGET,
                            game_id = table.game_id(),
                            hand_id = hand_id,
                            shuffler_id = self.shuffler_id,
                            sequence,
                            dealing_hash = dealing_hash_hex.as_str(),
                            seat = *seat,
                            hole_index = *hole_index,
                            contribution_count,
                            expected_contribs,
                            ciphertext_ready,
                            "dispatching player blinding request"
                        );
                        requests.push(DealShufflerRequest::PlayerBlinding(PlayerBlindingRequest {
                            game_id: table.game_id(),
                            hand_id,
                            deal_index,
                            seat: *seat,
                            hole_index: *hole_index,
                            player_public_key: player_public_key.clone(),
                        }));
                    }

                    let already_unblinded = dealing_snapshot
                        .player_unblinding_shares
                        .get(&(*seat, *hole_index))
                        .map_or(false, |shares| shares.contains_key(&self.shuffler_key));
                    if already_unblinded {
                        self.dealing.unblinding_sent.insert(deal_index);
                    }

                    if !already_unblinded && !self.dealing.unblinding_sent.contains(&deal_index) {
                        let expected_contribs = self.dealing.shuffler_keys.len();
                        let ciphertext_ready = dealing_snapshot
                            .player_ciphertexts
                            .contains_key(&(*seat, *hole_index));
                        debug!(
                            target = LOG_TARGET,
                            game_id = table.game_id(),
                            hand_id = hand_id,
                            shuffler_id = self.shuffler_id,
                            sequence,
                            dealing_hash = dealing_hash_hex.as_str(),
                            seat = *seat,
                            hole_index = *hole_index,
                            expected_contribs,
                            ciphertext_ready,
                            "evaluating player unblinding readiness"
                        );
                        if let Some(ciphertext) = dealing_snapshot
                            .player_ciphertexts
                            .get(&(*seat, *hole_index))
                            .cloned()
                        {
                            requests.push(DealShufflerRequest::PlayerUnblinding(
                                PlayerUnblindingRequest {
                                    game_id: table.game_id(),
                                    hand_id,
                                    deal_index,
                                    seat: *seat,
                                    hole_index: *hole_index,
                                    player_public_key: player_public_key.clone(),
                                    ciphertext,
                                },
                            ));
                            self.dealing.unblinding_sent.insert(deal_index);
                            debug!(
                                target = LOG_TARGET,
                                game_id = table.game_id(),
                                hand_id = hand_id,
                                shuffler_id = self.shuffler_id,
                                sequence,
                                dealing_hash = dealing_hash_hex.as_str(),
                                seat = *seat,
                                hole_index = *hole_index,
                                expected_contribs,
                                "ciphertext send unblinding request"
                            );
                        } else {
                            debug!(
                                target = LOG_TARGET,
                                game_id = table.game_id(),
                                hand_id = hand_id,
                                shuffler_id = self.shuffler_id,
                                sequence,
                                dealing_hash = dealing_hash_hex.as_str(),
                                seat = *seat,
                                hole_index = *hole_index,
                                expected_contribs,
                                "ciphertext not yet available; delaying player unblinding request"
                            );
                        }
                    }
                }
                CardDestination::Board { board_index } => {
                    if self.dealing.board_sent.contains(&deal_index) {
                        continue;
                    }
                    if !self.should_emit_board(*board_index, card_plan, dealing_snapshot) {
                        continue;
                    }
                    if let Some(dealt) = dealing_snapshot.assignments.get(&deal_index) {
                        let slot = board_slot_from_index(*board_index)
                            .ok_or_else(|| anyhow!("invalid board index {board_index}"))?;
                        requests.push(DealShufflerRequest::Board(BoardCardShufflerRequest {
                            game_id: table.game_id(),
                            hand_id,
                            deal_index,
                            slot,
                            ciphertext: dealt.clone(),
                        }));
                        self.dealing.board_sent.insert(deal_index);
                    }
                }
                CardDestination::Burn | CardDestination::Unused => {}
            }
        }

        Ok(requests)
    }
}

// ============================================================================
// Shuffling State
// ============================================================================

/// Shuffling phase state - contains only shuffling-specific data.
/// Parent-level data (nonce, aggregated key, RNG) moved to ShufflerHandState.
#[derive(Debug)]
pub struct ShufflingHandState<C: CurveGroup> {
    pub expected_order: Vec<CanonicalKey<C>>,
    pub buffered: Vec<EnvelopedMessage<C, GameShuffleMessage<C>>>,
    pub initial_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub latest_deck: [ElGamalCiphertext<C>; DECK_SIZE],
    pub acted: bool,
}

impl<C: CurveGroup> ShufflingHandState<C> {
    pub fn is_complete(&self) -> bool {
        self.buffered.len() >= self.expected_order.len()
    }
}

// ============================================================================
// Dealing State and Types
// ============================================================================

pub trait DealingTableView<C: CurveGroup> {
    fn game_id(&self) -> GameId;
    fn hand_id(&self) -> Option<HandId>;
    fn sequence(&self) -> SnapshotSeq;
    fn shufflers(&self) -> &Shared<ShufflerRoster<C>>;
    fn dealing(&self) -> &DealingSnapshot<C>;
    fn players(&self) -> &Shared<PlayerRoster<C>>;
    fn seating(&self) -> &Shared<SeatingMap<C>>;
}

impl<C: CurveGroup> DealingTableView<C> for TableAtDealing<C> {
    fn game_id(&self) -> GameId {
        self.game_id
    }

    fn hand_id(&self) -> Option<HandId> {
        self.hand_id
    }

    fn sequence(&self) -> SnapshotSeq {
        self.sequence
    }

    fn shufflers(&self) -> &Shared<ShufflerRoster<C>> {
        &self.shufflers
    }

    fn dealing(&self) -> &DealingSnapshot<C> {
        &self.dealing
    }

    fn players(&self) -> &Shared<PlayerRoster<C>> {
        &self.players
    }

    fn seating(&self) -> &Shared<SeatingMap<C>> {
        &self.seating
    }
}

impl<C: CurveGroup> DealingTableView<C> for TableAtPreflop<C> {
    fn game_id(&self) -> GameId {
        self.game_id
    }

    fn hand_id(&self) -> Option<HandId> {
        self.hand_id
    }

    fn sequence(&self) -> SnapshotSeq {
        self.sequence
    }

    fn shufflers(&self) -> &Shared<ShufflerRoster<C>> {
        &self.shufflers
    }

    fn dealing(&self) -> &DealingSnapshot<C> {
        &self.dealing
    }

    fn players(&self) -> &Shared<PlayerRoster<C>> {
        &self.players
    }

    fn seating(&self) -> &Shared<SeatingMap<C>> {
        &self.seating
    }
}

/// Request emitted to shufflers when they must contribute shares for a specific card.
#[derive(Clone, Debug)]
pub enum DealShufflerRequest<C: CurveGroup> {
    PlayerBlinding(PlayerBlindingRequest<C>),
    PlayerUnblinding(PlayerUnblindingRequest<C>),
    Board(BoardCardShufflerRequest<C>),
}

/// Player card blinding contribution request.
#[derive(Clone, Debug)]
pub struct PlayerBlindingRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub seat: SeatId,
    pub hole_index: u8,
    pub player_public_key: C,
}

/// Player card unblinding share request, providing the accessible ciphertext.
#[derive(Clone, Debug)]
pub struct PlayerUnblindingRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub seat: SeatId,
    pub hole_index: u8,
    pub player_public_key: C,
    pub ciphertext: PlayerAccessibleCiphertext<C>,
}

/// Community card contribution request (requires community share).
#[derive(Clone, Debug)]
pub struct BoardCardShufflerRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub slot: BoardCardSlot,
    pub ciphertext: DealtCard<C>,
}

/// Location of a community card within the board.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardCardSlot {
    Flop(u8),
    Turn,
    River,
}

/// Per-hand bookkeeping for dealing phase signalling.
#[derive(Debug)]
pub struct DealingHandState<C: CurveGroup> {
    card_plan: Option<CardPlan>,
    shuffler_keys: Vec<CanonicalKey<C>>,
    blinding_sent: BTreeSet<u8>,
    unblinding_sent: BTreeSet<u8>,
    board_sent: BTreeSet<u8>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: CurveGroup> DealingHandState<C> {
    pub fn new() -> Self {
        Self {
            card_plan: None,
            shuffler_keys: Vec::new(),
            blinding_sent: BTreeSet::new(),
            unblinding_sent: BTreeSet::new(),
            board_sent: BTreeSet::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn reset(&mut self) {
        self.card_plan = None;
        self.shuffler_keys.clear();
        self.blinding_sent.clear();
        self.unblinding_sent.clear();
        self.board_sent.clear();
    }
}

fn player_public_key_for_seat<C: CurveGroup, T>(table: &T, seat: SeatId) -> Result<C>
where
    T: DealingTableView<C>,
{
    let player_key = table
        .seating()
        .get(&seat)
        .and_then(|key| key.clone())
        .ok_or_else(|| anyhow!("no player seated at seat {seat}"))?;
    let identity = table
        .players()
        .get(&player_key)
        .ok_or_else(|| anyhow!("missing player identity for seat {seat}"))?;
    Ok(identity.public_key.clone())
}

fn board_slot_from_index(index: u8) -> Option<BoardCardSlot> {
    match index {
        0..=2 => Some(BoardCardSlot::Flop(index)),
        3 => Some(BoardCardSlot::Turn),
        4 => Some(BoardCardSlot::River),
        _ => None,
    }
}

// ============================================================================
// Hand Resources (Coordination Layer)
// ============================================================================

#[derive(Debug, Default)]
struct ShufflerTasks {
    shuffle: Option<JoinHandle<()>>,
    dealing_producer: Option<JoinHandle<()>>,
    dealing_worker: Option<JoinHandle<()>>,
}

/// Private coordination structure for managing hand resources and async tasks.
/// Holds pure state in a mutex and provides coordination primitives.
#[derive(Debug)]
pub struct HandResources<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub cancel: CancellationToken,
    pub state: Mutex<ShufflerHandState<C>>,
    tasks: Mutex<ShufflerTasks>,
    registry: Weak<DashMap<(GameId, HandId), Arc<HandResources<C>>>>,
}

impl<C: CurveGroup> HandResources<C> {
    pub fn new(
        state: ShufflerHandState<C>,
        registry: Weak<DashMap<(GameId, HandId), Arc<HandResources<C>>>>,
    ) -> Self {
        let game_id = state.game_id;
        let hand_id = state.hand_id;
        let cancel = CancellationToken::new();
        Self {
            game_id,
            hand_id,
            cancel,
            state: Mutex::new(state),
            tasks: Mutex::new(ShufflerTasks::default()),
            registry,
        }
    }

    pub fn set_shuffle_handle(&self, handle: JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        if let Some(existing) = tasks.shuffle.replace(handle) {
            existing.abort();
        }
    }

    pub fn set_dealing_handles(&self, producer: JoinHandle<()>, worker: JoinHandle<()>) {
        let mut tasks = self.tasks.lock();
        if let Some(existing) = tasks.dealing_producer.replace(producer) {
            existing.abort();
        }
        if let Some(existing) = tasks.dealing_worker.replace(worker) {
            existing.abort();
        }
    }

    pub fn cancel_all(&self) {
        self.cancel.cancel();
        let mut tasks = self.tasks.lock();
        if let Some(handle) = tasks.shuffle.take() {
            handle.abort();
        }
        if let Some(handle) = tasks.dealing_producer.take() {
            handle.abort();
        }
        if let Some(handle) = tasks.dealing_worker.take() {
            handle.abort();
        }
    }

    pub fn remove_from_registry(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.remove(&(self.game_id, self.hand_id));
        }
    }
}

pub struct HandSubscription<C>
where
    C: CurveGroup,
{
    resources: Arc<HandResources<C>>,
}

impl<C> HandSubscription<C>
where
    C: CurveGroup,
{
    pub fn new(resources: Arc<HandResources<C>>) -> Self {
        Self { resources }
    }

    pub fn cancel(&self) {
        self.resources.cancel_all();
    }
}

impl<C> Drop for HandSubscription<C>
where
    C: CurveGroup,
{
    fn drop(&mut self) {
        self.resources.cancel_all();
        self.resources.remove_from_registry();
    }
}
