use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;

use crate::curve_absorb::CurveAbsorb;
use crate::engine::nl::types::SeatId;
use crate::ledger::actor::ShufflerActor;
use crate::ledger::hash::default_poseidon_hasher;
use crate::ledger::messages::{AnyMessageEnvelope, MetadataEnvelope};
use crate::ledger::snapshot::{
    CardDestination, CardPlan, DealingSnapshot, DealtCard, PlayerRoster, SeatingMap, Shared,
    ShufflerRoster, SnapshotSeq, TableAtDealing, TableAtPreflop,
};
use crate::ledger::store::snapshot::compute_dealing_hash;
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;
use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, field::display, info, instrument, warn};

use super::api::ShufflerSigningSecret;
use super::{HandRuntime, ShufflerApi};

const LOG_TARGET: &str = "legit_poker::game::shuffler::deal";

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

    #[instrument(
        skip(self, table, self_member_key),
        fields(
            game_id = table.game_id(),
            hand_id = ?table.hand_id(),
            shuffler_id = self_shuffler_id,
            sequence = table.sequence(),
            dealing_hash = tracing::field::Empty
        )
    )]
    pub fn process_snapshot_and_make_responses<T>(
        &mut self,
        table: &T,
        self_shuffler_id: ShufflerId,
        self_member_key: &crate::ledger::CanonicalKey<C>,
    ) -> Result<Vec<DealShufflerRequest<C>>>
    where
        T: DealingTableView<C>,
        C: CanonicalSerialize + CurveAbsorb<C::BaseField> + Send + Sync + 'static,
        C::BaseField: PrimeField + CanonicalSerialize,
        C::ScalarField: PrimeField + Absorb + CanonicalSerialize,
        C::Affine: Absorb,
    {
        if self.card_plan.is_none() {
            self.card_plan = Some(table.dealing().card_plan.clone());
        }
        self.shuffler_keys = table
            .shufflers()
            .values()
            .map(|identity| identity.shuffler_key.clone())
            .collect();

        let card_plan = self
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
                    shuffler_id = self_shuffler_id,
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
            shuffler_id = self_shuffler_id,
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
                        .contains_key(&(self_member_key.clone(), *seat, *hole_index));
                    if already_blinded {
                        self.blinding_sent.insert(deal_index);
                    } else if self.blinding_sent.insert(deal_index) {
                        let expected_contribs = self.shuffler_keys.len();
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
                            shuffler_id = self_shuffler_id,
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
                        .map_or(false, |shares| shares.contains_key(self_member_key));
                    if already_unblinded {
                        self.unblinding_sent.insert(deal_index);
                    }

                    if !already_unblinded && !self.unblinding_sent.contains(&deal_index) {
                        let expected_contribs = self.shuffler_keys.len();
                        let ciphertext_ready = dealing_snapshot
                            .player_ciphertexts
                            .contains_key(&(*seat, *hole_index));
                        debug!(
                            target = LOG_TARGET,
                            game_id = table.game_id(),
                            hand_id = hand_id,
                            shuffler_id = self_shuffler_id,
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
                            self.unblinding_sent.insert(deal_index);
                            debug!(
                                target = LOG_TARGET,
                                game_id = table.game_id(),
                                hand_id = hand_id,
                                shuffler_id = self_shuffler_id,
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
                                shuffler_id = self_shuffler_id,
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
                    if self.board_sent.contains(&deal_index) {
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
                        self.board_sent.insert(deal_index);
                    }
                }
                CardDestination::Burn | CardDestination::Unused => {}
            }
        }

        Ok(requests)
    }
}

impl<C: CurveGroup> DealingHandState<C> {
    fn should_emit_board(
        &self,
        board_index: u8,
        card_plan: &CardPlan,
        dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
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

    fn all_hole_cards_served(&self, card_plan: &CardPlan) -> bool {
        card_plan
            .iter()
            .filter_map(|(&deal_index, destination)| match destination {
                CardDestination::Hole { .. } => Some(deal_index),
                _ => None,
            })
            .all(|deal_index| self.unblinding_sent.contains(&deal_index))
    }

    fn flop_revealed(
        &self,
        card_plan: &CardPlan,
        dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
    ) -> bool {
        card_plan
            .iter()
            .filter_map(|(&deal_index, destination)| match destination {
                CardDestination::Board { board_index } if *board_index < 3 => Some(deal_index),
                _ => None,
            })
            .all(|deal_index| dealing.community_cards.contains_key(&deal_index))
    }

    fn turn_revealed(
        &self,
        card_plan: &CardPlan,
        dealing: &crate::ledger::snapshot::DealingSnapshot<C>,
    ) -> bool {
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

pub async fn deal_loop<C, S, A>(
    runtime: Arc<HandRuntime<C>>,
    mut updates: broadcast::Receiver<DealShufflerRequest<C>>,
    submit: mpsc::Sender<AnyMessageEnvelope<C>>,
    shuffler: Arc<A>,
    actor: &ShufflerActor<C>,
    shuffler_index: usize,
) -> Result<()>
where
    C: CurveGroup + crate::curve_absorb::CurveAbsorb<C::BaseField> + Send + Sync + 'static,
    C::BaseField: ark_ff::PrimeField + Send + Sync,
    C::Affine: ark_crypto_primitives::sponge::Absorb,
    C::ScalarField: ark_ff::PrimeField
        + ark_crypto_primitives::sponge::Absorb
        + CanonicalSerialize
        + UniformRand,
    S: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
    S::Signature: crate::signing::SignatureBytes,
    S::SecretKey: ShufflerSigningSecret<C>,
    A: ShufflerApi<C, S> + Send + Sync,
{
    loop {
        tokio::select! {
            _ = runtime.cancel.cancelled() => {
                debug!(
                    target = LOG_TARGET,
                    game_id = runtime.game_id,
                    hand_id = runtime.hand_id,
                    shuffler_index,
                    "deal loop cancellation triggered"
                );
                break;
            }
            update = updates.recv() => {
                match update {
                    Ok(request) => {
                        debug!(
                            target = LOG_TARGET,
                            game_id = runtime.game_id,
                            hand_id = runtime.hand_id,
                            shuffler_index,
                            request = ?request,
                            "received dealing request"
                        );
                        match prepare_request_envelope(
                            &runtime,
                            request,
                            &shuffler,
                            actor,
                        )
                        .await
                        {
                            Ok(Some(envelope)) => {
                                if let Err(err) = submit.send(envelope).await {
                                    warn!(
                                        target = LOG_TARGET,
                                        game_id = runtime.game_id,
                                        hand_id = runtime.hand_id,
                                        shuffler_index,
                                        error = %err,
                                        "failed to submit dealing envelope"
                                    );
                                } else {
                                    debug!(
                                        target = LOG_TARGET,
                                        game_id = runtime.game_id,
                                        hand_id = runtime.hand_id,
                                        shuffler_index,
                                        "submitted dealing envelope"
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                warn!(
                                    target = LOG_TARGET,
                                    game_id = runtime.game_id,
                                    hand_id = runtime.hand_id,
                                    shuffler_index,
                                    error = %err,
                                    "failed to prepare deal request"
                                );
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            target = LOG_TARGET,
                            game_id = runtime.game_id,
                            hand_id = runtime.hand_id,
                            shuffler_index,
                            skipped,
                            "lagged on deal requests"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!(
                            target = LOG_TARGET,
                            game_id = runtime.game_id,
                            hand_id = runtime.hand_id,
                            shuffler_index,
                            "deal request channel closed"
                        );
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn prepare_request_envelope<C, Sig, Shuffler>(
    runtime: &Arc<HandRuntime<C>>,
    request: DealShufflerRequest<C>,
    shuffler: &Arc<Shuffler>,
    actor: &ShufflerActor<C>,
) -> Result<Option<AnyMessageEnvelope<C>>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + ark_ff::PrimeField + UniformRand + Absorb,
    C::BaseField: ark_ff::PrimeField,
    C::Affine: Absorb,
    Sig: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
    Sig::Signature: crate::signing::SignatureBytes,
    Sig::SecretKey: ShufflerSigningSecret<C>,
    Shuffler: ShufflerApi<C, Sig> + Send + Sync,
{
    match request {
        DealShufflerRequest::PlayerBlinding(req) => {
            prepare_player_blinding::<C, Sig, Shuffler>(runtime, req, shuffler, actor).await
        }
        DealShufflerRequest::PlayerUnblinding(req) => {
            prepare_player_unblinding::<C, Sig, Shuffler>(runtime, req, shuffler, actor).await
        }
        DealShufflerRequest::Board(req) => {
            prepare_board_request::<C, Sig>(runtime, req, actor).await
        }
    }
}

pub async fn prepare_player_blinding<C, Sig, Shuffler>(
    runtime: &Arc<HandRuntime<C>>,
    request: PlayerBlindingRequest<C>,
    shuffler: &Arc<Shuffler>,
    actor: &ShufflerActor<C>,
) -> Result<Option<AnyMessageEnvelope<C>>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + ark_ff::PrimeField + UniformRand + Absorb,
    C::BaseField: ark_ff::PrimeField,
    C::Affine: Absorb,
    Sig: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
    Sig::Signature: crate::signing::SignatureBytes,
    Sig::SecretKey: ShufflerSigningSecret<C>,
    Shuffler: ShufflerApi<C, Sig> + Send + Sync,
{
    if request.game_id != runtime.game_id || request.hand_id != runtime.hand_id {
        warn!(
            target = LOG_TARGET,
            expected_game = runtime.game_id,
            expected_hand = runtime.hand_id,
            request_game = request.game_id,
            request_hand = request.hand_id,
            "received player blinding request for mismatched hand"
        );
        return Ok(None);
    }

    let envelope = {
        let mut state = runtime.shuffling.lock();
        let ctx = make_metadata(runtime, actor, state.next_nonce);
        let aggregated = state.aggregated_public_key.clone();
        let (_, any) = shuffler
            .player_blinding_and_sign(
                &aggregated,
                &ctx,
                request.deal_index,
                &request.player_public_key,
                &mut state.rng,
            )
            .map_err(|err| anyhow!("failed to compute blinding contribution: {err}"))?;
        state.next_nonce = state.next_nonce.saturating_add(1);
        any
    };

    info!(
        target = LOG_TARGET,
        game_id = runtime.game_id,
        hand_id = runtime.hand_id,
        shuffler_id = actor.shuffler_id,
        deal_index = request.deal_index,
        seat = request.seat,
        hole_index = request.hole_index,
        "prepared player blinding share"
    );

    Ok(Some(envelope))
}

pub async fn prepare_player_unblinding<C, Sig, Shuffler>(
    runtime: &Arc<HandRuntime<C>>,
    request: PlayerUnblindingRequest<C>,
    shuffler: &Arc<Shuffler>,
    actor: &ShufflerActor<C>,
) -> Result<Option<AnyMessageEnvelope<C>>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + ark_ff::PrimeField + UniformRand + Absorb,
    C::BaseField: ark_ff::PrimeField,
    C::Affine: Absorb,
    Sig: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
    Sig::Signature: crate::signing::SignatureBytes,
    Sig::SecretKey: ShufflerSigningSecret<C>,
    Shuffler: ShufflerApi<C, Sig> + Send + Sync,
{
    if request.game_id != runtime.game_id || request.hand_id != runtime.hand_id {
        warn!(
            target = LOG_TARGET,
            expected_game = runtime.game_id,
            expected_hand = runtime.hand_id,
            request_game = request.game_id,
            request_hand = request.hand_id,
            "received player unblinding request for mismatched hand"
        );
        return Ok(None);
    }

    let envelope = {
        let mut state = runtime.shuffling.lock();
        let ctx = make_metadata(runtime, actor, state.next_nonce);
        let (_, any) = shuffler
            .player_unblinding_and_sign(
                &ctx,
                request.deal_index,
                &request.player_public_key,
                &request.ciphertext,
                &mut state.rng,
            )
            .map_err(|err| anyhow!("failed to compute partial unblinding share: {err}"))?;
        state.next_nonce = state.next_nonce.saturating_add(1);
        any
    };

    info!(
        target = LOG_TARGET,
        game_id = runtime.game_id,
        hand_id = runtime.hand_id,
        shuffler_id = actor.shuffler_id,
        deal_index = request.deal_index,
        seat = request.seat,
        hole_index = request.hole_index,
        "prepared player unblinding share"
    );

    Ok(Some(envelope))
}

pub async fn prepare_board_request<C, Sig>(
    runtime: &Arc<HandRuntime<C>>,
    request: BoardCardShufflerRequest<C>,
    actor: &ShufflerActor<C>,
) -> Result<Option<AnyMessageEnvelope<C>>>
where
    C: CurveGroup,
    C::Config: ark_ec::CurveConfig<ScalarField = C::ScalarField>,
    C::ScalarField: CanonicalSerialize + ark_ff::PrimeField + UniformRand,
    C::BaseField: ark_ff::PrimeField,
    Sig: ark_crypto_primitives::signature::SignatureScheme<PublicKey = C::Affine>,
    Sig::Signature: crate::signing::SignatureBytes,
{
    if request.game_id != runtime.game_id || request.hand_id != runtime.hand_id {
        warn!(
            target = LOG_TARGET,
            expected_game = runtime.game_id,
            expected_hand = runtime.hand_id,
            request_game = request.game_id,
            request_hand = request.hand_id,
            "received board deal request for mismatched hand"
        );
        return Ok(None);
    }

    // TODO: emit community decryption share once ledger message type is defined.
    debug!(
        target = LOG_TARGET,
        game_id = runtime.game_id,
        hand_id = runtime.hand_id,
        shuffler_id = actor.shuffler_id,
        deal_index = request.deal_index,
        ?request.slot,
        "board deal requests are not yet supported"
    );
    Ok(None)
}

pub fn make_metadata<C>(
    runtime: &HandRuntime<C>,
    actor: &ShufflerActor<C>,
    nonce: u64,
) -> MetadataEnvelope<C, ShufflerActor<C>>
where
    C: CurveGroup,
{
    MetadataEnvelope {
        hand_id: runtime.hand_id,
        game_id: runtime.game_id,
        actor: actor.clone(),
        nonce,
        public_key: runtime.shuffler_key.value().clone(),
    }
}
