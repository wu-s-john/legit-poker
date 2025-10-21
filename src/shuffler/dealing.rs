use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;

use crate::engine::nl::types::SeatId;
use crate::ledger::snapshot::{CardDestination, CardPlan, DealtCard, TableAtDealing};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;

/// Request emitted to shufflers when they must contribute shares for a specific card.
#[derive(Clone, Debug)]
pub enum DealShufflerRequest<C: CurveGroup> {
    Player(PlayerCardShufflerRequest<C>),
    Board(BoardCardShufflerRequest<C>),
}

/// Player card contribution request (blinding and/or unblinding).
#[derive(Clone, Debug)]
pub struct PlayerCardShufflerRequest<C: CurveGroup> {
    pub game_id: GameId,
    pub hand_id: HandId,
    pub deal_index: u8,
    pub seat: SeatId,
    pub hole_index: u8,
    pub player_public_key: C,
    /// When `true`, the shuffler must emit a blinding contribution.
    pub needs_blinding: bool,
    /// When `Some`, the shuffler must emit a partial unblinding share.
    pub ciphertext: Option<PlayerAccessibleCiphertext<C>>,
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
    shufflers: Vec<ShufflerId>,
    blinding_sent: BTreeSet<u8>,
    unblinding_sent: BTreeSet<u8>,
    board_sent: BTreeSet<u8>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: CurveGroup> DealingHandState<C> {
    pub fn new() -> Self {
        Self {
            card_plan: None,
            shufflers: Vec::new(),
            blinding_sent: BTreeSet::new(),
            unblinding_sent: BTreeSet::new(),
            board_sent: BTreeSet::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn reset(&mut self) {
        self.card_plan = None;
        self.shufflers.clear();
        self.blinding_sent.clear();
        self.unblinding_sent.clear();
        self.board_sent.clear();
    }

    pub fn process_snapshot_and_make_responses(
        &mut self,
        table: &TableAtDealing<C>,
        self_shuffler_id: ShufflerId,
        self_member_index: usize,
    ) -> Result<Vec<DealShufflerRequest<C>>> {
        if self.card_plan.is_none() {
            self.card_plan = Some(table.dealing.card_plan.clone());
        }
        self.shufflers = table.shufflers.keys().copied().collect();

        let card_plan = self
            .card_plan
            .as_ref()
            .ok_or_else(|| anyhow!("card plan unavailable for dealing snapshot"))?;

        let mut requests = Vec::new();

        for (&deal_index, destination) in card_plan.iter() {
            match destination {
                CardDestination::Hole { seat, hole_index } => {
                    let player_public_key = player_public_key_for_seat(table, *seat)?;
                    let already_blinded = table
                        .dealing
                        .player_blinding_contribs
                        .contains_key(&(self_shuffler_id, *seat, *hole_index));
                    if already_blinded {
                        self.blinding_sent.insert(deal_index);
                    } else if self.blinding_sent.insert(deal_index) {
                        let ciphertext = table
                            .dealing
                            .player_ciphertexts
                            .get(&(*seat, *hole_index))
                            .cloned();
                        requests.push(DealShufflerRequest::Player(PlayerCardShufflerRequest {
                            game_id: table.game_id,
                            hand_id: table.hand_id.expect("hand id for dealing snapshot"),
                            deal_index,
                            seat: *seat,
                            hole_index: *hole_index,
                            player_public_key: player_public_key.clone(),
                            needs_blinding: true,
                            ciphertext: ciphertext.clone(),
                        }));
                        if ciphertext.is_some() {
                            self.unblinding_sent.insert(deal_index);
                        }
                    }

                    let already_unblinded = table
                        .dealing
                        .player_unblinding_shares
                        .get(&(*seat, *hole_index))
                        .map_or(false, |shares| shares.contains_key(&self_member_index));
                    if already_unblinded {
                        self.unblinding_sent.insert(deal_index);
                    }

                    if !already_unblinded && !self.unblinding_sent.contains(&deal_index) {
                        if let Some(ciphertext) = table
                            .dealing
                            .player_ciphertexts
                            .get(&(*seat, *hole_index))
                            .cloned()
                        {
                            requests.push(DealShufflerRequest::Player(PlayerCardShufflerRequest {
                                game_id: table.game_id,
                                hand_id: table.hand_id.expect("hand id for dealing snapshot"),
                                deal_index,
                                seat: *seat,
                                hole_index: *hole_index,
                                player_public_key,
                                needs_blinding: false,
                                ciphertext: Some(ciphertext),
                            }));
                            self.unblinding_sent.insert(deal_index);
                        }
                    }
                }
                CardDestination::Board { board_index } => {
                    if self.board_sent.contains(&deal_index) {
                        continue;
                    }
                    if !self.should_emit_board(*board_index, card_plan, table) {
                        continue;
                    }
                    if let Some(dealt) = table.dealing.assignments.get(&deal_index) {
                        let slot = board_slot_from_index(*board_index)
                            .ok_or_else(|| anyhow!("invalid board index {board_index}"))?;
                        requests.push(DealShufflerRequest::Board(BoardCardShufflerRequest {
                            game_id: table.game_id,
                            hand_id: table.hand_id.expect("hand id for dealing snapshot"),
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
        table: &TableAtDealing<C>,
    ) -> bool {
        if !self.all_hole_cards_served(card_plan) {
            return false;
        }

        match board_index {
            0 | 1 | 2 => true,
            3 => self.flop_revealed(card_plan, table),
            4 => self.turn_revealed(card_plan, table),
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

    fn flop_revealed(&self, card_plan: &CardPlan, table: &TableAtDealing<C>) -> bool {
        card_plan
            .iter()
            .filter_map(|(&deal_index, destination)| match destination {
                CardDestination::Board { board_index } if *board_index < 3 => Some(deal_index),
                _ => None,
            })
            .all(|deal_index| table.dealing.community_cards.contains_key(&deal_index))
    }

    fn turn_revealed(&self, card_plan: &CardPlan, table: &TableAtDealing<C>) -> bool {
        if !self.flop_revealed(card_plan, table) {
            return false;
        }

        card_plan
            .iter()
            .find_map(|(&deal_index, destination)| match destination {
                CardDestination::Board { board_index } if *board_index == 3 => Some(deal_index),
                _ => None,
            })
            .map(|deal_index| table.dealing.community_cards.contains_key(&deal_index))
            .unwrap_or(false)
    }
}

fn player_public_key_for_seat<C: CurveGroup>(table: &TableAtDealing<C>, seat: SeatId) -> Result<C> {
    let player_id = table
        .seating
        .get(&seat)
        .copied()
        .flatten()
        .ok_or_else(|| anyhow!("no player seated at seat {seat}"))?;
    let identity = table
        .players
        .get(&player_id)
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
