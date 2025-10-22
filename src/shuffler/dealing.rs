use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use ark_ec::CurveGroup;

use crate::engine::nl::types::SeatId;
use crate::ledger::snapshot::{
    CardDestination, CardPlan, DealingSnapshot, DealtCard, PlayerRoster, SeatingMap, Shared,
    ShufflerRoster, TableAtDealing, TableAtPreflop,
};
use crate::ledger::types::{GameId, HandId, ShufflerId};
use crate::ledger::CanonicalKey;
use crate::shuffling::player_decryption::PlayerAccessibleCiphertext;
use tracing::debug;

const LOG_TARGET: &str = "legit_poker::game::shuffler::deal";

pub trait DealingTableView<C: CurveGroup> {
    fn game_id(&self) -> GameId;
    fn hand_id(&self) -> Option<HandId>;
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

    pub fn process_snapshot_and_make_responses<T>(
        &mut self,
        table: &T,
        self_shuffler_id: ShufflerId,
        self_member_key: &crate::ledger::CanonicalKey<C>,
    ) -> Result<Vec<DealShufflerRequest<C>>>
    where
        T: DealingTableView<C>,
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

        let mut requests = Vec::new();

        for (&deal_index, destination) in card_plan.iter() {
            match destination {
                CardDestination::Hole { seat, hole_index } => {
                    let player_public_key = player_public_key_for_seat(table, *seat)?;
                    let already_blinded = table
                        .dealing()
                        .player_blinding_contribs
                        .contains_key(&(self_member_key.clone(), *seat, *hole_index));
                    if already_blinded {
                        self.blinding_sent.insert(deal_index);
                    } else if self.blinding_sent.insert(deal_index) {
                        let expected_contribs = self.shuffler_keys.len();
                        let contribution_count = table
                            .dealing()
                            .player_blinding_contribs
                            .keys()
                            .filter(|(_, s, h)| *s == *seat && *h == *hole_index)
                            .count();
                        let ciphertext_ready = table
                            .dealing()
                            .player_ciphertexts
                            .contains_key(&(*seat, *hole_index));
                        debug!(
                            target = LOG_TARGET,
                            game_id = table.game_id(),
                            ?self_shuffler_id,
                            seat = *seat,
                            hole_index = *hole_index,
                            contribution_count,
                            expected_contribs,
                            ciphertext_ready,
                            "dispatching player blinding request"
                        );
                        let ciphertext = table
                            .dealing()
                            .player_ciphertexts
                            .get(&(*seat, *hole_index))
                            .cloned();
                        requests.push(DealShufflerRequest::Player(PlayerCardShufflerRequest {
                            game_id: table.game_id(),
                            hand_id: table.hand_id().expect("hand id for dealing snapshot"),
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
                        .dealing()
                        .player_unblinding_shares
                        .get(&(*seat, *hole_index))
                        .map_or(false, |shares| shares.contains_key(self_member_key));
                    if already_unblinded {
                        self.unblinding_sent.insert(deal_index);
                    }

                    if !already_unblinded && !self.unblinding_sent.contains(&deal_index) {
                        let expected_contribs = self.shuffler_keys.len();
                        let contribution_count = table
                            .dealing()
                            .player_blinding_contribs
                            .keys()
                            .filter(|(_, s, h)| *s == *seat && *h == *hole_index)
                            .count();
                        let ciphertext_ready = table
                            .dealing()
                            .player_ciphertexts
                            .contains_key(&(*seat, *hole_index));
                        debug!(
                            target = LOG_TARGET,
                            game_id = table.game_id(),
                            ?self_shuffler_id,
                            seat = *seat,
                            hole_index = *hole_index,
                            contribution_count,
                            expected_contribs,
                            ciphertext_ready,
                            "evaluating player unblinding readiness"
                        );
                        if let Some(ciphertext) = table
                            .dealing()
                            .player_ciphertexts
                            .get(&(*seat, *hole_index))
                            .cloned()
                        {
                            requests.push(DealShufflerRequest::Player(PlayerCardShufflerRequest {
                                game_id: table.game_id(),
                                hand_id: table.hand_id().expect("hand id for dealing snapshot"),
                                deal_index,
                                seat: *seat,
                                hole_index: *hole_index,
                                player_public_key,
                                needs_blinding: false,
                                ciphertext: Some(ciphertext),
                            }));
                            self.unblinding_sent.insert(deal_index);
                        } else {
                            debug!(
                                target = LOG_TARGET,
                                game_id = table.game_id(),
                                ?self_shuffler_id,
                                seat = *seat,
                                hole_index = *hole_index,
                                expected_contribs,
                                contribution_count,
                                "ciphertext not yet available; delaying player unblinding request"
                            );
                        }
                    }
                }
                CardDestination::Board { board_index } => {
                    if self.board_sent.contains(&deal_index) {
                        continue;
                    }
                    if !self.should_emit_board(*board_index, card_plan, table.dealing()) {
                        continue;
                    }
                    if let Some(dealt) = table.dealing().assignments.get(&deal_index) {
                        let slot = board_slot_from_index(*board_index)
                            .ok_or_else(|| anyhow!("invalid board index {board_index}"))?;
                        requests.push(DealShufflerRequest::Board(BoardCardShufflerRequest {
                            game_id: table.game_id(),
                            hand_id: table.hand_id().expect("hand id for dealing snapshot"),
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
