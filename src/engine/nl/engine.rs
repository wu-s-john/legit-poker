use super::actions::*;
use super::errors::*;
use super::events::*;
use super::legals::*;
use super::rules::*;
use super::seating::Seating;
use super::state::*;
use super::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    Continued { events: Vec<GameEvent>, next_to_act: SeatId },
    StreetEnd { events: Vec<GameEvent>, street: Street },
    HandEnd { events: Vec<GameEvent>, winner: SeatId, pots: Pots },
}

pub trait BettingEngineNL {
    fn new_after_deal(cfg: HandConfig, players: Vec<PlayerState>, pots: Pots) -> BettingState;
    fn legal_actions(state: &BettingState, seat: SeatId) -> LegalActions;
    fn apply_action(state: &mut BettingState, seat: SeatId, action: PlayerAction)
        -> Result<Transition, ActionError>;
    fn advance_street(state: &mut BettingState) -> Result<(), StateError>;
}

pub struct BettingEngine;

fn recompute_pots(players: &[PlayerState]) -> Pots {
    // gather contributions sorted
    let mut contribs: Vec<(SeatId, Chips, PlayerStatus)> = players
        .iter()
        .map(|p| (p.seat, p.committed_total, p.status))
        .collect();
    contribs.sort_by_key(|c| c.1);
    let mut levels: Vec<Chips> = contribs.iter().map(|c| c.1).filter(|&c| c > 0).collect();
    levels.sort();
    levels.dedup();
    if levels.is_empty() {
        return Pots::default();
    }
    let mut pots = Vec::new();
    let mut prev = 0;
    for level in levels {
        let contributors: Vec<&(SeatId, Chips, PlayerStatus)> =
            contribs.iter().filter(|c| c.1 >= level).collect();
        let diff = level - prev;
        let amount = diff * contributors.len() as Chips;
        let eligible: Vec<SeatId> = contributors
            .iter()
            .filter(|c| c.2 != PlayerStatus::Folded)
            .map(|c| c.0)
            .collect();
        pots.push(Pot { amount, eligible });
        prev = level;
    }
    let main = pots.remove(0);
    Pots { main, sides: pots }
}

fn update_pots(state: &mut BettingState) {
    let new_pots = recompute_pots(&state.players);
    if new_pots != state.pots {
        state.pots = new_pots;
    }
}

fn all_players_all_in(state: &BettingState) -> bool {
    state
        .players
        .iter()
        .filter(|p| p.status != PlayerStatus::Folded)
        .all(|p| p.status == PlayerStatus::AllIn)
}

fn only_one_player_remaining(state: &BettingState) -> Option<SeatId> {
    let mut remaining = state
        .players
        .iter()
        .filter(|p| p.status != PlayerStatus::Folded)
        .map(|p| p.seat);
    let first = remaining.next()?;
    if remaining.next().is_none() {
        Some(first)
    } else {
        None
    }
}

impl BettingEngineNL for BettingEngine {
    fn new_after_deal(cfg: HandConfig, mut players: Vec<PlayerState>, mut pots: Pots) -> BettingState {
        // compute pot if not provided
        if pots.main.amount == 0 && players.iter().any(|p| p.committed_total > 0) {
            pots = recompute_pots(&players);
        }
        let street = Street::Preflop;
        let mut state = BettingState {
            street,
            button: cfg.button,
            first_to_act: cfg.big_blind_seat, // temp
            to_act: cfg.big_blind_seat,
            current_bet_to_match: 0,
            last_full_raise_amount: cfg.stakes.big_blind,
            last_aggressor: Some(cfg.big_blind_seat),
            players,
            pots,
            cfg,
            pending_to_match: Vec::new(),
            betting_locked_all_in: false,
        };
        state.current_bet_to_match = state
            .players
            .iter()
            .map(|p| p.committed_this_round)
            .max()
            .unwrap_or(0);
        state.first_to_act = state.compute_first_to_act(street);
        state.to_act = state.first_to_act;
        state.pending_to_match = state
            .players
            .iter()
            .filter(|p| p.status == PlayerStatus::Active && p.committed_this_round < state.current_bet_to_match)
            .map(|p| p.seat)
            .collect();
        state
    }

    fn legal_actions(state: &BettingState, seat: SeatId) -> LegalActions {
        let mut legals = LegalActions::default();
        let player = state.player(seat);
        if player.status != PlayerStatus::Active || state.betting_locked_all_in {
            return legals;
        }
        legals.may_fold = true;
        let price = NoLimit::price_to_call(state, seat);
        legals.call_amount = Some(price);
        legals.may_check = price == 0;
        if state.current_bet_to_match == 0 {
            legals.bet_to_range = NoLimit::bet_to_bounds_unopened(state, seat);
        } else {
            if state.last_aggressor != Some(seat) || !player.has_acted_this_round {
                legals.raise_to_range = NoLimit::raise_to_bounds_opened(state, seat);
            }
        }
        legals
    }

    fn apply_action(state: &mut BettingState, seat: SeatId, action: PlayerAction) -> Result<Transition, ActionError> {
        if state.to_act != seat { return Err(ActionError::NotPlayersTurn); }
        let price = NoLimit::price_to_call(state, seat);
        let mut events = Vec::new();
        let mut normalized;
        let idx = state.players.iter().position(|p| p.seat == seat).unwrap();
        if state.players[idx].status != PlayerStatus::Active {
            return Err(ActionError::ActorCannotAct);
        }

        match action {
            PlayerAction::Fold => {
                state.players[idx].status = PlayerStatus::Folded;
                state.players[idx].has_acted_this_round = true;
                state.pending_to_match.retain(|s| *s != seat);
                normalized = NormalizedAction::Fold;
            }
            PlayerAction::Check => {
                if price > 0 { return Err(ActionError::CannotCheckFacingBet); }
                state.players[idx].has_acted_this_round = true;
                normalized = NormalizedAction::Check;
            }
            PlayerAction::Call => {
                let call_amt = price.min(state.players[idx].stack);
                if call_amt < price && state.players[idx].stack > call_amt { return Err(ActionError::BadCallAmount); }
                state.players[idx].stack -= call_amt;
                state.players[idx].committed_this_round += call_amt;
                state.players[idx].committed_total += call_amt;
                let full = call_amt == price;
                if state.players[idx].stack == 0 { state.players[idx].status = PlayerStatus::AllIn; }
                state.players[idx].has_acted_this_round = true;
                state.pending_to_match.retain(|s| *s != seat);
                normalized = NormalizedAction::Call { call_amount: call_amt, full_call: full };
            }
            PlayerAction::BetTo { to } => {
                if state.current_bet_to_match != 0 { return Err(ActionError::CannotBetWhenOpened); }
                let needed = to.saturating_sub(state.players[idx].committed_this_round);
                if needed > state.players[idx].stack { return Err(ActionError::InsufficientChips); }
                if to < state.cfg.stakes.big_blind { return Err(ActionError::IllegalAction); }
                state.players[idx].stack -= needed;
                state.players[idx].committed_this_round = to;
                state.players[idx].committed_total += needed;
                state.players[idx].has_acted_this_round = true;
                if state.players[idx].stack == 0 { state.players[idx].status = PlayerStatus::AllIn; }
                state.current_bet_to_match = to;
                state.last_full_raise_amount = to;
                state.last_aggressor = Some(seat);
                state.pending_to_match = state
                    .players
                    .iter()
                    .filter(|p| p.seat != seat && p.status == PlayerStatus::Active)
                    .map(|p| p.seat)
                    .collect();
                normalized = NormalizedAction::Bet { to };
            }
            PlayerAction::RaiseTo { to } => {
                if state.current_bet_to_match == 0 { return Err(ActionError::IllegalAction); }
                let min_to = state.current_bet_to_match + state.last_full_raise_amount;
                if to < min_to { return Err(ActionError::RaiseBelowMinimum); }
                let needed = to - state.players[idx].committed_this_round;
                if needed > state.players[idx].stack { return Err(ActionError::InsufficientChips); }
                state.players[idx].stack -= needed;
                state.players[idx].committed_this_round = to;
                state.players[idx].committed_total += needed;
                state.players[idx].has_acted_this_round = true;
                if state.players[idx].stack == 0 { state.players[idx].status = PlayerStatus::AllIn; }
                let raise_amt = to - state.current_bet_to_match;
                let full = NoLimit::is_full_raise(state, raise_amt);
                if full {
                    state.last_full_raise_amount = raise_amt;
                    state.last_aggressor = Some(seat);
                }
                state.current_bet_to_match = to;
                state.pending_to_match = state
                    .players
                    .iter()
                    .filter(|p| p.seat != seat && p.status == PlayerStatus::Active)
                    .filter(|p| p.committed_this_round < to)
                    .map(|p| p.seat)
                    .collect();
                normalized = NormalizedAction::Raise { to, raise_amount: raise_amt, full_raise: full };
            }
            PlayerAction::AllIn => {
                let total_to = state.players[idx].committed_this_round + state.players[idx].stack;
                if state.current_bet_to_match == 0 {
                    if total_to < state.cfg.stakes.big_blind { return Err(ActionError::IllegalAction); }
                    state.players[idx].committed_this_round = total_to;
                    state.players[idx].committed_total += state.players[idx].stack;
                    state.players[idx].stack = 0;
                    state.players[idx].status = PlayerStatus::AllIn;
                    state.players[idx].has_acted_this_round = true;
                    state.current_bet_to_match = total_to;
                    state.last_full_raise_amount = total_to;
                    state.last_aggressor = Some(seat);
                    state.pending_to_match = state
                        .players
                        .iter()
                        .filter(|p| p.seat != seat && p.status == PlayerStatus::Active)
                        .map(|p| p.seat)
                        .collect();
                    normalized = NormalizedAction::AllInAsBet { to: total_to };
                } else {
                    let needed = total_to - state.players[idx].committed_this_round;
                    state.players[idx].stack = 0;
                    state.players[idx].committed_this_round = total_to;
                    state.players[idx].committed_total += needed;
                    state.players[idx].status = PlayerStatus::AllIn;
                    state.players[idx].has_acted_this_round = true;
                    if total_to <= state.current_bet_to_match {
                        let call_amt = needed.min(price);
                        let full = total_to == state.current_bet_to_match;
                        state.pending_to_match.retain(|s| *s != seat);
                        normalized = NormalizedAction::AllInAsCall { call_amount: call_amt, full_call: full };
                    } else {
                        let raise_amt = total_to - state.current_bet_to_match;
                        let full = NoLimit::is_full_raise(state, raise_amt);
                        if full {
                            state.last_full_raise_amount = raise_amt;
                            state.last_aggressor = Some(seat);
                        }
                        state.current_bet_to_match = total_to;
                        state.pending_to_match = state
                            .players
                            .iter()
                            .filter(|p| p.seat != seat && p.status == PlayerStatus::Active)
                            .filter(|p| p.committed_this_round < total_to)
                            .map(|p| p.seat)
                            .collect();
                        normalized = NormalizedAction::AllInAsRaise { to: total_to, raise_amount: raise_amt, full_raise: full };
                    }
                }
            }
        }
        events.push(GameEvent::ActionApplied { seat, action: normalized.clone() });
        // update pots
        let before_pots = state.pots.clone();
        update_pots(state);
        if state.pots != before_pots {
            events.push(GameEvent::PotUpdated);
        }

        if let Some(winner) = only_one_player_remaining(state) {
            return Ok(Transition::HandEnd { events, winner, pots: state.pots.clone() });
        }
        if all_players_all_in(state) {
            state.betting_locked_all_in = true;
            events.push(GameEvent::AllPlayersAllIn);
        }
        let next = state.next_actor(seat);
        state.to_act = next;
        if state.pending_to_match.is_empty() && seat == state.last_aggressor.unwrap_or(seat) {
            events.push(GameEvent::StreetEnded { street: state.street });
            return Ok(Transition::StreetEnd { events, street: state.street });
        }
        Ok(Transition::Continued { events, next_to_act: next })
    }

    fn advance_street(state: &mut BettingState) -> Result<(), StateError> {
        state.street = match state.street {
            Street::Preflop => Street::Flop,
            Street::Flop => Street::Turn,
            Street::Turn => Street::River,
            Street::River => return Err(StateError::InvalidTransition),
        };
        state.current_bet_to_match = 0;
        state.last_full_raise_amount = state.cfg.stakes.big_blind;
        state.last_aggressor = Some(state.cfg.button);
        for p in state.players.iter_mut() {
            p.committed_this_round = 0;
            p.has_acted_this_round = false;
        }
        state.first_to_act = state.compute_first_to_act(state.street);
        state.to_act = state.first_to_act;
        state.pending_to_match.clear();
        state.betting_locked_all_in = false;
        Ok(())
    }
}
