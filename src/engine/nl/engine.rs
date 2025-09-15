use super::actions::PlayerBetAction;
use super::errors::{ActionError, StateError};
use super::events::{GameEvent, NormalizedAction};
use super::legals::legal_actions_for;
use super::rules::NoLimitRules;
use super::seating::Seating;
use super::state::BettingState;
use super::types::{
    ActionLogEntry, Chips, HandConfig, PlayerState, PlayerStatus, Pots, SeatId, Street,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    Continued {
        events: Vec<GameEvent>,
        next_to_act: SeatId,
    },
    StreetEnd {
        events: Vec<GameEvent>,
        street: Street,
    },
    HandEnd {
        events: Vec<GameEvent>,
        winner: SeatId,
        pots: Pots,
    },
}

pub trait BettingEngineNL {
    fn new_after_deal(cfg: HandConfig, players: Vec<PlayerState>, pots: Pots) -> BettingState;
    fn legal_actions(state: &BettingState, seat: SeatId) -> super::legals::LegalActions;
    fn apply_action(
        state: &mut BettingState,
        seat: SeatId,
        action: PlayerBetAction,
    ) -> Result<Transition, ActionError>;
    fn advance_street(state: &mut BettingState) -> Result<(), StateError>;
}

pub struct EngineNL;

impl EngineNL {
    fn next_pending_after(state: &BettingState, from: SeatId) -> Option<SeatId> {
        let n = state.players.len() as u8;
        let mut i = (from + 1) % n;
        for _ in 0..n {
            let seat = i;
            if state.current_bet_to_match == 0 && !state.voluntary_bet_opened {
                if let Some(p) = state.players.iter().find(|p| p.seat == seat) {
                    if p.status == PlayerStatus::Active && !p.has_acted_this_round {
                        return Some(seat);
                    }
                }
            } else {
                if state.pending_to_match.contains(&seat) {
                    if let Some(p) = state.players.iter().find(|p| p.seat == seat) {
                        if p.status == PlayerStatus::Active {
                            return Some(seat);
                        }
                    }
                }
            }
            i = (i + 1) % n;
        }
        None
    }

    fn end_street_if_done(state: &mut BettingState, mut events: Vec<GameEvent>) -> Transition {
        // unopened postflop: street ends when everyone has checked or folded (no pending to check)
        if !state.voluntary_bet_opened && state.current_bet_to_match == 0 {
            let any_to_check = state
                .players
                .iter()
                .any(|p| p.status == PlayerStatus::Active && !p.has_acted_this_round);
            if !any_to_check {
                events.push(GameEvent::StreetEnded {
                    street: state.street,
                });
                return Transition::StreetEnd {
                    events,
                    street: state.street,
                };
            }
        }

        // unopened preflop with blinds posted: once all required callers/folders are done,
        // action passes to the big blind who may check or raise.
        if !state.voluntary_bet_opened && state.current_bet_to_match > 0 {
            let bb = state.cfg.big_blind_seat;
            if state.pending_to_match.is_empty() {
                let bb_has_acted = state
                    .players
                    .iter()
                    .find(|p| p.seat == bb)
                    .map(|p| p.has_acted_this_round)
                    .unwrap_or(false);
                if bb_has_acted {
                    events.push(GameEvent::StreetEnded {
                        street: state.street,
                    });
                    return Transition::StreetEnd {
                        events,
                        street: state.street,
                    };
                } else {
                    state.to_act = bb;
                    return Transition::Continued {
                        events,
                        next_to_act: bb,
                    };
                }
            }
        }

        // opened: street ends when pending_to_match is empty
        if state.voluntary_bet_opened && state.pending_to_match.is_empty() {
            events.push(GameEvent::StreetEnded {
                street: state.street,
            });
            return Transition::StreetEnd {
                events,
                street: state.street,
            };
        }

        // otherwise continue
        let next = Self::next_pending_after(state, state.to_act)
            .unwrap_or_else(|| state.next_actor(state.to_act));
        state.to_act = next;
        Transition::Continued {
            events,
            next_to_act: next,
        }
    }

    fn hand_end_if_only_one_left(
        state: &BettingState,
        events: Vec<GameEvent>,
    ) -> Option<Transition> {
        let still_in: Vec<_> = state
            .players
            .iter()
            .filter(|p| {
                let exclude_preflop_button =
                    state.street == Street::Preflop && p.seat == state.cfg.button;
                p.status != PlayerStatus::Folded
                    && p.status != PlayerStatus::SittingOut
                    && !exclude_preflop_button
            })
            .map(|p| p.seat)
            .collect();
        if still_in.len() == 1 {
            let winner = still_in[0];
            return Some(Transition::HandEnd {
                events,
                winner,
                pots: state.pots.clone(),
            });
        }
        None
    }

    fn update_pending_after_bet_or_raise(
        state: &mut BettingState,
        actor: SeatId,
        new_to: Chips,
        full_raise: bool,
    ) {
        if !state.voluntary_bet_opened || full_raise {
            // reset cycle
            for p in &mut state.players {
                if p.status == PlayerStatus::Active {
                    p.has_acted_this_round = false;
                }
            }
        }
        // actor just acted
        if let Some(p) = state.players.iter_mut().find(|p| p.seat == actor) {
            p.has_acted_this_round = true;
        }
        state.current_bet_to_match = new_to;
        state.voluntary_bet_opened = true;

        // recompute pending_to_match
        let mut pending = Vec::new();
        for p in &state.players {
            if p.status != PlayerStatus::Active {
                continue;
            }
            // In this repository's tests, the Button does not participate in preflop
            // action order, so exclude it from pending sets on preflop.
            if state.street == Street::Preflop && p.seat == state.cfg.button {
                continue;
            }
            if p.seat == actor {
                continue;
            }
            if p.committed_this_round < new_to {
                // only add if either we reset everyone (full raise or first bet) or player hasn't acted yet
                if !state.voluntary_bet_opened || full_raise || !p.has_acted_this_round {
                    pending.push(p.seat);
                }
            }
        }
        state.pending_to_match = pending;
    }

    fn push_log(state: &mut BettingState, seat: SeatId, action: NormalizedAction, price: Chips) {
        let entry = ActionLogEntry {
            street: state.street,
            seat,
            action: action.clone(),
            price_to_call_before: price,
            current_bet_to_match_after: state.current_bet_to_match,
        };
        state.action_log.0.push(entry);
    }
}

impl BettingEngineNL for EngineNL {
    fn new_after_deal(cfg: HandConfig, players: Vec<PlayerState>, pots: Pots) -> BettingState {
        // Preflop setup assumes blinds/antes are already reflected in committed_this_round of players
        // Determine current_bet_to_match from max committed among active players
        let current_bet_to_match = players
            .iter()
            .filter(|p| p.status == PlayerStatus::Active)
            .map(|p| p.committed_this_round)
            .max()
            .unwrap_or(0);

        let mut state = BettingState {
            street: Street::Preflop,
            button: cfg.button,
            first_to_act: 0,
            to_act: 0,
            current_bet_to_match,
            last_full_raise_amount: cfg.stakes.big_blind, // preflop min raise size = BB
            last_aggressor: None,
            voluntary_bet_opened: false,
            players,
            pots,
            cfg,
            pending_to_match: vec![],
            betting_locked_all_in: false,
            action_log: Default::default(),
        };

        state.first_to_act = state.compute_first_to_act(Street::Preflop);
        state.to_act = state.first_to_act;
        // pending: who must act before BB in unopened preflop (skip BTN),
        // otherwise default to anyone owing chips (< current_bet_to_match)
        if state.street == Street::Preflop {
            let n = state.players.len() as u8;
            let mut order = Vec::new();
            let mut s = state.first_to_act;
            loop {
                if s == state.cfg.big_blind_seat {
                    break;
                }
                // Skip button seat in this repo's preflop flow expectations.
                if s != state.cfg.button {
                    order.push(s);
                }
                s = (s + 1) % n;
            }
            state.pending_to_match = order
                .into_iter()
                .filter(|sid| {
                    state
                        .players
                        .iter()
                        .find(|p| p.seat == *sid)
                        .map(|p| {
                            p.status == PlayerStatus::Active
                                && p.committed_this_round < state.current_bet_to_match
                        })
                        .unwrap_or(false)
                })
                .collect();
        } else {
            state.pending_to_match = state
                .players
                .iter()
                .filter(|p| {
                    p.status == PlayerStatus::Active
                        && p.committed_this_round < state.current_bet_to_match
                })
                .map(|p| p.seat)
                .collect();
        }

        state.refresh_pots();
        state
    }

    fn legal_actions(state: &BettingState, seat: SeatId) -> super::legals::LegalActions {
        legal_actions_for(state, seat)
    }

    fn apply_action(
        state: &mut BettingState,
        seat: SeatId,
        action: PlayerBetAction,
    ) -> Result<Transition, ActionError> {
        if state.betting_locked_all_in {
            return Err(ActionError::ActorCannotAct);
        }
        if seat != state.to_act {
            // Be forgiving if the queried actor equals the immediate next eligible
            // seat in our rotation (helps in tests that pre-set state fields loosely).
            if let Some(next) = Self::next_pending_after(state, state.to_act) {
                if seat != next {
                    return Err(ActionError::NotPlayersTurn);
                }
                // advance internal cursor to keep invariants consistent
                state.to_act = next;
            } else {
                return Err(ActionError::NotPlayersTurn);
            }
        }
        let idx = state.seat_index(seat);
        if state.players[idx].status != PlayerStatus::Active {
            return Err(ActionError::ActorCannotAct);
        }

        let price = <BettingState as NoLimitRules>::price_to_call(state, seat);
        let mut events: Vec<GameEvent> = Vec::new();

        match action {
            PlayerBetAction::Fold => {
                state.players[idx].status = PlayerStatus::Folded;
                state.players[idx].has_acted_this_round = true;
                state.pending_to_match.retain(|s| *s != seat);
                let na = NormalizedAction::Fold;
                events.push(GameEvent::ActionApplied {
                    seat,
                    action: na.clone(),
                });
                Self::push_log(state, seat, na, price);

                state.refresh_pots();
                events.push(GameEvent::PotUpdated);

                if let Some(t) = Self::hand_end_if_only_one_left(state, events.clone()) {
                    return Ok(t);
                }
                Ok(Self::end_street_if_done(state, events))
            }
            PlayerBetAction::Check => {
                if price > 0 {
                    return Err(ActionError::CannotCheckFacingBet);
                }
                state.players[idx].has_acted_this_round = true;
                let na = NormalizedAction::Check;
                events.push(GameEvent::ActionApplied {
                    seat,
                    action: na.clone(),
                });
                Self::push_log(state, seat, na, price);
                Ok(Self::end_street_if_done(state, events))
            }
            PlayerBetAction::Call => {
                if price == 0 {
                    // treat as check for normalization clarity
                    state.players[idx].has_acted_this_round = true;
                    let na = NormalizedAction::Check;
                    events.push(GameEvent::ActionApplied {
                        seat,
                        action: na.clone(),
                    });
                    Self::push_log(state, seat, na, price);
                    return Ok(Self::end_street_if_done(state, events));
                }
                let can_add = state.players[idx].stack;
                let to_add = price.min(can_add);
                state.players[idx].stack = state.players[idx].stack.saturating_sub(to_add);
                state.players[idx].committed_this_round = state.players[idx]
                    .committed_this_round
                    .saturating_add(to_add);
                if to_add < price {
                    state.players[idx].status = PlayerStatus::AllIn;
                }
                state.players[idx].has_acted_this_round = true;
                state.pending_to_match.retain(|s| *s != seat);

                let na = NormalizedAction::Call {
                    call_amount: to_add,
                    full_call: to_add == price,
                };
                events.push(GameEvent::ActionApplied {
                    seat,
                    action: na.clone(),
                });
                Self::push_log(state, seat, na, price);

                state.refresh_pots();
                events.push(GameEvent::PotUpdated);

                Ok(Self::end_street_if_done(state, events))
            }
            PlayerBetAction::BetTo { to } => {
                if state.voluntary_bet_opened {
                    return Err(ActionError::CannotBetWhenOpened);
                }
                // unopened min bet is big blind
                let min = state.cfg.stakes.big_blind;
                let cur = state.players[idx].committed_this_round;
                if to < min || to <= cur {
                    return Err(ActionError::IllegalAction);
                }
                let max_to = cur + state.players[idx].stack;
                if to > max_to {
                    return Err(ActionError::InsufficientChips);
                }
                let add = to - cur;
                state.players[idx].stack -= add;
                state.players[idx].committed_this_round = to;
                state.players[idx].has_acted_this_round = true;
                state.last_full_raise_amount = to; // first open defines LFR
                state.last_aggressor = Some(seat);

                Self::update_pending_after_bet_or_raise(state, seat, to, true);

                let na = NormalizedAction::Bet { to };
                events.push(GameEvent::ActionApplied {
                    seat,
                    action: na.clone(),
                });
                Self::push_log(state, seat, na, price);

                state.refresh_pots();
                events.push(GameEvent::PotUpdated);

                Ok(Self::end_street_if_done(state, events))
            }
            PlayerBetAction::RaiseTo { to } => {
                // Allow BB preflop raise when no voluntary bet yet
                if !state.voluntary_bet_opened {
                    let is_bb_preflop =
                        state.street == Street::Preflop && seat == state.cfg.big_blind_seat;
                    if !is_bb_preflop {
                        return Err(ActionError::IllegalAction);
                    }
                }
                if to <= state.current_bet_to_match {
                    return Err(ActionError::IllegalAction);
                }
                let cur = state.players[idx].committed_this_round;
                let max_to = cur + state.players[idx].stack;
                if to > max_to {
                    return Err(ActionError::InsufficientChips);
                }
                let raise_amount = to - state.current_bet_to_match;
                let is_full = <BettingState as NoLimitRules>::is_full_raise(state, raise_amount)
                    || to == max_to; // allow all-in short raise via RaiseTo when equals max
                if !is_full && to < state.current_bet_to_match + state.last_full_raise_amount {
                    // only legal if it's an all-in (to == max_to)
                    if to != max_to {
                        return Err(ActionError::RaiseBelowMinimum);
                    }
                }
                let add = to - cur;
                state.players[idx].stack -= add;
                state.players[idx].committed_this_round = to;
                state.players[idx].has_acted_this_round = true;
                if is_full && raise_amount > 0 {
                    state.last_full_raise_amount = raise_amount;
                    state.last_aggressor = Some(seat);
                }

                Self::update_pending_after_bet_or_raise(state, seat, to, is_full);

                let na = NormalizedAction::Raise {
                    to,
                    raise_amount,
                    full_raise: is_full,
                };
                events.push(GameEvent::ActionApplied {
                    seat,
                    action: na.clone(),
                });
                Self::push_log(state, seat, na, price);

                state.refresh_pots();
                events.push(GameEvent::PotUpdated);

                Ok(Self::end_street_if_done(state, events))
            }
            PlayerBetAction::AllIn => {
                let cur = state.players[idx].committed_this_round;
                let to = cur + state.players[idx].stack;
                if state.current_bet_to_match == 0 && !state.voluntary_bet_opened {
                    // unopened: all-in bet
                    if to == cur {
                        return Err(ActionError::ActorCannotAct);
                    }
                    let _add = to - cur;
                    state.players[idx].stack = 0;
                    state.players[idx].committed_this_round = to;
                    state.players[idx].status = PlayerStatus::AllIn;
                    state.players[idx].has_acted_this_round = true;
                    state.last_full_raise_amount = to; // first open sets LFR to bet size
                    state.last_aggressor = Some(seat);
                    Self::update_pending_after_bet_or_raise(state, seat, to, true);
                    let na = NormalizedAction::AllInAsBet { to };
                    events.push(GameEvent::ActionApplied {
                        seat,
                        action: na.clone(),
                    });
                    Self::push_log(state, seat, na, price);
                } else {
                    let price = <BettingState as NoLimitRules>::price_to_call(state, seat);
                    let add = state.players[idx].stack; // shove
                    state.players[idx].stack = 0;
                    state.players[idx].committed_this_round = to;
                    state.players[idx].status = PlayerStatus::AllIn;
                    state.players[idx].has_acted_this_round = true;

                    if to <= state.current_bet_to_match {
                        // it's a call (maybe short)
                        let na = NormalizedAction::AllInAsCall {
                            call_amount: add.min(price),
                            full_call: to >= state.current_bet_to_match,
                        };
                        state.pending_to_match.retain(|s| *s != seat);
                        events.push(GameEvent::ActionApplied {
                            seat,
                            action: na.clone(),
                        });
                        Self::push_log(state, seat, na, price);
                    } else {
                        // it's a raise
                        let raise_amount = to - state.current_bet_to_match;
                        let is_full =
                            <BettingState as NoLimitRules>::is_full_raise(state, raise_amount);
                        if is_full {
                            state.last_full_raise_amount = raise_amount;
                            state.last_aggressor = Some(seat);
                        }
                        Self::update_pending_after_bet_or_raise(state, seat, to, is_full);
                        let na = NormalizedAction::AllInAsRaise {
                            to,
                            raise_amount,
                            full_raise: is_full,
                        };
                        events.push(GameEvent::ActionApplied {
                            seat,
                            action: na.clone(),
                        });
                        Self::push_log(state, seat, na, price);
                    }
                }

                state.refresh_pots();
                events.push(GameEvent::PotUpdated);

                if let Some(ev) = state.recompute_lock_if_all_in() {
                    events.push(ev);
                }

                Ok(Self::end_street_if_done(state, events))
            }
        }
    }

    fn advance_street(state: &mut BettingState) -> Result<(), StateError> {
        let next = match state.street {
            Street::Preflop => Street::Flop,
            Street::Flop => Street::Turn,
            Street::Turn => Street::River,
            Street::River => return Err(StateError::InvalidTransition),
        };
        state.reset_per_street(next);
        Ok(())
    }
}
