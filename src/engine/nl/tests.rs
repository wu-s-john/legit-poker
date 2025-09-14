#![cfg(test)]

use crate::engine::nl::{BettingState, InvariantCheck};

use super::engine::{BettingEngineNL, EngineNL, Transition};
use super::events::GameEvent;
use super::types::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn stakes(sb: Chips, bb: Chips) -> TableStakes {
    TableStakes {
        small_blind: sb,
        big_blind: bb,
        ante: 0,
    }
}

fn cfg_6max(sb: Chips, bb: Chips) -> HandConfig {
    HandConfig {
        stakes: stakes(sb, bb),
        button: 0,
        small_blind_seat: 1,
        big_blind_seat: 2,
        check_raise_allowed: true,
    }
}

fn player_active(seat: SeatId, stack: Chips, committed: Chips) -> PlayerState {
    PlayerState {
        seat,
        player_id: None,
        stack,
        committed_this_round: committed,
        committed_total: 0,
        status: PlayerStatus::Active,
        has_acted_this_round: false,
    }
}

fn empty_pots() -> Pots {
    Pots {
        main: Pot {
            amount: 0,
            eligible: vec![],
        },
        sides: vec![],
    }
}

fn setup_preflop_6max(default_stack: Chips, sb: Chips, bb: Chips) -> BettingState {
    // seats: BTN=0, SB=1, BB=2, UTG=3, HJ=4, CO=5
    let cfg = cfg_6max(sb, bb);
    let mut players = vec![
        player_active(0, default_stack, 0),       // BTN
        player_active(1, default_stack - sb, sb), // SB posted
        player_active(2, default_stack - bb, bb), // BB posted
        player_active(3, default_stack, 0),       // UTG
        player_active(4, default_stack, 0),       // HJ
        player_active(5, default_stack, 0),       // CO
    ];
    EngineNL::new_after_deal(cfg, players.drain(..).collect(), empty_pots())
}

#[test]
fn preflop_action_starts_left_of_bb_bb_has_option_to_check_if_unraised() {
    // RATIONALE: action starts left of BB; BB may check if unraised.
    let mut st = setup_preflop_6max(300, 1, 3);
    assert_eq!(st.first_to_act, 3); // UTG
    assert_eq!(st.to_act, 3);

    // Seat 3 calls (pays 3)
    let t = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
    match t {
        Transition::Continued { next_to_act, .. } => assert_eq!(next_to_act, 4),
        _ => panic!("expected continued"),
    }
    // Seat 4 folds
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    // Seat 5 calls
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    // Seat 1 (SB) completes
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Call).unwrap();

    // BB options include Check (no voluntary bet yet). Also may RaiseTo, not BetTo.
    let legals = EngineNL::legal_actions(&st, 2);
    assert!(legals.may_check);
    assert!(legals.bet_to_range.is_none());
    assert!(legals.raise_to_range.is_some());

    let t = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Check).unwrap();
    match t {
        Transition::StreetEnd { street, .. } => assert_eq!(street, Street::Preflop),
        _ => panic!("expected street end"),
    }
}

#[test]
fn postflop_action_starts_left_of_button() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // Close preflop cheaply: everyone checks/calls to BB like above
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Check).unwrap();
    // Outer game deals flop, then advance_street
    super::engine::EngineNL::advance_street(&mut st).unwrap();
    assert_eq!(st.street, Street::Flop);
    assert_eq!(st.first_to_act, 1); // left of BTN=0
    assert_eq!(st.to_act, 1);
}

#[test]
fn unopened_min_bet_equals_big_blind() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // Fast-forward to flop with no betting
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Check).unwrap();
    super::engine::EngineNL::advance_street(&mut st).unwrap();
    // Flop unopened; first to act is seat 1
    let legals = EngineNL::legal_actions(&st, 1);
    let range = legals.bet_to_range.expect("unopened bet range");
    assert_eq!(*range.start(), 3);
}

#[test]
fn preflop_short_big_blind_with_2_on_bb_3_can_only_check() {
    // BB seat has only 2 chips total while BB is 3. They post 2 and have 0 behind.
    // We verify that when action returns to the BB (unopened preflop), they can only Check.
    let cfg = cfg_6max(1, 3);
    let mut players = vec![
        player_active(0, 100, 0), // BTN
        player_active(1, 99, 1),  // SB posted 1
        PlayerState {
            seat: 2, // BB posted only 2 (short)
            player_id: None,
            stack: 0,                // 0 behind
            committed_this_round: 2, // posted 2 total
            committed_total: 0,
            status: PlayerStatus::Active, // still acts preflop
            has_acted_this_round: false,
        },
        player_active(3, 100, 0), // UTG
        player_active(4, 100, 0), // HJ
        player_active(5, 100, 0), // CO
    ];
    let mut st = EngineNL::new_after_deal(cfg, players.drain(..).collect(), empty_pots());

    // With a short BB post, the current bet to match equals the posted amount (2)
    assert_eq!(st.current_bet_to_match, 2);
    assert_eq!(st.first_to_act, 3);
    assert_eq!(st.to_act, 3);

    // Bring action back to BB: UTG calls 2, HJ folds, CO calls, SB completes to 2
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    let tr = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Call).unwrap();
    match tr {
        Transition::Continued { next_to_act, .. } => assert_eq!(next_to_act, 2),
        _ => panic!("expected action to pass to BB"),
    }

    // Legal actions for the short BB: may Check, cannot Fold (price=0), no Bet, no Raise
    let legals_bb = EngineNL::legal_actions(&st, 2);
    assert_eq!(legals_bb.call_amount, Some(0));
    assert!(legals_bb.may_check);
    assert!(!legals_bb.may_fold);
    assert!(legals_bb.bet_to_range.is_none());
    assert!(legals_bb.raise_to_range.is_none());

    // Demonstrate the only action: BB checks and the street should end
    let tr2 = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Check).unwrap();
    match tr2 {
        Transition::StreetEnd { street, .. } => assert_eq!(street, Street::Preflop),
        _ => panic!("expected preflop street to end after BB check"),
    }
}

#[test]
fn min_raise_equals_last_full_raise_amount_and_updates_on_full_raises() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // UTG opens (first voluntary bet) to 7 using BetTo
    let t =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    // Next actor seat 4
    match t {
        Transition::Continued { next_to_act, .. } => assert_eq!(next_to_act, 4),
        _ => panic!("expected continued"),
    }
    // LFR should be 7 after first open
    assert_eq!(st.last_full_raise_amount, 7);
    // Min next raise-to should be 14
    let legals = EngineNL::legal_actions(&st, 4);
    let raise_range = legals.raise_to_range.expect("raise range");
    assert_eq!(*raise_range.start(), 14);

    // Seat 4 raises to 25 (full raise by 18)
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::RaiseTo { to: 25 })
        .unwrap();
    assert_eq!(st.last_full_raise_amount, 18);
    // Next min raise-to should be 43 (25 + 18)
    // Query for seat 5
    let legals = EngineNL::legal_actions(&st, 5);
    let raise_range = legals.raise_to_range.expect("raise range");
    assert_eq!(*raise_range.start(), 43);
}

#[test]
fn short_all_in_raise_does_not_update_lfr_or_reopen_action() {
    let mut st = setup_preflop_6max(20, 1, 3);
    // Seat 4 has small stack to create short all-in
    st.players[4] = player_active(4, 5, 0); // 5 behind only
                                            // UTG (3) opens to 7
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    let lfr_after_open = st.last_full_raise_amount;
    assert_eq!(lfr_after_open, 7);
    // Seat 4 shoves all-in to 5 total (actually cannot exceed 5); since committed is 0, AllIn is a bet -> we need it to be a raise: make them call first then shove? Adjust: give them 10 behind and do all-in to 12
    st.players[4].stack = 10; // now can all-in to 10
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::AllIn).unwrap();
    // Now current_bet_to_match should be 10; raise amount = 3 short (<7) so LFR unchanged
    assert_eq!(st.last_full_raise_amount, 7);
    // Original raiser (3) should not be reopened solely due to short raise; Since seat 3 already acted, they should not be in pending_to_match unless a full raise occurred
    assert!(!st.pending_to_match.contains(&3));
}

#[test]
fn full_raise_reopens_action_to_prior_players() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // UTG opens to 7
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    // MP (4) raises to 14 (full raise 7)
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::RaiseTo { to: 14 })
        .unwrap();
    // Original opener 3 should be pending again
    assert!(st.pending_to_match.contains(&3));
}

#[test]
fn cannot_check_when_facing_bet() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // UTG opens to 7
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    // Seat 4 attempting to Check should error
    let err = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Check).unwrap_err();
    assert_eq!(
        format!("{:?}", err),
        format!("{:?}", super::errors::ActionError::CannotCheckFacingBet)
    );
}

#[test]
fn cannot_bet_when_betting_is_already_opened() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // UTG opens to 7 (BetTo is ok because no voluntary bet yet)
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    // Now seat 4 cannot BetTo again
    let err = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::BetTo { to: 20 })
        .unwrap_err();
    assert_eq!(
        format!("{:?}", err),
        format!("{:?}", super::errors::ActionError::CannotBetWhenOpened)
    );
}

#[test]
fn short_call_sets_player_all_in_and_keeps_action_live_for_others() {
    let mut st = setup_preflop_6max(100, 1, 3);
    // UTG opens to 100
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 100 })
        .unwrap();
    // Seat 4 has only 60 to call -> short call leads to all-in and others must still act
    st.players[4].stack = 60;
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Call).unwrap();
    assert_eq!(st.players[4].status, PlayerStatus::AllIn);
    // Others (5,1,2) should still be pending if below 100
    for sid in [5u8, 1u8, 2u8] {
        if let Some(p) = st.players.iter().find(|p| p.seat == sid) {
            if p.committed_this_round < 100 && p.status == PlayerStatus::Active {
                assert!(st.pending_to_match.contains(&sid));
            }
        }
    }
}

#[test]
fn all_players_all_in_locks_betting_and_emits_event() {
    let mut st = setup_preflop_6max(50, 1, 3);
    // Force everyone to go all-in by successive shoves
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::AllIn).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::AllIn).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::AllIn).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::AllIn).unwrap();
    let tr = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::AllIn).unwrap();
    match tr {
        Transition::Continued { events, .. }
        | Transition::StreetEnd { events, .. }
        | Transition::HandEnd { events, .. } => {
            assert!(events
                .iter()
                .any(|e| matches!(e, GameEvent::AllPlayersAllIn)))
        }
    }
    assert!(st.betting_locked_all_in);
}

#[test]
fn single_side_pot_two_all_ins_different_sizes() {
    // Three players only for clarity: seats 3(A),4(B),5(C). Others fold out.
    let mut st = setup_preflop_6max(200, 1, 3);
    // Make only 3 players active
    for sid in [0u8, 1u8, 2u8] {
        // fold BTN, SB, BB for test simplicity
        let idx = st.players.iter().position(|p| p.seat == sid).unwrap();
        st.players[idx].status = PlayerStatus::Folded;
    }
    st.first_to_act = 3;
    st.to_act = 3;
    st.pending_to_match = vec![3, 4, 5];
    st.current_bet_to_match = 0;
    st.voluntary_bet_opened = false;

    // B (seat 4) bets to 100
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::BetTo { to: 100 })
        .unwrap();
    // A (seat 3) short-calls all-in to 30
    st.players.iter_mut().find(|p| p.seat == 3).unwrap().stack = 30;
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::AllIn).unwrap();
    // C (seat 5) calls full 100
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();

    // Compute pots
    let pots = &st.pots;
    // main: 30 from each of A,B,C = 90
    assert_eq!(pots.main.amount, 90);
    assert!(
        pots.main.eligible.contains(&3)
            && pots.main.eligible.contains(&4)
            && pots.main.eligible.contains(&5)
    );
    // side1: remaining 70 from B and C = 140; eligible B,C only
    assert_eq!(pots.sides[0].amount, 140);
    assert!(pots.sides[0].eligible.contains(&4) && pots.sides[0].eligible.contains(&5));
    assert!(!pots.sides[0].eligible.contains(&3));
}

#[test]
fn multiple_side_pots_three_all_ins() {
    // Four players A=3, B=4, C=5, D=1 with different stacks
    let mut st = setup_preflop_6max(200, 1, 3);
    // Fold out others except these four
    for sid in [0u8, 2u8] {
        let idx = st.players.iter().position(|p| p.seat == sid).unwrap();
        st.players[idx].status = PlayerStatus::Folded;
    }
    // Set effective all-ins
    st.players.iter_mut().find(|p| p.seat == 3).unwrap().stack = 20; // A
    st.players.iter_mut().find(|p| p.seat == 4).unwrap().stack = 50; // B
    st.players.iter_mut().find(|p| p.seat == 5).unwrap().stack = 120; // C
    st.players.iter_mut().find(|p| p.seat == 1).unwrap().stack = 120; // D (SB)
                                                                      // Reset street to unopened postflop-like
    st.current_bet_to_match = 0;
    st.voluntary_bet_opened = false;
    st.first_to_act = 3;
    st.to_act = 3;
    st.pending_to_match = vec![3, 4, 5, 1];

    // Everyone goes all-in
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::AllIn).unwrap(); // to 20
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::AllIn).unwrap(); // to 50
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::AllIn).unwrap(); // to 120
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::AllIn).unwrap(); // to 120

    // Expect pots: main 4*20=80; side1 (B,C,D) 30*3=90; side2 (C,D) 70*2=140
    assert_eq!(st.pots.main.amount, 80);
    assert_eq!(st.pots.sides[0].amount, 90);
    assert_eq!(st.pots.sides[1].amount, 140);
}

#[test]
fn folded_players_not_eligible_for_any_pot() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // Someone folds after contributing
    let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    // Folded seat 4 must not be present in eligibility sets
    assert!(!st.pots.main.eligible.contains(&4));
    assert!(st.pots.sides.iter().all(|p| !p.eligible.contains(&4)));
}

#[test]
fn street_ends_when_all_active_non_all_in_players_have_matched_or_folded() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // UTG opens to 9; others fold/call such that pending empties
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 9 }).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Fold).unwrap();
    // BB faces 6 more (9-3) and calls
    let tr = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Call).unwrap();
    match tr {
        Transition::StreetEnd { street, .. } => assert_eq!(street, Street::Preflop),
        _ => panic!("expected street end"),
    }
}

#[test]
fn hand_ends_immediately_when_only_one_player_remains_active() {
    let mut st = setup_preflop_6max(300, 1, 3);
    // Everyone folds to UTG
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 7 }).unwrap();
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Fold).unwrap();
    let tr = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Fold).unwrap();
    match tr {
        Transition::HandEnd { winner, .. } => assert_eq!(winner, 3),
        _ => panic!("expected hand end by folds"),
    }
}

// #[test]
// fn legal_actions_reflect_unopened_vs_opened_state_and_stack_bounds() {
//     let mut st = setup_preflop_6max(50, 1, 3);
//     // Postflop scenario for unopened
//     // Close preflop
//     let _ = EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::Call).unwrap();
//     let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::Call).unwrap();
//     let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
//     let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Call).unwrap();
//     let _ = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Check).unwrap();
//     super::engine::EngineNL::advance_street(&mut st).unwrap();

//     // Unopened: bet_to_range present
//     let legals = EngineNL::legal_actions(&st, st.first_to_act);
//     assert!(legals.bet_to_range.is_some());
//     assert!(legals.raise_to_range.is_none());

//     // Opened after a bet: raise_to_range present
//     let _ = EngineNL::apply_action(
//         &mut st,
//         st.first_to_act,
//         super::actions::PlayerAction::BetTo { to: 10 },
//     )
//     .unwrap();
//     let next = st.to_act;
//     let legals2 = EngineNL::legal_actions(&st, next);
//     assert!(legals2.bet_to_range.is_none());
//     assert!(legals2.raise_to_range.is_some());
// }

#[test]
fn invariants_hold_after_complex_sequences_with_side_pots() {
    let mut st = setup_preflop_6max(200, 1, 3);
    // Complex preflop sequence: open, short all-in, call, fold
    let _ =
        EngineNL::apply_action(&mut st, 3, super::actions::PlayerAction::BetTo { to: 20 }).unwrap();
    st.players.iter_mut().find(|p| p.seat == 4).unwrap().stack = 5;
    let _ = EngineNL::apply_action(&mut st, 4, super::actions::PlayerAction::AllIn).unwrap(); // short raise 5
    let _ = EngineNL::apply_action(&mut st, 5, super::actions::PlayerAction::Call).unwrap();
    let _ = EngineNL::apply_action(&mut st, 1, super::actions::PlayerAction::Fold).unwrap();
    let _ = EngineNL::apply_action(&mut st, 2, super::actions::PlayerAction::Call).unwrap();
    // Validate invariants
    super::state::BettingState::validate_invariants(&st).unwrap();
}

#[test]
fn e2e_random_full_hand_to_river() {
    // Deterministic RNG for reproducibility
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    // 6-max setup with blinds posted
    let mut st = setup_preflop_6max(300, 1, 3);

    // Run through all streets until we finish river (or earlier all-in lock or folds)
    // We avoid explicit folds to ensure we reach river; actions are random but legal.
    let mut steps = 0usize;
    loop {
        steps += 1;
        assert!(steps < 500, "too many steps without finishing");

        // If everyone relevant is all-in, just advance directly to river
        if st.betting_locked_all_in {
            while st.street != Street::River {
                super::engine::EngineNL::advance_street(&mut st).unwrap();
            }
            break;
        }

        let actor = st.to_act;
        let legals = EngineNL::legal_actions(&st, actor);

        // Build a random legal action set (exclude Fold to keep hand alive)
        let mut options: Vec<super::actions::PlayerAction> = Vec::new();

        if let Some(price) = legals.call_amount {
            if price == 0 {
                // Prefer checks postflop when unopened
                for _ in 0..3 {
                    options.push(super::actions::PlayerAction::Check);
                }
            } else {
                // Prefer calling to keep action moving
                for _ in 0..3 {
                    options.push(super::actions::PlayerAction::Call);
                }
            }
        }

        if let Some(range) = legals.bet_to_range.clone() {
            let start = *range.start();
            let end = *range.end();
            if start <= end {
                // Pick a random amount in range
                let to = if start == end {
                    start
                } else {
                    rng.gen_range(start..=end)
                };
                options.push(super::actions::PlayerAction::BetTo { to });
            }
        }

        if let Some(range) = legals.raise_to_range.clone() {
            let start = *range.start();
            let end = *range.end();
            if start <= end {
                // Bias slightly towards min-raise to avoid huge jumps
                let to = if start == end {
                    start
                } else if rng.gen_ratio(3, 4) {
                    start
                } else {
                    rng.gen_range(start..=end)
                };
                options.push(super::actions::PlayerAction::RaiseTo { to });
            }
        }

        // Occasionally allow an all-in shove (legal; engine will normalize) if chips remain
        let actor_idx = st.players.iter().position(|p| p.seat == actor).unwrap();
        if st.players[actor_idx].stack > 0 && rng.gen_ratio(1, 8) {
            options.push(super::actions::PlayerAction::AllIn);
        }

        // Fallback if somehow no options were populated
        if options.is_empty() {
            if let Some(price) = legals.call_amount {
                if price == 0 {
                    options.push(super::actions::PlayerAction::Check);
                } else {
                    options.push(super::actions::PlayerAction::Call);
                }
            } else if st.players[actor_idx].stack > 0 {
                options.push(super::actions::PlayerAction::AllIn);
            } else {
                // If still empty, advance to the next active actor and retry this loop iteration.
                let n = st.players.len() as u8;
                let mut s = (actor + 1) % n;
                for _ in 0..n {
                    if let Some(p) = st.players.iter().find(|p| p.seat == s) {
                        if p.status == PlayerStatus::Active {
                            st.to_act = s;
                            break;
                        }
                    }
                    s = (s + 1) % n;
                }
                continue;
            }
        }

        let idx = rng.gen_range(0..options.len());
        let action = options[idx].clone();

        let tr = EngineNL::apply_action(&mut st, actor, action).unwrap();

        match tr {
            Transition::Continued { .. } => {}
            Transition::StreetEnd { street, .. } => {
                if street == Street::River {
                    break;
                } else {
                    super::engine::EngineNL::advance_street(&mut st).unwrap();
                }
            }
            Transition::HandEnd { .. } => {
                // Hand ended by folds — acceptable, but we want to still complete streets.
                // For the purpose of this e2e test, just finish here.
                break;
            }
        }
    }

    // Final sanity checks
    super::state::BettingState::validate_invariants(&st).unwrap();
}
