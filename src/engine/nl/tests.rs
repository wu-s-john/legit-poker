#[cfg(test)]
mod nl_betting_tests {
    use crate::engine::nl::*;

    fn setup_cfg() -> HandConfig {
        HandConfig {
            stakes: TableStakes { small_blind: 1, big_blind: 3, ante: 0 },
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        }
    }

    fn setup_players(stacks: &[Chips]) -> Vec<PlayerState> {
        let mut players = Vec::new();
        for (i, &stack) in stacks.iter().enumerate() {
            let mut p = PlayerState::new(i as SeatId, stack);
            // post blinds
            if i == 1 { // SB
                p.stack -= 1;
                p.committed_this_round = 1;
                p.committed_total = 1;
            } else if i == 2 { // BB
                p.stack -= 3;
                p.committed_this_round = 3;
                p.committed_total = 3;
            }
            players.push(p);
        }
        players
    }

    // ---------- Order & blinds ----------

    #[test]
    fn preflop_action_starts_left_of_bb_bb_has_option_to_check_if_unraised() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        assert_eq!(state.first_to_act, 3); // UTG
        assert_eq!(state.to_act, 3);

        // UTG call, HJ fold, CO call, SB call -> BB should act last and may check
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        let t = BettingEngine::apply_action(&mut state, 1, PlayerAction::Call).unwrap();
        match t {
            Transition::Continued{next_to_act, ..} => assert_eq!(next_to_act, 2),
            _ => panic!(),
        }
        let legals_bb = BettingEngine::legal_actions(&state, 2);
        assert!(legals_bb.may_check);
        let t = BettingEngine::apply_action(&mut state, 2, PlayerAction::Check).unwrap();
        match t {
            Transition::StreetEnd{street, ..} => assert_eq!(street, Street::Preflop),
            _ => panic!(),
        }
    }

    #[test]
    fn postflop_action_starts_left_of_button() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // finish preflop by letting everyone check/call
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 2, PlayerAction::Check).unwrap();
        BettingEngine::advance_street(&mut state).unwrap();
        assert_eq!(state.street, Street::Flop);
        assert_eq!(state.first_to_act, 1); // left of button
        assert_eq!(state.to_act, 1);
    }

    // ---------- Unopened min bet & opened min raise ----------

    #[test]
    fn unopened_min_bet_equals_big_blind() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // play preflop to next street quickly
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 2, PlayerAction::Check).unwrap();
        BettingEngine::advance_street(&mut state).unwrap();
        let legals = BettingEngine::legal_actions(&state, state.to_act);
        assert_eq!(legals.bet_to_range.unwrap().start().clone(), cfg.stakes.big_blind);
    }

    #[test]
    fn min_raise_equals_last_full_raise_amount_and_updates_on_full_raises() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // UTG open to 7
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        // MP (seat4) raise to 25
        BettingEngine::apply_action(&mut state, 4, PlayerAction::RaiseTo{to:25}).unwrap();
        // check next actor min raise
        let legals = BettingEngine::legal_actions(&state, 5);
        assert_eq!(*legals.raise_to_range.as_ref().unwrap().start(), 25 + 18); // LFR=18
    }

    #[test]
    fn short_all_in_raise_does_not_update_lfr_or_reopen_action() {
        let cfg = setup_cfg();
        // make player seat4 short stack 12 total
        let mut stacks = [200;6]; stacks[4]=12; // seat4 MP short
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        // seat4 all-in (RaiseTo not allowed; use AllIn)
        BettingEngine::apply_action(&mut state, 4, PlayerAction::AllIn).unwrap();
        // others call
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 2, PlayerAction::Call).unwrap();
        // back to UTG
        let legals = BettingEngine::legal_actions(&state, 3);
        assert!(legals.raise_to_range.is_none());
        assert_eq!(state.last_full_raise_amount, 7);
    }

    #[test]
    fn full_raise_reopens_action_to_prior_players() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::RaiseTo{to:14}).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 2, PlayerAction::Call).unwrap();
        let legals = BettingEngine::legal_actions(&state, 3);
        assert!(legals.raise_to_range.is_some());
    }

    // ---------- Call / Check legality ----------

    #[test]
    fn cannot_check_when_facing_bet() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        let err = BettingEngine::apply_action(&mut state, 4, PlayerAction::Check).unwrap_err();
        assert_eq!(err, ActionError::CannotCheckFacingBet);
    }

    #[test]
    fn cannot_bet_when_betting_is_already_opened() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        let err = BettingEngine::apply_action(&mut state, 4, PlayerAction::BetTo{to:10}).unwrap_err();
        assert_eq!(err, ActionError::CannotBetWhenOpened);
    }

    // ---------- All-in semantics ----------

    #[test]
    fn short_call_sets_player_all_in_and_keeps_action_live_for_others() {
        let cfg = setup_cfg();
        let mut stacks = [200;6]; stacks[3]=60; // UTG 60
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // someone bets 100
        BettingEngine::apply_action(&mut state, 4, PlayerAction::RaiseTo{to:100}).unwrap();
        // UTG short call
        let t = BettingEngine::apply_action(&mut state, 3, PlayerAction::Call).unwrap();
        assert_eq!(state.player(3).status, PlayerStatus::AllIn);
        match t { Transition::Continued{..} => (), _ => panic!() }
    }

    #[test]
    fn all_players_all_in_locks_betting_and_emits_event() {
        let cfg = setup_cfg();
        let mut stacks = [200;6];
        stacks[3]=50; stacks[4]=50; stacks[5]=50; // make three short
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::AllIn).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::AllIn).unwrap();
        let tr = BettingEngine::apply_action(&mut state, 5, PlayerAction::AllIn).unwrap();
        match tr {
            Transition::StreetEnd{events, ..} => {
                assert!(events.iter().any(|e| matches!(e, GameEvent::AllPlayersAllIn)));
            }
            _ => panic!(),
        }
        assert!(state.betting_locked_all_in);
    }

    // ---------- Side pots ----------

    #[test]
    fn single_side_pot_two_all_ins_different_sizes() {
        let cfg = setup_cfg();
        let mut stacks = [200;6];
        stacks[3]=30; // A
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 4, PlayerAction::RaiseTo{to:100}).unwrap(); // B bet
        BettingEngine::apply_action(&mut state, 3, PlayerAction::AllIn).unwrap(); // A call all-in 30
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap(); // C call 100
        assert_eq!(state.pots.main.amount, 90); // 30 each from A,B,C
        assert_eq!(state.pots.sides[0].amount, 140); // remaining 70 from B and C
        assert_eq!(state.pots.sides[0].eligible.len(),2);
    }

    #[test]
    fn multiple_side_pots_three_all_ins() {
        let cfg = setup_cfg();
        let mut stacks = [200;6];
        stacks[3]=20; stacks[4]=50; stacks[5]=120; stacks[1]=120; // A,B,C,D
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // Everyone all-in preflop
        BettingEngine::apply_action(&mut state, 3, PlayerAction::AllIn).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::AllIn).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::AllIn).unwrap();
        let tr = BettingEngine::apply_action(&mut state, 1, PlayerAction::AllIn).unwrap();
        match tr { Transition::StreetEnd{..} => (), _=>panic!() }
        assert_eq!(state.pots.main.amount, 80); // 4*20
        assert_eq!(state.pots.sides.len(),2);
    }

    #[test]
    fn folded_players_not_eligible_for_any_pot() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Fold).unwrap();
        assert!(state.pots.main.eligible.iter().all(|&s| s != 3));
    }

    // ---------- Round/hand termination ----------

    #[test]
    fn street_ends_when_all_active_non_all_in_players_have_matched_or_folded() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // everyone call
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Call).unwrap();
        let tr = BettingEngine::apply_action(&mut state, 2, PlayerAction::Check).unwrap();
        match tr { Transition::StreetEnd{street, ..} => assert_eq!(street, Street::Preflop), _=>panic!() }
    }

    #[test]
    fn hand_ends_immediately_when_only_one_player_remains_active() {
        let cfg = setup_cfg();
        let players = setup_players(&[200;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Fold).unwrap();
        let tr = BettingEngine::apply_action(&mut state, 2, PlayerAction::Fold).unwrap();
        match tr { Transition::HandEnd{winner, ..} => assert_eq!(winner, 0), _=>panic!() }
    }

    // ---------- Legal actions view ----------

    #[test]
    fn legal_actions_reflect_unopened_vs_opened_state_and_stack_bounds() {
        let cfg = setup_cfg();
        let players = setup_players(&[50;6]);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        // unopened
        let legals = BettingEngine::legal_actions(&state, 3);
        assert!(legals.bet_to_range.is_some());
        // open with min raise
        BettingEngine::apply_action(&mut state, 3, PlayerAction::RaiseTo{to:7}).unwrap();
        let legals2 = BettingEngine::legal_actions(&state, 4);
        assert!(legals2.raise_to_range.is_some());
    }

    // ---------- Invariants ----------

    #[test]
    fn invariants_hold_after_complex_sequences_with_side_pots() {
        let cfg = setup_cfg();
        let mut stacks = [200;6]; stacks[3]=30; stacks[4]=50; stacks[5]=120;
        let players = setup_players(&stacks);
        let mut state = BettingEngine::new_after_deal(cfg.clone(), players, Pots::default());
        BettingEngine::apply_action(&mut state, 3, PlayerAction::AllIn).unwrap();
        BettingEngine::apply_action(&mut state, 4, PlayerAction::RaiseTo{to:80}).unwrap();
        BettingEngine::apply_action(&mut state, 5, PlayerAction::Call).unwrap();
        BettingEngine::apply_action(&mut state, 1, PlayerAction::Fold).unwrap();
        BettingEngine::apply_action(&mut state, 2, PlayerAction::Fold).unwrap();
        state.validate_invariants().unwrap();
    }
}
