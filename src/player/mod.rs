use std::cell::RefCell;

use anyhow::Result;
use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::signature::SignatureScheme;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use rand::rngs::StdRng;
use sha2::Digest;

use crate::engine::nl::actions::PlayerBetAction;
use crate::engine::nl::types::SeatId;
use crate::player::signing::{PlayerActionBet, WithSignature};
use crate::showdown::{choose_best5_from7, pack_score_field, Card, HandCategory, Index};
use crate::PlayerAccessibleCiphertext;

pub mod signing;
use rand::SeedableRng;

#[derive(Clone, Debug)]
pub struct PlayerShowdownResult<F: PrimeField> {
    pub category: HandCategory,
    pub best5: [Card; 5],
    pub tiebreak: [u8; 5],
    pub score_u32: u32,
    pub score_field: F,
}

/// Unblinding context (committee shares and configuration) for decrypting
/// player-targeted hole ciphertexts.
struct UnblindingContext<G: CurveGroup> {
    shares: [Vec<crate::shuffling::player_decryption::PartialUnblindingShare<G>>; 2],
    expected_members: usize,
}

// ============================================================================
// Player API
// ============================================================================

/// Runtime API for signing player actions and producing deterministic showdown results.
///
/// This trait is intentionally hollow with respect to engine state: it does not
/// mutate or inspect a betting state. The typical flow is:
/// - The caller asks the player to sign an action (place_bet), then verifies the
///   signature and applies the action to an engine-managed `BettingState`.
/// - At showdown, the caller may request a deterministic result based on the
///   player's encrypted hole cards and the public board.
pub trait PlayerApi {
    type SigScheme: SignatureScheme;
    /// Sign a betting action and return a signed envelope.
    ///
    /// This does not mutate any engine state. The caller is responsible for
    /// (a) verifying the signature and (b) applying the action to the betting
    /// engine, advancing streets as appropriate.
    fn place_bet(
        &self,
        action: PlayerBetAction,
    ) -> Result<WithSignature<<Self::SigScheme as SignatureScheme>::Signature, PlayerActionBet>>;

    /// Compute the player's showdown result deterministically from their two
    /// hole cards and the five-card public board.
    ///
    /// - `community_board` – Five public cards as `Index` values.
    ///
    /// Returns a [`PlayerShowdownResult`] containing the best 5-card hand,
    /// category, tie-break tuple, a compact `u32` score for native comparison,
    /// and a packed field element `score_field` for circuit usage. Errors if the
    /// player's hole cards have not been set.
    fn provide_showdown_result<F: PrimeField, C: CurveGroup>(
        &self,
        community_board: [Index; 5],
    ) -> Result<PlayerShowdownResult<F>>;
}

/// Simple signer-backed player that only produces signed actions.
///
/// Generic over a concrete `SignatureScheme` `S`. The signer owns the seat id
/// and keys; it does not maintain or mutate betting state.
pub struct PlayerSigner<S, G>
where
    S: SignatureScheme,
    G: CurveGroup,
{
    pub seat: SeatId,
    pub params: S::Parameters,
    pub pk: S::PublicKey,
    pub sk: S::SecretKey,
    rng: RefCell<StdRng>,
    domain_tag: &'static [u8],
    hole_ciphertexts: Option<[PlayerAccessibleCiphertext<G>; 2]>,

    /// Aggregated committee/shuffler public key Σ_j pk_j
    aggregated_shuffler_public_key: Option<G>,
    unblinding: Option<UnblindingContext<G>>,
}

impl<S, G: CurveGroup> PlayerSigner<S, G>
where
    S: SignatureScheme,
    G: CurveGroup,
{
    pub fn new(
        seat: SeatId,
        params: S::Parameters,
        pk: S::PublicKey,
        sk: S::SecretKey,
        seed: [u8; 32],
        domain_tag: &'static [u8],
    ) -> Self {
        let rng = StdRng::from_seed(seed);
        Self {
            seat,
            params,
            pk,
            sk: sk.clone(),
            rng: RefCell::new(rng),
            domain_tag,
            hole_ciphertexts: None,
            aggregated_shuffler_public_key: None,
            unblinding: None,
        }
    }

    pub fn set_hole_ciphertexts(&mut self, hole: [PlayerAccessibleCiphertext<G>; 2]) {
        self.hole_ciphertexts = Some(hole);
    }

    pub fn set_aggregated_shuffler_public_key(&mut self, pk: G) {
        self.aggregated_shuffler_public_key = Some(pk);
    }

    pub fn set_unblinding_context(
        &mut self,
        shares0: Vec<crate::shuffling::player_decryption::PartialUnblindingShare<G>>,
        shares1: Vec<crate::shuffling::player_decryption::PartialUnblindingShare<G>>,
        expected_members: usize,
    ) {
        self.unblinding = Some(UnblindingContext {
            shares: [shares0, shares1],
            expected_members,
        });
    }
}

impl<S, G> PlayerSigner<S, G>
where
    S: SignatureScheme,
    G: CurveGroup,
{
    /// Sign a betting action and return a signed envelope.
    pub fn sign_action(
        &self,
        action: PlayerBetAction,
    ) -> anyhow::Result<WithSignature<<S as SignatureScheme>::Signature, PlayerActionBet>> {
        let payload = PlayerActionBet {
            seat: self.seat,
            action,
            nonce: 0,
        };
        let mut rng = self.rng.borrow_mut();
        let env = WithSignature::<<S as SignatureScheme>::Signature, PlayerActionBet>::new::<
            S,
            StdRng,
        >(payload, self.domain_tag, &self.params, &self.sk, &mut *rng)?;
        Ok(env)
    }
}

impl<D, G> PlayerApi for PlayerSigner<Schnorr<G, D>, G>
where
    D: Digest + Send + Sync,
    G: CurveGroup,
{
    type SigScheme = Schnorr<G, D>;

    fn place_bet(
        &self,
        action: PlayerBetAction,
    ) -> Result<WithSignature<<Self::SigScheme as SignatureScheme>::Signature, PlayerActionBet>>
    {
        // Sign using our concrete scheme S.
        let payload = PlayerActionBet {
            seat: self.seat,
            action,
            nonce: 0,
        };
        let mut rng = self.rng.borrow_mut();
        let env =
            WithSignature::<<Self::SigScheme as SignatureScheme>::Signature, PlayerActionBet>::new::<
                Self::SigScheme,
                StdRng,
            >(payload, self.domain_tag, &self.params, &self.sk, &mut *rng)?;
        Ok(env)
    }

    fn provide_showdown_result<F: PrimeField, C: CurveGroup>(
        &self,
        community_board: [Index; 5],
    ) -> Result<PlayerShowdownResult<F>> {
        // For now, use pre-set hole indices recorded on the signer. Decryption of
        // `player_hole_cards` requires player secret and committee shares and is handled by
        // an operator in end-to-end tests.
        let cts = self
            .hole_ciphertexts
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("hole ciphertexts not set on PlayerSigner"))?;
        // Use the signing secret key (scalar) as the player decryption key, by design.
        // Use the same underlying secret (Schnorr secret key is a tuple struct over the scalar)
        // ensuring there is only one player secret driving both signing and decryption.
        let sk: G::ScalarField = self.sk.0.clone();
        let ctx = self
            .unblinding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("unblinding context not set on PlayerSigner"))?;

        let v0 = crate::shuffling::player_decryption::recover_card_value::<G>(
            &cts[0],
            sk,
            ctx.shares[0].clone(),
            ctx.expected_members,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        let v1 = crate::shuffling::player_decryption::recover_card_value::<G>(
            &cts[1],
            sk,
            ctx.shares[1].clone(),
            ctx.expected_members,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        let hole: [Index; 2] = [v0 + 1, v1 + 1];
        let idx7 = [
            hole[0],
            hole[1],
            community_board[0],
            community_board[1],
            community_board[2],
            community_board[3],
            community_board[4],
        ];
        let (best5, category, tiebreak, score_u32) = choose_best5_from7(idx7);
        let score_field = pack_score_field::<F>(category, tiebreak);
        Ok(PlayerShowdownResult {
            category,
            best5,
            tiebreak,
            score_u32,
            score_field,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::showdown::{idx_of, Suit};
    use crate::shuffling::data_structures::ElGamalCiphertext;
    use crate::shuffling::player_decryption::{
        combine_blinding_contributions_for_player, generate_committee_decryption_share,
        PlayerTargetedBlindingContribution,
    };
    use ark_bn254::Fr;
    use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
    use ark_ec::{AffineRepr, PrimeGroup};
    use ark_std::UniformRand;
    use sha2::Sha256;
    use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

    use crate::engine::nl::{engine::BettingEngineNL, engine::EngineNL, types::*, BettingState};
    use ark_std::Zero;

    fn empty_pots() -> Pots {
        Pots {
            main: Pot {
                amount: 0,
                eligible: vec![],
            },
            sides: vec![],
        }
    }

    use ark_grumpkin::Projective as GrumpkinProjective;
    type Scheme = Schnorr<GrumpkinProjective, Sha256>;

    fn new_signer(seat: SeatId) -> PlayerSigner<Scheme, GrumpkinProjective> {
        let mut rng = ark_std::test_rng();
        let params = Scheme::setup(&mut rng).expect("setup");
        let (pk, sk) = Scheme::keygen(&params, &mut rng).expect("keygen");
        PlayerSigner::new(seat, params, pk, sk, [7u8; 32], b"zkpoker/bet_v1")
    }

    fn setup_preflop_state() -> BettingState {
        let stakes = TableStakes {
            small_blind: 1,
            big_blind: 2,
            ante: 0,
        };
        let cfg = HandConfig {
            stakes,
            button: 0,
            small_blind_seat: 1,
            big_blind_seat: 2,
            check_raise_allowed: true,
        };
        // Seats 0..5; post blinds for 1(SB) and 2(BB)
        let mut players: Vec<PlayerState> = (0u8..6)
            .map(|seat| PlayerState {
                seat,
                player_id: None,
                stack: 100,
                committed_this_round: 0,
                committed_total: 0,
                status: PlayerStatus::Active,
                has_acted_this_round: false,
            })
            .collect();
        players[1].committed_this_round = 1; // SB
        players[2].committed_this_round = 2; // BB

        EngineNL::new_after_deal(cfg, players, empty_pots())
    }

    #[test]
    fn preflop_unopened_until_street_end_then_advance() {
        let mut state = setup_preflop_state();
        let signers: std::collections::HashMap<SeatId, PlayerSigner<Scheme, GrumpkinProjective>> =
            (0u8..6).map(|s| (s, new_signer(s))).collect();

        // UTG (3) call to 2
        let seat = 3u8;
        let action = PlayerBetAction::Call;
        let signed = signers.get(&seat).unwrap().sign_action(action).unwrap();
        assert!(Scheme::verify(
            &signers.get(&seat).unwrap().params,
            &signers.get(&seat).unwrap().pk,
            &signed.transcript,
            &signed.signature
        )
        .unwrap());
        let tr = EngineNL::apply_action(&mut state, seat, signed.value.action).unwrap();
        match tr {
            crate::engine::nl::engine::Transition::Continued { .. } => {}
            _ => panic!("expected continued"),
        }

        // MP (4) fold
        let seat = 4u8;
        let action = PlayerBetAction::Fold;
        let signed = signers.get(&seat).unwrap().sign_action(action).unwrap();
        assert!(Scheme::verify(
            &signers.get(&seat).unwrap().params,
            &signers.get(&seat).unwrap().pk,
            &signed.transcript,
            &signed.signature
        )
        .unwrap());
        let _ = EngineNL::apply_action(&mut state, seat, signed.value.action).unwrap();

        // CO (5) call
        let seat = 5u8;
        let action = PlayerBetAction::Call;
        let signed = signers.get(&seat).unwrap().sign_action(action).unwrap();
        assert!(Scheme::verify(
            &signers.get(&seat).unwrap().params,
            &signers.get(&seat).unwrap().pk,
            &signed.transcript,
            &signed.signature
        )
        .unwrap());
        let _ = EngineNL::apply_action(&mut state, seat, signed.value.action).unwrap();

        // SB (1) complete to 2
        let seat = 1u8;
        let action = PlayerBetAction::Call;
        let signed = signers.get(&seat).unwrap().sign_action(action).unwrap();
        let _ = EngineNL::apply_action(&mut state, seat, signed.value.action).unwrap();

        // BB (2) check -> should StreetEnd preflop
        let seat = 2u8;
        let action = PlayerBetAction::Check;
        let signed = signers.get(&seat).unwrap().sign_action(action).unwrap();
        let tr = EngineNL::apply_action(&mut state, seat, signed.value.action).unwrap();
        match tr {
            crate::engine::nl::engine::Transition::StreetEnd { street, .. } => {
                assert_eq!(street, Street::Preflop)
            }
            _ => panic!("expected preflop street end"),
        }

        // Assert invariants
        assert_eq!(state.current_bet_to_match, 2);
        assert_eq!(state.last_full_raise_amount, 2);
        assert!(state.pending_to_match.is_empty());

        // Compute expected pot = sum of committed_this_round among non-folded
        let expected_pot: Chips = state
            .players
            .iter()
            .filter(|p| p.status != PlayerStatus::Folded)
            .map(|p| p.committed_this_round + p.committed_total)
            .sum();
        assert_eq!(state.pots.main.amount, expected_pot);

        // Advance to flop and assert state reset
        EngineNL::advance_street(&mut state).unwrap();
        assert_eq!(state.street, Street::Flop);
        assert_eq!(state.current_bet_to_match, 0);
        assert_eq!(state.last_full_raise_amount, 0);
        assert!(!state.voluntary_bet_opened);
    }

    #[test]
    fn postflop_bet_call_until_street_end() {
        let mut state = setup_preflop_state();
        // Finish preflop quickly to go to flop: have UTG/CO/SB call, BB check as above
        {
            let signers: std::collections::HashMap<
                SeatId,
                PlayerSigner<Scheme, GrumpkinProjective>,
            > = (0u8..6).map(|s| (s, new_signer(s))).collect();
            // UTG call
            let _ = EngineNL::apply_action(
                &mut state,
                3,
                signers
                    .get(&3)
                    .unwrap()
                    .sign_action(PlayerBetAction::Call)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            // MP fold
            let _ = EngineNL::apply_action(
                &mut state,
                4,
                signers
                    .get(&4)
                    .unwrap()
                    .sign_action(PlayerBetAction::Fold)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            // CO call
            let _ = EngineNL::apply_action(
                &mut state,
                5,
                signers
                    .get(&5)
                    .unwrap()
                    .sign_action(PlayerBetAction::Call)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            // SB call
            let _ = EngineNL::apply_action(
                &mut state,
                1,
                signers
                    .get(&1)
                    .unwrap()
                    .sign_action(PlayerBetAction::Call)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            // BB check -> end
            let tr = EngineNL::apply_action(
                &mut state,
                2,
                signers
                    .get(&2)
                    .unwrap()
                    .sign_action(PlayerBetAction::Check)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            match tr {
                crate::engine::nl::engine::Transition::StreetEnd { street, .. } => {
                    assert_eq!(street, Street::Preflop)
                }
                _ => panic!("expected preflop street end"),
            }
        }

        // Advance to flop
        EngineNL::advance_street(&mut state).unwrap();

        // Fresh signers for flop actions
        let signers: std::collections::HashMap<SeatId, PlayerSigner<Scheme, GrumpkinProjective>> =
            (0u8..6).map(|s| (s, new_signer(s))).collect();

        // Actor A (first_to_act): Check
        let a = state.first_to_act;
        let _ = EngineNL::apply_action(
            &mut state,
            a,
            signers
                .get(&a)
                .unwrap()
                .sign_action(PlayerBetAction::Check)
                .unwrap()
                .value
                .action,
        )
        .unwrap();

        // Actor B: BetTo { to: 15 }
        let b = state.to_act;
        let _ = EngineNL::apply_action(
            &mut state,
            b,
            signers
                .get(&b)
                .unwrap()
                .sign_action(PlayerBetAction::BetTo { to: 15 })
                .unwrap()
                .value
                .action,
        )
        .unwrap();
        assert_eq!(state.current_bet_to_match, 15);
        assert_eq!(state.last_full_raise_amount, 15);
        assert!(state.voluntary_bet_opened);

        // Actor C: Call
        let c = state.to_act;
        let _ = EngineNL::apply_action(
            &mut state,
            c,
            signers
                .get(&c)
                .unwrap()
                .sign_action(PlayerBetAction::Call)
                .unwrap()
                .value
                .action,
        )
        .unwrap();

        // Continue applying default (Check/Call) until StreetEnd
        loop {
            if state.pending_to_match.is_empty() && state.voluntary_bet_opened {
                break;
            }
            let seat = state.to_act;
            let price = <BettingState as crate::engine::nl::rules::NoLimitRules>::price_to_call(
                &state, seat,
            );
            let act = if price == 0 {
                PlayerBetAction::Check
            } else {
                PlayerBetAction::Call
            };
            let tr = EngineNL::apply_action(
                &mut state,
                seat,
                signers
                    .get(&seat)
                    .unwrap()
                    .sign_action(act)
                    .unwrap()
                    .value
                    .action,
            )
            .unwrap();
            if let crate::engine::nl::engine::Transition::StreetEnd { street, .. } = tr {
                assert_eq!(street, Street::Flop);
                break;
            }
        }
    }

    #[test]
    fn showdown_results_multiple_players() {
        // Enable detailed tracing for debugging decryption issues in this test
        use tracing_subscriber::filter;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let _guard = {
            let filter = filter::Targets::new()
                .with_target(
                    "nexus_nova::shuffling::player_decryption",
                    tracing::Level::TRACE,
                )
                .with_target(
                    "nexus_nova::shuffling::community_decryption",
                    tracing::Level::TRACE,
                )
                .with_target("player_test", tracing::Level::TRACE);
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_test_writer())
                .with(filter)
                .set_default()
        };
        type G = GrumpkinProjective;
        type Scalar = <G as PrimeGroup>::ScalarField;

        // Three players with different holes
        let mut player1 = new_signer(1);
        let mut player2 = new_signer(2);
        let mut player3 = new_signer(3);

        // Committee/shufflers: 3 secrets and aggregated PK
        let mut rng = ark_std::test_rng();
        let shuffler_sk1 = Scalar::rand(&mut rng);
        let shuffler_sk2 = Scalar::rand(&mut rng);
        let shuffler_sk3 = Scalar::rand(&mut rng);
        let shuffler_pk1 = G::generator() * shuffler_sk1;
        let shuffler_pk2 = G::generator() * shuffler_sk2;
        let shuffler_pk3 = G::generator() * shuffler_sk3;
        let shuffler_agg_pk = shuffler_pk1 + shuffler_pk2 + shuffler_pk3;
        player1.set_aggregated_shuffler_public_key(shuffler_agg_pk);
        player2.set_aggregated_shuffler_public_key(shuffler_agg_pk);
        player3.set_aggregated_shuffler_public_key(shuffler_agg_pk);

        // For decryption we must use generator * secret (not Schnorr's derived PK).
        let player1_pk: G = G::generator() * player1.sk.0;
        let player2_pk: G = G::generator() * player2.sk.0;
        let player3_pk: G = G::generator() * player3.sk.0;

        // Helper to build player-accessible ciphertext with r=0
        let mut make_ct = |m_index_1based: u8, player_pk: G| {
            let m_scalar = Scalar::from((m_index_1based - 1) as u64);
            let message_point = G::generator() * m_scalar;
            tracing::info!(target = "player_test", m_index_1based, m_scalar = ?m_scalar, ?message_point, "Building player-accessible ciphertext for index");
            let initial_ct = ElGamalCiphertext::new(G::zero(), message_point);
            let c1 = PlayerTargetedBlindingContribution::generate(
                shuffler_sk1,
                shuffler_agg_pk,
                player_pk,
                &mut rng,
            );
            let c2 = PlayerTargetedBlindingContribution::generate(
                shuffler_sk2,
                shuffler_agg_pk,
                player_pk,
                &mut rng,
            );
            let c3 = PlayerTargetedBlindingContribution::generate(
                shuffler_sk3,
                shuffler_agg_pk,
                player_pk,
                &mut rng,
            );
            let contributions = vec![c1, c2, c3];
            let pact = combine_blinding_contributions_for_player(
                &initial_ct,
                &contributions,
                shuffler_agg_pk,
                player_pk,
            )
            .expect("combine contributions");
            tracing::info!(target = "player_test", blinded_base = ?pact.blinded_base, blinded_message = ?pact.blinded_message_with_player_key, helper = ?pact.player_unblinding_helper, "Built player-accessible ciphertext");
            pact
        };

        // Assign holes (AA, KK, QQ) and build ciphertexts + shares
        let p1_holes = [idx_of(14, Suit::Spades), idx_of(14, Suit::Hearts)];
        let p2_holes = [idx_of(13, Suit::Clubs), idx_of(13, Suit::Diamonds)];
        let p3_holes = [idx_of(12, Suit::Spades), idx_of(12, Suit::Hearts)];

        // Schnorr pk and generator*secret may differ; only generator*secret is used for decryption.

        let p1_ct0 = make_ct(p1_holes[0], player1_pk);
        let p1_ct1 = make_ct(p1_holes[1], player1_pk);
        let p2_ct0 = make_ct(p2_holes[0], player2_pk);
        let p2_ct1 = make_ct(p2_holes[1], player2_pk);
        let p3_ct0 = make_ct(p3_holes[0], player3_pk);
        let p3_ct1 = make_ct(p3_holes[1], player3_pk);

        player1.set_hole_ciphertexts([p1_ct0.clone(), p1_ct1.clone()]);
        player2.set_hole_ciphertexts([p2_ct0.clone(), p2_ct1.clone()]);
        player3.set_hole_ciphertexts([p3_ct0.clone(), p3_ct1.clone()]);

        let p1_shares0 = vec![
            generate_committee_decryption_share(&p1_ct0, shuffler_sk1, 0),
            generate_committee_decryption_share(&p1_ct0, shuffler_sk2, 1),
            generate_committee_decryption_share(&p1_ct0, shuffler_sk3, 2),
        ];
        tracing::info!(target = "player_test", shares = ?p1_shares0.iter().map(|s| &s.share).collect::<Vec<_>>(), "p1 first card shares");
        let p1_shares1 = vec![
            generate_committee_decryption_share(&p1_ct1, shuffler_sk1, 0),
            generate_committee_decryption_share(&p1_ct1, shuffler_sk2, 1),
            generate_committee_decryption_share(&p1_ct1, shuffler_sk3, 2),
        ];
        player1.set_unblinding_context(p1_shares0, p1_shares1, 3);

        let p2_shares0 = vec![
            generate_committee_decryption_share(&p2_ct0, shuffler_sk1, 0),
            generate_committee_decryption_share(&p2_ct0, shuffler_sk2, 1),
            generate_committee_decryption_share(&p2_ct0, shuffler_sk3, 2),
        ];
        let p2_shares1 = vec![
            generate_committee_decryption_share(&p2_ct1, shuffler_sk1, 0),
            generate_committee_decryption_share(&p2_ct1, shuffler_sk2, 1),
            generate_committee_decryption_share(&p2_ct1, shuffler_sk3, 2),
        ];
        player2.set_unblinding_context(p2_shares0, p2_shares1, 3);

        let p3_shares0 = vec![
            generate_committee_decryption_share(&p3_ct0, shuffler_sk1, 0),
            generate_committee_decryption_share(&p3_ct0, shuffler_sk2, 1),
            generate_committee_decryption_share(&p3_ct0, shuffler_sk3, 2),
        ];
        let p3_shares1 = vec![
            generate_committee_decryption_share(&p3_ct1, shuffler_sk1, 0),
            generate_committee_decryption_share(&p3_ct1, shuffler_sk2, 1),
            generate_committee_decryption_share(&p3_ct1, shuffler_sk3, 2),
        ];
        player3.set_unblinding_context(p3_shares0, p3_shares1, 3);

        // Public board
        let board: [Index; 5] = [
            idx_of(7, Suit::Clubs),
            idx_of(2, Suit::Diamonds),
            idx_of(9, Suit::Hearts),
            idx_of(3, Suit::Spades),
            idx_of(5, Suit::Clubs),
        ];

        // Manual sanity check removed: avoid direct scalar extraction from Schnorr secret key
        // to maintain a single-key representation while remaining compatible across versions.

        let res1 = player1.provide_showdown_result::<Fr, G>(board).unwrap();
        tracing::info!(target = "player_test", res1 = ?res1.score_u32, best5 = ?res1.best5, "player1 result");
        let res2 = player2.provide_showdown_result::<Fr, G>(board).unwrap();
        let res3 = player3.provide_showdown_result::<Fr, G>(board).unwrap();

        assert!(res1.score_u32 > res2.score_u32 && res2.score_u32 > res3.score_u32);
    }
}
