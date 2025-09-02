//! SNARK gadget for verifying poker hand reveal at showdown
//!
//! This module provides the circuit implementation for:
//! - Recovering encrypted card values using player decryption
//! - Verifying card selection using LogUp lookup argument
//! - Scoring the selected poker hand

use crate::logup::{uint_to_field, verify_lookup};
use crate::showdown::gadget::{uint8_sub, verify_and_score_from_indices, HandCategoryVar};
use crate::shuffling::player_decryption_gadget::{
    recover_card_point_gadget, PartialUnblindingShareVar, PlayerAccessibleCiphertextVar,
};
use crate::track_constraints;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    cmp::CmpGadget,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
    uint8::UInt8,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

const LOG_TARGET: &str = "nexus_nova::showdown::hand_reveal_showdown_gadget";

/// Helper function to check constraint satisfaction and log errors if any
#[inline]
fn check_constraint_satisfaction<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    step_description: &str,
) {
    #[cfg(test)]
    {
        if !cs.is_satisfied().unwrap() {
            tracing::error!(target: LOG_TARGET, "Constraint satisfaction failed after {}", step_description);
            if let Some(unsatisfied_idx) = cs.which_is_unsatisfied().unwrap() {
                tracing::error!(target: LOG_TARGET, "First unsatisfied constraint index: {}", unsatisfied_idx);
            }
        }
    }
    // Suppress unused variable warnings in non-test builds
    let _ = (cs, step_description);
}

/// Represents a community card with its value and LogUp count
#[derive(Clone)]
pub struct CommunityCardVar<F: PrimeField> {
    /// Card value (0-51) as field element
    pub value: FpVar<F>,
    /// LogUp count (must be 0 or 1)
    pub count: UInt8<F>,
}

/// Represents a hidden card with its encrypted value, LogUp count, and witnessed value
#[derive(Clone)]
pub struct HiddenCardVar<C, CV, F>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    F: PrimeField,
{
    /// The encrypted card ciphertext
    pub ciphertext: PlayerAccessibleCiphertextVar<C, CV>,
    /// LogUp count (must be 0 or 1)
    pub count: UInt8<F>,
    /// Witnessed card value (0-51) for efficient verification
    pub witnessed_value: UInt8<F>,
}

/// Verifies a player's poker hand at showdown
///
/// # Arguments
/// * `cs` - The constraint system
/// * `community_cards` - 5 community cards with their LogUp counts
/// * `hidden_cards` - 2 hidden player cards with ciphertexts and counts
/// * `player_secret` - Player's secret key as emulated field element
/// * `unblinding_shares` - Committee unblinding shares for decryption
/// * `expected_members` - Expected number of committee members
/// * `selected_cards` - The 5 cards selected by the player
/// * `claimed_cat` - The claimed hand category
/// * `alpha` - LogUp challenge point
///
/// # Returns
/// * Score and tie-break values for the hand
pub fn hand_reveal_showdown_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    community_cards: &[CommunityCardVar<C::BaseField>; 5],
    hidden_cards: &[HiddenCardVar<C, CV, C::BaseField>; 2],
    player_secret: &EmulatedFpVar<C::ScalarField, C::BaseField>,
    unblinding_shares: &[PartialUnblindingShareVar<C, CV>],
    expected_members: usize,
    selected_cards: &[FpVar<C::BaseField>; 5],
    claimed_cat: HandCategoryVar<C::BaseField>,
    alpha: &FpVar<C::BaseField>,
) -> Result<(FpVar<C::BaseField>, [UInt8<C::BaseField>; 5]), SynthesisError>
where
    C: CurveGroup + PrimeGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    track_constraints!(cs.clone(), "hand_reveal_showdown_gadget", LOG_TARGET, {
        hand_reveal_showdown_gadget_inner::<C, CV>(
            cs,
            community_cards,
            hidden_cards,
            player_secret,
            unblinding_shares,
            expected_members,
            selected_cards,
            claimed_cat,
            alpha,
        )
    })
}

fn hand_reveal_showdown_gadget_inner<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    community_cards: &[CommunityCardVar<C::BaseField>; 5],
    hidden_cards: &[HiddenCardVar<C, CV, C::BaseField>; 2],
    player_secret: &EmulatedFpVar<C::ScalarField, C::BaseField>,
    unblinding_shares: &[PartialUnblindingShareVar<C, CV>],
    expected_members: usize,
    selected_cards: &[FpVar<C::BaseField>; 5],
    claimed_cat: HandCategoryVar<C::BaseField>,
    alpha: &FpVar<C::BaseField>,
) -> Result<(FpVar<C::BaseField>, [UInt8<C::BaseField>; 5]), SynthesisError>
where
    C: CurveGroup + PrimeGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Step 1: Card Recovery and Verification
    // Convert non-native scalar field to bits for scalar multiplication
    let player_secret_bits = player_secret.to_bits_le()?;

    // Recover and verify each hidden card
    for (idx, hidden_card) in hidden_cards.iter().enumerate() {
        // Decrypt the card
        let recovered_point = recover_card_point_gadget(
            cs.clone(),
            &hidden_card.ciphertext,
            &player_secret_bits,
            unblinding_shares,
            expected_members,
        )?;

        // Verify recovered point matches witnessed value
        // Compute g^witnessed_value
        let generator = CV::constant(C::generator());
        let witnessed_bits = hidden_card.witnessed_value.to_bits_le()?;
        let expected_point = generator.scalar_mul_le(witnessed_bits.iter())?;

        // Enforce equality: recovered_point == g^witnessed_value
        recovered_point.enforce_equal(&expected_point)?;
        tracing::info!(target: LOG_TARGET, "Recovered hidden card {:?} matches witnessed value", hidden_card.witnessed_value.value());

        check_constraint_satisfaction(&cs, &format!("recovering hidden card {}", idx));
    }

    // Step 2: Boolean Constraints and Count Verification
    // Enforce all counts are 0 or 1
    for card in community_cards.iter() {
        let is_valid = card.count.is_le(&UInt8::constant(1))?;
        is_valid.enforce_equal(&Boolean::TRUE)?;
    }

    for hidden_card in hidden_cards.iter() {
        let is_valid = hidden_card.count.is_le(&UInt8::constant(1))?;
        is_valid.enforce_equal(&Boolean::TRUE)?;
    }

    // Enforce total count equals 5
    let total_count = community_cards
        .iter()
        .map(|c| uint_to_field(&c.count))
        .chain(hidden_cards.iter().map(|h| uint_to_field(&h.count)))
        .try_fold(FpVar::<C::BaseField>::zero(), |acc, count| {
            count.map(|c| acc + c)
        })?;

    total_count.enforce_equal(&FpVar::constant(C::BaseField::from(5u64)))?;

    check_constraint_satisfaction(&cs, "count verification");

    // Step 3: LogUp Verification
    // Build table entries functionally
    let table_entries: Vec<FpVar<C::BaseField>> = community_cards
        .iter()
        .map(|card| card.value.clone())
        .chain(
            hidden_cards
                .iter()
                .map(|hidden| uint_to_field(&hidden.witnessed_value).unwrap()),
        )
        .collect();

    // Build multiplicities functionally
    let multiplicities: Vec<UInt8<C::BaseField>> = community_cards
        .iter()
        .map(|card| card.count.clone())
        .chain(hidden_cards.iter().map(|hidden| hidden.count.clone()))
        .collect();

    // Verify lookup - ensures selected cards come from table and respects multiplicities
    verify_lookup(
        cs.clone(),
        alpha,
        &table_entries,
        selected_cards.as_ref(),
        &multiplicities,
    )?;

    tracing::info!(target: LOG_TARGET, "LogUp validation of the cards is successful");

    check_constraint_satisfaction::<_>(&cs, "LogUp verification");

    // Step 4: Hand Scoring
    // Convert selected cards to UInt8 indices functionally
    let card_indices: [UInt8<C::BaseField>; 5] = std::array::from_fn(|i| {
        // Since selected_cards are FpVar representing values 0-51,
        // we need to convert them back to UInt8 and add 1 for 1-based indexing
        // This requires witnessing the value and verifying it matches
        let witnessed_uint8 = UInt8::new_witness(cs.clone(), || {
            let v = selected_cards[i].value()?;
            // Convert field element to u64, then to u8
            // Card values are 0-51, so they always fit in u8
            let as_u64 = v.into_bigint().as_ref()[0];
            // Add 1 to convert from 0-based to 1-based indexing
            Ok((as_u64 + 1) as u8)
        })
        .unwrap();

        // Verify the witnessed value matches the FpVar + 1
        // We need to subtract 1 from the witnessed value to match the original selected_cards
        let witnessed_minus_one = uint8_sub(&witnessed_uint8, &UInt8::constant(1)).unwrap();
        let witnessed_fp = uint_to_field(&witnessed_minus_one).unwrap();
        witnessed_fp.enforce_equal(&selected_cards[i]).unwrap();

        // Debug: Check after each card index conversion
        #[cfg(test)]
        {
            if !cs.is_satisfied().unwrap() {
                tracing::error!(target: LOG_TARGET, "Constraint satisfaction failed after converting card index {}", i);
                tracing::error!(target: LOG_TARGET, "Selected card value: {:?}", selected_cards[i].value());
                tracing::error!(target: LOG_TARGET, "Witnessed uint8 value: {:?}", witnessed_uint8.value());
                check_constraint_satisfaction(&cs, &format!("converting card index {}", i));
            }
        }

        witnessed_uint8
    });

    // Score the hand
    let (score, tiebreak) = verify_and_score_from_indices(cs.clone(), claimed_cat, card_indices)?;

    tracing::info!(target: LOG_TARGET, "Score of the hand {:?} {:?}", score.value(), tiebreak.value());

    check_constraint_satisfaction(&cs, "hand scoring");

    Ok((score, tiebreak))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::showdown::{idx_of, pack_score_field, HandCategory, Suit};
    use crate::shuffling::data_structures::ElGamalKeys;
    use crate::shuffling::player_decryption::{recover_card_value, PlayerAccessibleCiphertext};
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        fields::fp::FpVar,
        groups::curves::short_weierstrass::ProjectiveVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_three_player_showdown_royal_flush_wins() {
        let _gaurd = setup_test_tracing();
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Setup encryption parameters
        let player1_keys = ElGamalKeys::<G1Projective>::new(Fr::rand(&mut rng));
        let player2_keys = ElGamalKeys::<G1Projective>::new(Fr::rand(&mut rng));
        let _player3_keys = ElGamalKeys::<G1Projective>::new(Fr::rand(&mut rng));

        // Community cards: 10♠, J♠, Q♠, 9♦, 2♣
        // Use 0-based indices for consistency with encryption
        let community_cards = [
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(10, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(1), // Player 1 uses this
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(11, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(1), // Player 1 uses this
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(12, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(1), // Player 1 uses this
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(9, Suit::Diamonds) - 1) as u64)),
                count: UInt8::constant(0), // Not used by Player 1
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(2, Suit::Clubs) - 1) as u64)),
                count: UInt8::constant(0), // Not used by Player 1
            },
        ];

        // Player 1 hidden cards: K♠, A♠ (for Royal Flush)
        // Note: idx_of returns 1-based indices (1-52), but encryption uses 0-based (0-51)
        let king_spades_idx = idx_of(13, Suit::Spades) - 1;
        let ace_spades_idx = idx_of(14, Suit::Spades) - 1;

        // For testing, we create a simplified PlayerAccessibleCiphertext
        // that works with our test setup (no committee members, no real shuffling)

        // The decryption formula is:
        // recovered = blinded_message_with_player_key - player_unblinding_helper * player_secret - combined_unblinding
        // With no committee (combined_unblinding = 0), we need:
        // g^card_value = blinded_message_with_player_key - player_unblinding_helper * player_secret
        // Therefore: blinded_message_with_player_key = g^card_value + player_unblinding_helper * player_secret

        let generator = G1Projective::generator();

        // Create simplified ciphertexts for testing
        // Use deterministic values for debugging
        let delta_king = Fr::from(12345u64); // Use a fixed value for reproducibility
        let player_unblinding_helper_king = generator * delta_king;
        let king_scalar = Fr::from(king_spades_idx as u64);
        let king_point = generator * king_scalar;

        tracing::debug!(
            target: TEST_TARGET,
            king_index = king_spades_idx,
            ?king_scalar,
            ?generator,
            ?king_point,
            ?delta_king,
            player_secret = ?player1_keys.private_key,
            ?player_unblinding_helper_king,
            "DETAILED KING ENCRYPTION DEBUG"
        );

        let blinding_term = player_unblinding_helper_king * player1_keys.private_key;
        let king_blinded_message = king_point + blinding_term;

        // Verify the math works
        let test_recovery = king_blinded_message - blinding_term;
        let points_match = test_recovery == king_point;

        tracing::debug!(
            target: TEST_TARGET,
            ?blinding_term,
            ?king_blinded_message,
            ?test_recovery,
            points_match,
            "King encryption math verification"
        );

        assert_eq!(test_recovery, king_point, "Basic math check failed!");

        tracing::debug!(
            target: TEST_TARGET,
            ?generator,
            player1_private_key = ?player1_keys.private_key,
            player1_public_key = ?player1_keys.public_key,
            ?delta_king,
            ?player_unblinding_helper_king,
            card_index = king_spades_idx,
            ?king_point,
            blinding_term = ?blinding_term,
            ?king_blinded_message,
            "King Card Encryption"
        );

        // Use original projective points without normalization
        let king_blinded_base = generator * Fr::from(99999u64);

        let mock_ciphertext_king = PlayerAccessibleCiphertext {
            blinded_base: king_blinded_base,
            blinded_message_with_player_key: king_blinded_message,
            player_unblinding_helper: player_unblinding_helper_king,
            shuffler_proofs: vec![],
        };

        tracing::debug!(
            target: TEST_TARGET,
            ?king_blinded_base,
            "Created king mock ciphertext with projective blinded_base"
        );

        let delta_ace = Fr::from(67890u64); // Use a fixed value for reproducibility
        let player_unblinding_helper_ace = generator * delta_ace;
        let ace_scalar = Fr::from(ace_spades_idx as u64);
        let ace_point = generator * ace_scalar;

        tracing::debug!(
            target: TEST_TARGET,
            ace_index = ace_spades_idx,
            ?ace_scalar,
            ?ace_point,
            ?delta_ace,
            ?player_unblinding_helper_ace,
            "DETAILED ACE ENCRYPTION DEBUG"
        );

        let blinding_term_ace = player_unblinding_helper_ace * player1_keys.private_key;
        let ace_blinded_message = ace_point + blinding_term_ace;

        // Verify the math works
        let test_recovery_ace = ace_blinded_message - blinding_term_ace;
        let ace_points_match = test_recovery_ace == ace_point;

        tracing::debug!(
            target: TEST_TARGET,
            ?blinding_term_ace,
            ?ace_blinded_message,
            ?test_recovery_ace,
            ace_points_match,
            "Ace encryption math verification"
        );

        assert_eq!(test_recovery_ace, ace_point, "Basic ace math check failed!");

        tracing::debug!(
            target: TEST_TARGET,
            ?delta_ace,
            ?player_unblinding_helper_ace,
            card_index = ace_spades_idx,
            ?ace_point,
            blinding_term = ?blinding_term_ace,
            ?ace_blinded_message,
            "Ace Card Encryption"
        );

        // Use original projective points without normalization
        let ace_blinded_base = generator * Fr::from(88888u64);

        let mock_ciphertext_ace = PlayerAccessibleCiphertext {
            blinded_base: ace_blinded_base,
            blinded_message_with_player_key: ace_blinded_message,
            player_unblinding_helper: player_unblinding_helper_ace,
            shuffler_proofs: vec![],
        };

        tracing::debug!(
            target: TEST_TARGET,
            ?ace_blinded_base,
            "Created ace mock ciphertext with projective blinded_base"
        );

        // Verify decryption works natively (optional but helps debugging)
        // Let's manually verify the math first
        let helper_times_secret =
            mock_ciphertext_king.player_unblinding_helper * player1_keys.private_key;
        let manual_king_recovered =
            mock_ciphertext_king.blinded_message_with_player_key - helper_times_secret;
        let king_verification_match = manual_king_recovered == king_point;

        tracing::debug!(
            target: TEST_TARGET,
            ciphertext_blinded_message = ?mock_ciphertext_king.blinded_message_with_player_key,
            ciphertext_helper = ?mock_ciphertext_king.player_unblinding_helper,
            player_secret = ?player1_keys.private_key,
            ?helper_times_secret,
            ?manual_king_recovered,
            expected_point = ?king_point,
            points_match = king_verification_match,
            "MANUAL KING DECRYPTION VERIFICATION"
        );

        assert_eq!(
            manual_king_recovered, king_point,
            "Manual king recovery failed - recovered point doesn't match expected g^50"
        );

        let recovered_king = recover_card_value(
            &mock_ciphertext_king,
            player1_keys.private_key,
            vec![], // No committee shares for this test
            0,      // No committee members
        )
        .expect("Failed to recover king");
        assert_eq!(recovered_king, king_spades_idx, "King recovery failed");

        let ace_helper_times_secret =
            mock_ciphertext_ace.player_unblinding_helper * player1_keys.private_key;
        let manual_ace_recovered =
            mock_ciphertext_ace.blinded_message_with_player_key - ace_helper_times_secret;
        let ace_verification_match = manual_ace_recovered == ace_point;

        tracing::debug!(
            target: TEST_TARGET,
            expected_card_index = ace_spades_idx,
            blinded_message = ?mock_ciphertext_ace.blinded_message_with_player_key,
            helper = ?mock_ciphertext_ace.player_unblinding_helper,
            helper_times_secret = ?ace_helper_times_secret,
            recovered = ?manual_ace_recovered,
            expected = ?ace_point,
            points_match = ace_verification_match,
            "Manual Ace Decryption"
        );

        tracing::debug!(
            target: TEST_TARGET,
            expected_card_index = ace_spades_idx,
            manual_recovery_point = ?manual_ace_recovered,
            expected_point = ?ace_point,
            "Testing ace decryption"
        );
        assert_eq!(
            manual_ace_recovered, ace_point,
            "Manual ace recovery failed"
        );

        let recovered_ace = recover_card_value(
            &mock_ciphertext_ace,
            player1_keys.private_key,
            vec![], // No committee shares for this test
            0,      // No committee members
        )
        .expect("Failed to recover ace");
        assert_eq!(recovered_ace, ace_spades_idx, "Ace recovery failed");

        // Allocate ciphertexts as circuit variables
        // Convert to affine to see actual coordinates
        let king_blinded_message_affine = mock_ciphertext_king
            .blinded_message_with_player_key
            .into_affine();
        let king_helper_affine = mock_ciphertext_king.player_unblinding_helper.into_affine();
        let king_blinded_base_affine = mock_ciphertext_king.blinded_base.into_affine();

        tracing::debug!(
            target: TEST_TARGET,
            king_blinded_message_projective = ?mock_ciphertext_king.blinded_message_with_player_key,
            king_blinded_message_affine = ?king_blinded_message_affine,
            king_helper_projective = ?mock_ciphertext_king.player_unblinding_helper,
            king_helper_affine = ?king_helper_affine,
            king_blinded_base_projective = ?mock_ciphertext_king.blinded_base,
            king_blinded_base_affine = ?king_blinded_base_affine,
            "BEFORE ALLOCATION TO CIRCUIT"
        );

        let ciphertext_king_var =
            PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
                cs.clone(),
                || {
                    tracing::debug!(
                        target: TEST_TARGET,
                        "King allocation closure called - returning ciphertext"
                    );
                    Ok(mock_ciphertext_king.clone())
                },
                AllocationMode::Witness,
            )
            .unwrap();

        // Get circuit values and convert to affine
        let circuit_king_blinded_message_proj = ciphertext_king_var
            .blinded_message_with_player_key
            .value()
            .unwrap();
        let circuit_king_helper_proj = ciphertext_king_var
            .player_unblinding_helper
            .value()
            .unwrap();
        let circuit_king_blinded_base_proj = ciphertext_king_var.blinded_base.value().unwrap();

        let circuit_king_blinded_message_affine = circuit_king_blinded_message_proj.into_affine();
        let circuit_king_helper_affine = circuit_king_helper_proj.into_affine();
        let circuit_king_blinded_base_affine = circuit_king_blinded_base_proj.into_affine();

        tracing::debug!(
            target: TEST_TARGET,
            circuit_king_blinded_message_projective = ?circuit_king_blinded_message_proj,
            circuit_king_blinded_message_affine = ?circuit_king_blinded_message_affine,
            circuit_king_helper_projective = ?circuit_king_helper_proj,
            circuit_king_helper_affine = ?circuit_king_helper_affine,
            circuit_king_blinded_base_projective = ?circuit_king_blinded_base_proj,
            circuit_king_blinded_base_affine = ?circuit_king_blinded_base_affine,
            "AFTER KING ALLOCATION"
        );

        let ciphertext_ace_var =
            PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
                cs.clone(),
                || {
                    tracing::debug!(
                        target: TEST_TARGET,
                        "Ace allocation closure called - returning ciphertext"
                    );
                    Ok(mock_ciphertext_ace.clone())
                },
                AllocationMode::Witness,
            )
            .unwrap();

        let player1_hidden = [
            HiddenCardVar {
                ciphertext: ciphertext_king_var,
                count: UInt8::constant(1), // Used
                witnessed_value: UInt8::constant(king_spades_idx),
            },
            HiddenCardVar {
                ciphertext: ciphertext_ace_var,
                count: UInt8::constant(1), // Used
                witnessed_value: UInt8::constant(ace_spades_idx),
            },
        ];

        // Player 1's selected cards for Royal Flush: A♠, K♠, Q♠, J♠, 10♠
        // Use 0-based indices for the selected cards, sorted in descending order by rank
        let player1_selected = [
            FpVar::constant(Fq::from(ace_spades_idx as u64)), // Ace (0-based)
            FpVar::constant(Fq::from(king_spades_idx as u64)), // King (0-based)
            FpVar::constant(Fq::from((idx_of(12, Suit::Spades) - 1) as u64)), // Queen (0-based)
            FpVar::constant(Fq::from((idx_of(11, Suit::Spades) - 1) as u64)), // Jack (0-based)
            FpVar::constant(Fq::from((idx_of(10, Suit::Spades) - 1) as u64)), // 10 (0-based)
        ];

        // Compute expected native score for Player 1's Royal Flush
        // Note: native function expects 1-based indices (1-52)
        use crate::showdown::native::verify_and_score_from_indices as native_verify;
        // Native verification expects cards sorted in descending order by rank
        let player1_cards_native = [
            idx_of(14, Suit::Spades) as u8, // Ace (1-based)
            idx_of(13, Suit::Spades) as u8, // King (1-based)
            idx_of(12, Suit::Spades) as u8, // Queen (1-based)
            idx_of(11, Suit::Spades) as u8, // Jack (1-based)
            idx_of(10, Suit::Spades) as u8, // 10 (1-based)
        ];

        let (score_u32, tiebreak_native, score_native) =
            native_verify(HandCategory::StraightFlush, player1_cards_native);

        tracing::debug!(
            target: TEST_TARGET,
            "Native verification for Player 1 Royal Flush: score_u32={}, score_fr={:?}, tiebreak={:?}",
            score_u32, score_native, tiebreak_native
        );

        // Native function returns the packed score, not a validity code
        // For StraightFlush with Ace high, we expect: (8 << 20) | (14 << 16) = 9306112
        assert_eq!(
            score_u32, 9306112,
            "Native verification should return correct packed score for Royal Flush"
        );

        // Allocate player secret as emulated field
        let player1_secret_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(player1_keys.private_key))
                .unwrap();

        // Create mock unblinding shares (empty for this test)
        let unblinding_shares = vec![];

        // Generate LogUp challenge
        let alpha = FpVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();

        // Player 1 verification (Royal Flush)
        let (score1, _tiebreak1) = hand_reveal_showdown_gadget(
            cs.clone(),
            &community_cards,
            &player1_hidden,
            &player1_secret_var,
            &unblinding_shares,
            0, // No committee members for this test
            &player1_selected,
            HandCategoryVar::constant(HandCategory::StraightFlush),
            &alpha,
        )
        .unwrap();

        // Verify the circuit score matches the native score
        let score1_circuit = score1.value().unwrap();
        let expected_score: Fq = pack_score_field(HandCategory::StraightFlush, tiebreak_native);

        tracing::debug!(
            target: TEST_TARGET,
            "Score comparison - Circuit: {:?}, Native: {:?}, Expected: {:?}",
            score1_circuit, score_native, expected_score
        );

        // Convert native Fr score to Fq for comparison
        let score_native_fq = Fq::from(score_native.into_bigint());

        assert_eq!(
            score1_circuit, score_native_fq,
            "Circuit score should match native score for Royal Flush"
        );

        // Verify Player 1's constraints are satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Player 1's circuit constraints should be satisfied"
        );

        // Now test Player 2 with Three of a Kind (9s)
        // Create a separate constraint system for Player 2
        let cs2 = ConstraintSystem::<Fq>::new_ref();

        // Community cards for Player 2 (different count allocations)
        // Use 0-based indices
        let community_cards_p2 = [
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(10, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(0), // Not used by Player 2
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(11, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(1), // Player 2 uses as kicker
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(12, Suit::Spades) - 1) as u64)),
                count: UInt8::constant(1), // Player 2 uses as kicker
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(9, Suit::Diamonds) - 1) as u64)),
                count: UInt8::constant(1), // Player 2 uses for trips
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from((idx_of(2, Suit::Clubs) - 1) as u64)),
                count: UInt8::constant(0), // Not used
            },
        ];

        // Player 2 hidden cards: 9♠, 9♣
        // Use 0-based indices for encryption
        let nine_spades_idx = idx_of(9, Suit::Spades) - 1;
        let nine_clubs_idx = idx_of(9, Suit::Clubs) - 1;

        // Create simplified ciphertexts for Player 2 (same approach as Player 1)
        let delta_9s = Fr::rand(&mut rng);
        let player_unblinding_helper_9s = generator * delta_9s;
        let nine_spades_point = generator * Fr::from(nine_spades_idx as u64);
        let nine_spades_blinded =
            nine_spades_point + (player_unblinding_helper_9s * player2_keys.private_key);

        let mock_ciphertext_9s = PlayerAccessibleCiphertext {
            blinded_base: generator * Fr::rand(&mut rng),
            blinded_message_with_player_key: nine_spades_blinded,
            player_unblinding_helper: player_unblinding_helper_9s,
            shuffler_proofs: vec![],
        };

        let delta_9c = Fr::rand(&mut rng);
        let player_unblinding_helper_9c = generator * delta_9c;
        let nine_clubs_point = generator * Fr::from(nine_clubs_idx as u64);
        let nine_clubs_blinded =
            nine_clubs_point + (player_unblinding_helper_9c * player2_keys.private_key);

        let mock_ciphertext_9c = PlayerAccessibleCiphertext {
            blinded_base: generator * Fr::rand(&mut rng),
            blinded_message_with_player_key: nine_clubs_blinded,
            player_unblinding_helper: player_unblinding_helper_9c,
            shuffler_proofs: vec![],
        };

        // Verify decryption works
        let recovered_9s =
            recover_card_value(&mock_ciphertext_9s, player2_keys.private_key, vec![], 0)
                .expect("Failed to recover 9 spades");
        assert_eq!(recovered_9s, nine_spades_idx, "9 spades recovery failed");

        let recovered_9c =
            recover_card_value(&mock_ciphertext_9c, player2_keys.private_key, vec![], 0)
                .expect("Failed to recover 9 clubs");
        assert_eq!(recovered_9c, nine_clubs_idx, "9 clubs recovery failed");

        let ciphertext_9s_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs2.clone(),
            || Ok(mock_ciphertext_9s),
            AllocationMode::Witness,
        )
        .unwrap();

        let ciphertext_9c_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs2.clone(),
            || Ok(mock_ciphertext_9c),
            AllocationMode::Witness,
        )
        .unwrap();

        let player2_hidden = [
            HiddenCardVar {
                ciphertext: ciphertext_9s_var,
                count: UInt8::constant(1),
                witnessed_value: UInt8::constant(nine_spades_idx),
            },
            HiddenCardVar {
                ciphertext: ciphertext_9c_var,
                count: UInt8::constant(1),
                witnessed_value: UInt8::constant(nine_clubs_idx),
            },
        ];

        // Player 2's selected cards for Three of a Kind: 9♦, 9♠, 9♣, Q♠, J♠
        // Three matching cards first, then kickers in descending order
        let player2_selected = [
            FpVar::constant(Fq::from((idx_of(9, Suit::Diamonds) - 1) as u64)), // 9♦
            FpVar::constant(Fq::from(nine_spades_idx as u64)),                 // 9♠
            FpVar::constant(Fq::from(nine_clubs_idx as u64)),                  // 9♣
            FpVar::constant(Fq::from((idx_of(12, Suit::Spades) - 1) as u64)),  // Q♠ (kicker 1)
            FpVar::constant(Fq::from((idx_of(11, Suit::Spades) - 1) as u64)),  // J♠ (kicker 2)
        ];

        let player2_secret_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs2.clone(), || Ok(player2_keys.private_key))
                .unwrap();

        // Generate a new LogUp challenge for Player 2's constraint system
        let alpha2 = FpVar::new_witness(cs2.clone(), || Ok(Fq::rand(&mut rng))).unwrap();

        let (score2, _tiebreak2) = hand_reveal_showdown_gadget(
            cs2.clone(),
            &community_cards_p2,
            &player2_hidden,
            &player2_secret_var,
            &unblinding_shares,
            0,
            &player2_selected,
            HandCategoryVar::constant(HandCategory::ThreeOfAKind),
            &alpha2,
        )
        .unwrap();

        // Verify Player 2's constraints are satisfied
        assert!(
            cs2.is_satisfied().unwrap(),
            "Player 2's circuit constraints should be satisfied"
        );

        // Verify Player 1 (Royal Flush) beats Player 2 (Three of a Kind)
        let score1_val = score1.value().unwrap();
        let score2_val = score2.value().unwrap();

        tracing::debug!(
            target: TEST_TARGET,
            player1_royal_flush_score = ?score1_val,
            player2_three_of_kind_score = ?score2_val,
            "Player scores"
        );

        // Royal Flush should have a much higher score than Three of a Kind
        assert!(
            score1_val > score2_val,
            "Royal Flush should beat Three of a Kind"
        );

        // Verify the score matches expected native computation for Royal Flush
        // Royal Flush is a straight flush with high card Ace (14)
        let expected_royal_flush_score: Fq =
            pack_score_field(HandCategory::StraightFlush, [14, 0, 0, 0, 0]);

        // The circuit should produce the same score
        // Note: Due to the mock setup, exact score matching might need adjustment
        tracing::debug!(
            "Expected Royal Flush score: {:?}",
            expected_royal_flush_score
        );
    }

    #[test]
    fn test_invalid_card_selection_fails() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Setup community cards without any Aces
        let community_cards = [
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(2, Suit::Clubs) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(3, Suit::Diamonds) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(4, Suit::Hearts) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(5, Suit::Spades) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(6, Suit::Clubs) as u64)),
                count: UInt8::constant(1),
            },
        ];

        // Hidden cards also without Aces (7♣, 8♦)
        let generator = G1Projective::generator();
        let seven_clubs_idx = idx_of(7, Suit::Clubs);
        let eight_diamonds_idx = idx_of(8, Suit::Diamonds);

        // Create properly formed encrypted cards for invalid selection test
        let delta_invalid = Fr::rand(&mut rng);
        let player_unblinding_helper_invalid = generator * delta_invalid;
        let player_secret_invalid = Fr::rand(&mut rng);

        let seven_clubs_point = generator * Fr::from(seven_clubs_idx as u64);
        let seven_clubs_blinded =
            seven_clubs_point + (player_unblinding_helper_invalid * player_secret_invalid);

        let mock_ciphertext_7 = PlayerAccessibleCiphertext {
            blinded_base: generator * Fr::rand(&mut rng),
            blinded_message_with_player_key: seven_clubs_blinded,
            player_unblinding_helper: player_unblinding_helper_invalid,
            shuffler_proofs: vec![],
        };

        let eight_diamonds_point = generator * Fr::from(eight_diamonds_idx as u64);
        let eight_diamonds_blinded =
            eight_diamonds_point + (player_unblinding_helper_invalid * player_secret_invalid);

        let mock_ciphertext_8 = PlayerAccessibleCiphertext {
            blinded_base: generator * Fr::rand(&mut rng),
            blinded_message_with_player_key: eight_diamonds_blinded,
            player_unblinding_helper: player_unblinding_helper_invalid,
            shuffler_proofs: vec![],
        };

        let ciphertext_7_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            || Ok(mock_ciphertext_7),
            AllocationMode::Witness,
        )
        .unwrap();

        let ciphertext_8_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            || Ok(mock_ciphertext_8),
            AllocationMode::Witness,
        )
        .unwrap();

        let hidden_cards = [
            HiddenCardVar {
                ciphertext: ciphertext_7_var,
                count: UInt8::constant(0), // Not used
                witnessed_value: UInt8::constant(seven_clubs_idx),
            },
            HiddenCardVar {
                ciphertext: ciphertext_8_var,
                count: UInt8::constant(0), // Not used
                witnessed_value: UInt8::constant(eight_diamonds_idx),
            },
        ];

        // Try to select an Ace that isn't available (invalid!)
        let invalid_selected = [
            FpVar::constant(Fq::from(idx_of(14, Suit::Spades) as u64)), // Ace not available!
            FpVar::constant(Fq::from(idx_of(2, Suit::Clubs) as u64)),
            FpVar::constant(Fq::from(idx_of(3, Suit::Diamonds) as u64)),
            FpVar::constant(Fq::from(idx_of(4, Suit::Hearts) as u64)),
            FpVar::constant(Fq::from(idx_of(5, Suit::Spades) as u64)),
        ];

        let player_secret = Fr::rand(&mut rng);
        let player_secret_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(player_secret)).unwrap();
        let unblinding_shares = vec![];
        let alpha = FpVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();

        let result = hand_reveal_showdown_gadget(
            cs.clone(),
            &community_cards,
            &hidden_cards,
            &player_secret_var,
            &unblinding_shares,
            0,
            &invalid_selected,
            HandCategoryVar::constant(HandCategory::HighCard),
            &alpha,
        );

        // Should fail LogUp verification or constraint satisfaction
        assert!(
            result.is_err() || !cs.is_satisfied().unwrap(),
            "Should fail when selecting unavailable card"
        );
    }

    #[test]
    fn test_duplicate_card_usage_fails() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Setup where we try to use the same card twice
        let ace_spades_idx = idx_of(14, Suit::Spades);

        let community_cards = [
            CommunityCardVar {
                value: FpVar::constant(Fq::from(ace_spades_idx as u64)),
                count: UInt8::constant(1), // Can only use once!
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(2, Suit::Clubs) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(3, Suit::Diamonds) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(4, Suit::Hearts) as u64)),
                count: UInt8::constant(1),
            },
            CommunityCardVar {
                value: FpVar::constant(Fq::from(idx_of(5, Suit::Spades) as u64)),
                count: UInt8::constant(0),
            },
        ];

        let generator = G1Projective::generator();
        let six_clubs_idx = idx_of(6, Suit::Clubs);
        let seven_diamonds_idx = idx_of(7, Suit::Diamonds);

        let mock_ciphertext_6 = PlayerAccessibleCiphertext {
            blinded_base: generator,
            blinded_message_with_player_key: generator * Fr::from(six_clubs_idx as u64),
            player_unblinding_helper: generator,
            shuffler_proofs: vec![],
        };

        let mock_ciphertext_7 = PlayerAccessibleCiphertext {
            blinded_base: generator,
            blinded_message_with_player_key: generator * Fr::from(seven_diamonds_idx as u64),
            player_unblinding_helper: generator,
            shuffler_proofs: vec![],
        };

        let ciphertext_6_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            || Ok(mock_ciphertext_6),
            AllocationMode::Witness,
        )
        .unwrap();

        let ciphertext_7_var = PlayerAccessibleCiphertextVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            || Ok(mock_ciphertext_7),
            AllocationMode::Witness,
        )
        .unwrap();

        let hidden_cards = [
            HiddenCardVar {
                ciphertext: ciphertext_6_var,
                count: UInt8::constant(0),
                witnessed_value: UInt8::constant(six_clubs_idx),
            },
            HiddenCardVar {
                ciphertext: ciphertext_7_var,
                count: UInt8::constant(1),
                witnessed_value: UInt8::constant(seven_diamonds_idx),
            },
        ];

        // Try to use A♠ twice (invalid!)
        let invalid_selected = [
            FpVar::constant(Fq::from(ace_spades_idx as u64)), // First use
            FpVar::constant(Fq::from(ace_spades_idx as u64)), // Second use - invalid!
            FpVar::constant(Fq::from(idx_of(2, Suit::Clubs) as u64)),
            FpVar::constant(Fq::from(idx_of(3, Suit::Diamonds) as u64)),
            FpVar::constant(Fq::from(idx_of(4, Suit::Hearts) as u64)),
        ];

        let player_secret = Fr::rand(&mut rng);
        let player_secret_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(player_secret)).unwrap();
        let unblinding_shares = vec![];
        let alpha = FpVar::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();

        let result = hand_reveal_showdown_gadget(
            cs.clone(),
            &community_cards,
            &hidden_cards,
            &player_secret_var,
            &unblinding_shares,
            0,
            &invalid_selected,
            HandCategoryVar::constant(HandCategory::OnePair),
            &alpha,
        );

        // Should fail LogUp multiplicity check
        assert!(
            result.is_err() || !cs.is_satisfied().unwrap(),
            "Should fail when using same card twice"
        );
    }
}
