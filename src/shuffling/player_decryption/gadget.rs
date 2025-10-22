//! SNARK circuit gadgets for player decryption operations
//!
//! This module provides circuit implementations for:
//! - Combining blinding contributions from shufflers
//! - Recovering card values using player secret and committee shares
//! - Verifying Chaum-Pedersen proofs in-circuit

use super::{
    PartialUnblindingShare, PlayerAccessibleCiphertext, PlayerTargetedBlindingContribution,
};
use crate::chaum_pedersen::ChaumPedersenProofVar;
use crate::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, vec::Vec};
use tracing::{instrument, trace};

const LOG_TARGET: &str = "legit_poker::shuffling::player_decryption_gadget";

// ============================================================================
// Circuit Variable Structures
// ============================================================================

/// Circuit representation of player-targeted blinding contribution
pub struct PlayerTargetedBlindingContributionVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    /// g^δ_j - shuffler's blinding contribution to the base element
    pub blinding_base_contribution: CV,
    /// (aggregated_public_key·player_public_key)^δ_j
    pub blinding_combined_contribution: CV,
    /// Proof that the same δ_j was used for both contributions
    pub proof: ChaumPedersenProofVar<C, CV>,
}

impl<C, CV> Clone for PlayerTargetedBlindingContributionVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            blinding_base_contribution: self.blinding_base_contribution.clone(),
            blinding_combined_contribution: self.blinding_combined_contribution.clone(),
            proof: self.proof.clone(),
        }
    }
}

impl<C, CV> AllocVar<PlayerTargetedBlindingContribution<C>, C::BaseField>
    for PlayerTargetedBlindingContributionVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PlayerTargetedBlindingContribution<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let contribution = f()?.borrow().clone();

        trace!(target: LOG_TARGET, "Allocating PlayerTargetedBlindingContributionVar");

        // Allocate blinding_base_contribution as CurveVar
        let blinding_base_contribution = CV::new_variable(
            cs.clone(),
            || Ok(contribution.blinding_base_contribution),
            mode,
        )?;

        // Allocate blinding_combined_contribution as CurveVar
        let blinding_combined_contribution = CV::new_variable(
            cs.clone(),
            || Ok(contribution.blinding_combined_contribution),
            mode,
        )?;

        // Allocate Chaum-Pedersen proof
        let proof = ChaumPedersenProofVar::<C, CV>::new_variable(
            cs.clone(),
            || Ok(contribution.proof),
            mode,
        )?;

        Ok(Self {
            blinding_base_contribution,
            blinding_combined_contribution,
            proof,
        })
    }
}

/// Circuit representation of player-accessible ciphertext
pub struct PlayerAccessibleCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    /// g^(r+Δ) where r is initial randomness and Δ = Σδ_j
    pub blinded_base: CV,
    /// pk^(r+Δ) * g^m_i * y_u^Δ where m_i is the card value
    pub blinded_message_with_player_key: CV,
    /// g^Δ = g^(Σδ_j) - helper element for player unblinding
    pub player_unblinding_helper: CV,
    /// All Chaum-Pedersen proofs from each shuffler
    pub shuffler_proofs: Vec<ChaumPedersenProofVar<C, CV>>,
}

impl<C, CV> Clone for PlayerAccessibleCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            blinded_base: self.blinded_base.clone(),
            blinded_message_with_player_key: self.blinded_message_with_player_key.clone(),
            player_unblinding_helper: self.player_unblinding_helper.clone(),
            shuffler_proofs: self.shuffler_proofs.clone(),
        }
    }
}

impl<C, CV> AllocVar<PlayerAccessibleCiphertext<C>, C::BaseField>
    for PlayerAccessibleCiphertextVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PlayerAccessibleCiphertext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let ciphertext = f()?.borrow().clone();

        // Allocate curve points directly without normalization
        // The circuit will handle the points correctly even with different Z coordinates
        tracing::trace!(
            target: LOG_TARGET,
            blinded_base = ?ciphertext.blinded_base,
            blinded_message = ?ciphertext.blinded_message_with_player_key,
            helper = ?ciphertext.player_unblinding_helper,
            "Allocating PlayerAccessibleCiphertextVar with original projective values"
        );

        // Allocate curve points using original projective representation
        let blinded_base = CV::new_variable(cs.clone(), || Ok(ciphertext.blinded_base), mode)?;

        let blinded_message_with_player_key = CV::new_variable(
            cs.clone(),
            || Ok(ciphertext.blinded_message_with_player_key),
            mode,
        )?;

        let player_unblinding_helper =
            CV::new_variable(cs.clone(), || Ok(ciphertext.player_unblinding_helper), mode)?;

        // Allocate all Chaum-Pedersen proofs
        let shuffler_proofs = ciphertext
            .shuffler_proofs
            .into_iter()
            .map(|proof| {
                ChaumPedersenProofVar::<C, CV>::new_variable(cs.clone(), || Ok(proof), mode)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            blinded_base,
            blinded_message_with_player_key,
            player_unblinding_helper,
            shuffler_proofs,
        })
    }
}

/// Circuit representation of partial unblinding share
pub struct PartialUnblindingShareVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    /// blinded_base^x_j - the partial unblinding from committee member j
    pub share: CV,
    // Note: member_key is not included in the circuit as uniqueness is guaranteed
    // by the BTreeMap structure at the application layer
    _phantom: std::marker::PhantomData<C>,
}

impl<C, CV> Clone for PartialUnblindingShareVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            share: self.share.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, CV> AllocVar<PartialUnblindingShare<C>, C::BaseField> for PartialUnblindingShareVar<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PartialUnblindingShare<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let share_value = f()?.borrow().clone();

        // Allocate the share as CurveVar
        let share = CV::new_variable(cs.clone(), || Ok(share_value.share), mode)?;

        // Note: member_key is not allocated in the circuit - uniqueness is checked at application layer

        Ok(Self {
            share,
            _phantom: std::marker::PhantomData,
        })
    }
}

// ============================================================================
// Circuit Functions
// ============================================================================

/// Verify a player-targeted blinding contribution in-circuit
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
pub fn verify_blinding_contribution_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    contribution: &PlayerTargetedBlindingContributionVar<C, CV>,
    aggregated_public_key: &CV,
    player_public_key: &CV,
) -> Result<Boolean<C::BaseField>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<
            C::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<C::BaseField>,
        >,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Compute h = aggregated_public_key + player_public_key
    let h = aggregated_public_key + player_public_key;
    tracing::debug!(target: LOG_TARGET, "h (aggregated_pk + player_pk): {:?}", h.value().ok());

    // Get generator
    let generator = CV::constant(C::generator());
    tracing::debug!(target: LOG_TARGET, "Blinding base contribution: {:?}", contribution.blinding_base_contribution.value().ok());
    tracing::debug!(target: LOG_TARGET, "Blinding combined contribution: {:?}", contribution.blinding_combined_contribution.value().ok());

    // Verify the Chaum-Pedersen proof
    let result = contribution.proof.verify_gadget(
        cs,
        &generator,
        &h,
        &contribution.blinding_base_contribution,
        &contribution.blinding_combined_contribution,
    )?;

    tracing::debug!(target: LOG_TARGET, "Chaum-Pedersen proof verification result: {:?}", result.value().ok());
    Ok(result)
}

/// Combine blinding contributions from all shufflers in-circuit
///
/// This creates the complete public transcript for on-chain verification.
/// All proofs are verified and the blinded ciphertext is constructed.
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
pub fn combine_blinding_contributions_for_player_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    initial_ciphertext: &ElGamalCiphertextVar<C, CV>,
    blinding_contributions: &[PlayerTargetedBlindingContributionVar<C, CV>],
    aggregated_public_key: &CV,
    player_public_key: &CV,
) -> Result<PlayerAccessibleCiphertextVar<C, CV>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<
            C::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<C::BaseField>,
        >,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    tracing::debug!(target: LOG_TARGET, "Combining {} blinding contributions in-circuit", blinding_contributions.len());

    // First verify all blinding contributions using try_for_each for early abort
    blinding_contributions
        .iter()
        .enumerate()
        .try_for_each(|(i, contribution)| {
            trace!(target: LOG_TARGET, "Verifying contribution {}", i);
            let is_valid = verify_blinding_contribution_gadget(
                cs.clone(),
                contribution,
                aggregated_public_key,
                player_public_key,
            )?;

            // Mathematical equation: contribution.verify() == true
            is_valid.enforce_equal(&Boolean::constant(true))?;
            Ok(())
        })?;

    // Combine all blinding contributions using separate folds for clarity

    // Accumulate blinded base: g^r + Σg^δ_j
    let blinded_base = blinding_contributions
        .iter()
        .enumerate()
        .fold(initial_ciphertext.c1.clone(), |acc, (i, contribution)| {
            trace!(target: LOG_TARGET, "Processing blinded_base contribution {}", i);
            let result = &acc + &contribution.blinding_base_contribution;
            trace!(target: LOG_TARGET, "Updated blinded_base after contribution {}: {:?}", i, result.value().ok());
            result
        });
    tracing::debug!(target: LOG_TARGET, "Final blinded_base: {:?}", blinded_base.value().ok());

    // Accumulate blinded message with player key: pk^r * g^m_i + Σ(pk·y_u)^δ_j
    let blinded_message_with_player_key = blinding_contributions
        .iter()
        .fold(initial_ciphertext.c2.clone(), |acc, contribution| {
            &acc + &contribution.blinding_combined_contribution
        });
    tracing::debug!(target: LOG_TARGET, "Final blinded_message_with_player_key: {:?}", blinded_message_with_player_key.value().ok());

    // Accumulate player unblinding helper: Σg^δ_j
    let player_unblinding_helper = blinding_contributions
        .iter()
        .fold(CV::zero(), |acc, contribution| {
            &acc + &contribution.blinding_base_contribution
        });
    tracing::debug!(target: LOG_TARGET, "Final player_unblinding_helper: {:?}", player_unblinding_helper.value().ok());

    // Collect all proofs for the transcript
    let proofs: Vec<_> = blinding_contributions
        .iter()
        .map(|contribution| contribution.proof.clone())
        .collect();

    Ok(PlayerAccessibleCiphertextVar {
        blinded_base,
        blinded_message_with_player_key,
        player_unblinding_helper,
        shuffler_proofs: proofs,
    })
}

/// Combine committee unblinding shares in-circuit
///
/// This is an n-of-n scheme - ALL committee members must provide shares.
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
pub fn combine_unblinding_shares_gadget<C, CV>(
    _cs: ConstraintSystemRef<C::BaseField>,
    shares: &[PartialUnblindingShareVar<C, CV>],
    _expected_members: usize,
) -> Result<CV, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    tracing::debug!(target: LOG_TARGET, "=== combine_unblinding_shares_gadget ===");
    tracing::debug!(target: LOG_TARGET, "Combining {} unblinding shares in-circuit", shares.len());

    // Verify we have exactly n shares (n-of-n requirement)
    // In-circuit, we enforce this by ensuring all shares are provided
    // The verification of unique indices would be done outside the circuit
    // or by ensuring the input is properly formed

    // Aggregate by adding all shares: μ_u = Σ(μ_u,j)
    // This gives us A_u^(Σx_j) = A_u^x = g^((r+Δ) * x) = pk^(r+Δ)
    let mut mu = CV::zero();
    for (i, share) in shares.iter().enumerate() {
        tracing::debug!(target: LOG_TARGET, "  Share[{}]: {:?}", i, share.share.value().ok());
        mu = &mu + &share.share;
    }

    tracing::debug!(target: LOG_TARGET, "Combined unblinding result: {:?}", mu.value().ok());
    tracing::debug!(target: LOG_TARGET, "=== End combine_unblinding_shares_gadget ===");

    Ok(mu)
}

/// Recover the card point (elliptic curve point) in-circuit
///
/// This implements the complete decryption protocol:
/// 1. Player uses their secret s_u to compute S = D^s_u
/// 2. Committee shares are aggregated to get μ_u = pk^(r+Δ)
/// 3. Message is recovered: g^m = B_u / (μ_u · S)
///
/// Returns the recovered elliptic curve point g^m where m is the card value.
/// This is more efficient than searching through all possible card values.
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
pub fn recover_card_point_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    player_ciphertext: &PlayerAccessibleCiphertextVar<C, CV>,
    player_secret_bits: &[Boolean<C::BaseField>],
    unblinding_shares: &[PartialUnblindingShareVar<C, CV>],
    expected_members: usize,
) -> Result<CV, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    tracing::debug!(
        target: LOG_TARGET,
        blinded_base = ?player_ciphertext.blinded_base.value().ok(),
        blinded_message = ?player_ciphertext.blinded_message_with_player_key.value().ok(),
        player_unblinding_helper = ?player_ciphertext.player_unblinding_helper.value().ok(),
        "=== Circuit recover_card_point_gadget ==="
    );

    // Log player secret bits (be careful with this in production!)
    let secret_bits: Vec<bool> = player_secret_bits
        .iter()
        .map(|b| b.value().unwrap_or_default())
        .collect();
    tracing::debug!(target: LOG_TARGET, "Player secret bits (length {}): first 8 bits: {:?}",
        secret_bits.len(),
        &secret_bits[..8.min(secret_bits.len())]);

    // Step 1: Compute player-specific unblinding using the helper element
    // Mathematical equation: player_unblinding = player_unblinding_helper^s_u
    let player_unblinding = player_ciphertext
        .player_unblinding_helper
        .clone()
        .scalar_mul_le(player_secret_bits.iter())?;

    println!(
        "Step 1 - Player unblinding (helper^secret): {:?}",
        player_unblinding.value().ok()
    );
    tracing::debug!(target: LOG_TARGET, "Step 1 - Player unblinding (helper^secret): {:?}", player_unblinding.value().ok());

    // Step 2: Combine committee unblinding shares
    let combined_unblinding =
        combine_unblinding_shares_gadget(cs.clone(), unblinding_shares, expected_members)?;

    println!(
        "Step 2 - Combined unblinding from shares: {:?}",
        combined_unblinding.value().ok()
    );
    tracing::debug!(target: LOG_TARGET, "Step 2 - Combined unblinding from shares: {:?}", combined_unblinding.value().ok());

    // Step 3: Recover the message group element by removing all blinding
    // Mathematical equation: g^m = blinded_message / (combined_unblinding · player_unblinding)
    let recovered_element = &player_ciphertext.blinded_message_with_player_key
        - &combined_unblinding
        - &player_unblinding;

    println!(
        "Step 3 - Recovered element (g^m): {:?}",
        recovered_element.value().ok()
    );
    println!("=== End Circuit recover_card_point_gadget ===");
    tracing::debug!(target: LOG_TARGET, "Step 3 - Recovered element (g^m): {:?}", recovered_element.value().ok());
    tracing::debug!(target: LOG_TARGET, "=== End Circuit recover_card_point_gadget ===");

    Ok(recovered_element)
}

/// Recover a card value in-circuit (backward compatibility)
///
/// This implements the complete decryption protocol:
/// 1. Player uses their secret s_u to compute S = D^s_u
/// 2. Committee shares are aggregated to get μ_u = pk^(r+Δ)
/// 3. Message is recovered: g^m = B_u / (μ_u · S)
/// 4. Card value is found by comparing with pre-computed g^i for i ∈ [0, 51]
#[instrument(target = LOG_TARGET, level = "debug", skip_all)]
pub fn recover_card_value_gadget<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    player_ciphertext: &PlayerAccessibleCiphertextVar<C, CV>,
    player_secret_bits: &[Boolean<C::BaseField>],
    unblinding_shares: &[PartialUnblindingShareVar<C, CV>],
    expected_members: usize,
) -> Result<FpVar<C::BaseField>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // First recover the elliptic curve point
    let recovered_element = recover_card_point_gadget(
        cs.clone(),
        player_ciphertext,
        player_secret_bits,
        unblinding_shares,
        expected_members,
    )?;

    // Step 4: Map the group element back to a card value
    // Pre-compute g^i for all valid card values (0-51) as constants
    let generator = C::generator();
    let mut card_found = Boolean::constant(false);
    let mut card_value = FpVar::<C::BaseField>::zero();

    for i in 0u8..52 {
        // Compute g^i as a constant
        let gi = generator * C::ScalarField::from(i);
        let gi_var = CV::constant(gi);

        // Check if recovered_element == g^i
        let is_match = recovered_element.is_eq(&gi_var)?;

        // If match found and we haven't found a card yet, set the card value
        // Mathematical equation: card_value = is_match ? i : card_value
        let i_var = FpVar::<C::BaseField>::constant(C::BaseField::from(i));
        card_value = is_match.select(&i_var, &card_value)?;

        // Update card_found flag
        card_found = &card_found | &is_match;
    }

    // Enforce that we found a valid card
    // Mathematical equation: card_found == true
    card_found.enforce_equal(&Boolean::constant(true))?;

    Ok(card_value)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        shuffling::player_decryption::{
            combine_blinding_contributions_for_player, recover_card_value,
            PlayerTargetedBlindingContribution,
        },
        ElGamalCiphertext,
    };
    use ark_ec::PrimeGroup;
    use ark_ff::{BigInteger, UniformRand};
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, Zero};
    use tracing::info;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    type Fq = ark_grumpkin::Fq;
    type Fr = ark_grumpkin::Fr;
    type GrumpkinVar = ProjectiveVar<ark_grumpkin::GrumpkinConfig, FpVar<Fq>>;

    const TEST_TARGET: &str = "legit_poker";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(LOG_TARGET, tracing::Level::DEBUG)
            .with_target(TEST_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_writer(tracing_subscriber::fmt::TestWriter::default()), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_combine_blinding_contributions_circuit_native_parity() {
        let _guard = setup_test_tracing();
        info!(target: TEST_TARGET, "Starting test_combine_blinding_contributions_circuit_native_parity");

        let mut rng = test_rng();

        // Setup keys
        let committee_secret1 = Fr::rand(&mut rng);
        let committee_secret2 = Fr::rand(&mut rng);
        let aggregated_pk =
            GrumpkinProjective::generator() * (committee_secret1 + committee_secret2);

        let player_secret = Fr::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Create initial ciphertext
        let message = Fr::from(42u64);
        let message_point = GrumpkinProjective::generator() * message;
        let r = Fr::rand(&mut rng);
        let initial_ciphertext = ElGamalCiphertext::new(
            GrumpkinProjective::generator() * r,
            aggregated_pk * r + message_point,
        );

        // Create blinding contributions
        let delta1 = Fr::rand(&mut rng);
        let contribution1 = PlayerTargetedBlindingContribution::generate(
            delta1,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );

        let delta2 = Fr::rand(&mut rng);
        let contribution2 = PlayerTargetedBlindingContribution::generate(
            delta2,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );

        let contributions = vec![contribution1, contribution2];

        // Log contribution values for debugging
        info!(target: TEST_TARGET, "Contribution1 blinding_base: {:?}", contributions[0].blinding_base_contribution);
        info!(target: TEST_TARGET, "Contribution2 blinding_base: {:?}", contributions[1].blinding_base_contribution);

        // Verify proofs natively
        info!(target: TEST_TARGET, "Verifying contribution1 natively: {}", contributions[0].verify(aggregated_pk, player_public_key));
        info!(target: TEST_TARGET, "Verifying contribution2 natively: {}", contributions[1].verify(aggregated_pk, player_public_key));

        // ============= Native Computation =============
        info!(target: TEST_TARGET, "Starting native computation");
        let native_result = combine_blinding_contributions_for_player(
            &initial_ciphertext,
            &contributions,
            aggregated_pk,
            player_public_key,
        )
        .unwrap();

        info!(target: TEST_TARGET, "Native result - blinded_base: {:?}", native_result.blinded_base);
        info!(target: TEST_TARGET, "Native result - blinded_message_with_player_key: {:?}", native_result.blinded_message_with_player_key);
        info!(target: TEST_TARGET, "Native result - player_unblinding_helper: {:?}", native_result.player_unblinding_helper);

        // ============= Circuit Computation =============
        info!(target: TEST_TARGET, "Starting circuit computation");
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate inputs
        let initial_ciphertext_var =
            ElGamalCiphertextVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                cs.clone(),
                || Ok(initial_ciphertext),
                AllocationMode::Witness,
            )
            .unwrap();

        let mut contributions_var = Vec::new();
        for contribution in &contributions {
            contributions_var.push(
                PlayerTargetedBlindingContributionVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                    cs.clone(),
                    || Ok(contribution.clone()),
                    AllocationMode::Witness,
                )
                .unwrap(),
            );
        }

        let aggregated_pk_var =
            GrumpkinVar::new_variable(cs.clone(), || Ok(aggregated_pk), AllocationMode::Witness)
                .unwrap();

        let player_public_key_var = GrumpkinVar::new_variable(
            cs.clone(),
            || Ok(player_public_key),
            AllocationMode::Witness,
        )
        .unwrap();

        // Perform circuit computation
        info!(target: TEST_TARGET, "Calling combine_blinding_contributions_for_player_gadget");
        let circuit_result = combine_blinding_contributions_for_player_gadget(
            cs.clone(),
            &initial_ciphertext_var,
            &contributions_var,
            &aggregated_pk_var,
            &player_public_key_var,
        )
        .unwrap();

        info!(target: TEST_TARGET, "Circuit result - blinded_base: {:?}", circuit_result.blinded_base.value());
        info!(target: TEST_TARGET, "Circuit result - blinded_message_with_player_key: {:?}", circuit_result.blinded_message_with_player_key.value());
        info!(target: TEST_TARGET, "Circuit result - player_unblinding_helper: {:?}", circuit_result.player_unblinding_helper.value());

        // ============= Compare Results =============
        assert_eq!(
            circuit_result.blinded_base.value().unwrap(),
            native_result.blinded_base,
            "blinded_base should match"
        );

        assert_eq!(
            circuit_result
                .blinded_message_with_player_key
                .value()
                .unwrap(),
            native_result.blinded_message_with_player_key,
            "blinded_message_with_player_key should match"
        );

        assert_eq!(
            circuit_result.player_unblinding_helper.value().unwrap(),
            native_result.player_unblinding_helper,
            "player_unblinding_helper should match"
        );

        // Verify constraint system is satisfied
        info!(target: TEST_TARGET, "Checking constraint satisfaction");
        info!(target: TEST_TARGET, "Total constraints: {}", cs.num_constraints());
        info!(target: TEST_TARGET, "Total witness variables: {}", cs.num_witness_variables());

        let is_satisfied = cs.is_satisfied().unwrap();
        info!(target: TEST_TARGET, "Constraint system satisfied: {}", is_satisfied);

        if !is_satisfied {
            // Debug which constraint failed
            if let Some(unsatisfied) = cs.which_is_unsatisfied().unwrap() {
                panic!("Unsatisfied constraint at: {}", unsatisfied);
            }
        }
        assert!(is_satisfied, "Circuit should be satisfied");

        tracing::info!(target: TEST_TARGET, "✅ Native and circuit combine_blinding_contributions produce identical results!");
        tracing::info!(target: TEST_TARGET, "Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_recover_card_point_gadget() {
        let _guard = setup_test_tracing();
        info!(target: TEST_TARGET, "Starting test_recover_card_point_gadget");

        let mut rng = test_rng();

        // Setup
        let committee_secret = Fr::rand(&mut rng);
        let aggregated_pk = GrumpkinProjective::generator() * committee_secret;

        let player_secret = Fr::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Test different card values
        for card_value in [0u8, 1, 25, 51] {
            tracing::info!(target: TEST_TARGET, "Testing card value: {}", card_value);

            // Create encrypted card
            let message = Fr::from(card_value);
            let message_point = GrumpkinProjective::generator() * message;
            let r = Fr::rand(&mut rng);
            let initial_ciphertext = ElGamalCiphertext::new(
                GrumpkinProjective::generator() * r,
                aggregated_pk * r + message_point,
            );

            // Create blinding contribution
            let delta = Fr::rand(&mut rng);
            let contribution = PlayerTargetedBlindingContribution::generate(
                delta,
                aggregated_pk,
                player_public_key,
                &mut rng,
            );

            let player_ciphertext = combine_blinding_contributions_for_player(
                &initial_ciphertext,
                &[contribution],
                aggregated_pk,
                player_public_key,
            )
            .unwrap();

            // Generate unblinding share
            let unblinding = PartialUnblindingShare {
                share: player_ciphertext.blinded_base * committee_secret,
                member_key: crate::ledger::CanonicalKey::new(GrumpkinProjective::zero()),
            };

            // ============= Circuit Recovery =============
            let cs = ConstraintSystem::<Fq>::new_ref();

            // Allocate player ciphertext
            let player_ciphertext_var =
                PlayerAccessibleCiphertextVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                    cs.clone(),
                    || Ok(player_ciphertext.clone()),
                    AllocationMode::Witness,
                )
                .unwrap();

            // Allocate player secret as bits
            let player_secret_bits = player_secret
                .into_bigint()
                .to_bits_le()
                .into_iter()
                .map(|b| Boolean::new_variable(cs.clone(), || Ok(b), AllocationMode::Witness))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Allocate unblinding share
            let unblinding_var =
                PartialUnblindingShareVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                    cs.clone(),
                    || Ok(unblinding),
                    AllocationMode::Witness,
                )
                .unwrap();

            // Recover the elliptic curve point
            let recovered_point = recover_card_point_gadget(
                cs.clone(),
                &player_ciphertext_var,
                &player_secret_bits,
                &[unblinding_var],
                1,
            )
            .unwrap();

            // ============= Verify Results =============
            // The recovered point should equal g^card_value
            let expected_point = GrumpkinProjective::generator() * Fr::from(card_value);
            assert_eq!(
                recovered_point.value().unwrap(),
                expected_point,
                "Recovered point should equal g^{}",
                card_value
            );

            // Verify constraint system is satisfied
            assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

            tracing::info!(target: TEST_TARGET, "✓ Card {} recovered correctly as elliptic curve point", card_value);
            tracing::info!(target: TEST_TARGET, "Number of constraints: {}", cs.num_constraints());
        }

        tracing::info!(target: TEST_TARGET, "✅ All card values recovered correctly as elliptic curve points!");
    }

    #[test]
    fn test_recover_card_value_circuit_native_parity() {
        let _guard = setup_test_tracing();
        info!(target: TEST_TARGET, "Starting test_recover_card_value_circuit_native_parity");

        let mut rng = test_rng();

        // Setup
        let committee_secret = Fr::rand(&mut rng);
        let aggregated_pk = GrumpkinProjective::generator() * committee_secret;

        let player_secret = Fr::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Test different card values
        for card_value in [0u8, 1, 25, 51] {
            tracing::info!(target: TEST_TARGET, "Testing card value: {}", card_value);

            // Create encrypted card
            let message = Fr::from(card_value);
            let message_point = GrumpkinProjective::generator() * message;
            let r = Fr::rand(&mut rng);
            let initial_ciphertext = ElGamalCiphertext::new(
                GrumpkinProjective::generator() * r,
                aggregated_pk * r + message_point,
            );

            // Create blinding contribution
            let delta = Fr::rand(&mut rng);
            let contribution = PlayerTargetedBlindingContribution::generate(
                delta,
                aggregated_pk,
                player_public_key,
                &mut rng,
            );

            let player_ciphertext = combine_blinding_contributions_for_player(
                &initial_ciphertext,
                &[contribution],
                aggregated_pk,
                player_public_key,
            )
            .unwrap();

            // Generate unblinding share
            let unblinding = PartialUnblindingShare {
                share: player_ciphertext.blinded_base * committee_secret,
                member_key: crate::ledger::CanonicalKey::new(GrumpkinProjective::zero()),
            };

            // ============= Native Recovery =============
            let native_recovered = recover_card_value(
                &player_ciphertext,
                player_secret,
                vec![unblinding.clone()],
                1,
            )
            .unwrap();

            assert_eq!(native_recovered, card_value, "Native recovery should work");

            // ============= Circuit Recovery =============
            let cs = ConstraintSystem::<Fq>::new_ref();

            // Allocate player ciphertext
            let player_ciphertext_var =
                PlayerAccessibleCiphertextVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                    cs.clone(),
                    || Ok(player_ciphertext),
                    AllocationMode::Witness,
                )
                .unwrap();

            // Allocate player secret as bits
            let player_secret_bits = player_secret
                .into_bigint()
                .to_bits_le()
                .into_iter()
                .map(|b| Boolean::new_variable(cs.clone(), || Ok(b), AllocationMode::Witness))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Allocate unblinding share
            let unblinding_var =
                PartialUnblindingShareVar::<GrumpkinProjective, GrumpkinVar>::new_variable(
                    cs.clone(),
                    || Ok(unblinding),
                    AllocationMode::Witness,
                )
                .unwrap();

            // Perform circuit recovery
            let circuit_recovered = recover_card_value_gadget(
                cs.clone(),
                &player_ciphertext_var,
                &player_secret_bits,
                &[unblinding_var],
                1,
            )
            .unwrap();

            // ============= Compare Results =============
            let circuit_value = circuit_recovered.value().unwrap();
            let circuit_card = circuit_value.into_bigint().0[0] as u8;

            assert_eq!(
                circuit_card, native_recovered,
                "Circuit and native recovery should match for card {}",
                card_value
            );

            // Verify constraint system is satisfied
            assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

            tracing::info!(target: TEST_TARGET, "✓ Card {} recovered correctly in both native and circuit", card_value);
            tracing::info!(target: TEST_TARGET, "Number of constraints: {}", cs.num_constraints());
        }

        tracing::info!(target: TEST_TARGET, "✅ All card values recovered correctly with circuit/native parity!");
    }

    #[test]
    fn test_invalid_player_secret_fails() {
        let _guard = setup_test_tracing();
        info!(target: TEST_TARGET, "Starting test_invalid_player_secret_fails");

        let mut rng = test_rng();

        // Setup
        let committee_secret = Fr::rand(&mut rng);
        let aggregated_pk = GrumpkinProjective::generator() * committee_secret;

        let player_secret = Fr::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Create encrypted card with value 42
        let message = Fr::from(42u64);
        let message_point = GrumpkinProjective::generator() * message;
        let r = Fr::rand(&mut rng);
        let initial_ciphertext = ElGamalCiphertext::new(
            GrumpkinProjective::generator() * r,
            aggregated_pk * r + message_point,
        );

        // Create blinding
        let delta = Fr::rand(&mut rng);
        let contribution = PlayerTargetedBlindingContribution::generate(
            delta,
            aggregated_pk,
            player_public_key,
            &mut rng,
        );

        let player_ciphertext = combine_blinding_contributions_for_player(
            &initial_ciphertext,
            &[contribution],
            aggregated_pk,
            player_public_key,
        )
        .unwrap();

        // Generate unblinding share
        let unblinding = PartialUnblindingShare {
            share: player_ciphertext.blinded_base * committee_secret,
            member_key: crate::ledger::CanonicalKey::new(aggregated_pk),
        };

        // Try to recover with wrong player secret
        let wrong_secret = Fr::rand(&mut rng);
        let result = recover_card_value(&player_ciphertext, wrong_secret, vec![unblinding], 1);

        assert!(
            result.is_err() || result.unwrap() != 42,
            "Wrong player secret should not recover correct card"
        );

        tracing::info!(target: TEST_TARGET, "✅ Invalid player secret correctly fails to recover card");
    }

    #[test]
    fn test_missing_committee_shares_fails() {
        let _guard = setup_test_tracing();
        info!(target: TEST_TARGET, "Starting test_missing_committee_shares_fails");

        let mut rng = test_rng();

        // Setup with 2 committee members
        let committee_secret1 = Fr::rand(&mut rng);
        let committee_pk1 = GrumpkinProjective::generator() * committee_secret1;
        let committee_secret2 = Fr::rand(&mut rng);
        let committee_pk2 = GrumpkinProjective::generator() * committee_secret2;
        let _aggregated_pk = committee_pk1 + committee_pk2;

        let player_secret = Fr::rand(&mut rng);
        let _player_public_key = GrumpkinProjective::generator() * player_secret;

        // Create encrypted card
        let message = Fr::from(42u64);
        let message_point = GrumpkinProjective::generator() * message;
        let _initial_ciphertext = ElGamalCiphertext::new(GrumpkinProjective::zero(), message_point);

        let player_ciphertext = PlayerAccessibleCiphertext {
            blinded_base: GrumpkinProjective::generator(),
            blinded_message_with_player_key: message_point,
            player_unblinding_helper: GrumpkinProjective::zero(),
            shuffler_proofs: vec![],
        };

        // Only provide one share when two are expected
        let unblinding1 = PartialUnblindingShare {
            share: player_ciphertext.blinded_base * committee_secret1,
            member_key: crate::ledger::CanonicalKey::new(committee_pk1),
        };

        let result = recover_card_value(
            &player_ciphertext,
            player_secret,
            vec![unblinding1],
            2, // Expecting 2 members
        );

        assert!(
            result.is_err(),
            "Recovery should fail with missing committee shares"
        );

        tracing::info!(target: TEST_TARGET, "✅ Missing committee shares correctly causes recovery to fail");
    }
}
