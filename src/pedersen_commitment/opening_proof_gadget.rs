//! SNARK circuit gadgets for Pedersen commitment opening proof verification
//!
//! This module provides circuit implementations for verifying the scalar folding
//! link between a Pedersen commitment and a secret vector without performing
//! any curve operations inside the circuit.
//!
//! The implementation uses `EmulatedFpVar` for scalar field arithmetic, which correctly
//! handles non-native field operations when the curve's scalar field differs from the
//! circuit's base field. This allows the gadget to work correctly with curves like
//! BN254 where Fr ≠ Fq.

use super::opening_proof::PedersenCommitmentOpeningProof;
use crate::config::poseidon_config;
use crate::curve_absorb::CurveAbsorbGadget;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, FieldVar},
    groups::CurveVar,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::vec::Vec;

const LOG_TARGET: &str = "nexus_nova::shuffling::pedersen_commitment_opening_gadget";

/// SNARK representation of a Pedersen commitment opening proof
///
/// This struct contains the public transcript elements needed to verify
/// the scalar folding link in-circuit, mirroring the native proof structure.
/// Note: The commitment C is passed separately to verification functions,
/// not stored in the proof itself.
pub struct PedersenCommitmentOpeningProofVar<C, GG>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, C::BaseField>,
{
    /// Folding round commitments: (L_k, R_k) pairs
    pub folding_challenge_commitment_rounds: Vec<(GG, GG)>,
    /// Final folded message scalar
    pub a_final: EmulatedFpVar<C::ScalarField, C::BaseField>,
    /// Final folded blinding factor
    pub r_final: EmulatedFpVar<C::ScalarField, C::BaseField>,
}

impl<C, GG> Clone for PedersenCommitmentOpeningProofVar<C, GG>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, C::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            folding_challenge_commitment_rounds: self.folding_challenge_commitment_rounds.clone(),
            a_final: self.a_final.clone(),
            r_final: self.r_final.clone(),
        }
    }
}

/// Allocate opening proof variables in the constraint system
impl<C, GG> PedersenCommitmentOpeningProofVar<C, GG>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    GG: CurveVar<C, C::BaseField>,
{
    /// Create new variables for the opening proof transcript
    ///
    /// # Arguments
    /// - `cs`: Constraint system
    /// - `proof`: The opening proof containing folding rounds and final scalar
    /// - `mode`: Allocation mode (Input/Witness/Constant)
    ///
    /// Note: The commitment C should be allocated separately and passed to
    /// verification functions as a separate parameter.
    pub fn new_variable(
        cs: impl Into<Namespace<C::BaseField>>,
        proof: &PedersenCommitmentOpeningProof<C>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        // Allocate folding round commitments
        let mut rounds_var = Vec::with_capacity(proof.folding_challenge_commitment_rounds.len());
        for (left, right) in &proof.folding_challenge_commitment_rounds {
            let left_var = GG::new_variable(cs.clone(), || Ok(*left), mode)?;
            let right_var = GG::new_variable(cs.clone(), || Ok(*right), mode)?;
            rounds_var.push((left_var, right_var));
        }

        // Allocate scalar field elements as emulated field variables
        let a_final_var = EmulatedFpVar::<C::ScalarField, C::BaseField>::new_variable(
            cs.clone(),
            || Ok(proof.a_final),
            mode,
        )?;

        let r_final_var = EmulatedFpVar::<C::ScalarField, C::BaseField>::new_variable(
            cs.clone(),
            || Ok(proof.r_final),
            mode,
        )?;

        Ok(Self {
            folding_challenge_commitment_rounds: rounds_var,
            a_final: a_final_var,
            r_final: r_final_var,
        })
    }
}

/// Convenience wrapper: Verify scalar folding link with automatic padding
///
/// This function takes an arbitrary length vector, pads it to the next power of 2,
/// and then verifies the scalar folding link.
///
/// # Arguments
/// - `cs`: Constraint system
/// - `c_commit_var`: The commitment C variable (passed separately)
/// - `proof_var`: The opening proof transcript variables (public inputs)
/// - `secret_message_var`: The secret message vector variables (any length)
///
/// # Returns
/// Ok(()) if the constraint is satisfied, error otherwise
#[zk_poker_macros::track_constraints(
    target = "nexus_nova::shuffling::pedersen_commitment_opening_gadget"
)]
pub fn verify_scalar_folding_link_gadget<C, GG>(
    cs: ConstraintSystemRef<C::BaseField>,
    c_commit_var: &GG,
    proof_var: &PedersenCommitmentOpeningProofVar<C, GG>,
    secret_message_var: &[EmulatedFpVar<C::ScalarField, C::BaseField>],
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
    for<'a> &'a GG: CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
{
    // Pad the message
    let padded_message_var = pad_to_power_of_two_gadget::<C>(cs.clone(), secret_message_var)?;

    // Calculate parameters
    let padded_size = padded_message_var.len();
    let num_rounds = padded_size.trailing_zeros() as usize;

    // Call the padded version
    verify_scalar_folding_link_padded_gadget::<C, GG>(
        cs,
        c_commit_var,
        proof_var,
        &padded_message_var,
        num_rounds,
        padded_size,
    )
}

/// Pad a vector of emulated scalar field elements to the next power of two
///
/// This function mirrors the native `pad_to_power_of_two` function but operates
/// on circuit variables. It allocates zero field elements as constants to pad
/// the vector to the next power of two length.
fn pad_to_power_of_two_gadget<C>(
    cs: ConstraintSystemRef<C::BaseField>,
    vec: &[EmulatedFpVar<C::ScalarField, C::BaseField>],
) -> Result<Vec<EmulatedFpVar<C::ScalarField, C::BaseField>>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    let len = vec.len();

    // Handle edge cases
    if len == 0 {
        return Ok(vec![EmulatedFpVar::new_constant(
            cs,
            C::ScalarField::zero(),
        )?]);
    }

    if len.is_power_of_two() {
        return Ok(vec.to_vec());
    }

    // Calculate next power of two
    let next_pow2 = len.next_power_of_two();

    // Create padded vector
    let mut padded = vec.to_vec();

    // Pad with zero constants
    for _ in len..next_pow2 {
        padded.push(EmulatedFpVar::new_constant(
            cs.clone(),
            C::ScalarField::zero(),
        )?);
    }

    Ok(padded)
}

/// In-circuit scalar folding algorithm for padded vectors (powers of 2)
///
/// This gadget performs the same scalar folding as the native version but
/// inside the constraint system. It rebuilds the Fiat-Shamir challenges
/// from the public transcript and folds the secret vector accordingly.
///
/// **IMPORTANT**: This function expects the input vector to already be padded to a power of 2.
/// Use `pad_to_power_of_two_gadget` to pad the vector before calling this function.
///
/// # Arguments
/// - `cs`: Constraint system
/// - `c_commit_var`: The commitment C variable (anchoring at C itself)
/// - `folding_rounds_var`: The folding round commitment variables
/// - `secret_message_padded_var`: The secret message vector variables (MUST be padded to power of 2)
/// - `num_rounds`: Number of folding rounds (log2 of padded size)
/// - `padded_size`: The padded vector size (MUST be power of 2)
///
/// # Returns
/// The final folded scalar as a circuit variable
#[zk_poker_macros::track_constraints(
    target = "nexus_nova::shuffling::pedersen_commitment_opening_gadget"
)]
fn fold_scalars_padded_gadget<C, GG>(
    cs: ConstraintSystemRef<C::BaseField>,
    c_commit_var: &GG,
    folding_rounds_var: &[(GG, GG)],
    secret_message_padded_var: &[EmulatedFpVar<C::ScalarField, C::BaseField>],
    num_rounds: usize,
    padded_size: usize,
) -> Result<EmulatedFpVar<C::ScalarField, C::BaseField>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
    for<'a> &'a GG: CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
{
    // Verify inputs
    assert!(
        padded_size.is_power_of_two(),
        "Padded size must be power of 2"
    );
    assert_eq!(
        padded_size,
        1 << num_rounds,
        "Padded size must be 2^num_rounds"
    );
    assert_eq!(
        secret_message_padded_var.len(),
        padded_size,
        "Message must be padded to padded_size"
    );
    assert_eq!(
        folding_rounds_var.len(),
        num_rounds,
        "Number of folding rounds must equal num_rounds"
    );

    // Initialize Fiat-Shamir transcript
    let config = poseidon_config::<C::BaseField>();
    let mut transcript = PoseidonSpongeVar::new(cs.clone(), &config);

    // Absorb C into transcript (now anchored at commitment C)
    tracing::trace!(target: LOG_TARGET, "fold_scalars_gadget: Absorbing C into transcript");
    c_commit_var.curve_absorb_gadget(&mut transcript)?;

    // Start with the message vector (already padded)
    let mut a_current = secret_message_padded_var.to_vec();

    // Process each folding round
    for (round_idx, (left_var, right_var)) in folding_rounds_var.iter().enumerate() {
        tracing::trace!(target: LOG_TARGET, round = round_idx, "Processing folding round in gadget");

        // Absorb left and right commitments
        left_var.curve_absorb_gadget(&mut transcript)?;
        right_var.curve_absorb_gadget(&mut transcript)?;

        // Get challenge from transcript in base field
        let x_base_var = transcript.squeeze_field_elements(1)?[0].clone();

        tracing::trace!(
            target: LOG_TARGET,
            round_idx,
            challenge = ?x_base_var.value().unwrap(),
            "Gadget challenge for round"
        );

        // Convert base field challenge to emulated scalar field
        let x_scalar_var =
            EmulatedFpVar::<C::ScalarField, C::BaseField>::new_witness(cs.clone(), || {
                use super::opening_proof::cf_to_cs;
                let x_base = x_base_var.value()?;
                let x_scalar = cf_to_cs::<C::BaseField, C::ScalarField>(x_base);
                Ok(x_scalar)
            })?;

        // Compute inverse in emulated scalar field
        let x_inv_scalar_var = x_scalar_var.inverse()?;

        tracing::trace!(target: LOG_TARGET, "Computed challenge and inverse in gadget");

        // Split the current vector in half
        let mid = a_current.len() / 2;
        let (a_left, a_right) = a_current.split_at(mid);

        // Fold: a_{k+1}[i] = x * a_k[i] + x^{-1} * a_k[mid + i]
        let a_folded: Vec<EmulatedFpVar<C::ScalarField, C::BaseField>> = a_left
            .iter()
            .zip(a_right.iter())
            .enumerate()
            .map(|(i, (al, ar))| -> Result<_, SynthesisError> {
                let folded = &x_scalar_var * al + &x_inv_scalar_var * ar;
                if round_idx == 0 && i == 0 {
                    tracing::trace!(
                        target: LOG_TARGET,
                        round_idx,
                        i,
                        left = ?al.value().unwrap(),
                        right = ?ar.value().unwrap(),
                        folded = ?folded.value().unwrap(),
                        "Gadget folding details"
                    );
                }
                Ok(folded)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        tracing::trace!(
            target: LOG_TARGET,
            old_len = a_current.len(),
            new_len = a_folded.len(),
            "Folded scalar vector in gadget"
        );

        a_current = a_folded;
    }

    // After all rounds, we should have a single scalar
    assert_eq!(a_current.len(), 1, "Folding should result in single scalar");
    let a_final = a_current[0].clone();

    tracing::debug!(target: LOG_TARGET, "Final folded scalar in gadget");
    Ok(a_final)
}

/// Verify scalar folding link gadget for padded vectors (powers of 2)
///
/// This gadget verifies that a secret message vector was used in creating
/// the Pedersen commitment by checking that its folded scalar matches the
/// public a_final from the proof.
///
/// **IMPORTANT**: This function expects the input vector to already be padded to a power of 2.
/// Use `pad_to_power_of_two_gadget` to pad the vector before calling this function.
///
/// # Arguments
/// - `cs`: Constraint system
/// - `c_commit_var`: The commitment C variable (passed separately)
/// - `proof_var`: The opening proof transcript variables (public inputs)
/// - `secret_message_padded_var`: The secret message vector variables (private witness, MUST be padded)
/// - `num_rounds`: Number of folding rounds (log2 of padded size)
/// - `padded_size`: The padded vector size (MUST be power of 2)
///
/// # Returns
/// Ok(()) if the constraint is satisfied, error otherwise
#[zk_poker_macros::track_constraints(
    target = "nexus_nova::shuffling::pedersen_commitment_opening_gadget"
)]
fn verify_scalar_folding_link_padded_gadget<C, GG>(
    cs: ConstraintSystemRef<C::BaseField>,
    c_commit_var: &GG,
    proof_var: &PedersenCommitmentOpeningProofVar<C, GG>,
    secret_message_padded_var: &[EmulatedFpVar<C::ScalarField, C::BaseField>],
    num_rounds: usize,
    padded_size: usize,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
    for<'a> &'a GG: CurveAbsorbGadget<C::BaseField, PoseidonSpongeVar<C::BaseField>>,
{
    // Fold the secret message using the public transcript
    let a_folded_var = fold_scalars_padded_gadget::<C, GG>(
        cs,
        c_commit_var,
        &proof_var.folding_challenge_commitment_rounds,
        secret_message_padded_var,
        num_rounds,
        padded_size,
    )?;

    // Enforce: a_tilde == a_hat
    a_folded_var.enforce_equal(&proof_var.a_final)?;

    tracing::info!(target: LOG_TARGET, "Scalar folding link constraint enforced in gadget");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::pedersen_commitment::{
        extract_pedersen_bases, fold_scalars, prove_with_flexible_size, verify_scalar_folding_link,
        PedersenParams,
    };
    use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Projective};
    use ark_crypto_primitives::commitment::pedersen::Window as PedersenWindow;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, Zero};

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<BaseField>>;

    const TEST_TARGET: &str = LOG_TARGET;

    /// Test window configuration
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct TestWindow;

    impl PedersenWindow for TestWindow {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 64;
    }

    /// Helper to setup test parameters
    fn setup_test_params(size: usize) -> PedersenParams<G1Projective> {
        use ark_crypto_primitives::commitment::{pedersen::Commitment, CommitmentScheme};

        let mut rng = test_rng();
        let arkworks_params =
            <Commitment<G1Projective, TestWindow> as CommitmentScheme>::setup(&mut rng).unwrap();

        let padded_size = if size.is_power_of_two() && size > 0 {
            size
        } else {
            size.next_power_of_two()
        };

        let (h, g_array) = extract_pedersen_bases::<G1Projective, 64>(&arkworks_params);
        let g = g_array[..padded_size].to_vec();

        PedersenParams {
            arkworks_params,
            g,
            h,
        }
    }

    /// Test that native and circuit scalar folding produce identical results
    #[test]
    fn test_scalar_folding_gadget_consistency() {
        let mut rng = test_rng();

        // Test with various sizes
        for size in [1, 2, 4, 8, 13, 52] {
            tracing::info!(target: TEST_TARGET, size, "Testing gadget consistency");

            // Generate random message
            let message: Vec<ScalarField> =
                (0..size).map(|_| ScalarField::rand(&mut rng)).collect();

            // Setup parameters
            let params = setup_test_params(size);

            // Compute commitment
            let r = ScalarField::rand(&mut rng);
            let commitment = {
                let mut result = G1Projective::zero();
                for i in 0..message.len() {
                    result = result + params.g[i] * message[i];
                }
                result = result + params.h * r;
                result
            };

            // Generate opening proof
            let proof = prove_with_flexible_size(&params, commitment, &message, r, &mut rng);

            // ============= Native Scalar Folding =============
            // Now we anchor at C itself (not C - rH)
            let native_folded = fold_scalars(
                &commitment,
                &proof.folding_challenge_commitment_rounds,
                &message,
            );

            // Verify it matches the proof
            assert_eq!(
                native_folded, proof.a_final,
                "Native folded scalar should match proof.a_final"
            );

            // ============= Circuit Scalar Folding =============
            let cs = ConstraintSystem::<BaseField>::new_ref();

            // Calculate padded size and number of rounds
            let padded_size = if size.is_power_of_two() && size > 0 {
                size
            } else {
                size.next_power_of_two()
            };
            let num_rounds = padded_size.trailing_zeros() as usize;

            // Allocate commitment C as public input
            let c_commit_var =
                G1Var::new_variable(cs.clone(), || Ok(commitment), AllocationMode::Input).unwrap();

            // Allocate proof variables as public inputs
            let proof_var = PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
                cs.clone(),
                &proof,
                AllocationMode::Input,
            )
            .unwrap();

            // Allocate secret message as emulated scalar field variables
            let message_var: Vec<EmulatedFpVar<ScalarField, BaseField>> = message
                .iter()
                .map(|m| {
                    EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(*m))
                        .unwrap()
                })
                .collect();

            // Pad the message in-circuit
            let padded_message_var =
                pad_to_power_of_two_gadget::<G1Projective>(cs.clone(), &message_var).unwrap();

            // Run the gadget
            verify_scalar_folding_link_padded_gadget::<G1Projective, G1Var>(
                cs.clone(),
                &c_commit_var,
                &proof_var,
                &padded_message_var,
                num_rounds,
                padded_size,
            )
            .unwrap();

            // Check constraint satisfaction
            if !cs.is_satisfied().unwrap() {
                // Debug: print values
                let computed_a_final = fold_scalars_padded_gadget::<G1Projective, G1Var>(
                    cs.clone(),
                    &c_commit_var,
                    &proof_var.folding_challenge_commitment_rounds,
                    &padded_message_var,
                    num_rounds,
                    padded_size,
                )
                .unwrap();

                tracing::debug!(
                    target: TEST_TARGET,
                    size,
                    proof_a_final_value = ?proof_var.a_final.value().unwrap(),
                    computed_a_final_value = ?computed_a_final.value().unwrap(),
                    native_proof_a_final = ?proof.a_final,
                    native_folded = ?native_folded,
                    "Debug values for constraint failure"
                );

                // Find which constraint is unsatisfied
                if let Some(unsatisfied_name) = cs.which_is_unsatisfied().unwrap() {
                    tracing::error!(
                        target: TEST_TARGET,
                        unsatisfied_name,
                        "Unsatisfied constraint"
                    );
                }
                panic!("Circuit should be satisfied for size {}", size);
            }

            tracing::info!(
                target: TEST_TARGET,
                size,
                constraints = cs.num_constraints(),
                "✅ Native and circuit produce identical results"
            );
        }
    }

    /// Test that wrong messages fail verification in circuit
    #[test]
    fn test_scalar_folding_gadget_wrong_message() {
        let mut rng = test_rng();
        let size = 8;

        // Generate random message
        let message: Vec<ScalarField> = (0..size).map(|_| ScalarField::rand(&mut rng)).collect();

        // Setup and generate proof
        let params = setup_test_params(size);
        let r = ScalarField::rand(&mut rng);
        let commitment = {
            let mut result = G1Projective::zero();
            for i in 0..message.len() {
                result = result + params.g[i] * message[i];
            }
            result = result + params.h * r;
            result
        };

        let proof = prove_with_flexible_size(&params, commitment, &message, r, &mut rng);

        // Create circuit
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Calculate padded size and number of rounds
        let padded_size = if size.is_power_of_two() && size > 0 {
            size
        } else {
            size.next_power_of_two()
        };
        let num_rounds = padded_size.trailing_zeros() as usize;

        // Allocate commitment C as public input
        let c_commit_var =
            G1Var::new_variable(cs.clone(), || Ok(commitment), AllocationMode::Input).unwrap();

        // Allocate proof variables
        let proof_var = PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            &proof,
            AllocationMode::Input,
        )
        .unwrap();

        // Allocate WRONG message (without padding initially)
        let wrong_message: Vec<ScalarField> =
            (0..size).map(|_| ScalarField::rand(&mut rng)).collect();

        let wrong_message_var: Vec<EmulatedFpVar<ScalarField, BaseField>> = wrong_message
            .iter()
            .map(|m| {
                EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(*m)).unwrap()
            })
            .collect();

        // Pad the wrong message in-circuit
        let padded_wrong_message_var =
            pad_to_power_of_two_gadget::<G1Projective>(cs.clone(), &wrong_message_var).unwrap();

        // Run the gadget (should make circuit unsatisfied)
        let _ = verify_scalar_folding_link_padded_gadget::<G1Projective, G1Var>(
            cs.clone(),
            &c_commit_var,
            &proof_var,
            &padded_wrong_message_var,
            num_rounds,
            padded_size,
        );

        // Circuit should NOT be satisfied
        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit should not be satisfied with wrong message"
        );

        tracing::info!(target: TEST_TARGET, "✅ Circuit correctly rejects wrong message");
    }

    /// Comprehensive test: native verify, native scalar folding, and gadget
    #[test]
    fn test_complete_verification_flow() {
        let mut rng = test_rng();

        // Generate random 52-element message (poker deck size)
        let size = 52;
        let message: Vec<ScalarField> = (0..size).map(|_| ScalarField::rand(&mut rng)).collect();

        tracing::info!(target: TEST_TARGET, "Testing complete verification flow with {} elements", size);

        // Setup parameters
        let params = setup_test_params(size);

        // Compute commitment
        let r = ScalarField::rand(&mut rng);
        let commitment = {
            let mut result = G1Projective::zero();
            for i in 0..message.len() {
                result = result + params.g[i] * message[i];
            }
            result = result + params.h * r;
            result
        };

        // Generate opening proof
        let proof = prove_with_flexible_size(&params, commitment, &message, r, &mut rng);

        // Step 1: Verify the proof with standard verify (would need flexible verify)
        // For now, we verify the scalar folding link

        // Step 2: Native scalar folding verification
        // Note: r parameter no longer needed as protocol now anchors at C
        let native_result = verify_scalar_folding_link(&commitment, &params, &proof, &message);
        assert!(
            native_result.is_ok(),
            "Native scalar folding should succeed"
        );

        // Step 3: Circuit scalar folding verification
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate commitment C as public input
        let c_commit_var =
            G1Var::new_variable(cs.clone(), || Ok(commitment), AllocationMode::Input).unwrap();

        // Allocate public inputs
        let proof_var = PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            &proof,
            AllocationMode::Input,
        )
        .unwrap();

        // Calculate padded size and number of rounds
        let padded_size = if size.is_power_of_two() && size > 0 {
            size
        } else {
            size.next_power_of_two()
        };
        let num_rounds = padded_size.trailing_zeros() as usize;

        // Allocate private witness
        let message_var: Vec<EmulatedFpVar<ScalarField, BaseField>> = message
            .iter()
            .map(|m| {
                EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(*m)).unwrap()
            })
            .collect();

        // Pad the message in-circuit
        let padded_message_var =
            pad_to_power_of_two_gadget::<G1Projective>(cs.clone(), &message_var).unwrap();

        // Run gadget
        let gadget_result = verify_scalar_folding_link_padded_gadget::<G1Projective, G1Var>(
            cs.clone(),
            &c_commit_var,
            &proof_var,
            &padded_message_var,
            num_rounds,
            padded_size,
        );
        assert!(gadget_result.is_ok(), "Gadget verification should succeed");

        // Check constraint satisfaction
        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

        // Log constraint counts
        let expected_constraints =
            2 * (size.next_power_of_two() - 1) + size.next_power_of_two().trailing_zeros() as usize;
        tracing::info!(
            target: TEST_TARGET,
            actual_constraints = cs.num_constraints(),
            expected_folding_constraints = expected_constraints,
            witness_vars = cs.num_witness_variables(),
            instance_vars = cs.num_instance_variables(),
            "Constraint counts for {} elements", size
        );

        tracing::info!(target: TEST_TARGET, "✅ Complete verification flow succeeded");
    }
}
