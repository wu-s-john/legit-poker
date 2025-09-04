//! RS shuffle verification circuits for SNARK

use super::data_structures::{PermutationWitnessData, PermutationWitnessDataVar};
use super::rs_shuffle_gadget::{
    rs_shuffle_indices, rs_shuffle_with_bayer_groth_linking_proof, rs_shuffle_with_reencryption,
};
use super::{LEVELS, N};
use crate::bayer_groth_permutation::bg_setup_gadget::BayerGrothTranscriptGadget;
use crate::rs_shuffle::permutation::{check_grand_product, IndexPositionPair};
use crate::rs_shuffle::{SortedRowVar, UnsortedRowVar};
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
use crate::track_constraints;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::groups::GroupOpsBounds;
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;
use std::ops::Not;

const LOG_TARGET: &str = "nexus_nova::shuffling::rs_shuffle::circuit";

// Note: RS shuffle gadget functions (rs_shuffle_indices, rs_shuffle, rs_shuffle_with_reencryption)
// have been moved to the rs_shuffle_gadget module for better organization.
// They are now imported and re-exported from this module for backward compatibility.

/// RS Shuffle Circuit - Main circuit for verifying RS shuffle
pub struct RSShuffleCircuit<F, C>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
{
    pub ct_init_pub: Vec<ElGamalCiphertext<C>>,
    pub ct_after_shuffle: Vec<ElGamalCiphertext<C>>,
    pub seed: F,
    pub alpha: F,
    pub beta: F,
    pub witness: PermutationWitnessData<N, LEVELS>,
    pub num_samples: usize,
}

/// RS Shuffle with Re-encryption Circuit - Complete circuit for shuffle + re-encryption
pub struct RSShuffleWithReencryptionCircuit<F, C, CV, const N: usize, const LEVELS: usize>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    /// Initial ciphertexts before shuffle (public input)
    pub ct_init_pub: [ElGamalCiphertext<C>; N],
    /// Intermediate ciphertexts after shuffle, before re-encryption (witness)
    pub ct_after_shuffle: [ElGamalCiphertext<C>; N],
    /// Final ciphertexts after shuffle and re-encryption (public input)
    pub ct_final_reencrypted: [ElGamalCiphertext<C>; N],
    /// Seed for deterministic witness generation
    pub seed: F,
    /// Shuffler's public key for re-encryption
    pub shuffler_pk: C,
    /// Re-encryption randomization values (witness)
    pub encryption_randomizations: [F; N],
    /// First Fiat-Shamir challenge
    pub alpha: F,
    /// Second Fiat-Shamir challenge
    pub beta: F,
    /// Witness data for the shuffle
    pub witness: PermutationWitnessData<N, LEVELS>,
    /// Number of samples used in bit generation
    pub num_samples: usize,
    /// Precomputed powers of the generator for efficient fixed-base scalar multiplication
    pub generator_powers: Vec<C>,
    _phantom: PhantomData<CV>,
}

impl<F, C, CV, const N: usize, const LEVELS: usize>
    RSShuffleWithReencryptionCircuit<F, C, CV, N, LEVELS>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    /// Create a new RSShuffleWithReencryptionCircuit instance
    pub fn new(
        ct_init_pub: [ElGamalCiphertext<C>; N],
        ct_after_shuffle: [ElGamalCiphertext<C>; N],
        ct_final_reencrypted: [ElGamalCiphertext<C>; N],
        seed: F,
        shuffler_pk: C,
        encryption_randomizations: [F; N],
        alpha: F,
        beta: F,
        witness: PermutationWitnessData<N, LEVELS>,
        num_samples: usize,
        generator_powers: Vec<C>,
    ) -> Self {
        Self {
            ct_init_pub,
            ct_after_shuffle,
            ct_final_reencrypted,
            seed,
            shuffler_pk,
            encryption_randomizations,
            alpha,
            beta,
            witness,
            num_samples,
            generator_powers,
            _phantom: PhantomData,
        }
    }
}

/// RS Shuffle Permutation Circuit - Circuit for verifying shuffle of indices only
#[derive(Clone)]
pub struct RSShufflePermutationCircuit<F, const N: usize, const LEVELS: usize>
where
    F: PrimeField,
{
    /// Initial indices (public input) - typically 0..N-1
    pub indices_init: Vec<F>,
    /// Shuffled indices (public input)
    pub indices_after_shuffle: Vec<F>,
    /// Seed for deterministic witness generation (public input)
    pub seed: F,
    /// Fiat-Shamir challenge (public input)
    pub alpha: F,
    /// Witness data for the shuffle
    pub witness: PermutationWitnessData<N, LEVELS>,
    /// Number of samples used in bit generation
    pub num_samples: usize,
}

/// RS Shuffle with Bayer-Groth Linking Circuit
///
/// This circuit verifies:
/// 1. RS shuffle correctness (indices are properly shuffled)
/// 2. Bayer-Groth permutation equality proof
/// 3. Linking between the shuffle and permutation proof
pub struct RSShuffleWithBayerGrothLinkCircuit<F, C, CV, const N: usize, const LEVELS: usize>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    // ============ Public Inputs ============
    /// RS shuffle challenge alpha
    pub alpha: F,
    /// Commitment to the permutation vector
    pub c_perm: C,
    /// Commitment to the power vector
    pub c_power: C,

    // ============ Private Inputs ============
    /// The actual permutation values (1-indexed)
    pub permutation: [C::ScalarField; N],
    /// RS shuffle witness data
    pub witness: PermutationWitnessData<N, LEVELS>,
    /// Initial indices (0..N-1)
    pub indices_init: [F; N],
    /// Shuffled indices
    pub indices_after_shuffle: [F; N],
    /// Blinding factors (r, s) for zero-knowledge
    pub blinding_factors: (C::ScalarField, C::ScalarField),

    // ============ Constants ============
    /// Generator point for commitments
    pub generator: C,
    /// Domain for transcript (Fiat-Shamir)
    pub domain: Vec<u8>,

    _phantom: PhantomData<CV>,
}

impl<F, C, CV, const N: usize, const LEVELS: usize>
    RSShuffleWithBayerGrothLinkCircuit<F, C, CV, N, LEVELS>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    /// Create a new RSShuffleWithBayerGrothLinkCircuit instance
    pub fn new(
        alpha: F,
        c_perm: C,
        c_power: C,
        permutation: [C::ScalarField; N],
        witness: PermutationWitnessData<N, LEVELS>,
        indices_init: [F; N],
        indices_after_shuffle: [F; N],
        blinding_factors: (C::ScalarField, C::ScalarField),
        generator: C,
        domain: Vec<u8>,
    ) -> Self {
        Self {
            alpha,
            c_perm,
            c_power,
            permutation,
            witness,
            indices_init,
            indices_after_shuffle,
            blinding_factors,
            generator,
            domain,
            _phantom: PhantomData,
        }
    }
}

impl<C, CV, const N: usize, const LEVELS: usize> ConstraintSynthesizer<C::BaseField>
    for RSShuffleWithReencryptionCircuit<C::BaseField, C, CV, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle with reencryption and variable allocation",
            LOG_TARGET,
            {
                // Allocate seed as public input
                let seed_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.seed), AllocationMode::Input)?;

                // Use prepare_witness_data_circuit to create witness data from seed
                let witness_var =
                    super::witness_preparation::prepare_witness_data_circuit::<
                        C::BaseField,
                        N,
                        LEVELS,
                    >(cs.clone(), &seed_var, &self.witness, self.num_samples)?;

                // Allocate initial ElGamal ciphertexts as public inputs
                let ct_init_vars: [ElGamalCiphertextVar<C, CV>; N] = self
                    .ct_init_pub
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Input,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate intermediate shuffled ciphertexts as witness
                let ct_after_shuffle_vars: [ElGamalCiphertextVar<C, CV>; N] = self
                    .ct_after_shuffle
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Witness,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate final re-encrypted ciphertexts as public inputs
                let ct_final_reencrypted_vars: Vec<ElGamalCiphertextVar<C, CV>> = self
                    .ct_final_reencrypted
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Input,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate shuffler public key as public input
                let shuffler_pk_var: CV = AllocVar::new_variable(
                    cs.clone(),
                    || Ok(self.shuffler_pk),
                    AllocationMode::Input,
                )?;

                // Allocate re-encryption randomizations as witness
                let encryption_randomizations_vars: [FpVar<C::BaseField>; N] = self
                    .encryption_randomizations
                    .iter()
                    .map(|r| FpVar::new_variable(cs.clone(), || Ok(*r), AllocationMode::Witness))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate challenges as public inputs
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;
                let beta_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.beta), AllocationMode::Input)?;

                // Call the main verification function directly with arrays
                let reencrypted_result = rs_shuffle_with_reencryption::<C, _, N, LEVELS>(
                    cs.clone(),
                    &ct_init_vars,
                    &ct_after_shuffle_vars,
                    &witness_var,
                    &encryption_randomizations_vars,
                    &shuffler_pk_var,
                    &alpha_var,
                    &beta_var,
                    &self.generator_powers,
                )?;

                // Verify that the result matches the expected final ciphertexts
                if reencrypted_result.len() != ct_final_reencrypted_vars.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                for (result_ct, expected_ct) in reencrypted_result
                    .iter()
                    .zip(ct_final_reencrypted_vars.iter())
                {
                    result_ct.c1.enforce_equal(&expected_ct.c1)?;
                    result_ct.c2.enforce_equal(&expected_ct.c2)?;
                }

                Ok(())
            }
        )
    }
}

impl<F, const N: usize, const LEVELS: usize> ConstraintSynthesizer<F>
    for RSShufflePermutationCircuit<F, N, LEVELS>
where
    F: PrimeField + Absorb,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle indices with variable allocation",
            LOG_TARGET,
            {
                // Allocate seed as public input
                let seed_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.seed), AllocationMode::Input)?;

                // Use prepare_witness_data_circuit to create witness data from seed
                let witness_var = super::witness_preparation::prepare_witness_data_circuit::<
                    F,
                    N,
                    LEVELS,
                >(
                    cs.clone(), &seed_var, &self.witness, self.num_samples
                )?;

                // Allocate initial indices as public inputs
                let indices_init_vars: Vec<FpVar<F>> = self
                    .indices_init
                    .iter()
                    .map(|idx| FpVar::new_variable(cs.clone(), || Ok(*idx), AllocationMode::Input))
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate shuffled indices as public inputs
                let indices_after_shuffle_vars: Vec<FpVar<F>> = self
                    .indices_after_shuffle
                    .iter()
                    .map(|idx| FpVar::new_variable(cs.clone(), || Ok(*idx), AllocationMode::Input))
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate challenge as public input
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;

                // Call the main verification function
                rs_shuffle_indices::<F, N, LEVELS>(
                    cs.clone(),
                    &indices_init_vars,
                    &indices_after_shuffle_vars,
                    &witness_var,
                    &alpha_var,
                )
            }
        )
    }
}

impl<C, CV, const N: usize, const LEVELS: usize> ConstraintSynthesizer<C::BaseField>
    for RSShuffleWithBayerGrothLinkCircuit<C::BaseField, C, CV, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    CV: CurveVar<C, C::BaseField> + CurveAbsorbGadget<C::BaseField> + Clone,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle with bayer groth linking proof",
            LOG_TARGET,
            {
                // ============ Step 1: Allocate Public Inputs ============
                tracing::debug!(target: LOG_TARGET, "Allocating public inputs");

                // Allocate alpha challenge as public input
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;

                // Allocate commitment to permutation vector as public input
                let c_perm_var =
                    CV::new_variable(cs.clone(), || Ok(self.c_perm), AllocationMode::Input)?;

                // Allocate commitment to power vector as public input
                let c_power_var =
                    CV::new_variable(cs.clone(), || Ok(self.c_power), AllocationMode::Input)?;

                // ============ Step 2: Allocate Private Inputs ============
                tracing::debug!(target: LOG_TARGET, "Allocating private inputs");

                // Allocate permutation as EmulatedFpVar (scalar field in base field circuit)
                let permutation_vars: [EmulatedFpVar<C::ScalarField, C::BaseField>; N] =
                    std::array::from_fn(|i| {
                        EmulatedFpVar::new_variable(
                            cs.clone(),
                            || Ok(self.permutation[i]),
                            AllocationMode::Witness,
                        )
                        .expect("Failed to allocate permutation element")
                    });

                // Allocate witness data
                let witness_var = PermutationWitnessDataVar::new_variable(
                    cs.clone(),
                    || Ok(&self.witness),
                    AllocationMode::Witness,
                )?;

                // Allocate initial indices
                let indices_init_vars: [FpVar<C::BaseField>; N] = std::array::from_fn(|i| {
                    FpVar::new_variable(
                        cs.clone(),
                        || Ok(self.indices_init[i]),
                        AllocationMode::Witness,
                    )
                    .expect("Failed to allocate initial index")
                });

                // Allocate shuffled indices
                let indices_after_shuffle_vars: [FpVar<C::BaseField>; N] =
                    std::array::from_fn(|i| {
                        FpVar::new_variable(
                            cs.clone(),
                            || Ok(self.indices_after_shuffle[i]),
                            AllocationMode::Witness,
                        )
                        .expect("Failed to allocate shuffled index")
                    });

                // Allocate blinding factors as EmulatedFpVar
                let blinding_r_var = EmulatedFpVar::new_variable(
                    cs.clone(),
                    || Ok(self.blinding_factors.0),
                    AllocationMode::Witness,
                )?;
                let blinding_s_var = EmulatedFpVar::new_variable(
                    cs.clone(),
                    || Ok(self.blinding_factors.1),
                    AllocationMode::Witness,
                )?;
                let blinding_factors_var = (blinding_r_var, blinding_s_var);

                // ============ Step 3: Allocate Constants ============
                tracing::debug!(target: LOG_TARGET, "Allocating constants");

                // Allocate generator as constant
                let generator_var = CV::new_constant(cs.clone(), self.generator)?;

                // ============ Step 4: Create Transcript Gadget ============
                tracing::debug!(target: LOG_TARGET, "Creating transcript gadget");

                let mut transcript_gadget =
                    BayerGrothTranscriptGadget::new(cs.clone(), &self.domain)?;

                // ============ Step 5: Run Combined Protocol ============
                tracing::debug!(target: LOG_TARGET, "Running RS shuffle + Bayer-Groth protocol");

                let (_proof_point, _bg_params) =
                    rs_shuffle_with_bayer_groth_linking_proof::<C::BaseField, C, CV, N, LEVELS>(
                        cs.clone(),
                        &alpha_var,
                        &c_perm_var,
                        &c_power_var,
                        &generator_var,
                        &permutation_vars,
                        &witness_var,
                        &indices_init_vars,
                        &indices_after_shuffle_vars,
                        &blinding_factors_var,
                        &mut transcript_gadget,
                    )?;

                // The proof_point and bg_params are now constrained by the gadget
                // No additional constraints needed as the gadget handles all verification

                tracing::debug!(
                    target: LOG_TARGET,
                    "Successfully generated constraints for RS shuffle + Bayer-Groth proof"
                );

                // Optionally, we could expose the proof_point as a public output
                // by allocating it as an Input variable and enforcing equality
                // For now, the verification is complete within the circuit

                Ok(())
            }
        )
    }
}

/// Verify row-local constraints for one level using circuit variables
pub fn verify_row_constraints<F, const N: usize>(
    cs: ConstraintSystemRef<F>,
    unsorted: &[UnsortedRowVar<F>; N],
) -> Result<Vec<IndexPositionPair<F>>, SynthesisError>
where
    F: PrimeField,
{
    let mut idx_next_pos_pairs = Vec::new();

    for i in 0..N {
        let u = &unsorted[i];
        let u_next = if i + 1 < N {
            Some(&unsorted[i + 1])
        } else {
            None
        };

        // ============================================================
        // Row-Local Constraint (1): BITNESS
        // Since we're using Boolean<F>, this constraint is automatically enforced
        // Boolean<F> guarantees b_i ∈ {0, 1}
        // ============================================================
        let one = FpVar::<F>::one();
        let _zero = FpVar::<F>::zero();

        // Convert Boolean to FpVar for arithmetic operations
        let bit_as_fp: FpVar<F> = u.bit.clone().into();
        let one_minus_bit = &one - &bit_as_fp;

        // ============================================================
        // Row-Local Constraint (2): PREFIX-COUNTER EVOLUTION
        //
        // Using indicator last_i to handle both internal and tail rows:
        //
        // If last_i = 0 (internal row):
        //   z_{i+1} = z_i + (1 - b_i)  [zeros counter increments if bit=0]
        //   o_{i+1} = o_i + b_i        [ones counter increments if bit=1]
        //
        // If last_i = 1 (final row in bucket):
        //   z_i = Z_i - (1 - b_i)  [final zeros count matches total minus current]
        //   o_i = (L_i - Z_i) - b_i  [final ones count matches total minus current]
        //
        // Combined equations:
        //   z_{i+1} - z_i - (1 - b_i) = last_i * (Z_i - z_i - (1 - b_i))
        //   o_{i+1} - o_i - b_i = last_i * ((L_i - Z_i) - o_i - b_i)
        // ============================================================

        // Determine if this is the last row in its bucket
        let is_last_in_bucket = if let Some(next) = u_next {
            // Check if next row is in a different bucket
            u.bucket_id.is_eq(&next.bucket_id)?.not()
        } else {
            // Last row of entire array is always last in its bucket
            Boolean::constant(true)
        };

        // Process counter evolution and bucket constants for non-final rows
        if let Some(next) = u_next {
            let same_bucket = is_last_in_bucket.clone().not();

            // Counter evolution constraints (when not last in bucket)
            // same_bucket * (z_{i+1} - z_i - (1 - b_i)) = 0
            // When same_bucket is true: enforce z_{i+1} = z_i + (1 - b_i)
            let expected_next_zeros = &u.num_zeros + &one_minus_bit;
            let selected_zeros = same_bucket.select(&expected_next_zeros, &next.num_zeros)?;
            next.num_zeros.enforce_equal(&selected_zeros)?;

            // same_bucket * (o_{i+1} - o_i - b_i) = 0
            // When same_bucket is true: enforce o_{i+1} = o_i + b_i
            let expected_next_ones = &u.num_ones + &bit_as_fp;
            let selected_ones = same_bucket.select(&expected_next_ones, &next.num_ones)?;
            next.num_ones.enforce_equal(&selected_ones)?;

            // ============================================================
            // Row-Local Constraint (3): BUCKET CONSTANTS STAY CONSTANT
            //
            // For internal rows (last_i = 0):
            //   (1 - last_i) * (Z_{i+1} - Z_i) = 0  [total zeros constant]
            //   (1 - last_i) * (L_{i+1} - L_i) = 0  [bucket length constant]
            //
            // Since last_i = 0 for internal rows, (1 - last_i) = 1
            // Therefore: Z_{i+1} = Z_i and L_{i+1} = L_i within same bucket
            // ============================================================

            // same_bucket * (Z_{i+1} - Z_i) = 0
            // When same_bucket is true: enforce Z_{i+1} = Z_i
            let selected_total_zeros =
                same_bucket.select(&u.total_zeros_in_bucket, &next.total_zeros_in_bucket)?;
            next.total_zeros_in_bucket
                .enforce_equal(&selected_total_zeros)?;

            // same_bucket * (L_{i+1} - L_i) = 0
            // When same_bucket is true: enforce L_{i+1} = L_i
            let selected_length = same_bucket.select(&u.bucket_length, &next.bucket_length)?;
            next.bucket_length.enforce_equal(&selected_length)?;
        }

        // ============================================================
        // Final tallies constraint (when last_i = 1):
        //   z_i = Z_i - (1 - b_i)  [final zeros count]
        //   o_i = (L_i - Z_i) - b_i  [final ones count]
        // ============================================================

        // last_i * (Z_i - z_i - (1 - b_i)) = 0
        // When is_last_in_bucket is true: enforce z_i = Z_i - (1 - b_i)
        let expected_final_zeros = &u.total_zeros_in_bucket - &one_minus_bit;
        let selected_final_zeros = is_last_in_bucket
            .clone()
            .select(&expected_final_zeros, &u.num_zeros)?;
        u.num_zeros.enforce_equal(&selected_final_zeros)?;

        // last_i * ((L_i - Z_i) - o_i - b_i) = 0
        // When is_last_in_bucket is true: enforce o_i = (L_i - Z_i) - b_i
        let bit_as_fp: FpVar<F> = u.bit.clone().into();
        let expected_final_ones = &u.bucket_length - &u.total_zeros_in_bucket - &bit_as_fp;
        let selected_final_ones = is_last_in_bucket.select(&expected_final_ones, &u.num_ones)?;
        u.num_ones.enforce_equal(&selected_final_ones)?;

        // ============================================================
        // Row-Local Constraint (4): DESTINATION SLOT COMPUTATION
        //
        // Define base_i := pos_i - (z_i + o_i) [left edge of bucket]
        //
        // Destination formula:
        //   rhs_i = base_i + z_i + b_i * (Z_i - z_i + o_i)
        //        = pos_i - o_i + b_i * (Z_i - z_i)
        //
        // If b_i = 0 (zero bit):
        //   rhs = pos_i - o_i  [stays in zero zone, preserves order]
        //
        // If b_i = 1 (one bit):
        //   rhs = pos_i - o_i + Z_i - z_i = base_i + Z_i + o_i
        //   [jumps past all zeros, preserves ones order]
        //
        // Invariant: 0 ≤ z_i ≤ Z_i ≤ L_i and 0 ≤ o_i ≤ L_i - Z_i
        // Therefore offset < L_i, ensuring row stays within bucket
        // ============================================================
        let pos = FpVar::new_constant(cs.clone(), F::from(i as u64))?;
        let base = &pos - (&u.num_zeros + &u.num_ones); // base_i = pos_i - (z_i + o_i)

        // Compute offset: z_i + b_i * (Z_i - z_i + o_i)
        let offset =
            &u.num_zeros + &bit_as_fp * (&u.total_zeros_in_bucket - &u.num_zeros + &u.num_ones);
        let expected_dest = base + offset;

        // Enforce: next_pos_i = expected_dest
        u.next_pos.enforce_equal(&expected_dest)?;

        // Collect (idx, next_pos) pairs for multiset equality check
        idx_next_pos_pairs.push(IndexPositionPair::new(u.idx.clone(), u.next_pos.clone()));
    }

    Ok(idx_next_pos_pairs)
}

/// Verify one level of the RS shuffle including row constraints and permutation check
///
/// This function encapsulates:
/// 1. Row-local constraint verification (bitness, counter evolution, bucket constants, destination computation)
/// 2. Building the right-side index-position pairs from the next array
/// 3. Checking multiset equality using grand product with provided challenges
///
/// # Type Parameters
/// - `F`: The prime field type
/// - `N`: The size of the arrays (number of elements)
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `unsorted`: The unsorted row variables for this level
/// - `next_arr`: The next (sorted) row variables for this level
/// - `alpha`: The first challenge for the grand product
/// - `beta`: The second challenge for the grand product
///
/// # Returns
/// - `Ok(())` if all constraints are satisfied
/// - `Err(SynthesisError)` if any constraint fails
pub fn verify_shuffle_level<F, const N: usize>(
    cs: ConstraintSystemRef<F>,
    unsorted_arr: &[UnsortedRowVar<F>; N],
    sorted_arr: &[SortedRowVar<F>; N],
    alpha: &FpVar<F>,
    beta: &FpVar<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    track_constraints!(&cs, "verify shuffle level", LOG_TARGET, {
        // Step 1: Verify row-local constraints
        let idx_next_pos_pairs = verify_row_constraints::<_, N>(cs.clone(), unsorted_arr)?;

        // Step 2: Build right-side pairs (idx, pos) from next array
        let idx_pos_pairs: Vec<IndexPositionPair<F>> = sorted_arr
            .iter()
            .enumerate()
            .map(|(j, nr)| {
                IndexPositionPair::new(
                    nr.idx.clone(),
                    FpVar::new_constant(cs.clone(), F::from(j as u64)).unwrap(),
                )
            })
            .collect();

        // Step 3: Check multiset equality for this level using 2 challenges
        check_grand_product::<F, IndexPositionPair<F>, 2>(
            cs.clone(),
            &idx_next_pos_pairs,
            &idx_pos_pairs,
            &[alpha.clone(), beta.clone()],
        )?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::rs_shuffle::data_structures::{
        SortedRow, SortedRowVar, UnsortedRow, UnsortedRowVar,
    };
    use crate::shuffling::rs_shuffle::prepare_witness_data_circuit;
    use crate::shuffling::rs_shuffle::rs_shuffle_gadget::rs_shuffle;
    use crate::shuffling::rs_shuffle::witness_preparation::build_level;
    use ark_bls12_381::Fr as TestField;
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::CurveConfig;
    use ark_ff::AdditiveGroup;
    use ark_grumpkin::GrumpkinConfig;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

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

    /// Helper function to allocate an array of UnsortedRow as UnsortedRowVar in the constraint system
    fn allocate_unsorted_rows<F: PrimeField, const N: usize>(
        cs: ConstraintSystemRef<F>,
        unsorted: &[UnsortedRow; N],
    ) -> Result<[UnsortedRowVar<F>; N], SynthesisError> {
        let vars: Vec<UnsortedRowVar<F>> = unsorted
            .iter()
            .map(|row| {
                UnsortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        vars.try_into().map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Helper function to allocate an array of SortedRow as SortedRowVar in the constraint system
    fn allocate_next_rows<F: PrimeField, const N: usize>(
        cs: ConstraintSystemRef<F>,
        next_rows: &[SortedRow; N],
    ) -> Result<[SortedRowVar<F>; N], SynthesisError> {
        let vars: Vec<SortedRowVar<F>> = next_rows
            .iter()
            .map(|row| {
                SortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        vars.try_into().map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Helper function to check if constraint system is satisfied and provide detailed error info
    fn check_cs_satisfied<F: PrimeField>(cs: &ConstraintSystemRef<F>) -> Result<(), String> {
        match cs.is_satisfied() {
            Ok(true) => Ok(()),
            Ok(false) => {
                // Try to get which constraint is unsatisfied
                match cs.which_is_unsatisfied() {
                    Ok(Some(unsatisfied_name)) => {
                        // Find the index if we have constraint names
                        let constraint_names = cs.constraint_names().unwrap_or_default();
                        let index = constraint_names
                            .iter()
                            .position(|name| name == &unsatisfied_name)
                            .map(|i| format!(" at index {}", i))
                            .unwrap_or_default();
                        Err(format!(
                            "Constraint '{}'{} is not satisfied",
                            unsatisfied_name, index
                        ))
                    }
                    Ok(None) => Err("Constraint system is not satisfied".to_string()),
                    Err(e) => Err(format!("Error checking unsatisfied constraint: {:?}", e)),
                }
            }
            Err(e) => Err(format!("Error checking constraint satisfaction: {:?}", e)),
        }
    }

    #[test]
    fn test_verify_row_constraints_single_level_alternating() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        // Create a single bucket with all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Alternating bit pattern [0,1,0,1,0,1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness using build_level as oracle
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows in constraint system
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate unsorted rows");

        // Run verify_row_constraints
        let idx_next_pos_pairs = verify_row_constraints(cs.clone(), &unsorted_vars)
            .expect("verify_row_constraints failed");

        // Check that constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid witness");

        // Verify we got the expected number of pairs
        assert_eq!(idx_next_pos_pairs.len(), N);

        // Additional checks on the witness data
        // With alternating bits, we should have 4 zeros and 4 ones
        let zero_count = bits.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Verify that zeros are placed in positions 0..4 and ones in 4..8
        for i in 0..zero_count {
            assert_eq!(next[i].bucket, 0); // Zeros go to bucket 0
        }
        for i in zero_count..N {
            assert_eq!(next[i].bucket, 1); // Ones go to bucket 1
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Single level with alternating bits");
    }

    #[test]
    fn test_verify_row_constraints_two_successive_levels() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        // Level 0: Single bucket containing all elements
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1: Alternating bits [0,1,0,1,0,1,0,1]
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness for level 1
        let (unsorted1, next1) = build_level::<N>(&prev0, &bits1);

        // Create constraint system for level 1
        let cs1 = ConstraintSystem::<TestField>::new_ref();

        // Allocate and verify level 1
        let unsorted1_vars = allocate_unsorted_rows(cs1.clone(), &unsorted1)
            .expect("Failed to allocate level 1 unsorted rows");

        let idx_next_pos_pairs1 = verify_row_constraints(cs1.clone(), &unsorted1_vars)
            .expect("verify_row_constraints failed for level 1");

        check_cs_satisfied(&cs1)
            .expect("Level 1: Constraint system should be satisfied for valid witness");

        assert_eq!(idx_next_pos_pairs1.len(), N);

        // Verify level 1 produced correct buckets
        assert!(next1[0..4].iter().all(|r| r.bucket == 0));
        assert!(next1[4..8].iter().all(|r| r.bucket == 1));

        tracing::debug!(target: TEST_TARGET, "✓ Level 1 verification passed");

        // Level 2: Different bit pattern to split each bucket
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        // Generate witness for level 2
        let (unsorted2, next2) = build_level::<N>(&next1, &bits2);

        // Create constraint system for level 2
        let cs2 = ConstraintSystem::<TestField>::new_ref();

        // Allocate and verify level 2
        let unsorted2_vars = allocate_unsorted_rows(cs2.clone(), &unsorted2)
            .expect("Failed to allocate level 2 unsorted rows");

        let idx_next_pos_pairs2 = verify_row_constraints(cs2.clone(), &unsorted2_vars)
            .expect("verify_row_constraints failed for level 2");

        check_cs_satisfied(&cs2)
            .expect("Level 2: Constraint system should be satisfied for valid witness");

        assert_eq!(idx_next_pos_pairs2.len(), N);

        // Verify level 2 produced 4 buckets (0,1,2,3)
        assert!(next2[0..2].iter().all(|r| r.bucket == 0));
        assert!(next2[2..4].iter().all(|r| r.bucket == 1));
        assert!(next2[4..6].iter().all(|r| r.bucket == 2));
        assert!(next2[6..8].iter().all(|r| r.bucket == 3));

        tracing::debug!(target: TEST_TARGET, "✓ Level 2 verification passed");
        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Two successive levels");
    }

    #[test]
    fn test_verify_row_constraints_edge_cases() {
        let _guard = setup_test_tracing();
        const N: usize = 4;

        // Test case 1: All zeros
        let prev_all_zeros: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));
        let bits_all_zeros: [bool; N] = [false; N];
        let (unsorted_zeros, next_zeros) = build_level::<N>(&prev_all_zeros, &bits_all_zeros);

        let cs_zeros = ConstraintSystem::<TestField>::new_ref();
        let unsorted_zeros_vars = allocate_unsorted_rows(cs_zeros.clone(), &unsorted_zeros)
            .expect("Failed to allocate all-zeros unsorted rows");

        let pairs_zeros = verify_row_constraints(cs_zeros.clone(), &unsorted_zeros_vars)
            .expect("verify_row_constraints failed for all zeros");

        check_cs_satisfied(&cs_zeros).expect("All zeros: Constraint system should be satisfied");

        // All elements should stay in bucket 0
        assert!(next_zeros.iter().all(|r| r.bucket == 0));
        assert_eq!(pairs_zeros.len(), N);

        tracing::debug!(target: TEST_TARGET, "✓ Edge case passed: All zeros");

        // Test case 2: All ones
        let prev_all_ones: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));
        let bits_all_ones: [bool; N] = [true; N];
        let (unsorted_ones, next_ones) = build_level::<N>(&prev_all_ones, &bits_all_ones);

        let cs_ones = ConstraintSystem::<TestField>::new_ref();
        let unsorted_ones_vars = allocate_unsorted_rows(cs_ones.clone(), &unsorted_ones)
            .expect("Failed to allocate all-ones unsorted rows");

        let pairs_ones = verify_row_constraints(cs_ones.clone(), &unsorted_ones_vars)
            .expect("verify_row_constraints failed for all ones");

        check_cs_satisfied(&cs_ones).expect("All ones: Constraint system should be satisfied");

        // All elements should go to bucket 1
        assert!(next_ones.iter().all(|r| r.bucket == 1));
        assert_eq!(pairs_ones.len(), N);

        tracing::debug!(target: TEST_TARGET, "✓ Edge case passed: All ones");
    }

    #[test]
    fn test_verify_row_constraints_multi_bucket() {
        let _guard = setup_test_tracing();
        const N: usize = 6;

        // Create two initial buckets
        let prev_rows: [SortedRow; N] = [
            SortedRow::new_with_bucket(0, 3, 0),
            SortedRow::new_with_bucket(1, 3, 0),
            SortedRow::new_with_bucket(2, 3, 0),
            SortedRow::new_with_bucket(3, 3, 1),
            SortedRow::new_with_bucket(4, 3, 1),
            SortedRow::new_with_bucket(5, 3, 1),
        ];

        // Mixed bit pattern: [0,1,0 | 1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true];

        // Generate witness
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate multi-bucket unsorted rows");

        // Run verify_row_constraints
        let idx_next_pos_pairs = verify_row_constraints(cs.clone(), &unsorted_vars)
            .expect("verify_row_constraints failed for multi-bucket");

        // Check constraint satisfaction
        check_cs_satisfied(&cs).expect("Multi-bucket: Constraint system should be satisfied");

        assert_eq!(idx_next_pos_pairs.len(), N);

        // Verify bucket assignments
        // Bucket 0 splits into buckets 0 (2 zeros) and 1 (1 one)
        assert_eq!(next[0].bucket, 0);
        assert_eq!(next[1].bucket, 0);
        assert_eq!(next[2].bucket, 1);

        // Bucket 1 splits into buckets 2 (1 zero) and 3 (2 ones)
        assert_eq!(next[3].bucket, 2);
        assert_eq!(next[4].bucket, 3);
        assert_eq!(next[5].bucket, 3);

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Multi-bucket configuration");
    }

    #[test]
    fn test_verify_shuffle_level_single() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        tracing::debug!(target: TEST_TARGET, "Starting test_verify_shuffle_level_single");

        // Create a single bucket with all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Alternating bit pattern [0,1,0,1,0,1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness using build_level as oracle
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows in constraint system
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate unsorted rows");

        // Allocate next rows in constraint system
        let next_vars =
            allocate_next_rows(cs.clone(), &next).expect("Failed to allocate next rows");

        // Create test challenges
        let alpha =
            FpVar::new_constant(cs.clone(), TestField::from(2u64)).expect("Failed to create alpha");
        let beta =
            FpVar::new_constant(cs.clone(), TestField::from(3u64)).expect("Failed to create beta");

        // Run verify_shuffle_level
        verify_shuffle_level::<_, N>(cs.clone(), &unsorted_vars, &next_vars, &alpha, &beta)
            .expect("verify_shuffle_level failed");

        // Check that constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid shuffle");

        // Verify expected structure
        let zero_count = bits.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Verify that zeros are placed in positions 0..4 and ones in 4..8
        for i in 0..zero_count {
            assert_eq!(next[i].bucket, 0); // Zeros go to bucket 0
        }
        for i in zero_count..N {
            assert_eq!(next[i].bucket, 1); // Ones go to bucket 1
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Single shuffle level verification");
    }

    #[test]
    fn test_verify_shuffle_level_two_successive() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        tracing::debug!(target: TEST_TARGET, "Starting test_verify_shuffle_level_two_successive");

        // Level 0: Single bucket containing all elements
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1: Alternating bits [0,1,0,1,0,1,0,1]
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness for level 1
        let (unsorted1, next1) = build_level::<N>(&prev0, &bits1);

        // Create constraint system for level 1
        let cs1 = ConstraintSystem::<TestField>::new_ref();

        // Allocate level 1 variables
        let unsorted1_vars = allocate_unsorted_rows(cs1.clone(), &unsorted1)
            .expect("Failed to allocate level 1 unsorted rows");
        let next1_vars =
            allocate_next_rows(cs1.clone(), &next1).expect("Failed to allocate level 1 next rows");

        // Create test challenges for level 1
        let alpha1 = FpVar::new_constant(cs1.clone(), TestField::from(5u64))
            .expect("Failed to create alpha1");
        let beta1 = FpVar::new_constant(cs1.clone(), TestField::from(7u64))
            .expect("Failed to create beta1");

        // Verify level 1
        verify_shuffle_level::<_, N>(cs1.clone(), &unsorted1_vars, &next1_vars, &alpha1, &beta1)
            .expect("verify_shuffle_level failed for level 1");

        check_cs_satisfied(&cs1)
            .expect("Level 1: Constraint system should be satisfied for valid shuffle");

        // Verify level 1 produced correct buckets
        assert!(next1[0..4].iter().all(|r| r.bucket == 0));
        assert!(next1[4..8].iter().all(|r| r.bucket == 1));

        tracing::debug!(target: TEST_TARGET, "✓ Level 1 shuffle verification passed");

        // Level 2: Different bit pattern to split each bucket
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        // Generate witness for level 2
        let (unsorted2, next2) = build_level::<N>(&next1, &bits2);

        // Create constraint system for level 2
        let cs2 = ConstraintSystem::<TestField>::new_ref();

        // Allocate level 2 variables
        let unsorted2_vars = allocate_unsorted_rows(cs2.clone(), &unsorted2)
            .expect("Failed to allocate level 2 unsorted rows");
        let next2_vars =
            allocate_next_rows(cs2.clone(), &next2).expect("Failed to allocate level 2 next rows");

        // Create test challenges for level 2
        let alpha2 = FpVar::new_constant(cs2.clone(), TestField::from(11u64))
            .expect("Failed to create alpha2");
        let beta2 = FpVar::new_constant(cs2.clone(), TestField::from(13u64))
            .expect("Failed to create beta2");

        // Verify level 2
        verify_shuffle_level::<_, N>(cs2.clone(), &unsorted2_vars, &next2_vars, &alpha2, &beta2)
            .expect("verify_shuffle_level failed for level 2");

        check_cs_satisfied(&cs2)
            .expect("Level 2: Constraint system should be satisfied for valid shuffle");

        // Verify level 2 produced 4 buckets (0,1,2,3)
        assert!(next2[0..2].iter().all(|r| r.bucket == 0));
        assert!(next2[2..4].iter().all(|r| r.bucket == 1));
        assert!(next2[4..6].iter().all(|r| r.bucket == 2));
        assert!(next2[6..8].iter().all(|r| r.bucket == 3));

        tracing::debug!(target: TEST_TARGET, "✓ Level 2 shuffle verification passed");
        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Two successive shuffle levels verification");
    }

    #[test]
    fn test_rs_shuffle_ordinary_case() {
        let _guard = setup_test_tracing();
        const N: usize = 52;
        const LEVELS: usize = 5;

        use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
        use crate::shuffling::rs_shuffle::witness_preparation::prepare_witness_data;
        use ark_bn254::Fr as BaseField;
        use ark_ec::PrimeGroup;
        use ark_grumpkin::Projective as GrumpkinProjective;
        use ark_std::UniformRand;

        tracing::debug!(target: TEST_TARGET, "Starting test_rs_shuffle_ordinary_case");

        // 1. Create 52 ElGamal ciphertexts using the Grumpkin curve
        let mut rng = ark_std::test_rng();
        let generator = GrumpkinProjective::generator();

        // Generate a public key for encryption
        let private_key = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = generator * private_key;

        // Create 52 ciphertexts with distinct messages
        let ct_init: Vec<ElGamalCiphertext<GrumpkinProjective>> = (0..N)
            .map(|i| {
                let message = <GrumpkinConfig as CurveConfig>::ScalarField::from((i + 1) as u64);
                let randomness = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
                ElGamalCiphertext::encrypt_scalar(message, randomness, public_key)
            })
            .collect();

        // 2. Use a regular seed value to generate witness data with mixed bits
        let seed = BaseField::from(42u64);
        let (witness_data, num_samples) = prepare_witness_data::<BaseField, N, LEVELS>(seed);

        tracing::debug!(
            target: TEST_TARGET,
            "Generated witness data with {} samples",
            num_samples
        );

        // 3. Prepare witness data and extract the final permutation
        // The final permutation is encoded in witness_data.next_levels[LEVELS - 1]
        // where each SortedRow.idx tells us which original element ends up at that position
        let final_sorted = &witness_data.next_levels[LEVELS - 1];

        // 4. Permute the ciphertexts according to the witness data's final permutation
        let mut ct_after_shuffle = vec![ct_init[0].clone(); N];
        for (position, sorted_row) in final_sorted.iter().enumerate() {
            // sorted_row.idx is the original index that should be at this position
            ct_after_shuffle[position] = ct_init[sorted_row.idx as usize].clone();
        }

        // 5. Create constraint system and allocate all circuit variables
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate initial ciphertexts as witness
        let ct_init_vars: Vec<ElGamalCiphertextVar<Projective<GrumpkinConfig>, _>> = ct_init
            .iter()
            .map(|ct| {
                ElGamalCiphertextVar::new_variable(cs.clone(), || Ok(ct), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to allocate initial ciphertexts");

        // Allocate shuffled ciphertexts as witness
        let ct_final_vars: Vec<ElGamalCiphertextVar<Projective<GrumpkinConfig>, _>> =
            ct_after_shuffle
                .iter()
                .map(|ct| {
                    ElGamalCiphertextVar::new_variable(
                        cs.clone(),
                        || Ok(ct),
                        AllocationMode::Witness,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("Failed to allocate shuffled ciphertexts");

        track_constraints!(
            &cs,
            "rs_shuffle test - witness preparation and verification",
            TEST_TARGET,
            {
                // Allocate seed as a circuit variable
                let seed_var =
                    FpVar::new_constant(cs.clone(), seed).expect("Failed to allocate seed");

                // Allocate witness data
                let witness_var = prepare_witness_data_circuit::<BaseField, N, LEVELS>(
                    cs.clone(),
                    &seed_var,
                    &witness_data,
                    num_samples,
                )
                .expect("Failed to allocate witness data");

                // Create realistic Fiat-Shamir challenges
                let alpha = FpVar::new_constant(cs.clone(), BaseField::from(17u64))
                    .expect("Failed to create alpha");
                let beta = FpVar::new_constant(cs.clone(), BaseField::from(23u64))
                    .expect("Failed to create beta");

                // 6. Run the rs_shuffle verification function
                rs_shuffle::<
                    GrumpkinProjective,
                    ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
                    N,
                    LEVELS,
                >(
                    cs.clone(),
                    &ct_init_vars,
                    &ct_final_vars,
                    &witness_var,
                    &alpha,
                    &beta,
                )
                .expect("rs_shuffle verification failed");
            }
        );

        // 7. Verify the constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid shuffle");

        // 8. Check that the permutation preserves the multiset of ciphertexts
        // Verify that we have exactly N elements and they form a permutation
        let mut index_set: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for sorted_row in final_sorted.iter() {
            assert!(
                index_set.insert(sorted_row.idx),
                "Duplicate index {} in permutation",
                sorted_row.idx
            );
        }
        assert_eq!(index_set.len(), N, "Permutation should contain all indices");

        // Check that the bits across all levels are mixed (not all 0s or all 1s)
        for level in 0..LEVELS {
            let ones_count = witness_data.bits_mat[level].iter().filter(|&&b| b).count();
            tracing::debug!(
                target: TEST_TARGET,
                "Level {} has {} ones out of {} bits",
                level,
                ones_count,
                N
            );
            // In ordinary case, we expect mixed bits (neither all 0s nor all 1s)
            assert!(ones_count > 0, "Level {} should have some 1s", level);
            assert!(ones_count < N, "Level {} should have some 0s", level);
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: RS shuffle ordinary case");

        // Log ciphertexts before and after permutation for debugging
        tracing::trace!(target: TEST_TARGET, "Ciphertexts before permutation:");
        for (i, ct) in ct_init.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "ct_init[{}]: c1=({:?}, {:?}, {:?}), c2=({:?}, {:?}, {:?})",
                i, ct.c1.x, ct.c1.y, ct.c1.z, ct.c2.x, ct.c2.y, ct.c2.z
            );
        }

        tracing::trace!(target: TEST_TARGET, "Ciphertexts after permutation:");
        for (i, ct) in ct_after_shuffle.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "ct_after_shuffle[{}]: c1=({:?}, {:?}, {:?}), c2=({:?}, {:?}, {:?})",
                i, ct.c1.x, ct.c1.y, ct.c1.z, ct.c2.x, ct.c2.y, ct.c2.z
            );
        }

        tracing::trace!(target: TEST_TARGET, "Permutation mapping:");
        for (position, sorted_row) in final_sorted.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "Position {} <- Original index {}",
                position,
                sorted_row.idx
            );
        }
    }

    #[test]
    fn test_rs_shuffle_with_reencryption() {
        let _guard = setup_test_tracing();
        const N: usize = 52;
        const LEVELS: usize = 5;

        use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
        use crate::shuffling::rs_shuffle::witness_preparation::apply_rs_shuffle_permutation;
        use ark_bn254::Fr as BaseField;
        use ark_ec::PrimeGroup;
        use ark_ff::BigInteger;
        use ark_grumpkin::Projective as GrumpkinProjective;
        use ark_std::UniformRand;

        tracing::debug!(target: TEST_TARGET, "Starting test_rs_shuffle_with_reencryption");

        // 1. Setup: Create ElGamal ciphertexts and keys
        let mut rng = ark_std::test_rng();
        let generator = GrumpkinProjective::generator();

        // Generate shuffler keys
        let shuffler_private_key = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
        let shuffler_public_key = generator * shuffler_private_key;

        // Create N ciphertexts with distinct messages
        let ct_init: [ElGamalCiphertext<GrumpkinProjective>; N] = std::array::from_fn(|i| {
            let message = <GrumpkinConfig as CurveConfig>::ScalarField::from((i + 1) as u64);
            let randomness = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, shuffler_public_key)
        });

        // 2. Native execution
        let seed = BaseField::from(42u64);

        // Apply RS shuffle permutation
        let (witness_data, num_samples, ct_after_shuffle_native) =
            apply_rs_shuffle_permutation::<BaseField, _, N, LEVELS>(seed, &ct_init);

        tracing::debug!(
            target: TEST_TARGET,
            "Native shuffle completed with {} samples",
            num_samples
        );

        // Generate re-encryption randomizations
        let rerandomizations: [<GrumpkinConfig as CurveConfig>::ScalarField; N] =
            std::array::from_fn(|_| <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng));

        // Apply re-encryption natively
        let ct_final_native: [ElGamalCiphertext<GrumpkinProjective>; N] =
            std::array::from_fn(|i| {
                ct_after_shuffle_native[i]
                    .add_encryption_layer(rerandomizations[i], shuffler_public_key)
            });

        // 3. SNARK Circuit execution
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate initial ciphertexts
        let ct_init_vars: [ElGamalCiphertextVar<
            GrumpkinProjective,
            ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
        >; N] = std::array::from_fn(|i| {
            ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(&ct_init[i]),
                AllocationMode::Witness,
            )
            .expect("Failed to allocate initial ciphertext")
        });

        // Allocate shuffled ciphertexts (intermediate state)
        let ct_after_shuffle_vars = std::array::from_fn(|i| {
            ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(&ct_after_shuffle_native[i]),
                AllocationMode::Witness,
            )
            .expect("Failed to allocate shuffled ciphertext")
        });

        // Allocate witness data
        let seed_var = FpVar::new_constant(cs.clone(), seed).expect("Failed to allocate seed");
        let witness_var = prepare_witness_data_circuit::<BaseField, N, LEVELS>(
            cs.clone(),
            &seed_var,
            &witness_data,
            num_samples,
        )
        .expect("Failed to allocate witness data");

        // Allocate re-encryption randomizations
        let rerandomizations_vars: [FpVar<BaseField>; N] = std::array::from_fn(|i| {
            // Convert ScalarField to BaseField
            let scalar_bytes = rerandomizations[i].into_bigint().to_bytes_le();
            let base_field_value = BaseField::from_le_bytes_mod_order(&scalar_bytes);
            FpVar::new_witness(cs.clone(), || Ok(base_field_value))
                .expect("Failed to allocate rerandomization")
        });

        // Allocate shuffler public key
        let shuffler_pk_var: ProjectiveVar<GrumpkinConfig, FpVar<BaseField>> =
            AllocVar::new_witness(cs.clone(), || Ok(shuffler_public_key))
                .expect("Failed to allocate shuffler public key");

        // Allocate Fiat-Shamir challenges
        let alpha = FpVar::new_constant(cs.clone(), BaseField::from(17u64))
            .expect("Failed to create alpha");
        let beta =
            FpVar::new_constant(cs.clone(), BaseField::from(23u64)).expect("Failed to create beta");

        // Generate precomputed generator powers
        let num_bits = BaseField::MODULUS_BIT_SIZE as usize;
        let generator_powers = (0..num_bits)
            .scan(GrumpkinProjective::generator(), |acc, _| {
                let current = *acc;
                *acc = acc.double();
                Some(current)
            })
            .collect::<Vec<_>>();

        // 4. Run the SNARK function
        let ct_final_snark = rs_shuffle_with_reencryption::<
            GrumpkinProjective,
            ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
            N,
            LEVELS,
        >(
            cs.clone(),
            &ct_init_vars,
            &ct_after_shuffle_vars,
            &witness_var,
            &rerandomizations_vars,
            &shuffler_pk_var,
            &alpha,
            &beta,
            &generator_powers,
        )
        .expect("rs_shuffle_with_reencryption failed");

        // 5. Verify the constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied");

        // 6. Verify SNARK output matches native execution
        assert_eq!(ct_final_snark.len(), N, "Output size mismatch");

        for i in 0..N {
            // Extract values from SNARK variables
            let snark_c1 = ct_final_snark[i]
                .c1
                .value()
                .expect("Failed to get c1 value");
            let snark_c2 = ct_final_snark[i]
                .c2
                .value()
                .expect("Failed to get c2 value");

            // Compare with native values
            assert_eq!(
                snark_c1, ct_final_native[i].c1,
                "Mismatch in c1 at index {}",
                i
            );
            assert_eq!(
                snark_c2, ct_final_native[i].c2,
                "Mismatch in c2 at index {}",
                i
            );
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: RS shuffle with re-encryption");
    }
}
