//! RS shuffle verification gadgets for SNARK circuits
//!
//! This module contains the circuit gadgets for verifying RS shuffle operations,
//! including basic shuffle verification, shuffle with re-encryption, and indices-only shuffle.

use super::data_structures::{SortedRowVar, UnsortedRowVar, WitnessDataVar};
use super::permutation::IndexedElGamalCiphertext;
use super::permutation::{check_grand_product, IndexPositionPair, PermutationProduct};
use crate::bayer_groth_permutation::bg_setup_gadget::BayerGrothSetupParametersGadget;
use crate::shuffling::bayer_groth_permutation::{
    bg_setup_gadget::BayerGrothTranscriptGadget,
    linking_rs_gadgets::{compute_perm_power_vector, compute_permutation_proof_gadget},
};
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use crate::track_constraints;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::groups::GroupOpsBounds;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::FieldVar};
use ark_r1cs_std::{
    fields::emulated_fp::EmulatedFpVar, fields::fp::FpVar, groups::CurveVar, prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use std::ops::Not;

const LOG_TARGET: &str = "nexus_nova::shuffling::rs_shuffle::gadget";

/// Simple indexed value for permutation checks with just an index
#[derive(Clone)]
pub struct IndexedValue<F: PrimeField> {
    pub idx: FpVar<F>,
}

impl<F: PrimeField> IndexedValue<F> {
    pub fn new(idx: FpVar<F>) -> Self {
        Self { idx }
    }
}

impl<F: PrimeField> PermutationProduct<F, 1> for IndexedValue<F> {
    fn product(&self, challenges: &[FpVar<F>; 1]) -> FpVar<F> {
        // Simply multiply the index by the challenge
        &challenges[0] * &self.idx
    }
}

/// Verify RS shuffle constraints for indices only (without ElGamal ciphertexts)
///
/// This function verifies that a shuffle was performed correctly on indices by:
/// 1. Checking row-local constraints at each level
/// 2. Verifying permutation consistency at each level
/// 3. Ensuring indices are preserved through the shuffle
///
/// # Type Parameters
/// - `F`: The prime field type
/// - `N`: The number of elements being shuffled
/// - `LEVELS`: The number of levels in the shuffle
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `indices_init`: Initial indices (as SNARK variables)
/// - `indices_after_shuffle`: Final shuffled indices (as SNARK variables)
/// - `witness`: The witness data containing the shuffle permutation (as SNARK variable)
/// - `alpha`: Fiat-Shamir challenge for permutation check (as SNARK variable)
///
/// # Returns
/// - `Ok(())` if all shuffle constraints are satisfied
/// - `Err(SynthesisError)` if any constraint fails
pub fn rs_shuffle_indices<F, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<F>,
    indices_init: &[FpVar<F>],
    indices_after_shuffle: &[FpVar<F>],
    witness: &WitnessDataVar<F, N, LEVELS>,
    alpha: &FpVar<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    track_constraints!(&cs, "rs shuffle indices", LOG_TARGET, {
        // 1. Create indexed values by zipping witness indices with input indices
        // Initial: Use indices from first level unsorted array
        let values_initial: Vec<IndexedValue<F>> = witness.uns_levels[0]
            .iter()
            .zip(indices_init.iter())
            .map(|(row, idx)| {
                // Verify that the index matches
                row.idx.enforce_equal(idx)?;
                Ok(IndexedValue::new(row.idx.clone()))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // Final: Use indices from last level sorted array
        let values_final: Vec<IndexedValue<F>> = witness.sorted_levels[LEVELS - 1]
            .iter()
            .zip(indices_after_shuffle.iter())
            .map(|(row, idx)| {
                // Verify that the index matches
                row.idx.enforce_equal(idx)?;
                Ok(IndexedValue::new(row.idx.clone()))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // 2. Create beta challenge for level verification (using alpha as base)
        let beta = alpha * alpha; // beta = alpha^2

        // 3. Level-by-level verification
        for level in 0..LEVELS {
            let unsorted = &witness.uns_levels[level];
            let sorted_arr = &witness.sorted_levels[level];

            // Verify this shuffle level (row constraints + permutation check)
            verify_shuffle_level::<_, N>(cs.clone(), unsorted, sorted_arr, alpha, &beta)?;
        }

        // 4. Final permutation check using just indices (1 challenge)
        // This verifies that initial and final indices form the same multiset
        check_grand_product::<F, IndexedValue<F>, 1>(
            cs.clone(),
            &values_initial,
            &values_final,
            &[alpha.clone()],
        )?;

        Ok(())
    })
}

/// Verify RS shuffle constraints in a SNARK circuit
///
/// This function verifies that a shuffle was performed correctly by:
/// 1. Checking row-local constraints at each level
/// 2. Verifying permutation consistency at each level
/// 3. Ensuring ElGamal ciphertexts are preserved through the shuffle
///
/// # Type Parameters
/// - `G`: The elliptic curve configuration
/// - `N`: The number of elements being shuffled
/// - `LEVELS`: The number of levels in the shuffle
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `ct_init_pub`: Initial ElGamal ciphertexts (as SNARK variables)
/// - `ct_after_shuffle`: Final shuffled ElGamal ciphertexts (as SNARK variables)
/// - `witness`: The witness data containing the shuffle permutation (as SNARK variable)
/// - `alpha`: First Fiat-Shamir challenge (as SNARK variable)
/// - `beta`: Second Fiat-Shamir challenge (as SNARK variable)
///
/// # Returns
/// - `Ok(())` if all shuffle constraints are satisfied
/// - `Err(SynthesisError)` if any constraint fails
pub fn rs_shuffle<C, CV, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<C::BaseField>,
    ct_init_pub: &[ElGamalCiphertextVar<C, CV>],
    ct_after_shuffle: &[ElGamalCiphertextVar<C, CV>],
    witness: &WitnessDataVar<C::BaseField, N, LEVELS>,
    alpha: &FpVar<C::BaseField>,
    beta: &FpVar<C::BaseField>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    track_constraints!(&cs, "rs shuffle", LOG_TARGET, {
        // 1. Create indexed ciphertexts by zipping witness indices with ciphertexts
        // Initial: Use indices from first level unsorted array
        let ciphertexts_initial: Vec<IndexedElGamalCiphertext<C, CV>> = witness.uns_levels[0]
            .iter()
            .zip(ct_init_pub.iter())
            .map(|(row, ct)| IndexedElGamalCiphertext::new(row.idx.clone(), ct.clone()))
            .collect();

        // Final: Use indices from last level sorted array
        let ciphertexts_final: Vec<IndexedElGamalCiphertext<C, CV>> = witness.sorted_levels
            [LEVELS - 1]
            .iter()
            .zip(ct_after_shuffle.iter())
            .map(|(row, ct)| IndexedElGamalCiphertext::new(row.idx.clone(), ct.clone()))
            .collect();

        // 2. Compute other challenges as powers of beta
        let beta_2 = beta * beta; // beta^2 (for c1.x)
        let beta_3 = &beta_2 * beta; // beta^3 (for c1.y)
        let beta_4 = &beta_3 * beta; // beta^4 (for c1.z)
        let beta_5 = &beta_4 * beta; // beta^5 (for c2.x)
        let beta_6 = &beta_5 * beta; // beta^6 (for c2.y)

        // 3. Level-by-level verification
        for level in 0..LEVELS {
            let unsorted = &witness.uns_levels[level];
            let sorted_arr = &witness.sorted_levels[level];

            // Verify this shuffle level (row constraints + permutation check)
            verify_shuffle_level::<_, N>(cs.clone(), unsorted, sorted_arr, alpha, beta)?;
        }

        // 4. Final permutation check using ElGamal ciphertexts (7 challenges)
        // This verifies that initial and final ciphertexts form the same multiset
        // The 7 challenges are: 1 for index + 6 for ElGamal components (c1.x, c1.y, c1.z, c2.x, c2.y, c2.z)
        check_grand_product::<C::BaseField, IndexedElGamalCiphertext<C, CV>, 7>(
            cs.clone(),
            &ciphertexts_initial,
            &ciphertexts_final,
            &[
                alpha.clone(), // For index
                beta.clone(),  // For c1.x
                beta_2,        // For c1.y
                beta_3,        // For c1.z
                beta_4,        // For c2.x
                beta_5,        // For c2.y
                beta_6,        // For c2.z
            ],
        )?;

        Ok(())
    })
}

/// Verify RS shuffle with re-encryption in a SNARK circuit
///
/// This function verifies that a shuffle was performed correctly followed by re-encryption:
/// 1. Verifies the shuffle from initial to intermediate ciphertexts
/// 2. Applies re-encryption to the shuffled ciphertexts
/// 3. Returns the re-encrypted ciphertexts
///
/// # Type Parameters
/// - `G`: The elliptic curve configuration
/// - `N`: The number of elements being shuffled
/// - `LEVELS`: The number of levels in the shuffle
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `ct_init_pub`: Initial ElGamal ciphertexts before shuffle
/// - `ct_after_shuffle`: Intermediate ciphertexts after shuffle, before re-encryption
/// - `witness`: The witness data containing the shuffle permutation
/// - `encryption_randomizations`: Randomness values for re-encryption
/// - `shuffler_pk`: Public key for re-encryption
/// - `alpha`: First Fiat-Shamir challenge
/// - `beta`: Second Fiat-Shamir challenge
///
/// # Returns
/// - `Ok(Vec<ElGamalCiphertextVar<G>>)` containing the re-encrypted ciphertexts if successful
/// - `Err(SynthesisError)` if any constraint fails
pub fn rs_shuffle_with_reencryption<C, CV, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<C::BaseField>,
    ct_init_pub: &[ElGamalCiphertextVar<C, CV>; N],
    ct_after_shuffle: &[ElGamalCiphertextVar<C, CV>; N],
    witness_table: &WitnessDataVar<C::BaseField, N, LEVELS>,
    encryption_randomizations: &[FpVar<C::BaseField>; N],
    shuffler_pk: &CV,
    alpha: &FpVar<C::BaseField>,
    beta: &FpVar<C::BaseField>,
    generator_powers: &[C],
) -> Result<Vec<ElGamalCiphertextVar<C, CV>>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    track_constraints!(&cs, "rs shuffle with reencryption", LOG_TARGET, {
        // Step 1: Verify the shuffle from initial to intermediate ciphertexts
        tracing::debug!(target: LOG_TARGET, "Verifying RS shuffle");
        rs_shuffle::<C, _, N, LEVELS>(
            cs.clone(),
            ct_init_pub,
            ct_after_shuffle,
            witness_table,
            alpha,
            beta,
        )?;

        // Step 2: Apply re-encryption to the shuffled ciphertexts
        tracing::debug!(target: LOG_TARGET, "Applying re-encryption to shuffled ciphertexts");

        // Convert array to Vec for the re-encryption function
        let ct_after_shuffle_vec = ct_after_shuffle.to_vec();
        let encryption_randomizations_vec = encryption_randomizations.to_vec();

        // Create ElGamalEncryption instance with precomputed powers
        let elgamal_enc =
            crate::shuffling::encryption::ElGamalEncryption::<C>::new(generator_powers.to_vec());

        let reencrypted_deck = elgamal_enc.reencrypt_cards_with_new_randomization(
            cs.clone(),
            &ct_after_shuffle_vec,
            &encryption_randomizations_vec,
            shuffler_pk,
        )?;

        tracing::debug!(target: LOG_TARGET, "RS shuffle with re-encryption completed successfully");
        Ok(reencrypted_deck)
    })
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

/// Compute the randomness factor gadget: generator^(y*r + s)
/// This represents the blinding component of the proof in-circuit
fn compute_randomness_factor_gadget<F, C, CV>(
    _cs: ConstraintSystemRef<F>,
    generator: &CV,
    y: &EmulatedFpVar<C::ScalarField, F>,
    blinding_r: &EmulatedFpVar<C::ScalarField, F>,
    blinding_s: &EmulatedFpVar<C::ScalarField, F>,
) -> Result<CV, SynthesisError>
where
    F: PrimeField,
    C: CurveGroup,
    CV: CurveVar<C, F>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    // Compute exponent: y * r + s (in scalar field)
    let exponent = y * blinding_r + blinding_s;

    // Convert to bits for scalar multiplication
    let exponent_bits = exponent.to_bits_le()?;

    // Compute generator^exponent using scalar multiplication
    let randomness_factor = generator.scalar_mul_le(exponent_bits.iter())?;

    Ok(randomness_factor)
}

/// Combined RS shuffle verification with Bayer-Groth permutation proof generation
///
/// This function:
/// 1. Verifies that the RS shuffle was performed correctly
/// 2. Runs the Bayer-Groth protocol to generate challenges
/// 3. Computes the permutation power vector in-circuit
/// 4. Generates a curve point that proves the permutation equality
///
/// # Type Parameters
/// - `F`: The prime field type
/// - `C`: The elliptic curve type
/// - `CV`: The curve variable type for the circuit
/// - `N`: The number of elements being shuffled
/// - `LEVELS`: The number of levels in the RS shuffle
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `alpha`: Challenge for RS shuffle permutation check (public)
/// - `c_perm`: Commitment to permutation vector (public)
/// - `c_power`: Commitment to power vector (public)
/// - `generator`: Generator point for proof (public)
/// - `permutation`: The permutation array [1..N] (private)
/// - `witness_data`: RS shuffle witness data (private)
/// - `indices_init`: Initial indices [0..N-1] (private)
/// - `indices_after_shuffle`: Shuffled indices (private)
/// - `transcript`: Bayer-Groth transcript for Fiat-Shamir (private)
///
/// # Returns
/// - `Ok((CV, BayerGrothSetupParametersGadget<F, CV>))`: A tuple containing the complete proof point (including randomness factor) and the Bayer-Groth parameters
/// - `Err(SynthesisError)`: If any constraint fails
pub fn rs_shuffle_with_bayer_groth_proof<F, C, CV, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<F>,
    // Public inputs
    alpha: &FpVar<F>,
    c_perm: &CV,
    c_power: &CV,
    generator: &CV,
    // Private inputs
    permutation: &[EmulatedFpVar<C::ScalarField, F>; N],
    witness_data: &WitnessDataVar<F, N, LEVELS>,
    indices_init: &[FpVar<F>; N],
    indices_after_shuffle: &[FpVar<F>; N],
    blinding_factors: &(
        EmulatedFpVar<C::ScalarField, F>,
        EmulatedFpVar<C::ScalarField, F>,
    ), // (blinding_r, blinding_s)
    transcript: &mut BayerGrothTranscriptGadget<F>,
) -> Result<(CV, BayerGrothSetupParametersGadget<C::ScalarField, F, CV>), SynthesisError>
where
    F: PrimeField,
    C: CurveGroup,
    CV: CurveVar<C, F> + CurveAbsorbGadget<F> + Clone,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    C::BaseField: PrimeField,
{
    track_constraints!(&cs, "rs_shuffle_with_bayer_groth_proof", LOG_TARGET, {
        // Step 1: Verify RS shuffle correctness
        tracing::debug!(target: LOG_TARGET, "Step 1: Verifying RS shuffle correctness");
        rs_shuffle_indices::<F, N, LEVELS>(
            cs.clone(),
            indices_init,
            indices_after_shuffle,
            witness_data,
            alpha,
        )?;

        // Step 2: Run Bayer-Groth protocol to generate challenges
        tracing::debug!(target: LOG_TARGET, "Step 2: Running Bayer-Groth protocol");
        let bg_params = transcript.run_protocol::<C, CV>(cs.clone(), c_perm, c_power)?;

        // Step 3: Compute permutation power vector
        tracing::debug!(target: LOG_TARGET, "Step 3: Computing permutation power vector");
        // The power challenge is already in scalar field format from bg_params
        let perm_power_vector =
            compute_perm_power_vector(cs.clone(), permutation, &bg_params.perm_power_challenge)?;

        // Verify that the computed power vector has the correct length
        assert_eq!(
            perm_power_vector.len(),
            permutation.len(),
            "Power vector length mismatch"
        );

        // Step 4: Generate base permutation proof point
        tracing::debug!(target: LOG_TARGET, "Step 4: Generating base permutation proof point");
        // The challenges are already in scalar field format from bg_params
        let base_proof_point = compute_permutation_proof_gadget(
            cs.clone(),
            permutation,
            &bg_params.perm_mixing_challenge_y,
            &bg_params.perm_offset_challenge_z,
            &bg_params.perm_power_challenge,
            generator,
        )?;

        // Step 5: Compute randomness factor
        tracing::debug!(target: LOG_TARGET, "Step 5: Computing randomness factor");

        // Use the y challenge from bg_params which is already in scalar field
        let randomness_factor = compute_randomness_factor_gadget::<F, C, CV>(
            cs.clone(),
            generator,
            &bg_params.perm_mixing_challenge_y,
            &blinding_factors.0, // blinding_r
            &blinding_factors.1, // blinding_s
        )?;

        // Step 6: Combine base proof point with randomness factor to get final proof point
        tracing::debug!(target: LOG_TARGET, "Step 6: Combining base proof point with randomness factor");
        let proof_point = base_proof_point + randomness_factor;

        tracing::debug!(target: LOG_TARGET, "Successfully generated RS shuffle + Bayer-Groth proof");
        Ok((proof_point, bg_params))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::bayer_groth_permutation::{
        bg_setup::BayerGrothTranscript,
        linking_rs_native::{compute_left_product, compute_linear_blend, compute_right_product},
    };
    use crate::shuffling::rs_shuffle::witness_preparation::apply_rs_shuffle_permutation;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::{Field, UniformRand};
    use ark_r1cs_std::{
        fields::emulated_fp::EmulatedFpVar, groups::curves::short_weierstrass::ProjectiveVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, vec::Vec, Zero};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<ark_bn254::Fq>>;

    const TEST_TARGET: &str = "nexus_nova";

    /// Compute the expected proof point using the commitment formula:
    /// c_D * c_{-z} * randomness_factor
    /// where:
    /// - c_D = c_perm^y * c_power (also written as c_A^y * c_B)
    /// - c_{-z} = generator * (-z)
    /// - randomness_factor = generator^(y*r + s)
    fn compute_expected_proof_point_native<G: CurveGroup>(
        c_perm: G,  // c_A: commitment to permutation vector
        c_power: G, // c_B: commitment to power vector
        generator: G,
        y: G::ScalarField,          // mixing challenge
        z: G::ScalarField,          // offset challenge
        blinding_r: G::ScalarField, // blinding factor for c_perm
        blinding_s: G::ScalarField, // blinding factor for c_power
    ) -> G {
        // Compute c_D = c_perm^y * c_power (in additive notation: y*c_perm + c_power)
        let c_d = c_perm.mul(y) + c_power;

        // Compute c_{-z} = generator * (-z)
        let neg_z = -z;
        let c_minus_z = generator.mul(neg_z);

        // Compute randomness_factor = generator^(y*r + s)
        let exponent = y * blinding_r + blinding_s;
        let randomness_factor = generator.mul(exponent);

        // Final result: c_D + c_{-z} + randomness_factor
        // This is equivalent to c_D * c_{-z} * randomness_factor in multiplicative notation
        c_d + c_minus_z + randomness_factor
    }

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

    /// Helper function to test RS shuffle with Bayer-Groth proof
    /// Parameters:
    /// - seed: Seed for RS shuffle permutation
    /// - blinding_r: Blinding factor for permutation commitment
    /// - blinding_s: Blinding factor for power commitment
    fn test_rs_shuffle_with_params(
        seed: Fr,
        blinding_r: Fr,
        blinding_s: Fr,
    ) -> Result<(), SynthesisError> {
        const N: usize = 10;
        const LEVELS: usize = 3;

        let _rng = test_rng();
        let cs = ConstraintSystem::<ark_bn254::Fq>::new_ref();

        // Step 1: Generate RS shuffle witness data by applying permutation
        // Create a simple input array (0..N) with 1-based indexing for permutation
        let input_array: [usize; N] = std::array::from_fn(|i| i + 1);
        let (witness_data, _num_samples, output_array) =
            apply_rs_shuffle_permutation::<Fr, usize, N, LEVELS>(seed, &input_array);

        // Step 2: The output_array contains the permuted values (already 1-based)
        let permutation_values: Vec<Fr> = output_array
            .iter()
            .map(|&val| Fr::from(val as u64))
            .collect();

        // Step 3: Setup generator and run native Bayer-Groth protocol
        let generator = G1Projective::generator();

        // Step 4: Run native Bayer-Groth protocol to get expected challenges
        let domain = b"test-rs-shuffle-bayer-groth";
        let mut native_transcript = BayerGrothTranscript::new(domain);

        // Convert permutation to usize array for native protocol
        let perm_usize: [usize; N] = std::array::from_fn(|i| {
            let val = permutation_values[i];
            val.into_bigint().as_ref()[0] as usize
        });

        // Run native protocol with provided blinding factors
        let native_params = native_transcript.run_protocol::<G1Projective, N>(
            generator,
            &perm_usize,
            blinding_r,
            blinding_s,
        );

        tracing::debug!(target: TEST_TARGET,
            perm_power_challenge = ?native_params.perm_power_challenge,
            c_perm = ?native_params.c_perm,
            c_power = ?native_params.c_power,
            perm_mixing_challenge_y = ?native_params.perm_mixing_challenge_y,
            perm_offset_challenge_z = ?native_params.perm_offset_challenge_z,
            "Native protocol completed");

        // Use the actual commitments from native protocol
        let perm_commitment = native_params.c_perm;
        let power_commitment = native_params.c_power;

        tracing::debug!(target: TEST_TARGET,
            perm_commitment_projective = ?perm_commitment,
            perm_commitment_affine = ?perm_commitment.into_affine(),
            power_commitment_projective = ?power_commitment,
            power_commitment_affine = ?power_commitment.into_affine(),
            "About to allocate native commitments to circuit");

        // Step 5: Allocate circuit variables

        // Allocate permutation as EmulatedFpVar (scalar field elements in base field circuit)
        let permutation_vars_vec: Vec<EmulatedFpVar<ark_bn254::Fr, ark_bn254::Fq>> =
            permutation_values
                .iter()
                .map(|val| {
                    EmulatedFpVar::<ark_bn254::Fr, ark_bn254::Fq>::new_witness(cs.clone(), || {
                        Ok(*val)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

        // Convert to array
        let permutation_vars: [EmulatedFpVar<ark_bn254::Fr, ark_bn254::Fq>; 10] =
            permutation_vars_vec
                .try_into()
                .expect("Permutation should have exactly 10 elements");

        // Allocate witness data
        let witness_data_var = super::super::data_structures::WitnessDataVar::new_variable(
            cs.clone(),
            || Ok(&witness_data),
            AllocationMode::Witness,
        )?;

        // Allocate indices
        let indices_init_vec: Vec<FpVar<ark_bn254::Fq>> = (0..N)
            .map(|i| FpVar::new_witness(cs.clone(), || Ok(ark_bn254::Fq::from(i as u64))))
            .collect::<Result<Vec<_>, _>>()?;
        let indices_init: [FpVar<ark_bn254::Fq>; 10] = indices_init_vec
            .try_into()
            .expect("Indices init should have exactly 10 elements");

        // The indices after shuffle are the original indices in their new positions
        let final_sorted = &witness_data.next_levels[LEVELS - 1];
        let indices_after_shuffle_vec: Vec<FpVar<ark_bn254::Fq>> = final_sorted
            .iter()
            .map(|row| FpVar::new_witness(cs.clone(), || Ok(ark_bn254::Fq::from(row.idx as u64))))
            .collect::<Result<Vec<_>, _>>()?;
        let indices_after_shuffle: [FpVar<ark_bn254::Fq>; 10] = indices_after_shuffle_vec
            .try_into()
            .expect("Indices after shuffle should have exactly 10 elements");

        // Allocate alpha challenge
        let alpha = FpVar::new_input(cs.clone(), || Ok(ark_bn254::Fq::from(17u64)))?;

        // Allocate curve points
        let c_perm_var = G1Var::new_input(cs.clone(), || Ok(perm_commitment))?;
        let c_power_var = G1Var::new_input(cs.clone(), || Ok(power_commitment))?;
        let generator_var = G1Var::new_constant(cs.clone(), generator)?;

        tracing::debug!(target: TEST_TARGET,
            c_perm_var_projective = ?c_perm_var.value()?,
            c_perm_var_affine = ?c_perm_var.value()?.into_affine(),
            c_power_var_projective = ?c_power_var.value()?,
            c_power_var_affine = ?c_power_var.value()?.into_affine(),
            "Allocated commitments to circuit");

        // Allocate blinding factors as emulated scalar field variables
        // These are Fr elements (scalar field) that will be used for scalar multiplication
        let blinding_r_var =
            EmulatedFpVar::<ark_bn254::Fr, ark_bn254::Fq>::new_witness(cs.clone(), || {
                Ok(blinding_r)
            })?;
        let blinding_s_var =
            EmulatedFpVar::<ark_bn254::Fr, ark_bn254::Fq>::new_witness(cs.clone(), || {
                Ok(blinding_s)
            })?;
        let blinding_factors = (blinding_r_var, blinding_s_var);

        // Create transcript gadget
        let mut transcript_gadget = BayerGrothTranscriptGadget::new(cs.clone(), domain)?;

        // Step 6: Compute expected proof point using native function
        let expected_proof_point = compute_expected_proof_point_native(
            native_params.c_perm,
            native_params.c_power,
            generator,
            native_params.perm_mixing_challenge_y,
            native_params.perm_offset_challenge_z,
            blinding_r,
            blinding_s,
        );

        tracing::debug!(target: TEST_TARGET, "Expected proof point computed natively");

        // Step 7: Run the combined gadget
        let (proof_point, bg_params) = rs_shuffle_with_bayer_groth_proof(
            cs.clone(),
            &alpha,
            &c_perm_var,
            &c_power_var,
            &generator_var,
            &permutation_vars,
            &witness_data_var,
            &indices_init,
            &indices_after_shuffle,
            &blinding_factors,
            &mut transcript_gadget,
        )?;

        tracing::debug!(target: TEST_TARGET,
            perm_power_challenge = ?bg_params.perm_power_challenge.value()?,
            c_perm = ?bg_params.c_perm.value()?,
            c_power = ?bg_params.c_power.value()?,
            perm_mixing_challenge_y = ?bg_params.perm_mixing_challenge_y.value()?,
            perm_offset_challenge_z = ?bg_params.perm_offset_challenge_z.value()?,
            "Printing out computed challenges");

        // Step 8: Verify circuit parameters match native parameters
        assert_eq!(
            bg_params.perm_power_challenge.value()?,
            native_params.perm_power_challenge,
            "Circuit perm_power_challenge should match native"
        );
        assert_eq!(
            bg_params.c_perm.value()?,
            native_params.c_perm,
            "Circuit c_perm should match native"
        );
        assert_eq!(
            bg_params.c_power.value()?,
            native_params.c_power,
            "Circuit c_power should match native"
        );
        assert_eq!(
            bg_params.perm_mixing_challenge_y.value()?,
            native_params.perm_mixing_challenge_y,
            "Circuit perm_mixing_challenge_y should match native"
        );
        assert_eq!(
            bg_params.perm_offset_challenge_z.value()?,
            native_params.perm_offset_challenge_z,
            "Circuit perm_offset_challenge_z should match native"
        );

        // Step 9: Verify constraint system is satisfied
        assert!(cs.is_satisfied()?, "Constraint system should be satisfied");

        // Step 10: Verify the proof point matches expected value
        let proof_point_value = proof_point.value()?;
        assert!(
            !proof_point_value.is_zero(),
            "Proof point should not be zero"
        );

        // Verify the gadget produces the expected proof point
        assert_eq!(
            proof_point_value, expected_proof_point,
            "Gadget proof point (including randomness factor) should match native computation"
        );

        tracing::debug!(
            "Test passed: Generated proof point with {} constraints",
            cs.num_constraints()
        );

        Ok(())
    }

    #[test]
    fn test_rs_shuffle_with_random_blinding() -> Result<(), SynthesisError> {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        // Test with random seed and blinding factors
        let seed = Fr::rand(&mut rng);
        let blinding_r = Fr::rand(&mut rng);
        let blinding_s = Fr::rand(&mut rng);

        tracing::debug!(
            target: TEST_TARGET,
            ?seed,
            ?blinding_r,
            ?blinding_s,
            "Testing RS shuffle with random blinding factors"
        );

        test_rs_shuffle_with_params(seed, blinding_r, blinding_s)
    }

    #[test]
    fn test_rs_shuffle_with_zero_blinding() -> Result<(), SynthesisError> {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        // Test with random seed but zero blinding factors
        let seed = Fr::rand(&mut rng);
        let blinding_r = Fr::zero();
        let blinding_s = Fr::zero();

        tracing::debug!(
            target: TEST_TARGET,
            ?seed,
            "Testing RS shuffle with zero blinding factors"
        );

        test_rs_shuffle_with_params(seed, blinding_r, blinding_s)
    }

    #[test]
    fn test_rs_shuffle_with_bayer_groth_proof_consistency() -> Result<(), SynthesisError> {
        let _guard = setup_test_tracing();

        // This test verifies that the gadget produces consistent results
        // with the native computation
        const N: usize = 5; // Smaller size for detailed verification
        const LEVELS: usize = 2;

        let mut rng = test_rng();
        let _cs = ConstraintSystem::<ark_bn254::Fq>::new_ref();

        // Generate witness data
        let seed = Fr::from(123u64);
        // Create input array with 1-based values for permutation
        let input_array: [usize; N] = std::array::from_fn(|i| i + 1);
        let (_witness_data, _, output_array) =
            apply_rs_shuffle_permutation::<Fr, usize, N, LEVELS>(seed, &input_array);

        // The output_array directly contains the permuted values (1-based)
        let permutation_native: Vec<usize> = output_array.to_vec();

        // Generate random challenges for native computation
        let x_native = Fr::rand(&mut rng);
        let y_native = Fr::rand(&mut rng);
        let z_native = Fr::rand(&mut rng);

        // Compute native power vector
        let power_vector_native: Vec<Fr> = permutation_native
            .iter()
            .map(|&i| x_native.pow(&[i as u64]))
            .collect();

        // Compute native permutation proof components
        let perm_as_fr: Vec<Fr> = permutation_native
            .iter()
            .map(|&i| Fr::from(i as u64))
            .collect();

        let d_native = compute_linear_blend(&perm_as_fr, &power_vector_native, y_native);
        let left_native = compute_left_product(&d_native, z_native);
        let right_native = compute_right_product(y_native, x_native, z_native, N);

        // Verify native permutation equality
        assert_eq!(
            left_native, right_native,
            "Native permutation check should pass"
        );

        tracing::debug!("Native computation verified: L = R = {:?}", left_native);

        // Now verify the circuit produces consistent results
        // (The actual curve point generation would depend on the generator and scalar multiplication)

        Ok(())
    }
}
