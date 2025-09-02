//! RS shuffle verification gadgets for SNARK circuits
//!
//! This module contains the circuit gadgets for verifying RS shuffle operations,
//! including basic shuffle verification, shuffle with re-encryption, and indices-only shuffle.

use super::data_structures::{SortedRowVar, UnsortedRowVar, WitnessDataVar};
use super::permutation::IndexedElGamalCiphertext;
use super::permutation::{check_grand_product, IndexPositionPair, PermutationProduct};
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use crate::track_constraints;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::FieldVar};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
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
