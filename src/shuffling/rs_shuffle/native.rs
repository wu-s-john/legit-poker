//! Witness generation for RS shuffle (prover-side logic)

use super::bit_generation::{derive_split_bits, derive_split_bits_circuit};
use super::data_structures::*;
// Removed unused imports - N and LEVELS are now generic parameters
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Run RS shuffle permutation on a collection
///
/// This function generates the witness trace for RS shuffle and applies the resulting
/// permutation to the input collection.
///
/// # Parameters
/// - `seed`: The seed for deterministic permutation generation
/// - `input`: The input array to be permuted
///
/// # Returns
/// An `RSShuffleTrace` containing:
/// - The witness trace for the shuffle
/// - The number of samples used in bit generation
/// - The permuted array
pub fn run_rs_shuffle_permutation<F, T, const N: usize, const LEVELS: usize>(
    seed: F,
    input: &[T; N],
) -> RSShuffleTrace<T, N, LEVELS>
where
    F: Field + PrimeField + Absorb,
    T: Clone + std::fmt::Debug,
{
    // Generate witness trace - we need to specify the const generics
    let (witness_trace, num_samples) = prepare_rs_witness_trace::<F, N, LEVELS>(seed);

    // Extract final permutation from last level
    let final_sorted = &witness_trace.next_levels[LEVELS - 1];

    // Apply permutation to create output array
    // For each position in the output, get the element from the original index
    let output: Vec<T> = final_sorted
        .iter()
        .map(|sorted_row| input[sorted_row.idx as usize].clone())
        .collect();

    // Convert Vec to array
    let permuted_output: [T; N] = output
        .try_into()
        .expect("Permutation should preserve array size");

    RSShuffleTrace {
        witness_trace,
        num_samples,
        permuted_output,
    }
}

pub(crate) fn prepare_rs_witness_trace<F, const N: usize, const LEVELS: usize>(
    seed: F,
) -> (PermutationWitnessTrace<N, LEVELS>, usize)
where
    F: Field + PrimeField + Absorb,
{
    // Derive split bits from seed - returns bits and number of samples used
    let (bits_mat, num_samples) = derive_split_bits::<F, N, LEVELS>(seed);

    // Initialize with level-0 rows (one bucket of full length)
    let prev_vec: Vec<SortedRow> = (0..N)
        .map(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0))
        .collect();

    let prev: [SortedRow; N] = prev_vec
        .try_into()
        .expect("Initial array should have exactly N elements");

    // Process all levels using scan to thread prev through each iteration
    let level_results: Vec<([UnsortedRow; N], [SortedRow; N])> = (0..LEVELS)
        .scan(prev, |prev_state, level| {
            // Get bits for this level directly from the array
            let bits_level = &bits_mat[level];

            // Build level with current prev state
            let (uns_array, nxt_array) = build_level::<N>(prev_state, bits_level);

            // Update prev state for next iteration
            *prev_state = nxt_array.clone();

            // Return the result for this level
            Some((uns_array, nxt_array))
        })
        .collect();

    // Convert Vec of tuples to arrays using array::from_fn
    let uns_levels: [[UnsortedRow; N]; LEVELS] =
        std::array::from_fn(|i| level_results[i].0.clone());
    let next_levels: [[SortedRow; N]; LEVELS] = std::array::from_fn(|i| level_results[i].1.clone());

    (
        PermutationWitnessTrace {
            bits_mat,
            uns_levels,
            next_levels,
        },
        num_samples,
    )
}

/// Build witness tables for one level using functional approach
pub(crate) fn build_level<const N: usize>(
    prev_rows: &[SortedRow; N],
    bits_lvl: &[bool; N],
) -> ([UnsortedRow; N], [SortedRow; N]) {
    use std::collections::HashMap;

    // Zip prev_rows with bits
    let rows_with_bits: Vec<(&SortedRow, bool)> =
        prev_rows.iter().zip(bits_lvl.iter().copied()).collect();

    // Separate maps for clarity
    let mut bucket_zeros: HashMap<u16, u16> = HashMap::new(); // bucket -> total zeros in bucket
    let mut bucket_ones: HashMap<u16, u16> = HashMap::new(); // bucket -> total ones in bucket
    let mut bucket_starts: HashMap<u16, u16> = HashMap::new(); // bucket -> start position
    let mut bucket_lengths: HashMap<u16, u16> = HashMap::new(); // bucket -> length

    // First pass: compute bucket statistics
    let mut current_pos = 0u16;
    for (row, bit) in &rows_with_bits {
        let bucket = row.bucket;

        // Track start position for each bucket
        bucket_starts.entry(bucket).or_insert(current_pos);

        // Count zeros and ones
        if !bit {
            *bucket_zeros.entry(bucket).or_insert(0) += 1;
        } else {
            *bucket_ones.entry(bucket).or_insert(0) += 1;
        }

        // Track bucket length
        *bucket_lengths.entry(bucket).or_insert(0) += 1;

        current_pos += 1;
    }

    // Create unsorted rows with running counters that reset on bucket change
    let mut unsorted = Vec::new();
    let mut current_bucket = None;
    let mut num_zeros = 0u16;
    let mut num_ones = 0u16;

    for (_i, (row, bit)) in rows_with_bits.iter().enumerate() {
        let bucket = row.bucket;

        // Check if we're entering a new bucket
        if current_bucket != Some(bucket) {
            // Reset counters for new bucket
            num_zeros = 0;
            num_ones = 0;
            current_bucket = Some(bucket);
        }

        // Get all the bucket stats from our separate maps
        let num_zeros_in_bucket = *bucket_zeros.get(&bucket).unwrap_or(&0);
        let bucket_length = *bucket_lengths.get(&bucket).unwrap_or(&0);
        let bucket_start = *bucket_starts.get(&bucket).unwrap_or(&0);

        // Compute destination position
        let offset = if !bit {
            num_zeros
        } else {
            num_zeros_in_bucket + num_ones
        };
        let next_pos = bucket_start + offset;

        // Create the unsorted row
        unsorted.push(UnsortedRow::new(
            *bit,
            num_zeros,
            num_ones,
            num_zeros_in_bucket,
            bucket_length,
            row.idx,
            next_pos,
            bucket,
        ));

        // Update counters after processing this element
        if !bit {
            num_zeros += 1;
        } else {
            num_ones += 1;
        }
    }

    // Create indexed tuples for sorting
    let mut sortable: Vec<(u16, u16, bool, u16)> = unsorted
        .iter()
        .zip(&rows_with_bits)
        .map(|(uns, (row, bit))| (uns.next_pos, row.idx, *bit, row.bucket))
        .collect();

    // Stable sort by next_pos
    sortable.sort_by_key(|&(next_pos, _, _, _)| next_pos);

    // Build the next array with correct bucket sizes
    let next_arr: Vec<SortedRow> = sortable
        .into_iter()
        .map(|(_, idx, bit, parent_bucket)| {
            let num_zeros_in_bucket = *bucket_zeros.get(&parent_bucket).unwrap_or(&0);
            let num_ones_in_bucket = *bucket_ones.get(&parent_bucket).unwrap_or(&0);

            // Next level bucket is determined by parent bucket and bit
            let next_bucket = if !bit {
                parent_bucket * 2
            } else {
                parent_bucket * 2 + 1
            };

            // Bucket length for next level is determined by zeros/ones count
            let next_bucket_length = if !bit {
                num_zeros_in_bucket
            } else {
                num_ones_in_bucket
            };

            SortedRow::new_with_bucket(idx, next_bucket_length, next_bucket)
        })
        .collect();

    // Convert to fixed-size arrays
    let unsorted_array: [UnsortedRow; N] = unsorted
        .try_into()
        .expect("Unsorted array should have exactly N elements");
    let next_array: [SortedRow; N] = next_arr
        .try_into()
        .expect("Next array should have exactly N elements");

    (unsorted_array, next_array)
}

/// SNARK circuit version of witness preparation
///
/// This function creates a circuit-compatible witness data structure by:
/// 1. Using `derive_split_bits_circuit` to generate bits from the seed
/// 2. Allocating witness data fields as witness variables
/// 3. Replacing the bit field in unsorted rows with bits from the circuit
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `seed`: The seed as a circuit variable (FpVar)
/// - `rs_witness_trace`: The witness trace computed natively (used as advice)
/// - `num_samples`: Number of Poseidon hash samples needed
///
/// # Returns
/// - `Result<WitnessDataVar<F, N, LEVELS>, SynthesisError>` - The circuit witness data
pub(crate) fn prepare_rs_witness_data_circuit<F, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<F>,
    seed: &FpVar<F>,
    rs_witness_trace: &PermutationWitnessTrace<N, LEVELS>,
    num_samples: usize,
) -> Result<PermutationWitnessTraceVar<F, N, LEVELS>, SynthesisError>
where
    F: PrimeField + Absorb,
{
    // 1. Generate bits from seed using the circuit version
    let bits_mat = derive_split_bits_circuit::<F, N, LEVELS>(cs.clone(), seed, num_samples)?;

    // 2. Allocate unsorted rows without the bit field (we'll use bits from derive_split_bits_circuit)
    let uns_levels: [[UnsortedRowVar<F>; N]; LEVELS] = std::array::from_fn(|level| {
        std::array::from_fn(|i| {
            let row = &rs_witness_trace.uns_levels[level][i];

            // Allocate all fields except bit (which comes from derive_split_bits_circuit)
            UnsortedRowVar {
                bit: bits_mat[level][i].clone(), // Use bit from circuit generation
                num_zeros: FpVar::new_witness(cs.clone(), || Ok(F::from(row.num_zeros as u64)))
                    .expect("Failed to allocate num_zeros"),
                num_ones: FpVar::new_witness(cs.clone(), || Ok(F::from(row.num_ones as u64)))
                    .expect("Failed to allocate num_ones"),
                total_zeros_in_bucket: FpVar::new_witness(cs.clone(), || {
                    Ok(F::from(row.num_zeros_in_bucket as u64))
                })
                .expect("Failed to allocate total_zeros_in_bucket"),
                bucket_length: FpVar::new_witness(cs.clone(), || {
                    Ok(F::from(row.bucket_length as u64))
                })
                .expect("Failed to allocate bucket_length"),
                idx: FpVar::new_witness(cs.clone(), || Ok(F::from(row.idx as u64)))
                    .expect("Failed to allocate idx"),
                next_pos: FpVar::new_witness(cs.clone(), || Ok(F::from(row.next_pos as u64)))
                    .expect("Failed to allocate next_pos"),
                bucket_id: FpVar::new_witness(cs.clone(), || Ok(F::from(row.bucket_id as u64)))
                    .expect("Failed to allocate bucket_id"),
            }
        })
    });

    // 3. Allocate sorted rows (all fields are witness variables)
    let sorted_levels: [[SortedRowVar<F>; N]; LEVELS] = std::array::from_fn(|level| {
        std::array::from_fn(|i| {
            let row = &rs_witness_trace.next_levels[level][i];

            SortedRowVar {
                idx: FpVar::new_witness(cs.clone(), || Ok(F::from(row.idx as u64)))
                    .expect("Failed to allocate sorted idx"),
                // length: FpVar::new_witness(cs.clone(), || Ok(F::from(row.length as u64)))
                //     .expect("Failed to allocate sorted length"),
                // bucket: FpVar::new_witness(cs.clone(), || Ok(F::from(row.bucket as u64)))
                //     .expect("Failed to allocate sorted bucket"),
            }
        })
    });

    Ok(PermutationWitnessTraceVar {
        bits_mat,
        uns_levels,
        sorted_levels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// Helper function to assert all invariants for build_level
    fn assert_build_level_invariants(
        prev_rows: &[SortedRow],
        bits: &[bool],
        uns: &[UnsortedRow],
        nxt: &[SortedRow],
    ) -> Result<(), String> {
        let n = prev_rows.len();
        assert_eq!(uns.len(), n, "Unsorted array length mismatch");
        assert_eq!(nxt.len(), n, "Next array length mismatch");
        assert_eq!(bits.len(), n, "Bits array length mismatch");

        // Compute contiguous bucket segments: start & length per bucket
        let mut bucket_starts: HashMap<u16, usize> = HashMap::new();
        let mut bucket_lengths: HashMap<u16, usize> = HashMap::new();
        let mut current_bucket: Option<u16> = None;
        let mut run_start = 0usize;

        for (i, row) in prev_rows.iter().enumerate() {
            match current_bucket {
                None => {
                    current_bucket = Some(row.bucket);
                    run_start = i;
                }
                Some(b) if b != row.bucket => {
                    // Close old bucket run
                    bucket_starts.entry(b).or_insert(run_start);
                    *bucket_lengths.entry(b).or_insert(0) += i - run_start;
                    // Start new bucket
                    current_bucket = Some(row.bucket);
                    run_start = i;
                }
                _ => {}
            }
        }
        // Close final bucket
        if let Some(b) = current_bucket {
            bucket_starts.entry(b).or_insert(run_start);
            *bucket_lengths.entry(b).or_insert(0) += n - run_start;
        }

        // Compute zero counts per bucket from bits
        let mut zeros_per_bucket: HashMap<u16, u16> = HashMap::new();
        for (i, row) in prev_rows.iter().enumerate() {
            if !bits[i] {
                *zeros_per_bucket.entry(row.bucket).or_insert(0) += 1;
            }
        }

        // Track positions seen to ensure bijection
        let mut seen_positions = HashSet::new();

        // Running counters per contiguous bucket segment
        let mut current_bucket_check: Option<u16> = None;
        let mut z_prefix = 0u16;
        let mut o_prefix = 0u16;

        for (i, (prev_row, uns_row)) in prev_rows.iter().zip(uns).enumerate() {
            let bit = bits[i];

            // Reset counters on bucket change
            if current_bucket_check != Some(prev_row.bucket) {
                current_bucket_check = Some(prev_row.bucket);
                z_prefix = 0;
                o_prefix = 0;
            }

            // 1. Check prefix counters match
            if uns_row.num_zeros != z_prefix {
                return Err(format!(
                    "Row {}: num_zeros mismatch. Expected {}, got {}",
                    i, z_prefix, uns_row.num_zeros
                ));
            }
            if uns_row.num_ones != o_prefix {
                return Err(format!(
                    "Row {}: num_ones mismatch. Expected {}, got {}",
                    i, o_prefix, uns_row.num_ones
                ));
            }

            // 2. Check bucket constants
            let total_zeros = *zeros_per_bucket.get(&prev_row.bucket).unwrap_or(&0);
            let bucket_len = *bucket_lengths.get(&prev_row.bucket).unwrap_or(&0) as u16;

            if uns_row.num_zeros_in_bucket != total_zeros {
                return Err(format!(
                    "Row {}: total_zeros_in_bucket mismatch. Expected {}, got {}",
                    i, total_zeros, uns_row.num_zeros_in_bucket
                ));
            }
            if uns_row.bucket_length != bucket_len {
                return Err(format!(
                    "Row {}: bucket_length mismatch. Expected {}, got {}",
                    i, bucket_len, uns_row.bucket_length
                ));
            }
            if uns_row.bucket_id != prev_row.bucket {
                return Err(format!(
                    "Row {}: bucket_id mismatch. Expected {}, got {}",
                    i, prev_row.bucket, uns_row.bucket_id
                ));
            }

            // 3. Check destination formula
            let base = *bucket_starts.get(&prev_row.bucket).unwrap_or(&0) as u16;
            let offset = if !bit {
                z_prefix
            } else {
                total_zeros + o_prefix
            };
            let expected_next_pos = base + offset;

            if uns_row.next_pos != expected_next_pos {
                return Err(format!(
                    "Row {}: next_pos mismatch. Expected {}, got {}",
                    i, expected_next_pos, uns_row.next_pos
                ));
            }

            // 4. Check no collisions
            if !seen_positions.insert(expected_next_pos as usize) {
                return Err(format!(
                    "Row {}: Collision at position {}",
                    i, expected_next_pos
                ));
            }

            // 5. Check correct placement in next array
            let next_row = &nxt[expected_next_pos as usize];
            if next_row.idx != prev_row.idx {
                return Err(format!(
                    "Row {}: idx not preserved at dst {}. Expected {}, got {}",
                    i, expected_next_pos, prev_row.idx, next_row.idx
                ));
            }

            // Check next bucket assignment (2*parent + bit)
            let expected_bucket = prev_row.bucket * 2 + (bit as u16);
            if next_row.bucket != expected_bucket {
                return Err(format!(
                    "Row {}: bucket mismatch at dst {}. Expected {}, got {}",
                    i, expected_next_pos, expected_bucket, next_row.bucket
                ));
            }

            // Check next bucket length
            let ones_in_bucket = bucket_len - total_zeros;
            let expected_length = if !bit { total_zeros } else { ones_in_bucket };
            if next_row.length != expected_length {
                return Err(format!(
                    "Row {}: length mismatch at dst {}. Expected {}, got {}",
                    i, expected_next_pos, expected_length, next_row.length
                ));
            }

            // Advance prefix counters
            if !bit {
                z_prefix += 1;
            } else {
                o_prefix += 1;
            }
        }

        // 6. Check full coverage (permutation)
        if seen_positions.len() != n {
            return Err(format!(
                "Not a full permutation. Only {} positions covered out of {}",
                seen_positions.len(),
                n
            ));
        }

        // 7. Check stability within each bucket
        for (&bucket, &bucket_len) in bucket_lengths.iter() {
            let base = bucket_starts[&bucket];
            let total_zeros = *zeros_per_bucket.get(&bucket).unwrap_or(&0) as usize;

            // Collect indices in this bucket in original order
            let mut bucket_indices = Vec::new();
            let mut bucket_bits = Vec::new();
            for i in base..base + bucket_len {
                if prev_rows[i].bucket == bucket {
                    bucket_indices.push(prev_rows[i].idx);
                    bucket_bits.push(bits[i]);
                }
            }

            // Expected order: zeros first (stable), then ones (stable)
            let zeros_expected: Vec<u16> = bucket_indices
                .iter()
                .zip(bucket_bits.iter())
                .filter_map(|(&idx, &b)| if !b { Some(idx) } else { None })
                .collect();

            let ones_expected: Vec<u16> = bucket_indices
                .iter()
                .zip(bucket_bits.iter())
                .filter_map(|(&idx, &b)| if b { Some(idx) } else { None })
                .collect();

            // Actual order in next array
            let zeros_actual: Vec<u16> = (0..total_zeros).map(|j| nxt[base + j].idx).collect();

            let ones_actual: Vec<u16> = (total_zeros..bucket_len)
                .map(|j| nxt[base + j].idx)
                .collect();

            if zeros_actual != zeros_expected {
                return Err(format!(
                    "Bucket {}: Zeros not stable. Expected {:?}, got {:?}",
                    bucket, zeros_expected, zeros_actual
                ));
            }
            if ones_actual != ones_expected {
                return Err(format!(
                    "Bucket {}: Ones not stable. Expected {:?}, got {:?}",
                    bucket, ones_expected, ones_actual
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn test_build_level_single_bucket_split() {
        const N: usize = 8;

        // Single bucket containing all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Mixed bits pattern: [0,1,0,1,1,0,0,1]
        // This gives us 4 zeros and 4 ones
        let bits_lvl: [bool; N] = [false, true, false, true, true, false, false, true];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        // Run comprehensive invariant checks
        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("Single bucket split test failed");

        // Additional specific checks for this test case
        let zero_count = bits_lvl.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Zeros should be in positions 0..4, ones in 4..8
        // Check that first 4 elements are zeros (bucket 0)
        for i in 0..zero_count {
            assert_eq!(
                nxt[i].bucket, 0,
                "First {} should be in bucket 0",
                zero_count
            );
            assert_eq!(nxt[i].length, zero_count as u16);
        }

        // Check that last 4 elements are ones (bucket 1)
        for i in zero_count..N {
            assert_eq!(nxt[i].bucket, 1, "Last {} should be in bucket 1", one_count);
            assert_eq!(nxt[i].length, one_count as u16);
        }

        // Verify stability: zeros should be [0,2,5,6], ones should be [1,3,4,7]
        let expected_zero_indices = vec![0, 2, 5, 6];
        let expected_one_indices = vec![1, 3, 4, 7];

        let actual_zero_indices: Vec<u16> = (0..zero_count).map(|i| nxt[i].idx).collect();
        let actual_one_indices: Vec<u16> = (zero_count..N).map(|i| nxt[i].idx).collect();

        assert_eq!(
            actual_zero_indices, expected_zero_indices,
            "Zero indices not stable"
        );
        assert_eq!(
            actual_one_indices, expected_one_indices,
            "One indices not stable"
        );
    }

    #[test]
    fn test_build_level_two_successive_layers() {
        const N: usize = 8;

        // Level 0: Single bucket
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1 bits: [0,1,0,1,0,1,0,1] - perfectly alternating
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        let (uns1, nxt1) = build_level::<N>(&prev0, &bits1);

        // Verify level 1
        assert_build_level_invariants(&prev0[..], &bits1[..], &uns1[..], &nxt1[..])
            .expect("Level 1 failed");

        // After level 1: nxt1 should have bucket 0 (zeros) and bucket 1 (ones)
        assert_eq!(nxt1[0..4].iter().all(|r| r.bucket == 0), true);
        assert_eq!(nxt1[4..8].iter().all(|r| r.bucket == 1), true);

        // Level 2 bits: split each bucket again
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        let (uns2, nxt2) = build_level::<N>(&nxt1, &bits2);

        // Verify level 2
        assert_build_level_invariants(&nxt1[..], &bits2[..], &uns2[..], &nxt2[..])
            .expect("Level 2 failed");

        // After level 2: should have 4 buckets (0,1,2,3)
        // Bucket 0: parent=0, bit=0 -> positions 0..2
        // Bucket 1: parent=0, bit=1 -> positions 2..4
        // Bucket 2: parent=1, bit=0 -> positions 4..6
        // Bucket 3: parent=1, bit=1 -> positions 6..8
        assert_eq!(nxt2[0..2].iter().all(|r| r.bucket == 0), true);
        assert_eq!(nxt2[2..4].iter().all(|r| r.bucket == 1), true);
        assert_eq!(nxt2[4..6].iter().all(|r| r.bucket == 2), true);
        assert_eq!(nxt2[6..8].iter().all(|r| r.bucket == 3), true);

        // Verify the final permutation matches expected
        // Level 1 placed: [0,2,4,6] then [1,3,5,7]
        // Level 2 with bits2=[1,0,0,1,0,1,1,0]:
        //   Bucket 0 zeros: [2,4], ones: [0,6]
        //   Bucket 1 zeros: [1,7], ones: [3,5]
        let expected_final_indices = vec![2, 4, 0, 6, 1, 7, 3, 5];
        let actual_final_indices: Vec<u16> = nxt2.iter().map(|r| r.idx).collect();
        assert_eq!(
            actual_final_indices, expected_final_indices,
            "Final permutation after 2 layers doesn't match expected"
        );
    }

    #[test]
    fn test_build_level_multi_bucket() {
        const N: usize = 12;

        // Three buckets: bucket 0 (size 3), bucket 1 (size 5), bucket 2 (size 4)
        let prev_rows: [SortedRow; N] = [
            SortedRow::new_with_bucket(0, 3, 0),
            SortedRow::new_with_bucket(1, 3, 0),
            SortedRow::new_with_bucket(2, 3, 0),
            SortedRow::new_with_bucket(3, 5, 1),
            SortedRow::new_with_bucket(4, 5, 1),
            SortedRow::new_with_bucket(5, 5, 1),
            SortedRow::new_with_bucket(6, 5, 1),
            SortedRow::new_with_bucket(7, 5, 1),
            SortedRow::new_with_bucket(8, 4, 2),
            SortedRow::new_with_bucket(9, 4, 2),
            SortedRow::new_with_bucket(10, 4, 2),
            SortedRow::new_with_bucket(11, 4, 2),
        ];

        // Mixed pattern: [0,1,0 | 1,1,0,0,1 | 0,0,1,1]
        let bits_lvl: [bool; N] = [
            false, true, false, // bucket 0: 2 zeros, 1 one
            true, true, false, false, true, // bucket 1: 2 zeros, 3 ones
            false, false, true, true, // bucket 2: 2 zeros, 2 ones
        ];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        // Run comprehensive invariant checks
        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("Multi-bucket test failed");

        // Verify bucket assignments and sizes
        // Bucket 0 splits into buckets 0 (2 zeros) and 1 (1 one)
        assert_eq!(nxt[0].bucket, 0);
        assert_eq!(nxt[0].length, 2);
        assert_eq!(nxt[1].bucket, 0);
        assert_eq!(nxt[1].length, 2);
        assert_eq!(nxt[2].bucket, 1);
        assert_eq!(nxt[2].length, 1);

        // Bucket 1 splits into buckets 2 (2 zeros) and 3 (3 ones)
        assert_eq!(nxt[3].bucket, 2);
        assert_eq!(nxt[3].length, 2);
        assert_eq!(nxt[4].bucket, 2);
        assert_eq!(nxt[4].length, 2);
        assert_eq!(nxt[5].bucket, 3);
        assert_eq!(nxt[5].length, 3);
        assert_eq!(nxt[6].bucket, 3);
        assert_eq!(nxt[6].length, 3);
        assert_eq!(nxt[7].bucket, 3);
        assert_eq!(nxt[7].length, 3);

        // Bucket 2 splits into buckets 4 (2 zeros) and 5 (2 ones)
        assert_eq!(nxt[8].bucket, 4);
        assert_eq!(nxt[8].length, 2);
        assert_eq!(nxt[9].bucket, 4);
        assert_eq!(nxt[9].length, 2);
        assert_eq!(nxt[10].bucket, 5);
        assert_eq!(nxt[10].length, 2);
        assert_eq!(nxt[11].bucket, 5);
        assert_eq!(nxt[11].length, 2);
    }

    #[test]
    fn test_build_level_all_zeros() {
        const N: usize = 6;

        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // All zeros
        let bits_lvl: [bool; N] = [false; N];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("All zeros test failed");

        // All elements should go to bucket 0
        for i in 0..N {
            assert_eq!(nxt[i].bucket, 0);
            assert_eq!(nxt[i].length, N as u16);
            assert_eq!(nxt[i].idx, i as u16); // Should maintain order
            assert_eq!(uns[i].next_pos, i as u16); // Should stay in place
        }
    }

    #[test]
    fn test_build_level_all_ones() {
        const N: usize = 6;

        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // All ones
        let bits_lvl: [bool; N] = [true; N];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("All ones test failed");

        // All elements should go to bucket 1
        for i in 0..N {
            assert_eq!(nxt[i].bucket, 1);
            assert_eq!(nxt[i].length, N as u16);
            assert_eq!(nxt[i].idx, i as u16); // Should maintain order
            assert_eq!(uns[i].next_pos, i as u16); // Should stay in place (Z=0, so offset=o_i)
        }
    }
}
