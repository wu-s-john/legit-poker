use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::{gr1cs, gr1cs::SynthesisError};
use std::borrow::Borrow;

/// Row in the unsorted (witness) table for one level
#[derive(Clone, Debug)]
pub(crate) struct UnsortedRow {
    /// Split bit (0 or 1)
    pub bit: bool,
    /// Number of zeros seen before this row in its bucket
    pub num_zeros: u16,
    /// Number of ones seen before this row in its bucket
    pub num_ones: u16,
    /// Total zeros in this bucket (constant for all rows of bucket)
    pub num_zeros_in_bucket: u16,
    /// Length of this bucket (constant for all rows of bucket)
    pub bucket_length: u16,
    /// Stable original index
    pub idx: u16,
    /// Computed destination position for next level
    pub next_pos: u16,
    /// Bucket ID this row belongs to
    pub bucket_id: u16,
}

/// Row in the next (sorted) array after placement
#[derive(Clone, Debug)]
pub(crate) struct SortedRow {
    /// Stable original index
    pub idx: u16,
    /// Length of the bucket this row enters (for next level)
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) length: u16,
    /// Bucket index this row belongs to
    pub bucket: u16,
}

/// Witness data for all levels
#[derive(Clone, Debug)]
pub struct PermutationWitnessTrace<const N: usize, const LEVELS: usize> {
    /// Split bits matrix (LEVELS × N)
    pub bits_mat: [[bool; N]; LEVELS],
    /// Unsorted witness rows per level
    pub(crate) uns_levels: [[UnsortedRow; N]; LEVELS],
    /// Next-arraycar per level
    pub(crate) next_levels: [[SortedRow; N]; LEVELS],
}

/// Output of the RS shuffle permutation operation
/// Contains the witness trace, sample count, and permuted output
#[derive(Clone, Debug)]
pub struct RSShuffleTrace<T, const N: usize, const LEVELS: usize> {
    /// The witness trace for the shuffle
    pub witness_trace: PermutationWitnessTrace<N, LEVELS>,
    /// The number of samples used in bit generation
    pub num_samples: usize,
    /// The permuted array
    pub permuted_output: [T; N],
}

impl<T, const N: usize, const LEVELS: usize> RSShuffleTrace<T, N, LEVELS> {
    /// Extract the permutation array (0-indexed) from the witness trace
    /// This is useful for protocols that need the explicit permutation mapping
    pub fn extract_permutation_array(&self) -> [usize; N] {
        let final_sorted = &self.witness_trace.next_levels[LEVELS - 1];
        std::array::from_fn(|i| {
            // The permutation is 0-indexed, convert from u16 to usize
            final_sorted[i].idx as usize
        })
    }
}

impl UnsortedRow {
    pub fn new(
        bit: bool,
        num_zeros: u16,
        num_ones: u16,
        num_zeros_in_bucket: u16,
        bucket_length: u16,
        idx: u16,
        next_pos: u16,
        bucket_id: u16,
    ) -> Self {
        Self {
            bit,
            num_zeros,
            num_ones,
            num_zeros_in_bucket,
            bucket_length,
            idx,
            next_pos,
            bucket_id,
        }
    }
}

impl SortedRow {
    pub fn new_with_bucket(idx: u16, length: u16, bucket: u16) -> Self {
        Self {
            idx,
            length,
            bucket,
        }
    }
}

// ============================================================================
// Circuit Variable Versions for SNARK Constraints
// ============================================================================

/// Circuit variable version of UnsortedRow for use in SNARK constraints
#[derive(Clone)]
pub(crate) struct UnsortedRowVar<F: PrimeField> {
    /// Split bit (0 or 1)
    pub bit: Boolean<F>,
    /// Number of zeros seen before this row in its bucket
    pub num_zeros: FpVar<F>,
    /// Number of ones seen before this row in its bucket
    pub num_ones: FpVar<F>,
    /// Total zeros in this bucket (constant for all rows of bucket)
    pub total_zeros_in_bucket: FpVar<F>,
    /// Length of this bucket (constant for all rows of bucket)
    pub bucket_length: FpVar<F>,
    /// Stable original index
    pub idx: FpVar<F>,
    /// Computed destination position for next level
    pub next_pos: FpVar<F>,
    /// Bucket ID this row belongs to
    pub bucket_id: FpVar<F>,
}

impl<F: PrimeField> AllocVar<UnsortedRow, F> for UnsortedRowVar<F> {
    fn new_variable<T: Borrow<UnsortedRow>>(
        cs: impl Into<gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let value = f()?;
        let row = value.borrow();

        Ok(Self {
            bit: Boolean::new_variable(cs.clone(), || Ok(row.bit), mode)?,
            num_zeros: FpVar::new_variable(cs.clone(), || Ok(F::from(row.num_zeros as u64)), mode)?,
            num_ones: FpVar::new_variable(cs.clone(), || Ok(F::from(row.num_ones as u64)), mode)?,
            total_zeros_in_bucket: FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(row.num_zeros_in_bucket as u64)),
                mode,
            )?,
            bucket_length: FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(row.bucket_length as u64)),
                mode,
            )?,
            idx: FpVar::new_variable(cs.clone(), || Ok(F::from(row.idx as u64)), mode)?,
            next_pos: FpVar::new_variable(cs.clone(), || Ok(F::from(row.next_pos as u64)), mode)?,
            bucket_id: FpVar::new_variable(cs.clone(), || Ok(F::from(row.bucket_id as u64)), mode)?,
        })
    }
}

/// Circuit variable version of SortedRow for use in SNARK constraints
#[derive(Clone)]
pub(crate) struct SortedRowVar<F>
where
    F: PrimeField,
{
    /// Stable original index
    pub idx: FpVar<F>,
    // /// Length of the bucket this row enters (for next level)
    // length: FpVar<F>,
    // /// Bucket index this row belongs to
    // bucket: FpVar<F>,
}

impl<F: PrimeField> AllocVar<SortedRow, F> for SortedRowVar<F> {
    fn new_variable<T: Borrow<SortedRow>>(
        cs: impl Into<gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let value = f()?;
        let row = value.borrow();

        Ok(Self {
            idx: FpVar::new_variable(cs.clone(), || Ok(F::from(row.idx as u64)), mode)?,
            // length: FpVar::new_variable(cs.clone(), || Ok(F::from(row.length as u64)), mode)?,
            // bucket: FpVar::new_variable(cs.clone(), || Ok(F::from(row.bucket as u64)), mode)?,
        })
    }
}

/// Circuit variable version of WitnessData for use in SNARK constraints
#[derive(Clone)]
pub struct PermutationWitnessTraceVar<F: PrimeField, const N: usize, const LEVELS: usize> {
    /// Split bits matrix (LEVELS × N) as witness variables
    pub bits_mat: [[Boolean<F>; N]; LEVELS],
    /// Unsorted witness rows per level
    pub(crate) uns_levels: [[UnsortedRowVar<F>; N]; LEVELS],
    /// Next-array per level
    pub(crate) sorted_levels: [[SortedRowVar<F>; N]; LEVELS],
}

impl<F: PrimeField, const N: usize, const LEVELS: usize>
    AllocVar<PermutationWitnessTrace<N, LEVELS>, F> for PermutationWitnessTraceVar<F, N, LEVELS>
{
    fn new_variable<T: Borrow<PermutationWitnessTrace<N, LEVELS>>>(
        cs: impl Into<gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let value = f()?;
        let witness_data = value.borrow();

        // Helper to allocate a single bit
        let alloc_bit = |bit: &bool| Boolean::new_variable(cs.clone(), || Ok(*bit), mode);

        // Helper to allocate a level of bits
        let alloc_bit_level = |level: &[bool; N]| -> Result<[Boolean<F>; N], SynthesisError> {
            level
                .iter()
                .map(alloc_bit)
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)
        };

        // Allocate all bits immutably
        let bits_mat = witness_data
            .bits_mat
            .iter()
            .map(alloc_bit_level)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        // Helper to allocate an unsorted row
        let alloc_unsorted_row =
            |row: &UnsortedRow| UnsortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), mode);

        // Helper to allocate a level of unsorted rows
        let alloc_unsorted_level =
            |level: &[UnsortedRow; N]| -> Result<[UnsortedRowVar<F>; N], SynthesisError> {
                level
                    .iter()
                    .map(alloc_unsorted_row)
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)
            };

        // Allocate all unsorted rows immutably
        let uns_levels = witness_data
            .uns_levels
            .iter()
            .map(alloc_unsorted_level)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        // Helper to allocate a sorted row
        let alloc_sorted_row =
            |row: &SortedRow| SortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), mode);

        // Helper to allocate a level of sorted rows
        let alloc_sorted_level =
            |level: &[SortedRow; N]| -> Result<[SortedRowVar<F>; N], SynthesisError> {
                level
                    .iter()
                    .map(alloc_sorted_row)
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)
            };

        // Allocate all sorted rows immutably
        let next_levels = witness_data
            .next_levels
            .iter()
            .map(alloc_sorted_level)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        Ok(Self {
            bits_mat,
            uns_levels,
            sorted_levels: next_levels,
        })
    }
}

impl<F: PrimeField, const N: usize, const LEVELS: usize> PermutationWitnessTraceVar<F, N, LEVELS> {
    /// Get the number of levels in the witness data (always LEVELS)
    pub const fn num_levels(&self) -> usize {
        LEVELS
    }

    /// Get the number of elements at a specific level (always N)
    pub const fn level_size(&self, _level: usize) -> usize {
        N
    }
}
