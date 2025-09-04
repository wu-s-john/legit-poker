//! RS (Rao-Sandelius) Shuffling Algorithm Implementation
//!
//! This module implements the stable-partition shuffle with bucket-local constraints
//! and grand-product permutation checks.

/// Number of ciphertexts (deck size)
pub const N: usize = 52;

/// Depth of shuffle levels
pub const LEVELS: usize = 5;

/// Total number of split bits needed (N * LEVELS)
pub const BITS_NEED: usize = N * LEVELS; // 260 split bits total

pub mod bit_generation;
pub mod circuit;
pub mod data_structures;
pub mod permutation;
pub mod rs_shuffle_gadget;
pub mod witness_preparation;

// Main verification functions (re-exported from rs_shuffle_gadget)
pub use rs_shuffle_gadget::{rs_shuffle, rs_shuffle_indices, rs_shuffle_with_reencryption};

// Data structures
pub use data_structures::{
    PermutationWitnessData, PermutationWitnessDataVar, SortedRow, SortedRowVar, UnsortedRow,
    UnsortedRowVar,
};

// Witness preparation
pub use witness_preparation::{prepare_witness_data, prepare_witness_data_circuit};

// Main circuit implementation
pub use circuit::{RSShuffleCircuit, RSShufflePermutationCircuit};
