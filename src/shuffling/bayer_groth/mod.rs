//! Bayer-Groth verifiable shuffle implementation
//!
//! Pairing-free verification using Pedersen commitments for n=52 cards
//! Product decomposition: n = m * r with m=4, r=13

pub mod commitment;
pub mod decomposition;
pub mod prover;
pub mod transcript;
pub mod types;
pub mod verifier;

// Re-export main types and functions
pub use commitment::BgCommitment;
pub use prover::prove;
pub use types::{BgParams, BgProof, ShuffleInstance, ShuffleWitness};
pub use verifier::verify;

// Constants for product decomposition
pub const M: usize = 4; // Number of rows
pub const R: usize = 13; // Number of columns
pub const N: usize = M * R; // Total size (52)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(N, 52);
        assert_eq!(M * R, N);
    }
}
