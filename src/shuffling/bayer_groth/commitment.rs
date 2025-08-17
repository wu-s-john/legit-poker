//! Commitment wrapper for Bayer-Groth using arkworks Pedersen

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_crypto_primitives::commitment::{
    pedersen::{Commitment as PedersenCommitment, Parameters, Randomness, Window},
    CommitmentScheme,
};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use ark_std::Zero;

/// Window type for Pedersen commitment
#[derive(Clone)]
pub struct BgWindow;

impl Window for BgWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 64;  // 4×64 = 256 bits for Fr elements
}

/// Type alias for our Pedersen commitment scheme
pub type Pedersen = PedersenCommitment<G1Projective, BgWindow>;

/// Wrapper for BG-specific commitment operations
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BgCommitment {
    pub commitment: G1Affine,
}

impl BgCommitment {
    /// Create a new commitment to a scalar value
    pub fn commit(
        params: &Parameters<G1Projective>,
        value: &Fr,
        rng: &mut impl Rng,
    ) -> (Self, Randomness<G1Projective>) {
        // Convert scalar to bytes for commitment
        let mut input = Vec::new();
        value.serialize_compressed(&mut input).unwrap();

        // Generate randomness
        let randomness = Randomness::<G1Projective>::rand(rng);

        // Compute commitment
        let commitment = Pedersen::commit(params, &input, &randomness).unwrap();

        (
            BgCommitment {
                commitment,
            },
            randomness,
        )
    }

    /// Verify a commitment opening
    pub fn verify(
        &self,
        params: &Parameters<G1Projective>,
        value: &Fr,
        randomness: &Randomness<G1Projective>,
    ) -> bool {
        let mut input = Vec::new();
        value.serialize_compressed(&mut input).unwrap();

        // Recompute the commitment and check if it matches
        let recomputed = Pedersen::commit(params, &input, randomness).unwrap();
        self.commitment == recomputed
    }

    /// Aggregate multiple commitments with weights for batched verification
    /// Returns: weighted_sum(commitments)
    pub fn aggregate(commitments: &[BgCommitment], weights: &[Fr]) -> G1Projective {
        assert_eq!(commitments.len(), weights.len());

        let mut result = G1Projective::zero();
        for (com, weight) in commitments.iter().zip(weights.iter()) {
            result += com.commitment.mul_bigint(weight.into_bigint());
        }
        result
    }

    /// Aggregate randomness values with weights
    /// Note: In arkworks, Pedersen Randomness<G> contains a scalar field element
    pub fn aggregate_randomness(
        randomness: &[Randomness<G1Projective>],
        weights: &[Fr],
    ) -> Randomness<G1Projective> {
        assert_eq!(randomness.len(), weights.len());

        // Aggregate the randomness scalars
        let mut aggregated = Fr::zero();

        for (r, w) in randomness.iter().zip(weights.iter()) {
            // Randomness(scalar) structure - aggregate the scalars
            aggregated += r.0 * w;
        }

        // Return aggregated randomness
        Randomness(aggregated)
    }
}

/// Helper to setup Pedersen parameters for BG
pub fn setup_pedersen_params(rng: &mut impl Rng) -> Parameters<G1Projective> {
    // Setup Pedersen parameters
    Pedersen::setup(rng).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_commitment_and_verify() {
        let mut rng = test_rng();
        let params = setup_pedersen_params(&mut rng);

        let value = Fr::rand(&mut rng);
        let (com, rand) = BgCommitment::commit(&params, &value, &mut rng);

        assert!(com.verify(&params, &value, &rand));

        // Wrong value should fail
        let wrong_value = Fr::rand(&mut rng);
        assert!(!com.verify(&params, &wrong_value, &rand));
    }

    #[test]
    fn test_aggregation() {
        let mut rng = test_rng();
        let params = setup_pedersen_params(&mut rng);

        let n = 5;
        let mut commitments = Vec::new();
        let mut weights = Vec::new();

        for _ in 0..n {
            let value = Fr::rand(&mut rng);
            let (com, _) = BgCommitment::commit(&params, &value, &mut rng);
            commitments.push(com);
            weights.push(Fr::rand(&mut rng));
        }

        let aggregated = BgCommitment::aggregate(&commitments, &weights);
        assert!(!aggregated.is_zero());
    }
}
