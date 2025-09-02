//! Native (non-SNARK) implementation of Bayer-Groth permutation equality proof

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::vec::Vec;

/// Compute linear blend: d_i = perm_mixing_challenge_y * perm_vector_i + perm_power_vector_i for i = 1, ..., N
pub fn compute_linear_blend<F: Field>(perm_vector: &[F], perm_power_vector: &[F], perm_mixing_challenge_y: F) -> Vec<F> {
    assert_eq!(perm_vector.len(), perm_power_vector.len(), "Permutation vector and power vector must have same length");

    perm_vector.iter()
        .zip(perm_power_vector.iter())
        .map(|(perm_i, power_i)| perm_mixing_challenge_y * perm_i + power_i)
        .collect()
}

/// Compute left product: L = ∏_{i=1}^N (d_i - perm_offset_challenge_z)
pub fn compute_left_product<F: Field>(d: &[F], perm_offset_challenge_z: F) -> F {
    d.iter().fold(F::one(), |acc, d_i| acc * (*d_i - perm_offset_challenge_z))
}

/// Compute right product: R = ∏_{i=1}^N (perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z)
/// Uses running power computation for efficiency
pub fn compute_right_product<F: Field>(perm_mixing_challenge_y: F, perm_power_challenge: F, perm_offset_challenge_z: F, n: usize) -> F {
    let mut result = F::one();
    let mut power_of_challenge = F::one(); // perm_power_challenge^0 = 1

    for i in 1..=n {
        power_of_challenge *= perm_power_challenge; // perm_power_challenge^i
        let i_scalar = F::from(i as u64);
        let term = perm_mixing_challenge_y * i_scalar + power_of_challenge - perm_offset_challenge_z;
        result *= term;
    }

    result
}

/// Fixed-base scalar multiplication: P = [scalar]G
/// Uses precomputed tables for efficiency
pub fn fixed_base_scalar_mul<G: CurveGroup>(scalar: G::ScalarField, base: G::Affine) -> G {
    // For simplicity, using variable base MSM with single element
    // In production, would use precomputed window tables with bit decomposition
    G::msm(&[base], &[scalar]).unwrap()
}

/// Complete permutation equality proof computation (native)
///
/// Given:
/// - perm_vector: permutation vector (π(1), ..., π(N))
/// - perm_power_vector: power vector (x^π(1), ..., x^π(N))
/// - perm_mixing_challenge_y: challenge for linear combination
/// - perm_offset_challenge_z: offset challenge for polynomial evaluation
/// - perm_power_challenge: challenge x for computing powers
///
/// Returns: (L, R, P) where:
/// - L = ∏(d_i - perm_offset_challenge_z) where d_i = perm_mixing_challenge_y*perm_vector_i + perm_power_vector_i
/// - R = ∏(perm_mixing_challenge_y*i + perm_power_challenge^i - perm_offset_challenge_z)
/// - P = [L]G
pub fn compute_permutation_proof<F, G>(
    perm_vector: &[F],
    perm_power_vector: &[F],
    perm_mixing_challenge_y: F,
    perm_offset_challenge_z: F,
    perm_power_challenge: F,
    generator: G::Affine,
) -> (F, F, G)
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let n = perm_vector.len();
    assert_eq!(perm_power_vector.len(), n, "Permutation vector and power vector must have same length");

    // Step 1: Linear blend
    let d = compute_linear_blend(perm_vector, perm_power_vector, perm_mixing_challenge_y);

    // Step 2: Left product
    let left = compute_left_product(&d, perm_offset_challenge_z);

    // Step 3: Right product
    let right = compute_right_product(perm_mixing_challenge_y, perm_power_challenge, perm_offset_challenge_z, n);

    // Step 4: Fixed-base scalar multiplication
    let point = fixed_base_scalar_mul::<G>(left, generator);

    (left, right, point)
}

/// Compute the permutation power vector = (perm_power_challenge^π(1), ..., perm_power_challenge^π(N))
/// given a permutation and power challenge
pub fn compute_perm_power_vector<F: Field>(permutation: &[usize], perm_power_challenge: F) -> Vec<F> {
    // power_vector[i] = perm_power_challenge^π(i+1) since permutation is 1-indexed
    permutation.iter().map(|&pi| perm_power_challenge.pow(&[pi as u64])).collect()
}

/// Verify that a permutation proof is correct (native)
pub fn verify_permutation_equality<F: Field>(left_product: F, right_product: F) -> bool {
    left_product == right_product
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_linear_blend() {
        let mut rng = test_rng();
        let n = 10;

        let perm_vector: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let perm_power_vector: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let perm_mixing_challenge_y = Fr::rand(&mut rng);

        let d = compute_linear_blend(&perm_vector, &perm_power_vector, perm_mixing_challenge_y);

        // Verify each element
        for i in 0..n {
            assert_eq!(d[i], perm_mixing_challenge_y * perm_vector[i] + perm_power_vector[i]);
        }
    }

    #[test]
    fn test_left_product() {
        let d = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let perm_offset_challenge_z = Fr::from(1u64);

        let result = compute_left_product(&d, perm_offset_challenge_z);

        // (2-1) * (3-1) * (4-1) = 1 * 2 * 3 = 6
        assert_eq!(result, Fr::from(6u64));
    }

    #[test]
    fn test_right_product() {
        let perm_mixing_challenge_y = Fr::from(2u64);
        let perm_power_challenge = Fr::from(3u64);
        let perm_offset_challenge_z = Fr::from(1u64);
        let n = 3;

        let result = compute_right_product(perm_mixing_challenge_y, perm_power_challenge, perm_offset_challenge_z, n);

        // (2*1 + 3^1 - 1) * (2*2 + 3^2 - 1) * (2*3 + 3^3 - 1)
        // = (2 + 3 - 1) * (4 + 9 - 1) * (6 + 27 - 1)
        // = 4 * 12 * 32 = 1536
        assert_eq!(result, Fr::from(1536u64));
    }

    #[test]
    fn test_permutation_equality_holds() {
        // For a valid permutation, with correct power vector,
        // the left and right products should be equal
        let mut rng = test_rng();
        let n = 5;

        // Create a permutation: [3, 1, 4, 2, 5]
        let perm = vec![3, 1, 4, 2, 5];
        let perm_vector: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        let perm_power_challenge = Fr::rand(&mut rng);
        let perm_mixing_challenge_y = Fr::rand(&mut rng);
        let perm_offset_challenge_z = Fr::rand(&mut rng);

        // Compute power vector = (perm_power_challenge^3, perm_power_challenge^1, perm_power_challenge^4, perm_power_challenge^2, perm_power_challenge^5)
        let perm_power_vector: Vec<Fr> = perm.iter().map(|&i| perm_power_challenge.pow(&[i as u64])).collect();

        // Compute linear blend
        let d = compute_linear_blend(&perm_vector, &perm_power_vector, perm_mixing_challenge_y);

        // Compute products
        let left = compute_left_product(&d, perm_offset_challenge_z);
        let right = compute_right_product(perm_mixing_challenge_y, perm_power_challenge, perm_offset_challenge_z, n);

        // They should be equal for a valid permutation
        assert_eq!(left, right);
    }
}
