//! Native (non-SNARK) implementation of Bayer-Groth permutation equality proof

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::vec::Vec;

/// Compute linear blend: d_i = y * a_i + b_i for i = 1, ..., N
pub fn compute_linear_blend<F: Field>(a: &[F], b: &[F], y: F) -> Vec<F> {
    assert_eq!(a.len(), b.len(), "Vectors a and b must have same length");

    a.iter()
        .zip(b.iter())
        .map(|(a_i, b_i)| y * a_i + b_i)
        .collect()
}

/// Compute left product: L = ∏_{i=1}^N (d_i - z)
pub fn compute_left_product<F: Field>(d: &[F], z: F) -> F {
    d.iter().fold(F::one(), |acc, d_i| acc * (*d_i - z))
}

/// Compute right product: R = ∏_{i=1}^N (y*i + x^i - z)
/// Uses running power computation for efficiency
pub fn compute_right_product<F: Field>(y: F, x: F, z: F, n: usize) -> F {
    let mut result = F::one();
    let mut x_power = F::one(); // x^0 = 1

    for i in 1..=n {
        x_power *= x; // x^i
        let i_scalar = F::from(i as u64);
        let term = y * i_scalar + x_power - z;
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
/// - a: permutation vector (π(1), ..., π(N))
/// - b: hidden vector (x^π(1), ..., x^π(N))
/// - y, z: Fiat-Shamir challenges
/// - x: challenge for computing b
///
/// Returns: (L, R, P) where:
/// - L = ∏(d_i - z) where d_i = y*a_i + b_i
/// - R = ∏(y*i + x^i - z)
/// - P = [L]G
pub fn compute_permutation_proof<F, G>(
    a: &[F],
    b: &[F],
    y: F,
    z: F,
    x: F,
    generator: G::Affine,
) -> (F, F, G)
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let n = a.len();
    assert_eq!(b.len(), n, "Vectors a and b must have same length");

    // Step 1: Linear blend
    let d = compute_linear_blend(a, b, y);

    // Step 2: Left product
    let left = compute_left_product(&d, z);

    // Step 3: Right product
    let right = compute_right_product(y, x, z, n);

    // Step 4: Fixed-base scalar multiplication
    let point = fixed_base_scalar_mul::<G>(left, generator);

    (left, right, point)
}

/// Compute the hidden vector b = (x^π(1), ..., x^π(N))
/// given a permutation and challenge x
pub fn compute_hidden_vector<F: Field>(permutation: &[usize], x: F) -> Vec<F> {
    // b[i] = x^π(i+1) since permutation is 1-indexed
    permutation.iter().map(|&pi| x.pow(&[pi as u64])).collect()
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

        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let y = Fr::rand(&mut rng);

        let d = compute_linear_blend(&a, &b, y);

        // Verify each element
        for i in 0..n {
            assert_eq!(d[i], y * a[i] + b[i]);
        }
    }

    #[test]
    fn test_left_product() {
        let d = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let z = Fr::from(1u64);

        let result = compute_left_product(&d, z);

        // (2-1) * (3-1) * (4-1) = 1 * 2 * 3 = 6
        assert_eq!(result, Fr::from(6u64));
    }

    #[test]
    fn test_right_product() {
        let y = Fr::from(2u64);
        let x = Fr::from(3u64);
        let z = Fr::from(1u64);
        let n = 3;

        let result = compute_right_product(y, x, z, n);

        // (2*1 + 3^1 - 1) * (2*2 + 3^2 - 1) * (2*3 + 3^3 - 1)
        // = (2 + 3 - 1) * (4 + 9 - 1) * (6 + 27 - 1)
        // = 4 * 12 * 32 = 1536
        assert_eq!(result, Fr::from(1536u64));
    }

    #[test]
    fn test_permutation_equality_holds() {
        // For a valid permutation, with correct b vector,
        // the left and right products should be equal
        let mut rng = test_rng();
        let n = 5;

        // Create a permutation: [3, 1, 4, 2, 5]
        let perm = vec![3, 1, 4, 2, 5];
        let a: Vec<Fr> = perm.iter().map(|&i| Fr::from(i as u64)).collect();

        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let z = Fr::rand(&mut rng);

        // Compute b = (x^3, x^1, x^4, x^2, x^5)
        let b: Vec<Fr> = perm.iter().map(|&i| x.pow(&[i as u64])).collect();

        // Compute linear blend
        let d = compute_linear_blend(&a, &b, y);

        // Compute products
        let left = compute_left_product(&d, z);
        let right = compute_right_product(y, x, z, n);

        // They should be equal for a valid permutation
        assert_eq!(left, right);
    }
}
