//! Test utility functions for ElGamal ciphertext generation and shuffling operations
//!
//! This module provides reusable test helper functions to eliminate code duplication
//! across the test suite, particularly for:
//! - Generating random ElGamal ciphertexts with sequential values
//! - Shuffling and rerandomizing ciphertext decks
//! - Permutation utilities

use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalKeys};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

/// Generate N random ElGamal ciphertexts with sequential message values (1, 2, ..., N).
///
/// This is the standard test pattern for creating an initial deck of encrypted cards.
///
/// # Returns
/// - Array of N ciphertexts
/// - Array of N randomness values used for encryption
///
/// # Example
/// ```ignore
/// let (ciphertexts, randomness) = generate_random_ciphertexts::<G1Projective, 52>(&keys, &mut rng);
/// ```
pub fn generate_random_ciphertexts<C: CurveGroup, const N: usize>(
    public_key: &C,
    rng: &mut impl Rng,
) -> ([ElGamalCiphertext<C>; N], [C::ScalarField; N])
where
    C::ScalarField: PrimeField,
{
    let g = C::generator();
    let mut randomness_values = Vec::with_capacity(N);

    let ciphertexts = core::array::from_fn(|i| {
        let r = C::ScalarField::rand(rng);
        randomness_values.push(r);

        let message = g * C::ScalarField::from((i + 1) as u64); // Card value i+1
        ElGamalCiphertext {
            c1: g * r,
            c2: message + *public_key * r,
        }
    });

    let randomness: [C::ScalarField; N] = randomness_values.try_into().unwrap();
    (ciphertexts, randomness)
}

/// Apply a permutation and rerandomization to a deck of ciphertexts.
///
/// This function shuffles the deck according to the given permutation and adds
/// a fresh encryption layer using the provided rerandomization values.
///
/// # Formula
/// `C'[i] = C[permutation[i]].add_encryption_layer(rerandomizations[i], public_key)`
///
/// # Example
/// ```ignore
/// let shuffled = shuffle_and_rerandomize(&input_deck, &permutation, &rerandomizations, public_key);
/// ```
pub fn shuffle_and_rerandomize<C: CurveGroup, const N: usize>(
    input_deck: &[ElGamalCiphertext<C>; N],
    permutation: &[usize; N],
    rerandomizations: &[C::ScalarField; N],
    public_key: C,
) -> [ElGamalCiphertext<C>; N]
where
    C::ScalarField: PrimeField,
{
    core::array::from_fn(|i| {
        input_deck[permutation[i]].add_encryption_layer(rerandomizations[i], public_key)
    })
}

/// Apply a permutation and random rerandomization to a deck of ciphertexts.
///
/// This function shuffles the deck and generates fresh random rerandomization values.
///
/// # Returns
/// - Shuffled and rerandomized deck
/// - Array of randomness values used for rerandomization
///
/// # Example
/// ```ignore
/// let (shuffled_deck, rerandomizations) = shuffle_and_rerandomize_random(
///     &input_deck,
///     &permutation,
///     public_key,
///     &mut rng
/// );
/// ```
pub fn shuffle_and_rerandomize_random<C: CurveGroup, const N: usize>(
    input_deck: &[ElGamalCiphertext<C>; N],
    permutation: &[usize; N],
    public_key: C,
    rng: &mut impl Rng,
) -> ([ElGamalCiphertext<C>; N], [C::ScalarField; N])
where
    C::ScalarField: PrimeField + UniformRand,
{
    let mut rerandomizations_vec = Vec::with_capacity(N);

    let output_deck = core::array::from_fn(|i| {
        let r = C::ScalarField::rand(rng);
        rerandomizations_vec.push(r);
        input_deck[permutation[i]].add_encryption_layer(r, public_key)
    });

    let rerandomizations: [C::ScalarField; N] = rerandomizations_vec.try_into().unwrap();
    (output_deck, rerandomizations)
}

/// Apply only a permutation to a deck without rerandomization.
///
/// Useful for tests that need to verify permutation logic separately from rerandomization.
///
/// # Example
/// ```ignore
/// let permuted_deck = apply_permutation(&input_deck, &permutation);
/// ```
pub fn apply_permutation<C: CurveGroup, const N: usize>(
    input_deck: &[ElGamalCiphertext<C>; N],
    permutation: &[usize; N],
) -> [ElGamalCiphertext<C>; N] {
    core::array::from_fn(|i| input_deck[permutation[i]].clone())
}

/// Generate a random permutation of size N using Fisher-Yates shuffle.
///
/// Creates a permutation array where permutation[i] indicates which input position
/// maps to output position i.
///
/// # Example
/// ```ignore
/// let perm = generate_random_permutation::<52>(&mut rng);
/// // perm[0] = 37 means input position 37 goes to output position 0
/// ```
pub fn generate_random_permutation<const N: usize>(rng: &mut impl Rng) -> [usize; N] {
    let mut perm = [0; N];
    for i in 0..N {
        perm[i] = i;
    }

    // Fisher-Yates shuffle
    for i in (1..N).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        perm.swap(i, j);
    }

    perm
}

/// Invert a permutation array.
///
/// If `perm[i] = j`, then `inv[j] = i`.
///
/// # Example
/// ```ignore
/// let perm = [2, 0, 1];  // 0->2, 1->0, 2->1
/// let inv = invert_permutation(&perm);  // [1, 2, 0]
/// ```
pub fn invert_permutation<const N: usize>(perm: &[usize; N]) -> [usize; N] {
    let mut inv = [0; N];
    for i in 0..N {
        inv[perm[i]] = i;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_std::test_rng;

    #[test]
    fn test_generate_random_ciphertexts() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let keys = ElGamalKeys::new(sk);

        const N: usize = 5;
        let (ciphertexts, randomness) =
            generate_random_ciphertexts::<G1Projective, N>(&keys.public_key, &mut rng);

        assert_eq!(ciphertexts.len(), N);
        assert_eq!(randomness.len(), N);

        // Verify encryption structure
        let g = G1Projective::generator();
        for i in 0..N {
            assert_eq!(ciphertexts[i].c1, g * randomness[i]);
            // c2 = message + pk * r, where message = g * (i+1)
            let expected_c2 = g * Fr::from((i + 1) as u64) + keys.public_key * randomness[i];
            assert_eq!(ciphertexts[i].c2, expected_c2);
        }
    }

    #[test]
    fn test_permutation_operations() {
        let mut rng = test_rng();

        const N: usize = 5;
        let perm = generate_random_permutation::<N>(&mut rng);

        // Check permutation is valid (contains each element exactly once)
        let mut seen = [false; N];
        for &p in &perm {
            assert!(p < N);
            assert!(!seen[p]);
            seen[p] = true;
        }

        // Test inversion
        let inv = invert_permutation(&perm);
        for i in 0..N {
            assert_eq!(inv[perm[i]], i);
            assert_eq!(perm[inv[i]], i);
        }
    }

    #[test]
    fn test_shuffle_and_rerandomize() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let keys = ElGamalKeys::new(sk);

        const N: usize = 4;
        let (input_deck, _) =
            generate_random_ciphertexts::<G1Projective, N>(&keys.public_key, &mut rng);
        let perm = generate_random_permutation::<N>(&mut rng);

        // Test with random rerandomization
        let (output_deck, rerandomizations) =
            shuffle_and_rerandomize_random(&input_deck, &perm, keys.public_key, &mut rng);

        assert_eq!(output_deck.len(), N);
        assert_eq!(rerandomizations.len(), N);

        // Test without rerandomization
        let permuted_only = apply_permutation(&input_deck, &perm);
        for i in 0..N {
            assert_eq!(permuted_only[i], input_deck[perm[i]]);
        }
    }
}
