pub mod bayer_groth;
pub mod bayer_groth_permutation;
pub use crate::chaum_pedersen;
pub mod og_shuffling;
pub use og_shuffling as circuit;
pub mod community_decryption;
pub use crate::curve_absorb;
pub mod data_structures;
pub mod encryption;
pub mod error;
pub use crate::field_conversion_gadget;
pub use crate::pedersen_commitment;
pub mod permutation_proof;
pub mod permutation_serialization;
pub mod player_decryption;
pub use player_decryption::gadget as player_decryption_gadget;
pub mod proof_system;
use ark_ff::Field;
use ark_std::rand::Rng;

/// Draw a random shuffler secret/public key pair.
/// Returns `(secret_key, public_key)`.
pub fn draw_shuffler_public_key<C, R>(rng: &mut R) -> (C::ScalarField, C)
where
    C: CurveGroup,
    C::ScalarField: Field,
    R: Rng,
{
    let secret_key = C::ScalarField::rand(rng);
    let generator = C::generator();
    let public_key = generator * secret_key;
    (secret_key, public_key)
}

/// Merge multiple shuffler public keys to create the global public key.
/// `pk_global = sum(pk_i) = (sum(sk_i)) * G`.
pub fn make_global_public_keys<C>(shuffler_keys: Vec<C>) -> C
where
    C: CurveGroup,
{
    shuffler_keys
        .into_iter()
        .fold(C::zero(), |acc, pk| acc + pk)
}
pub mod rs_shuffle;
pub mod shuffling_proof;
pub mod utils;

pub use community_decryption::*;
pub use data_structures::*;
pub use encryption::*;
pub use error::*;
pub use player_decryption::*;

// ============================================================================
// Core Shuffling Utility Functions
// ============================================================================

use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};

/// Generate N random ElGamal ciphertexts with sequential message values (0, 1, ..., N-1).
///
/// This is the standard pattern for creating an initial deck of encrypted cards.
///
/// # Returns
/// - Array of N ciphertexts
/// - Array of N randomness values used for encryption
///
/// # Example
/// ```rust
/// use ark_bn254::G1Projective;
/// use ark_std::test_rng;
/// use zk_poker::shuffling;
///
/// let mut rng = test_rng();
/// let (_sk1, pk1) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let (_sk2, pk2) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let public_key = shuffling::make_global_public_keys(vec![pk1, pk2]);
/// let (_ciphertexts, _randomness) =
///     shuffling::generate_random_ciphertexts::<G1Projective, 4>(&public_key, &mut rng);
/// ```
pub fn generate_random_ciphertexts<C: CurveGroup, const N: usize>(
    public_key: &C,
    rng: &mut impl Rng,
) -> ([ElGamalCiphertext<C>; N], [C::ScalarField; N])
where
    C::ScalarField: PrimeField + UniformRand,
    C::Config: CurveConfig<ScalarField = C::ScalarField>,
{
    let g = C::generator();
    let randomness = generate_randomization_array::<C::Config, N>(rng);

    let ciphertexts = core::array::from_fn(|i| {
        let r = randomness[i];
        let message = g * C::ScalarField::from(i as u64); // Card value = index (0-based)
        ElGamalCiphertext {
            c1: g * r,
            c2: message + *public_key * r,
        }
    });

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
/// ```rust
/// use ark_bn254::{Fr, G1Projective};
/// use ark_std::test_rng;
/// use zk_poker::shuffling;
/// let mut rng = test_rng();
/// let (_sk1, pk1) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let (_sk2, pk2) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let public_key = shuffling::make_global_public_keys(vec![pk1, pk2]);
/// let (deck, _) = shuffling::generate_random_ciphertexts::<G1Projective, 4>(&public_key, &mut rng);
/// let permutation = [1usize, 0, 3, 2];
/// let rerandomizations = [Fr::from(1u64); 4];
/// let _shuffled = shuffling::shuffle_and_rerandomize(&deck, &permutation, &rerandomizations, public_key);
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
/// ```rust
/// use ark_bn254::G1Projective;
/// use ark_std::test_rng;
/// use zk_poker::shuffling;
/// let mut rng = test_rng();
/// let (_sk1, pk1) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let (_sk2, pk2) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let public_key = shuffling::make_global_public_keys(vec![pk1, pk2]);
/// let (deck, _) = shuffling::generate_random_ciphertexts::<G1Projective, 4>(&public_key, &mut rng);
/// let permutation = [1usize, 0, 3, 2];
/// let (_shuffled, _rerand) = shuffling::shuffle_and_rerandomize_random(
///     &deck,
///     &permutation,
///     public_key,
///     &mut rng,
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
    C::Config: CurveConfig<ScalarField = C::ScalarField>,
{
    let rerandomizations = generate_randomization_array::<C::Config, N>(rng);

    let output_deck = core::array::from_fn(|i| {
        input_deck[permutation[i]].add_encryption_layer(rerandomizations[i], public_key)
    });

    (output_deck, rerandomizations)
}

/// Apply only a permutation to a deck without rerandomization.
///
/// Useful for tests that need to verify permutation logic separately from rerandomization.
///
/// # Example
/// ```rust
/// use ark_bn254::G1Projective;
/// use ark_std::test_rng;
/// use zk_poker::shuffling;
/// let mut rng = test_rng();
/// let (_sk1, pk1) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let (_sk2, pk2) = shuffling::draw_shuffler_public_key::<G1Projective, _>(&mut rng);
/// let public_key = shuffling::make_global_public_keys(vec![pk1, pk2]);
/// let (deck, _) = shuffling::generate_random_ciphertexts::<G1Projective, 4>(&public_key, &mut rng);
/// let permutation = [1usize, 0, 3, 2];
/// let _permuted = shuffling::apply_permutation(&deck, &permutation);
/// ```
pub fn apply_permutation<C: CurveGroup, const N: usize>(
    input_deck: &[ElGamalCiphertext<C>; N],
    permutation: &[usize; N],
) -> [ElGamalCiphertext<C>; N] {
    core::array::from_fn(|i| input_deck[permutation[i]].clone())
}

#[cfg(test)]
mod tests {
    use crate::shuffling::{
        apply_permutation, generate_random_ciphertexts, shuffle_and_rerandomize_random, ElGamalKeys,
    };
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
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
            // c2 = message + pk * r, where message = g * i (0-based)
            let expected_c2 = g * Fr::from(i as u64) + keys.public_key * randomness[i];
            assert_eq!(ciphertexts[i].c2, expected_c2);
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

        // Use a simple test permutation instead of generating one
        let perm = [2, 0, 3, 1]; // A fixed permutation for testing

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
