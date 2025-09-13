use super::data_structures::*;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::{convert::ToBitsGadget, fields::fp::FpVar, groups::CurveVar};
use ark_relations::{
    gr1cs::{ConstraintSystemRef, SynthesisError},
    ns,
};
use ark_std::rand::Rng;

const LOG_TARGET: &str = "shuffle::encryption";

/// Generate an array of N random scalar field elements for rerandomization
///
/// This centralized function provides a consistent way to generate
/// randomization arrays throughout the shuffling implementation.
///
/// # Type Parameters
/// - `C`: The curve configuration
/// - `N`: The size of the array to generate
///
/// # Returns
/// An array of N random scalar field elements
pub fn generate_randomization_array<C, const N: usize>(
    rng: &mut impl Rng,
) -> [<C as CurveConfig>::ScalarField; N]
where
    C: CurveConfig,
    <C as CurveConfig>::ScalarField: UniformRand,
{
    std::array::from_fn(|_| <C as CurveConfig>::ScalarField::rand(rng))
}

/// ElGamal encryption operations
pub struct ElGamalEncryption<C: CurveGroup> {
    /// Precomputed powers of the generator for efficient fixed-base scalar multiplication
    pub generator_powers: Vec<C>,
}

impl<C: CurveGroup> ElGamalEncryption<C>
where
    C::BaseField: PrimeField,
{
    /// Create a new ElGamalEncryption instance with precomputed generator powers
    pub fn new(generator_powers: Vec<C>) -> Self {
        Self { generator_powers }
    }

    /// ElGamal encryption circuit for a single card
    /// Implements: c1 = m0 + R, c2 = m1 + P where R = r*g, P = r*pk
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn encrypt_card<CV>(
        cs: ConstraintSystemRef<C::BaseField>,
        m0: &CV,
        m1: &CV,
        pk: &CV,
        r: &FpVar<C::BaseField>,
    ) -> Result<(CV, CV), SynthesisError>
    where
        CV: CurveVar<C, C::BaseField>,
    {
        ns!(cs, "encrypt_card");

        // Fixed-base multiplication: R = r * g
        let generator = CV::constant(C::generator());

        let r_bits = r.to_bits_le()?;
        let r_point = generator.scalar_mul_le(r_bits.iter())?;

        // c1 = m0 + R
        let c1 = m0.clone() + r_point;

        // Variable-base multiplication: P = r * pk
        let p_point = pk.scalar_mul_le(r_bits.iter())?;

        // c2 = m1 + P
        let c2 = m1.clone() + p_point;

        Ok((c1, c2))
    }

    /// Single-share partial decryption circuit
    /// Implements: c2' = c2 - s_i * c1
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn partial_decrypt<CV>(
        _cs: ConstraintSystemRef<C::BaseField>,
        c1: &CV,
        c2: &CV,
        secret_share: &FpVar<C::BaseField>,
    ) -> Result<CV, SynthesisError>
    where
        CV: CurveVar<C, C::BaseField>,
    {
        // Variable-base multiplication: S = s_i * c1
        let s_bits = secret_share.to_bits_le()?;
        let s_point = c1.scalar_mul_le(s_bits.iter())?;

        // c2' = c2 - S
        let c2_prime = c2.clone() - s_point;

        Ok(c2_prime)
    }

    /// Re-randomization circuit for shuffling
    /// Implements: c1' = c1 + r' * g, c2' = c2 + r' * pk_shuffler
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    #[zk_poker_macros::track_constraints_impl(target = "shuffle::encryption")]
    pub fn rerandomize_ciphertext<CV>(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        ciphertext: &ElGamalCiphertextVar<C, CV>,
        rerandomization: &FpVar<C::BaseField>,
        shuffler_pk: &CV,
    ) -> Result<ElGamalCiphertextVar<C, CV>, SynthesisError>
    where
        CV: CurveVar<C, C::BaseField>,
    {
        // Convert randomization to bits
        let r_bits = rerandomization.to_bits_le()?;

        // Fixed-base multiplication using precomputed powers: r' * g
        let mut r_g = CV::zero();
        r_g.precomputed_base_scalar_mul_le(r_bits.iter().zip(&self.generator_powers))?;

        // Variable-base multiplication: r' * pk_shuffler
        let r_pk = shuffler_pk.scalar_mul_le(r_bits.iter())?;

        // c1' = c1 + r' * g
        let c1_prime = ciphertext.c1.clone() + r_g;

        // c2' = c2 + r' * pk_shuffler
        let c2_prime = ciphertext.c2.clone() + r_pk;

        Ok(ElGamalCiphertextVar::new(c1_prime, c2_prime))
    }

    /// Re-encrypt a deck of cards with new randomization values
    /// This function applies re-randomization to each card in the input deck
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    #[zk_poker_macros::track_constraints_impl(target = "shuffle::encryption")]
    pub fn reencrypt_cards_with_new_randomization<CV>(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        input_deck: &Vec<ElGamalCiphertextVar<C, CV>>,
        encryption_randomizations: &Vec<FpVar<C::BaseField>>,
        shuffler_pk: &CV,
    ) -> Result<Vec<ElGamalCiphertextVar<C, CV>>, SynthesisError>
    where
        CV: CurveVar<C, C::BaseField>,
    {
        if input_deck.len() != encryption_randomizations.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut output_deck = Vec::with_capacity(input_deck.len());

        for (i, (card, encryption_randomization)) in input_deck
            .iter()
            .zip(encryption_randomizations.iter())
            .enumerate()
        {
            tracing::info!(
                target: LOG_TARGET,
                "Rerandomizing card {} of {}",
                i + 1,
                input_deck.len()
            );

            // Apply rerandomization to the ciphertext
            let rerandomized_card = self.rerandomize_ciphertext(
                cs.clone(),
                card,
                encryption_randomization,
                shuffler_pk,
            )?;

            output_deck.push(rerandomized_card);
        }

        Ok(output_deck)
    }

    /// Verify that a deck has been correctly re-randomized
    #[tracing::instrument(target = LOG_TARGET, name = "verify_rerandomization", skip_all)]
    pub fn verify_rerandomization<CV>(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        input_deck: Vec<ElGamalCiphertextVar<C, CV>>,
        output_deck: Vec<ElGamalCiphertextVar<C, CV>>,
        rerandomizations: Vec<FpVar<C::BaseField>>,
        shuffler_pk: &CV,
        permutation: Vec<usize>,
    ) -> Result<(), SynthesisError>
    where
        CV: CurveVar<C, C::BaseField>,
    {
        if input_deck.len() != output_deck.len() || input_deck.len() != rerandomizations.len() {
            tracing::error!("Input and output decks have different lengths");
            return Err(SynthesisError::Unsatisfiable);
        }

        // For each card, verify that output[i] = rerandomize(input[perm[i]], r[i])
        for (i, perm_idx) in permutation.iter().enumerate() {
            // Compute expected re-randomization
            let expected = self.rerandomize_ciphertext(
                cs.clone(),
                &input_deck[*perm_idx],
                &rerandomizations[i],
                shuffler_pk,
            )?;

            // Verify c1 matches
            expected.c1.enforce_equal(&output_deck[i].c1)?;

            // Verify c2 matches
            expected.c2.enforce_equal(&output_deck[i].c2)?;
        }

        Ok(())
    }
}
