use super::data_structures::*;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig, PrimeGroup,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    prelude::*,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use std::marker::PhantomData;

const LOG_TARGET: &str = "shuffle::encryption";

/// ElGamal encryption operations
pub struct ElGamalEncryption<G: CurveConfig> {
    _phantom: PhantomData<G>,
}

impl<G: CurveConfig> ElGamalEncryption<G>
where
    G: SWCurveConfig,
    G::BaseField: PrimeField,
{
    /// ElGamal encryption circuit for a single card
    /// Implements: c1 = m0 + R, c2 = m1 + P where R = r*g, P = r*pk
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn encrypt_card(
        cs: ConstraintSystemRef<G::BaseField>,
        m0: &ProjectiveVar<G, FpVar<G::BaseField>>,
        m1: &ProjectiveVar<G, FpVar<G::BaseField>>,
        pk: &ProjectiveVar<G, FpVar<G::BaseField>>,
        r: &FpVar<G::BaseField>,
    ) -> Result<
        (
            ProjectiveVar<G, FpVar<G::BaseField>>,
            ProjectiveVar<G, FpVar<G::BaseField>>,
        ),
        SynthesisError,
    > {
        let cs = ns!(cs, "encrypt_card");

        // Fixed-base multiplication: R = r * g
        let generator = ProjectiveVar::<G, FpVar<G::BaseField>>::new_constant(
            cs.clone(),
            Projective::<G>::generator(),
        )?;

        let r_bits = r.to_bits_le()?;
        let r_point = generator.scalar_mul_le(r_bits.iter())?;

        // c1 = m0 + R
        let c1 = m0 + &r_point;

        // Variable-base multiplication: P = r * pk
        let p_point = pk.scalar_mul_le(r_bits.iter())?;

        // c2 = m1 + P
        let c2 = m1 + &p_point;

        Ok((c1, c2))
    }

    /// Single-share partial decryption circuit
    /// Implements: c2' = c2 - s_i * c1
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn partial_decrypt(
        _cs: ConstraintSystemRef<G::BaseField>,
        c1: &ProjectiveVar<G, FpVar<G::BaseField>>,
        c2: &ProjectiveVar<G, FpVar<G::BaseField>>,
        secret_share: &FpVar<G::BaseField>,
    ) -> Result<ProjectiveVar<G, FpVar<G::BaseField>>, SynthesisError> {
        // Variable-base multiplication: S = s_i * c1
        let s_bits = secret_share.to_bits_le()?;
        let s_point = c1.scalar_mul_le(s_bits.iter())?;

        // c2' = c2 - S
        let c2_prime = c2 - &s_point;

        Ok(c2_prime)
    }

    /// Re-randomization circuit for shuffling
    /// Implements: c1' = c1 + r' * g, c2' = c2 + r' * pk_shuffler
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn rerandomize_ciphertext(
        cs: ConstraintSystemRef<G::BaseField>,
        ciphertext: &ElGamalCiphertextVar<G>,
        rerandomization: &FpVar<G::BaseField>,
        shuffler_pk: &ProjectiveVar<G, FpVar<G::BaseField>>,
    ) -> Result<ElGamalCiphertextVar<G>, SynthesisError> {
        let n = ns!(cs, "rerandomize");
        let cs = n.cs();

        crate::track_constraints!(&cs, "rerandomize_ciphertext", LOG_TARGET, {
            // Fixed-base multiplication: r' * g
            let generator = ProjectiveVar::<G, FpVar<G::BaseField>>::new_constant(
                cs.clone(),
                Projective::<G>::generator(),
            )?;
            let r_bits = rerandomization.to_bits_le()?;
            let r_g = generator.scalar_mul_le(r_bits.iter())?;

            // Variable-base multiplication: r' * pk_shuffler
            let r_pk = shuffler_pk.scalar_mul_le(r_bits.iter())?;

            // c1' = c1 + r' * g
            let c1_prime = &ciphertext.c1 + &r_g;

            // c2' = c2 + r' * pk_shuffler
            let c2_prime = &ciphertext.c2 + &r_pk;

            Ok(ElGamalCiphertextVar::new(c1_prime, c2_prime))
        })
    }

    /// Re-encrypt a deck of cards with new randomization values
    /// This function applies re-randomization to each card in the input deck
    #[tracing::instrument(target = LOG_TARGET, skip_all)]
    pub fn reencrypt_cards_with_new_randomization(
        cs: ConstraintSystemRef<G::BaseField>,
        input_deck: &Vec<ElGamalCiphertextVar<G>>,
        encryption_randomizations: &Vec<FpVar<G::BaseField>>,
        shuffler_pk: &ProjectiveVar<G, FpVar<G::BaseField>>,
    ) -> Result<Vec<ElGamalCiphertextVar<G>>, SynthesisError>
    where
        G::BaseField: PrimeField,
    {
        crate::track_constraints!(&cs, "reencrypt_cards_with_new_randomization", LOG_TARGET, {
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
                let rerandomized_card = Self::rerandomize_ciphertext(
                    cs.clone(),
                    card,
                    encryption_randomization,
                    shuffler_pk,
                )?;

                output_deck.push(rerandomized_card);
            }

            Ok(output_deck)
        })
    }

    /// Verify that a deck has been correctly re-randomized
    #[tracing::instrument(target = LOG_TARGET, name = "verify_rerandomization", skip_all)]
    pub fn verify_rerandomization(
        cs: ConstraintSystemRef<G::BaseField>,
        input_deck: Vec<ElGamalCiphertextVar<G>>,
        output_deck: Vec<ElGamalCiphertextVar<G>>,
        rerandomizations: Vec<FpVar<G::BaseField>>,
        shuffler_pk: &ProjectiveVar<G, FpVar<G::BaseField>>,
        permutation: Vec<usize>,
    ) -> Result<(), SynthesisError> {
        if input_deck.len() != output_deck.len() || input_deck.len() != rerandomizations.len() {
            tracing::error!("Input and output decks have different lengths");
            return Err(SynthesisError::Unsatisfiable);
        }

        // For each card, verify that output[i] = rerandomize(input[perm[i]], r[i])
        for (i, perm_idx) in permutation.iter().enumerate() {
            // Compute expected re-randomization
            let expected = Self::rerandomize_ciphertext(
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
