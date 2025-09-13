use super::gadget::{
    generate_random_values_for_deck, verify_equivalance_through_grand_product, verify_sorting_order,
};
use crate::shuffling::data_structures::*;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Circuit for verifying card shuffling
#[derive(Clone)]
pub struct ShuffleCircuit<C: CurveGroup, CV: CurveVar<C, C::BaseField>>
where
    C::BaseField: PrimeField,
{
    pub shuffler_public_key: C,
    pub proof: ShuffleProof<C>,
    pub seed: C::BaseField,
    _phantom: std::marker::PhantomData<CV>,
}

impl<C: CurveGroup, CV: CurveVar<C, C::BaseField>> ShuffleCircuit<C, CV>
where
    C::BaseField: PrimeField,
{
    pub fn new(shuffler_public_key: C, proof: ShuffleProof<C>, seed: C::BaseField) -> Self {
        Self {
            shuffler_public_key,
            proof,
            seed,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for ShuffleCircuit<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        // Inputs
        let seed_var =
            FpVar::<C::BaseField>::new_input(ark_relations::ns!(cs, "seed"), || Ok(self.seed))?;
        let shuffler_pk_var: CV = AllocVar::new_variable(
            ark_relations::ns!(cs, "shuffler_pk"),
            || Ok(self.shuffler_public_key),
            AllocationMode::Witness,
        )?;

        // Allocate proof
        let proof_var =
            ShuffleProofVar::new_variable(cs.clone(), || Ok(&self.proof), AllocationMode::Witness)?;

        // Generate transcript randomness
        let random_values = generate_random_values_for_deck::<C>(
            cs.clone(),
            &seed_var,
            proof_var.input_deck.len(),
        )?;

        // Create ElGamal helper
        let num_bits = C::BaseField::MODULUS_BIT_SIZE as usize;
        let generator_powers = (0..num_bits)
            .scan(C::generator(), |acc, _| {
                let current = *acc;
                *acc = acc.double();
                Some(current)
            })
            .collect::<Vec<_>>();
        let elgamal = super::super::encryption::ElGamalEncryption::<C>::new(generator_powers);

        // Rerandomize deck
        let rerandomized_deck = elgamal.reencrypt_cards_with_new_randomization(
            cs.clone(),
            &proof_var.input_deck,
            &proof_var.encryption_randomization_values,
            &shuffler_pk_var,
        )?;

        // Pair with randomness
        let deck_with_rerandomizations: Vec<(ElGamalCiphertextVar<C, CV>, FpVar<C::BaseField>)> =
            rerandomized_deck
                .into_iter()
                .zip(random_values.iter().cloned())
                .collect();

        // Challenges (placeholder deterministic values)
        let alpha = FpVar::new_witness(cs.clone(), || Ok(C::BaseField::from(7u64)))?;
        let beta = FpVar::new_witness(cs.clone(), || Ok(C::BaseField::from(13u64)))?;

        // Verify relations
        let deck_refs: Vec<(&ElGamalCiphertextVar<C, CV>, FpVar<C::BaseField>)> =
            deck_with_rerandomizations
                .iter()
                .map(|(c, r)| (c, r.clone()))
                .collect();
        verify_equivalance_through_grand_product::<C, CV>(
            cs.clone(),
            &deck_refs,
            &proof_var.sorted_deck,
            &alpha,
            &beta,
        )?;

        verify_sorting_order::<C, CV>(cs.clone(), &proof_var)?;

        Ok(())
    }
}
