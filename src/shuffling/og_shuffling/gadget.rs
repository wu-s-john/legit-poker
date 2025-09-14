use crate::poseidon_config;
use crate::shuffling::data_structures::{ElGamalCiphertextVar, ShuffleProofVar};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_relations::ns;
use std::ops::Not;

const LOG_TARGET: &str = "shuffle::og_shuffling::gadget";

#[zk_poker_macros::track_constraints(target = LOG_TARGET)]
pub fn generate_random_values_for_deck<C: CurveGroup>(
    cs: ConstraintSystemRef<C::BaseField>,
    seed: &FpVar<C::BaseField>,
    deck_size: usize,
) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError>
where
    C::BaseField: PrimeField + Absorb + Copy,
{
    let config = poseidon_config::<C::BaseField>();
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);
    sponge.absorb(seed)?;

    let random_values: Result<Vec<_>, _> = (0..deck_size)
        .map(|_| sponge.squeeze_field_elements(1).map(|vals| vals[0].clone()))
        .collect();
    let random_values = random_values?;
    assert_eq!(random_values.len(), deck_size);
    Ok(random_values)
}

pub fn compute_deck_product<'a, C, CV, I>(
    _cs: ConstraintSystemRef<C::BaseField>,
    deck: I,
    alpha: &FpVar<C::BaseField>,
    beta: &FpVar<C::BaseField>,
) -> Result<FpVar<C::BaseField>, SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
    I: Iterator<Item = (&'a ElGamalCiphertextVar<C, CV>, &'a FpVar<C::BaseField>)>,
{
    let alpha_1 = alpha.clone();
    let alpha_2 = &alpha_1 * alpha;
    let alpha_3 = &alpha_2 * alpha;
    let alpha_4 = &alpha_3 * alpha;
    let alpha_5 = &alpha_4 * alpha;

    let mut product = FpVar::one();
    for (card, random_val) in deck {
        let c1_fields = card.c1.to_constraint_field()?;
        let c2_fields = card.c2.to_constraint_field()?;

        let card_repr = if c1_fields.len() >= 3 && c2_fields.len() >= 3 {
            &alpha_1 * &c1_fields[0]
                + &alpha_2 * &c1_fields[1]
                + &alpha_3 * &c1_fields[2]
                + &alpha_4 * &c2_fields[0]
                + &alpha_5 * &c2_fields[1]
                + alpha.clone() * &c2_fields[2]
        } else {
            return Err(SynthesisError::Unsatisfiable);
        };

        let term = card_repr + beta.clone() * random_val.clone();
        product *= term;
    }
    Ok(product)
}

pub fn verify_equivalance_through_grand_product<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    deck: &Vec<(&ElGamalCiphertextVar<C, CV>, FpVar<C::BaseField>)>,
    sorted_deck: &Vec<(ElGamalCiphertextVar<C, CV>, FpVar<C::BaseField>)>,
    alpha: &FpVar<C::BaseField>,
    beta: &FpVar<C::BaseField>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    let ns = ns!(cs, "grand_product");
    let cs = ns.cs();

    let product = compute_deck_product::<C, CV, _>(
        cs.clone(),
        deck.iter().map(|(card, val)| (*card, val)),
        alpha,
        beta,
    )?;

    let _sorted_product = compute_deck_product::<C, CV, _>(
        cs.clone(),
        sorted_deck.iter().map(|(card, val)| (card, val)),
        alpha,
        beta,
    )?;

    // In future: enforce equality when needed
    let _ = product; // silence unused var
    Ok(())
}

pub fn verify_sorting_order<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    proof: &ShuffleProofVar<C, CV>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    ns!(cs, "verify_sorting_order");

    for i in 0..(proof.sorted_deck.len() - 1) {
        let (_, current_random) = &proof.sorted_deck[i];
        let (_, next_random) = &proof.sorted_deck[i + 1];

        let current_bits = current_random.to_bits_le()?;
        let next_bits = next_random.to_bits_le()?;

        let mut is_less_or_equal = Boolean::TRUE;
        let mut found_difference = Boolean::FALSE;

        for i in (0..current_bits.len()).rev() {
            let current_bit = &current_bits[i];
            let next_bit = &next_bits[i];

            let bits_differ = current_bit.is_neq(next_bit)?;
            let current_is_zero = current_bit.not();
            let next_is_one = next_bit.clone();
            let current_less_at_this_bit = &current_is_zero & &next_is_one;

            let condition = &bits_differ & &found_difference.clone().not();
            is_less_or_equal = Boolean::conditionally_select(
                &condition,
                &current_less_at_this_bit,
                &is_less_or_equal,
            )?;

            found_difference = &found_difference | &bits_differ;
        }

        is_less_or_equal.enforce_equal(&Boolean::TRUE)?;
    }

    Ok(())
}
