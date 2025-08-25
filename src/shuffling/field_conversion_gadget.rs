use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;

pub fn from_emulated_to_circuit_field<TargetF: PrimeField, BaseF: PrimeField>(
    x: EmulatedFpVar<TargetF, BaseF>,
) -> ark_relations::gr1cs::Result<FpVar<BaseF>> {
    let bits = x.to_bits_le()?; // EmulatedFpVar implements ToBitsGadget
    let y = Boolean::<BaseF>::le_bits_to_fp(&bits)?; // y ≡ x (mod q=|BaseF|)
    Ok(y)
}

pub fn embed_to_emulated<TargetF: PrimeField, BaseF: PrimeField>(
    cs: ConstraintSystemRef<BaseF>,
    x_native: FpVar<BaseF>,
) -> Result<EmulatedFpVar<TargetF, BaseF>, SynthesisError> {
    let bits = x_native.to_bits_le()?; // bits of x in BaseF
    let k = TargetF::MODULUS_BIT_SIZE as usize;

    // Range-check: enforce x < p_target by zeroing higher bits
    for b in &bits[k..] {
        b.enforce_equal(&Boolean::constant(false))?;
    }

    // Witness y = x (viewed as TargetF)
    let y = EmulatedFpVar::<TargetF, BaseF>::new_witness(cs, || {
        x_native.value().map(|v| {
            let bytes = v.into_bigint().to_bytes_le();
            TargetF::from_le_bytes_mod_order(&bytes)
        })
    })?;

    // Link representations: first k bits must match
    let y_bits = y.to_bits_le()?;
    for (a, b) in y_bits.iter().zip(bits.iter()).take(k) {
        a.enforce_equal(b)?;
    }

    Ok(y)
}
