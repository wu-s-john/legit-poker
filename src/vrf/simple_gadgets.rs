//! Simple VRF-like gadget
//!
//! In-circuit version that absorbs a hidden base-field message and a scalar-field
//! secret key into a provided sponge variable, and enforces `public_key == sk * G`.

use crate::field_conversion::scalar_to_base_field_elements_gadget;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::groups::GroupOpsBounds;
use ark_r1cs_std::{
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    groups::CurveVar,
    prelude::ToBitsGadget,
};
use ark_relations::gr1cs::SynthesisError;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Deterministically derive an output by hashing a hidden base-field message and a secret key
/// with the provided cryptographic sponge variable, enforcing `public_key == secret_key * G`.
pub fn prove_simple_vrf_gadget<C, GG, RO, ROVar>(
    sponge: &mut ROVar,
    hidden_message: &FpVar<ConstraintF<C>>,
    secret_key: &EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
    public_key: &GG,
) -> Result<FpVar<ConstraintF<C>>, SynthesisError>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
    ConstraintF<C>: PrimeField + Absorb,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    RO: CryptographicSponge,
    ROVar: CryptographicSpongeVar<ConstraintF<C>, RO>,
{
    // Enforce public key consistency: pk = sk * G
    let g = GG::constant(C::generator());
    let sk_bits = secret_key.to_bits_le()?;
    let pk_computed = g.scalar_mul_le(sk_bits.iter())?;
    pk_computed.enforce_equal(public_key)?;

    // Absorb hidden message (base field)
    sponge.absorb(hidden_message)?;

    // Absorb secret key as base-field bytes
    let sk_base_fields = scalar_to_base_field_elements_gadget::<C>(secret_key)?;
    sponge.absorb(&sk_base_fields)?;

    // Output one base-field element
    let out = sponge.squeeze_field_elements(1)?[0].clone();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrf::simple::prove_simple_vrf;
    use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Projective as C};
    use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge};
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
        groups::curves::short_weierstrass::ProjectiveVar,
        GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;

    type CVar = ProjectiveVar<ark_bn254::g1::Config, FpVar<BaseField>>;

    #[test]
    fn test_simple_vrf_gadget() {
        let mut rng = ark_std::test_rng();

        // Keys and inputs
        let sk = ScalarField::rand(&mut rng);
        let pk = C::generator() * sk;
        let nonce = BaseField::rand(&mut rng);

        // Circuit simple VRF
        let cs = ConstraintSystem::<BaseField>::new_ref();
        let config = crate::config::poseidon_config::<BaseField>();
        let mut sponge_var = PoseidonSpongeVar::<BaseField>::new(cs.clone(), &config);
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let pk_var = CVar::new_witness(cs.clone(), || Ok(pk)).unwrap();

        let beta_var = prove_simple_vrf_gadget::<
            C,
            CVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(&mut sponge_var, &nonce_var, &sk_var, &pk_var)
        .unwrap();

        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");

        // Verify result is deterministic in circuit
        let mut sponge_var2 = PoseidonSpongeVar::<BaseField>::new(cs.clone(), &config);
        let beta_var2 = prove_simple_vrf_gadget::<
            C,
            CVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(&mut sponge_var2, &nonce_var, &sk_var, &pk_var)
        .unwrap();

        assert_eq!(
            beta_var.value().unwrap(),
            beta_var2.value().unwrap(),
            "Circuit VRF should be deterministic"
        );
    }

    #[test]
    fn test_simple_vrf_native_vs_gadget() {
        let mut rng = ark_std::test_rng();

        // Keys and inputs
        let sk = ScalarField::rand(&mut rng);
        let pk = C::generator() * sk;
        let nonce = BaseField::rand(&mut rng);

        // Native simple VRF
        let config = crate::config::poseidon_config::<BaseField>();
        let mut sponge_native = PoseidonSponge::<BaseField>::new(&config);
        let beta_native = prove_simple_vrf::<C, _>(&mut sponge_native, &nonce, &sk, &pk);

        // Circuit simple VRF
        let cs = ConstraintSystem::<BaseField>::new_ref();
        let mut sponge_var = PoseidonSpongeVar::<BaseField>::new(cs.clone(), &config);
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let pk_var = CVar::new_witness(cs.clone(), || Ok(pk)).unwrap();
        let beta_var = prove_simple_vrf_gadget::<
            C,
            CVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(&mut sponge_var, &nonce_var, &sk_var, &pk_var)
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(beta_var.value().unwrap(), beta_native);
    }

    #[test]
    fn test_simple_vrf_wrong_pk_fails() {
        let mut rng = ark_std::test_rng();

        // Keys and inputs
        let sk = ScalarField::rand(&mut rng);
        let wrong_sk = ScalarField::rand(&mut rng);
        let wrong_pk = C::generator() * wrong_sk; // Wrong public key
        let nonce = BaseField::rand(&mut rng);

        // Circuit should fail to satisfy constraints
        let cs = ConstraintSystem::<BaseField>::new_ref();
        let config = crate::config::poseidon_config::<BaseField>();
        let mut sponge_var = PoseidonSpongeVar::<BaseField>::new(cs.clone(), &config);
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let pk_var = CVar::new_witness(cs.clone(), || Ok(wrong_pk)).unwrap();

        let _ = prove_simple_vrf_gadget::<
            C,
            CVar,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
        >(&mut sponge_var, &nonce_var, &sk_var, &pk_var)
        .unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "Circuit should not be satisfied with wrong public key"
        );
    }
}
