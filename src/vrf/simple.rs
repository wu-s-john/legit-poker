//! Simple VRF-like native function
//!
//! A minimal function that absorbs a hidden base-field message and a scalar-field
//! secret key into a caller-provided cryptographic sponge, after enforcing that
//! the provided public key equals `sk * G`.

use crate::field_conversion::scalar_to_base_field_elements;
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

/// Deterministically derive an output by hashing a hidden base-field message and a secret key
/// with the provided cryptographic sponge, enforcing `public_key == secret_key * G`.
pub fn prove_simple_vrf<C, RO>(
    sponge: &mut RO,
    hidden_message: &C::BaseField,
    secret_key: &C::ScalarField,
    public_key: &C,
) -> C::BaseField
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
    C::BaseField: PrimeField + Absorb,
    RO: CryptographicSponge,
{
    // Enforce public key consistency
    let expected_pk = C::generator() * *secret_key;
    assert!(
        expected_pk == *public_key,
        "public key does not match secret key"
    );

    // Absorb hidden message (base field)
    sponge.absorb(hidden_message);

    // Absorb secret key as base-field bytes
    let sk_base_fields: Vec<C::BaseField> = scalar_to_base_field_elements(secret_key);
    for field_elem in sk_base_fields {
        sponge.absorb(&field_elem);
    }

    // Output one field element
    sponge.squeeze_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Projective as C};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;

    #[test]
    fn test_simple_vrf_native() {
        let mut rng = ark_std::test_rng();

        // Keys and inputs
        let sk = ScalarField::rand(&mut rng);
        let pk = C::generator() * sk;
        let nonce = BaseField::rand(&mut rng);

        // Native simple VRF
        let config = crate::config::poseidon_config::<BaseField>();
        let mut sponge = PoseidonSponge::<BaseField>::new(&config);
        let beta = prove_simple_vrf::<C, _>(&mut sponge, &nonce, &sk, &pk);

        // Verify result is deterministic
        let mut sponge2 = PoseidonSponge::<BaseField>::new(&config);
        let beta2 = prove_simple_vrf::<C, _>(&mut sponge2, &nonce, &sk, &pk);
        assert_eq!(beta, beta2, "VRF should be deterministic");

        // Test with different nonce produces different output
        let nonce2 = BaseField::rand(&mut rng);
        let mut sponge3 = PoseidonSponge::<BaseField>::new(&config);
        let beta3 = prove_simple_vrf::<C, _>(&mut sponge3, &nonce2, &sk, &pk);
        assert_ne!(
            beta, beta3,
            "Different nonce should produce different output"
        );
    }

    #[test]
    #[should_panic(expected = "public key does not match secret key")]
    fn test_simple_vrf_wrong_pk() {
        let mut rng = ark_std::test_rng();

        let sk = ScalarField::rand(&mut rng);
        let wrong_sk = ScalarField::rand(&mut rng);
        let pk = C::generator() * wrong_sk; // Wrong public key
        let nonce = BaseField::rand(&mut rng);

        let config = crate::config::poseidon_config::<BaseField>();
        let mut sponge = PoseidonSponge::<BaseField>::new(&config);
        let _ = prove_simple_vrf::<C, _>(&mut sponge, &nonce, &sk, &pk);
    }
}
