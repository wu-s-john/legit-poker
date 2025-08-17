use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

const _LOG_TARGET: &str = "shuffling::util";

pub fn generate_random_values<F: Absorb + PrimeField>(seed: F, count: usize) -> Vec<F> {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb the seed
    sponge.absorb(&seed);

    // Squeeze all values at once to ensure proper state advancement
    // This is more efficient and ensures proper randomness
    let values = sponge.squeeze_field_elements(count);

    values
}

/// Generate deterministic witness for Chaum-Pedersen proof
/// Absorbs all public values to ensure determinism
pub fn generate_chaum_pedersen_witness<F, C>(
    g: &C,
    h: &C,
    secret: &F,
    alpha: &C,
    beta: &C,
    domain_separator: &[u8],
) -> F
where
    F: PrimeField + Absorb,
    C: CanonicalSerialize,
{
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb domain separator as field elements
    for byte in domain_separator {
        sponge.absorb(&F::from(*byte as u64));
    }

    // Serialize and absorb each curve point
    let mut bytes = Vec::new();
    
    g.serialize_compressed(&mut bytes).unwrap();
    for byte in &bytes {
        sponge.absorb(&F::from(*byte as u64));
    }

    bytes.clear();
    h.serialize_compressed(&mut bytes).unwrap();
    for byte in &bytes {
        sponge.absorb(&F::from(*byte as u64));
    }

    // Absorb the secret
    sponge.absorb(&secret);

    bytes.clear();
    alpha.serialize_compressed(&mut bytes).unwrap();
    for byte in &bytes {
        sponge.absorb(&F::from(*byte as u64));
    }

    bytes.clear();
    beta.serialize_compressed(&mut bytes).unwrap();
    for byte in &bytes {
        sponge.absorb(&F::from(*byte as u64));
    }

    // Generate deterministic witness
    sponge.squeeze_field_elements(1)[0]
}
