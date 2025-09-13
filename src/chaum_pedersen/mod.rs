pub mod native;
pub mod gadget;

// Re-export common types/functions for ergonomic imports
pub use native::*;
pub use gadget::*;

use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

/// Generate a deterministic witness scalar for the Chaum–Pedersen transcript.
///
/// Absorbs a domain separator, the curve points (g, h, α, β) and the secret scalar
/// into a Poseidon sponge over the field `F`, then squeezes one field element.
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

    // Serialize and absorb each curve point as bytes mapped into F
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
    sponge.absorb(secret);

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
