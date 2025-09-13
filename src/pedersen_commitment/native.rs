// Moved module declarations to top-level pedersen_commitment::mod

use crate::shuffling::data_structures::ElGamalCiphertext;
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::RngCore;

// Re-exports handled in parent module

const LOG_TARGET: &str = "nexus_nova::shuffling::pedersen_commitment";

pub struct WithCommitment<G: CurveGroup, const N: usize> {
    pub comm: G,
    pub value: [G::ScalarField; N],
}

impl<G: CurveGroup, const N: usize> WithCommitment<G, N> {
    /// Create a new WithCommitment by generating a random blinding factor and computing the commitment.
    /// Returns the WithCommitment and the blinding factor used.
    pub fn new(
        params: &Parameters<G>,
        value: [G::ScalarField; N],
        rng: &mut impl RngCore,
    ) -> (Self, G::ScalarField) {
        let blinding_factor = G::ScalarField::rand(rng);
        let comm = pedersen_commit_scalars(params, &value, blinding_factor);

        (Self { comm, value }, blinding_factor)
    }
}

/// MSM over ciphertexts: ∏ (ciphertexts[i])^{scalars[i]} in EC additive notation:
/// accumulates (Σ scalars[i]·c1_i,  Σ scalars[i]·c2_i).
#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
pub fn msm_ciphertexts<G: CurveGroup, const N: usize>(
    ciphertexts: &[ElGamalCiphertext<G>; N],
    scalars: &[G::ScalarField; N],
) -> ElGamalCiphertext<G> {
    let mut result = ElGamalCiphertext {
        c1: G::zero(),
        c2: G::zero(),
    };
    for i in 0..N {
        result.c1 += ciphertexts[i].c1 * scalars[i];
        result.c2 += ciphertexts[i].c2 * scalars[i];
    }
    result
}

/// Extract N bases for a linear (scalar-vector) Pedersen commitment from the Pedersen parameters.
/// We reuse the window generators as a long list of bases.
/// Returns (H, [G_1..G_N]) such that com(v;r) = H^r * Π_j G_j^{v_j}.
///
/// This provides the bases for a linearly homomorphic Pedersen commitment over scalar field elements,
/// which is required for the Sigma protocol's algebraic structure.
///
/// IMPORTANT: Normalizes all bases to affine form to ensure consistent representation
/// between native and circuit implementations.
pub fn extract_pedersen_bases<G, const N: usize>(params: &Parameters<G>) -> (G, [G; N])
where
    G: CurveGroup,
{
    // Use the first element of randomness_generator as H (blinding base)
    // Normalize to affine and back to projective to ensure Z=1
    let blinding_base = params.randomness_generator[0].into_affine().into();

    // Flatten the 2D generator table and take the first N bases for message elements
    // Normalize each base to ensure consistent representation
    let mut generator_iter = params.generators.iter().flat_map(|row| row.iter());

    let message_bases: [G; N] = std::array::from_fn(|_| {
        let base = generator_iter
            .next()
            .expect("Not enough Pedersen generators for the requested N");
        // Normalize to affine and back to projective to ensure Z=1
        base.into_affine().into()
    });

    (blinding_base, message_bases)
}

/// Compute a linearly homomorphic Pedersen commitment over scalar field elements.
///
/// This implements the standard Pedersen commitment formula:
///     com(values; randomness) = H^{randomness} * Π_j G_j^{values[j]}
///
/// This commitment scheme is linearly homomorphic, which is essential for the Sigma protocol:
///     com(v1; r1) * com(v2; r2) = com(v1 + v2; r1 + r2)
///
/// Note: This differs from arkworks' byte-oriented `PedersenCommitment::commit` which
/// is designed for arbitrary byte data. Here we need direct scalar field element commitments
/// to preserve the algebraic structure required by the protocol.
#[tracing::instrument(target = LOG_TARGET, skip_all, fields(N = N))]
pub fn pedersen_commit_scalars<G: CurveGroup, const N: usize>(
    params: &Parameters<G>,
    values: &[G::ScalarField; N],
    randomness: G::ScalarField,
) -> G {
    let (blinding_base, message_bases) = extract_pedersen_bases::<G, N>(params);

    // Compute: H^randomness * Π_j G_j^{values[j]}
    // Using fold for more functional style
    let commitment = message_bases
        .iter()
        .zip(values.iter())
        .fold(blinding_base * randomness, |acc, (base, value)| {
            acc + (*base * value)
        });

    commitment
}
