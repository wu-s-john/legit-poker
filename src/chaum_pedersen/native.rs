use crate::curve_absorb::CurveAbsorb;
use crate::poseidon_config;
use crate::shuffling::data_structures::append_curve_point;
use crate::signing::{Signable, TranscriptBuilder};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::Zero;

const LOG_TARGET: &str = "legit_poker::shuffling::chaum_pedersen";

/// Chaum-Pedersen proof for proving equality of discrete logarithms
/// Proves that the same secret was used to compute α = g^secret and β = H^secret
/// This is a non-interactive proof using the Fiat-Shamir heuristic
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChaumPedersenProof<C: CurveGroup> {
    /// First commitment: T_g = g^w
    pub t_g: C,
    /// Second commitment: T_H = H^w
    pub t_h: C,
    /// Response: z = w + c·secret
    pub z: C::ScalarField,
}

impl<C> Signable for ChaumPedersenProof<C>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    fn domain_kind(&self) -> &'static str {
        "chaum_pedersen/proof_v1"
    }

    fn write_transcript(&self, builder: &mut TranscriptBuilder) {
        append_curve_point(builder, &self.t_g);
        append_curve_point(builder, &self.t_h);
        builder.append_bytes(&self.z.into_bigint().to_bytes_be());
    }
}

impl<C: CurveGroup> ChaumPedersenProof<C>
where
    C::ScalarField: PrimeField + Absorb,
    C::BaseField: PrimeField,
{
    /// Generate a non-interactive Chaum-Pedersen proof deterministically
    ///
    /// Proves that α = g^secret and β = h^secret for the same secret value
    ///
    /// # Arguments
    /// * `secret` - The secret exponent used in both α and β
    /// * `g` - First base point (usually the generator)
    /// * `h` - Second base point
    /// * `alpha` - First public value: g^secret
    /// * `beta` - Second public value: h^secret
    pub fn prove<R: Rng, RO>(
        sponge: &mut RO,
        secret: C::ScalarField,
        g: C,
        h: C,
        rng: &mut R,
    ) -> Self
    where
        RO: CryptographicSponge,
        C: CurveAbsorb<C::BaseField, RO>,
    {
        // Step 1: Generate deterministic witness
        let w = C::ScalarField::rand(rng);

        // Step 2: Compute commitments
        let t_g = g * w;
        let t_h = h * w;

        // Step 3: Compute Fiat-Shamir challenge from commitments
        let challenge = Self::compute_challenge(sponge, t_g, t_h);
        tracing::debug!(target: LOG_TARGET, "Generated Challenge: {}", challenge);

        // Step 4: Compute response
        let z = w + challenge * secret;

        ChaumPedersenProof { t_g, t_h, z }
    }

    /// Verify a Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `g` - First base point
    /// * `h` - Second base point
    /// * `alpha` - First public value (should be g^secret)
    /// * `beta` - Second public value (should be h^secret)
    pub fn verify<RO>(&self, sponge: &mut RO, g: C, h: C, alpha: C, beta: C) -> bool
    where
        RO: CryptographicSponge,
        C: CurveAbsorb<C::BaseField, RO>,
    {
        tracing::debug!(target: LOG_TARGET, "Starting Chaum-Pedersen verification (native)");

        // Recompute the challenge from commitments
        tracing::debug!(target: LOG_TARGET, "Computing Fiat-Shamir challenge");
        let challenge = Self::compute_challenge(sponge, self.t_g, self.t_h);

        // Verify equation 1: g^z = T_g · α^c
        let lhs1 = g * self.z;
        tracing::debug!(target: LOG_TARGET, "lhs1 (g^z) = {:?}", lhs1);
        let rhs1 = self.t_g + alpha * challenge;
        tracing::debug!(target: LOG_TARGET, "rhs1 (T_g · α^c) = {:?}", rhs1);
        let check1 = lhs1 == rhs1;
        tracing::debug!(target: LOG_TARGET, "Equation 1 result: {}", check1);

        // Verify equation 2: h^z = T_h · β^c
        let lhs2 = h * self.z;
        tracing::debug!(target: LOG_TARGET, "lhs2 (h^z) = {:?}", lhs2);
        let rhs2 = self.t_h + beta * challenge;
        tracing::debug!(target: LOG_TARGET, "rhs2 (T_h · β^c) = {:?}", rhs2);
        let check2 = lhs2 == rhs2;
        tracing::debug!(target: LOG_TARGET, "Equation 2 result: {}", check2);

        let result = check1 && check2;
        tracing::debug!(target: LOG_TARGET, "Final verification result: {}", result);
        result
    }

    /// Compute the Fiat-Shamir challenge from commitments
    fn compute_challenge<RO>(sponge: &mut RO, t_g: C, t_h: C) -> C::ScalarField
    where
        C::BaseField: PrimeField,
        RO: CryptographicSponge,
        C: CurveAbsorb<C::BaseField, RO>,
    {
        tracing::debug!(target: LOG_TARGET, "Computing Fiat-Shamir challenge (native)");

        // Absorb t_g as affine point (matching circuit behavior)
        tracing::debug!(target: LOG_TARGET, "Absorbing t_g: {:?}", t_g);
        t_g.curve_absorb(sponge);

        // Absorb t_h as affine point (matching circuit behavior)
        tracing::debug!(target: LOG_TARGET, "Absorbing t_h: {:?}", t_h);
        t_h.curve_absorb(sponge);

        // Generate challenge in base field
        let challenge_base: C::BaseField = sponge.squeeze_field_elements::<C::BaseField>(1)[0];
        tracing::debug!(target: LOG_TARGET, "Computed challenge (base field): {:?}", challenge_base);

        // Convert to scalar field - must match circuit's embed_to_emulated behavior
        let bytes = challenge_base.into_bigint().to_bytes_le();
        let challenge_scalar = C::ScalarField::from_le_bytes_mod_order(&bytes);

        tracing::debug!(target: LOG_TARGET, "Converted challenge (scalar field): {:?}", challenge_scalar);

        challenge_scalar
    }
}

/// Batch verification for multiple Chaum-Pedersen proofs with the same bases
pub fn batch_verify_chaum_pedersen<C, RO, R>(
    proofs: &[ChaumPedersenProof<C>],
    g: C,
    h: C,
    alphas: &[C],
    betas: &[C],
    rng: &mut R,
    mut sponge_factory: impl FnMut() -> RO,
) -> bool
where
    C: CurveGroup + CurveAbsorb<C::BaseField, RO>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    RO: CryptographicSponge,
    R: Rng,
{
    if proofs.len() != alphas.len() || proofs.len() != betas.len() || proofs.is_empty() {
        return false;
    }

    // Sample random coefficients for batching
    let rhos: Vec<C::ScalarField> = (0..proofs.len())
        .map(|_| C::ScalarField::rand(rng))
        .collect();

    // Accumulate the batched equations
    let mut acc_z = C::ScalarField::zero();
    let mut acc_tg = C::zero();
    let mut acc_th = C::zero();
    let mut acc_alpha = C::zero();
    let mut acc_beta = C::zero();

    for i in 0..proofs.len() {
        let rho = rhos[i];
        let mut sponge = sponge_factory();
        let challenge =
            ChaumPedersenProof::<C>::compute_challenge(&mut sponge, proofs[i].t_g, proofs[i].t_h);

        // Accumulate values
        acc_z += rho * proofs[i].z;
        acc_tg += proofs[i].t_g * rho;
        acc_th += proofs[i].t_h * rho;
        acc_alpha += alphas[i] * (rho * challenge);
        acc_beta += betas[i] * (rho * challenge);
    }

    // Batch verify equation 1: g^(Σρ_i·z_i) = Π(T_g,i^ρ_i) · Π(α_i^(ρ_i·c_i))
    let lhs1 = g * acc_z;
    let rhs1 = acc_tg + acc_alpha;

    // Batch verify equation 2: h^(Σρ_i·z_i) = Π(T_h,i^ρ_i) · Π(β_i^(ρ_i·c_i))
    let lhs2 = h * acc_z;
    let rhs2 = acc_th + acc_beta;

    lhs1 == rhs1 && lhs2 == rhs2
}

/// Convenience function for batch verification using PoseidonSponge
pub fn batch_verify_chaum_pedersen_with_poseidon<C, R>(
    proofs: &[ChaumPedersenProof<C>],
    g: C,
    h: C,
    alphas: &[C],
    betas: &[C],
    rng: &mut R,
) -> bool
where
    C: CurveGroup + CurveAbsorb<C::BaseField, PoseidonSponge<C::BaseField>>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    R: Rng,
{
    let config = poseidon_config::<C::BaseField>();
    batch_verify_chaum_pedersen(proofs, g, h, alphas, betas, rng, || {
        PoseidonSponge::<C::BaseField>::new(&config)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::PrimeGroup;
    use ark_std::test_rng;

    #[test]
    fn test_chaum_pedersen_proof() {
        let mut rng = test_rng();
        type ScalarField = <G1Projective as PrimeGroup>::ScalarField;

        // Setup
        let g = G1Projective::generator();
        let h_scalar = ScalarField::rand(&mut rng);
        let h = g * h_scalar; // Some other base point

        // Secret value
        let secret = ScalarField::rand(&mut rng);

        // Compute public values
        let alpha = g * secret;
        let beta = h * secret;

        // Generate proof (deterministic)
        let config = poseidon_config::<<G1Projective as CurveGroup>::BaseField>();
        let mut sponge = PoseidonSponge::new(&config);
        let proof = ChaumPedersenProof::prove(&mut sponge, secret, g, h, &mut rng);

        // Verify proof
        let mut verify_sponge = PoseidonSponge::new(&config);
        assert!(
            proof.verify(&mut verify_sponge, g, h, alpha, beta),
            "Valid proof should verify"
        );
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = test_rng();
        type ScalarField = <G1Projective as PrimeGroup>::ScalarField;

        let g = G1Projective::generator();
        let h = g * ScalarField::rand(&mut rng);

        let num_proofs = 5;
        let mut proofs = Vec::new();
        let mut alphas = Vec::new();
        let mut betas = Vec::new();

        // Generate valid proofs
        for _ in 0..num_proofs {
            let secret = ScalarField::rand(&mut rng);
            let alpha = g * secret;
            let beta = h * secret;
            let config = poseidon_config::<<G1Projective as CurveGroup>::BaseField>();
            let mut sponge = PoseidonSponge::new(&config);
            let proof = ChaumPedersenProof::prove(&mut sponge, secret, g, h, &mut rng);

            proofs.push(proof);
            alphas.push(alpha);
            betas.push(beta);
        }

        // Batch verification should succeed
        assert!(
            batch_verify_chaum_pedersen_with_poseidon(&proofs, g, h, &alphas, &betas, &mut rng),
            "Batch verification of valid proofs should succeed"
        );

        // Tamper with one proof
        alphas[2] = g * ScalarField::rand(&mut rng);
        assert!(
            !batch_verify_chaum_pedersen_with_poseidon(&proofs, g, h, &alphas, &betas, &mut rng),
            "Batch verification with tampered proof should fail"
        );
    }
}
