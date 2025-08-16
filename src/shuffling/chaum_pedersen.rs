use super::utils::generate_chaum_pedersen_witness;
use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::Zero;

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

impl<C: CurveGroup> ChaumPedersenProof<C>
where
    C::ScalarField: PrimeField + Absorb,
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
    pub fn generate(secret: C::ScalarField, g: C, h: C, alpha: C, beta: C) -> Self {
        // Step 1: Generate deterministic witness
        let w = generate_chaum_pedersen_witness(&g, &h, &secret, &alpha, &beta, b"CP-DLEQ-v1");

        // Step 2: Compute commitments
        let t_g = g * w;
        let t_h = h * w;

        // Step 3: Compute Fiat-Shamir challenge from commitments
        let challenge = Self::compute_challenge(t_g, t_h);

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
    pub fn verify(&self, g: C, h: C, alpha: C, beta: C) -> bool {
        // Recompute the challenge from commitments
        let challenge = Self::compute_challenge(self.t_g, self.t_h);

        // Verify equation 1: g^z = T_g · α^c
        let lhs1 = g * self.z;
        let rhs1 = self.t_g + alpha * challenge;

        // Verify equation 2: h^z = T_h · β^c
        let lhs2 = h * self.z;
        let rhs2 = self.t_h + beta * challenge;

        lhs1 == rhs1 && lhs2 == rhs2
    }

    /// Compute the Fiat-Shamir challenge from commitments
    fn compute_challenge(t_g: C, t_h: C) -> C::ScalarField {
        let config = poseidon_config::<C::ScalarField>();
        let mut sponge = PoseidonSponge::new(&config);

        // Absorb domain separator
        for byte in b"CP-challenge-v1" {
            sponge.absorb(&C::ScalarField::from(*byte as u64));
        }

        // Serialize and absorb commitments
        let mut bytes = Vec::new();

        t_g.serialize_compressed(&mut bytes).unwrap();
        for byte in &bytes {
            sponge.absorb(&C::ScalarField::from(*byte as u64));
        }

        bytes.clear();
        t_h.serialize_compressed(&mut bytes).unwrap();
        for byte in &bytes {
            sponge.absorb(&C::ScalarField::from(*byte as u64));
        }

        // Generate challenge
        sponge.squeeze_field_elements(1)[0]
    }
}

/// Batch verification for multiple Chaum-Pedersen proofs with the same bases
pub fn batch_verify_chaum_pedersen<C, R>(
    proofs: &[ChaumPedersenProof<C>],
    g: C,
    h: C,
    alphas: &[C],
    betas: &[C],
    rng: &mut R,
) -> bool
where
    C: CurveGroup,
    C::ScalarField: PrimeField + Absorb,
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
        let challenge = ChaumPedersenProof::<C>::compute_challenge(proofs[i].t_g, proofs[i].t_h);

        // Accumulate values
        acc_z += rho * proofs[i].z;
        acc_tg = acc_tg + proofs[i].t_g * rho;
        acc_th = acc_th + proofs[i].t_h * rho;
        acc_alpha = acc_alpha + alphas[i] * (rho * challenge);
        acc_beta = acc_beta + betas[i] * (rho * challenge);
    }

    // Batch verify equation 1: g^(Σρ_i·z_i) = Π(T_g,i^ρ_i) · Π(α_i^(ρ_i·c_i))
    let lhs1 = g * acc_z;
    let rhs1 = acc_tg + acc_alpha;

    // Batch verify equation 2: h^(Σρ_i·z_i) = Π(T_h,i^ρ_i) · Π(β_i^(ρ_i·c_i))
    let lhs2 = h * acc_z;
    let rhs2 = acc_th + acc_beta;

    lhs1 == rhs1 && lhs2 == rhs2
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;

    #[test]
    fn test_chaum_pedersen_proof() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Setup
        let g = GrumpkinProjective::generator();
        let h_scalar = ScalarField::rand(&mut rng);
        let h = g * h_scalar; // Some other base point

        // Secret value
        let secret = ScalarField::rand(&mut rng);

        // Compute public values
        let alpha = g * secret;
        let beta = h * secret;

        // Generate proof (deterministic)
        let proof = ChaumPedersenProof::generate(secret, g, h, alpha, beta);

        // Verify proof
        assert!(proof.verify(g, h, alpha, beta), "Valid proof should verify");

        // Test that the same inputs produce the same proof (determinism)
        let proof2 = ChaumPedersenProof::generate(secret, g, h, alpha, beta);
        assert_eq!(proof.t_g, proof2.t_g, "Proofs should be deterministic");
        assert_eq!(proof.t_h, proof2.t_h, "Proofs should be deterministic");
        assert_eq!(proof.z, proof2.z, "Proofs should be deterministic");

        // Test invalid proofs
        let wrong_alpha = g * ScalarField::rand(&mut rng);
        assert!(
            !proof.verify(g, h, wrong_alpha, beta),
            "Proof with wrong alpha should fail"
        );

        let wrong_beta = h * ScalarField::rand(&mut rng);
        assert!(
            !proof.verify(g, h, alpha, wrong_beta),
            "Proof with wrong beta should fail"
        );
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        let g = GrumpkinProjective::generator();
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
            let proof = ChaumPedersenProof::generate(secret, g, h, alpha, beta);

            proofs.push(proof);
            alphas.push(alpha);
            betas.push(beta);
        }

        // Batch verification should succeed
        assert!(
            batch_verify_chaum_pedersen(&proofs, g, h, &alphas, &betas, &mut rng),
            "Batch verification of valid proofs should succeed"
        );

        // Tamper with one proof
        alphas[2] = g * ScalarField::rand(&mut rng);
        assert!(
            !batch_verify_chaum_pedersen(&proofs, g, h, &alphas, &betas, &mut rng),
            "Batch verification with tampered proof should fail"
        );
    }
}
