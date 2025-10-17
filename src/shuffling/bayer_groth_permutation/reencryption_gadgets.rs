//! SNARK circuit gadgets for non-interactive Σ-protocol verification
//!
//! This module provides type-safe circuit gadgets for verifying the Σ-protocol
//! inside a SNARK, ensuring the same witness b is used throughout.
//!
//! Key fixes vs the previous version:
//! 1) commit_vector_gadget implements Pedersen commitment directly using curve operations
//!    (H^randomness * Π_j G_j^{values[j]}) to maintain full control over the computation.
//! 2) The Fiat–Shamir challenge `c` is passed into the circuit (do not recompute it
//!    in-circuit) to avoid field/domain mismatch with the native transcript.

use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, vec::Vec};
use tracing::instrument;

use super::reencryption_protocol::ReencryptionProof;
use ark_crypto_primitives::sponge::{constraints::CryptographicSpongeVar, CryptographicSponge};

const LOG_TARGET: &str = "legit_poker::shuffling::bayer_groth_permutation::reencryption_gadgets";

/// Circuit proof representation with const generic N
///
/// Note: We use a generic FieldVar to represent scalar field elements
/// in the base field circuit, allowing flexibility in the field representation
pub struct ReencryptionProofVar<G, GG, FV, const N: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    FV: FieldVar<G::ScalarField, G::BaseField>,
{
    pub blinding_factor_commitment: GG,
    pub blinding_rerandomization_commitment: ElGamalCiphertextVar<G, GG>,
    pub sigma_response_power_permutation_vector: [FV; N],
    pub sigma_response_blinding: FV,
    pub sigma_response_rerand: FV,
}

impl<G, GG, FV, const N: usize> Clone for ReencryptionProofVar<G, GG, FV, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + Clone,
    FV: FieldVar<G::ScalarField, G::BaseField> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            blinding_factor_commitment: self.blinding_factor_commitment.clone(),
            blinding_rerandomization_commitment: self.blinding_rerandomization_commitment.clone(),
            sigma_response_power_permutation_vector: self
                .sigma_response_power_permutation_vector
                .clone(),
            sigma_response_blinding: self.sigma_response_blinding.clone(),
            sigma_response_rerand: self.sigma_response_rerand.clone(),
        }
    }
}

impl<G, GG, FV, const N: usize> AllocVar<ReencryptionProof<G, N>, G::BaseField>
    for ReencryptionProofVar<G, GG, FV, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    FV: FieldVar<G::ScalarField, G::BaseField>,
{
    fn new_variable<T: Borrow<ReencryptionProof<G, N>>>(
        cs: impl Into<Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let proof = f()?.borrow().clone();

        // Allocate blinding_factor_commitment
        let blinding_factor_commitment =
            GG::new_variable(cs.clone(), || Ok(proof.blinding_factor_commitment), mode)?;

        // Allocate blinding_rerandomization_commitment
        let blinding_rerandomization_commitment = ElGamalCiphertextVar::new_variable(
            cs.clone(),
            || Ok(proof.blinding_rerandomization_commitment),
            mode,
        )?;

        // Allocate sigma_response_power_permutation_vector array as FieldVar
        let mut sigma_response_power_permutation_vector_vec = Vec::with_capacity(N);
        for i in 0..N {
            let var = FV::new_variable(
                cs.clone(),
                || Ok(proof.sigma_response_power_permutation_vector[i]),
                mode,
            )?;
            sigma_response_power_permutation_vector_vec.push(var);
        }
        let sigma_response_power_permutation_vector: [FV; N] =
            sigma_response_power_permutation_vector_vec
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?;

        // Allocate sigma_response_blinding as FieldVar
        let sigma_response_blinding =
            FV::new_variable(cs.clone(), || Ok(proof.sigma_response_blinding), mode)?;

        // Allocate sigma_response_rerand as FieldVar
        let sigma_response_rerand =
            FV::new_variable(cs.clone(), || Ok(proof.sigma_response_rerand), mode)?;

        Ok(Self {
            blinding_factor_commitment,
            blinding_rerandomization_commitment,
            sigma_response_power_permutation_vector,
            sigma_response_blinding,
            sigma_response_rerand,
        })
    }
}

/// Absorb public inputs into the transcript (in-circuit version)
/// Mirrors the native absorb_public_inputs function
fn absorb_public_inputs_gadget<G, GG, S, ROVar>(
    transcript: &mut ROVar,
    input_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    b_vector_commitment: &GG,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    S: CryptographicSponge,
    ROVar: CryptographicSpongeVar<G::BaseField, S>,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField, ROVar>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Absorb aggregated input ciphertexts (matching native absorb_public_inputs)
    let input_aggregator_sum = &input_ciphertext_aggregator.c1 + &input_ciphertext_aggregator.c2;
    tracing::trace!(
        target: LOG_TARGET,
        "absorb_public_inputs_gadget: input_aggregator_sum = {:?}",
        input_aggregator_sum.value()
    );
    input_aggregator_sum.curve_absorb_gadget(transcript)?;

    // Note: Native verify doesn't absorb output aggregator - only input aggregator

    // Absorb b_vector_commitment
    tracing::trace!(
        target: LOG_TARGET,
        "absorb_public_inputs_gadget: b_vector_commitment = {:?}",
        b_vector_commitment.value()
    );
    b_vector_commitment.curve_absorb_gadget(transcript)?;

    Ok(())
}

/// Compute the Fiat-Shamir challenge in-circuit
/// This mirrors the native absorption strategy for efficiency
#[instrument(level = "trace", skip_all, fields(N = N))]
fn compute_challenge_gadget<G, GG, FV, S, ROVar, const N: usize>(
    transcript: &mut ROVar,
    input_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    permutation_power_vector_commitment: &GG,
    proof: &ReencryptionProofVar<G, GG, FV, N>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    S: CryptographicSponge,
    ROVar: CryptographicSpongeVar<G::BaseField, S>,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField, ROVar>,
    FV: FieldVar<G::ScalarField, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Absorb public inputs (matching native verify)
    absorb_public_inputs_gadget::<G, GG, S, ROVar>(
        transcript,
        input_ciphertext_aggregator,
        permutation_power_vector_commitment,
    )?;

    tracing::debug!(
        target: LOG_TARGET,
        input_ciphertext_aggregator = ?input_ciphertext_aggregator.value().ok(),
        b_vector_commitment = ?permutation_power_vector_commitment.value().ok(),
        blinding_factor_commitment = ?proof.blinding_factor_commitment.value().ok(),
        "Absorbed public inputs and proof commitments"
    );
    proof
        .blinding_factor_commitment
        .curve_absorb_gadget(transcript)?;

    tracing::debug!(
        target: LOG_TARGET,
        "Absorbing blinding_rerandomization_commitment: {:?}",
        proof.blinding_rerandomization_commitment.value()
    );
    proof
        .blinding_rerandomization_commitment
        .c1
        .curve_absorb_gadget(transcript)?;

    proof
        .blinding_rerandomization_commitment
        .c2
        .curve_absorb_gadget(transcript)?;

    // Squeeze the challenge
    let challenge = transcript.squeeze_field_elements(1)?[0].clone();
    tracing::debug!(
        target: LOG_TARGET,
        "Squeezed challenge from transcript: {:?}",
        challenge.value()
    );
    Ok(challenge)
}

/// Verifies the reencryption protocol inside a SNARK circuit, ensuring the same witness is used
/// throughout the entire proof system. Returns a Boolean constraint indicating validity.
///
/// ## Constraints Enforced (NEW Algorithm):
///
/// 1. **Commitment Consistency**: com(sigma_response_power_permutation_vector; sigma_response_blinding) = blinding_factor_commitment · power_perm_commitment^c
///    - Uses the same Pedersen vector bases as the native verifier.
/// 2. **Shuffle Correctness**: E(1; sigma_response_rerand) · ∏input_ciphertexts[j]^{sigma_response_power_permutation_vector[j]} = blinding_rerandomization_commitment · (input_ciphertext_aggregator)^c
///    - Note: Uses input_ciphertext_aggregator in RHS (not output) per the new algorithm
///
/// The challenge is computed using the provided transcript for efficiency.
#[instrument(target = LOG_TARGET, level = "trace", skip_all)]
pub fn verify_gadget<G, GG, FV, S, ROVar, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    transcript: &mut ROVar,
    public_key: &GG,                  // ElGamal PK = x·G
    pedersen_blinding_base: &GG,      // H for Pedersen commitment
    pedersen_message_bases: &[GG; N], // [G_1, ..., G_N] for Pedersen commitment
    input_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    output_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    perm_power_challenge: &FV,  // a_i = x^(i+1)
    power_perm_commitment: &GG, // Pedersen commitment to b
    proof: &ReencryptionProofVar<G, GG, FV, N>,
) -> Result<Boolean<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    S: CryptographicSponge,
    ROVar: CryptographicSpongeVar<G::BaseField, S>,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField, ROVar> + Clone,
    FV: FieldVar<G::ScalarField, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
    for<'a> &'a FV: FieldOpsBounds<'a, G::ScalarField, FV>,
    for<'a> GG: std::ops::Mul<&'a FV, Output = GG>,
{
    tracing::debug!(target: LOG_TARGET, N = N, "Starting non-interactive verification");

    // Compute powers sequence [x^1, x^2, ..., x^N] matching native implementation
    let mut powers = Vec::with_capacity(N);
    let mut current = perm_power_challenge.clone();
    powers.push(current.clone());

    for _ in 1..N {
        current = &current * perm_power_challenge;
        powers.push(current.clone());
    }
    let powers: [FV; N] = powers.try_into().unwrap();

    // Trace the powers vector for debugging
    tracing::trace!(
        target: LOG_TARGET,
        "Gadget verify: perm_power_challenge = {:?}",
        perm_power_challenge.value()
    );
    for (i, power) in powers.iter().enumerate() {
        tracing::trace!(
            target: LOG_TARGET,
            "Gadget verify: powers[{}] = {:?}",
            i,
            power.value()
        );
    }

    // Compute input aggregator C^a where a_i = x^(i+1)
    for (i, ct) in input_ciphertexts.iter().enumerate() {
        tracing::trace!(
            target: LOG_TARGET,
            "Gadget verify: input_ciphertexts[{}].c1 = {:?}",
            i,
            ct.c1.value()
        );
    }
    let input_ciphertext_aggregator = msm_ciphertexts_gadget_emulated(input_ciphertexts, &powers)?;

    // Trace the input_ciphertext_aggregator
    tracing::trace!(
        target: LOG_TARGET,
        "Gadget verify: input_ciphertext_aggregator.c1 = {:?}",
        input_ciphertext_aggregator.c1.value()
    );
    tracing::trace!(
        target: LOG_TARGET,
        "Gadget verify: input_ciphertext_aggregator.c2 = {:?}",
        input_ciphertext_aggregator.c2.value()
    );

    // Note: Native verify doesn't compute output aggregator - it's only used in prove

    // Compute the Fiat-Shamir challenge using the provided transcript
    // Updated to match native: only uses input aggregator, not output
    let challenge_c = compute_challenge_gadget::<G, GG, FV, S, ROVar, N>(
        transcript,
        &input_ciphertext_aggregator,
        power_perm_commitment,
        proof,
    )?;

    tracing::debug!(
        target: LOG_TARGET,
        "Computed challenge_c: {:?}",
        challenge_c.value()
    );

    // 1) com(sigma_response_power_permutation_vector; sigma_response_blinding) = blinding_factor_commitment + (c · power_perm_commitment)
    // Debug: Log the values being committed
    tracing::debug!(
        target: LOG_TARGET,
        "Committing values in circuit: sigma_response_power_permutation_vector[0] = {:?}",
        proof.sigma_response_power_permutation_vector[0].value()
    );
    tracing::debug!(
        target: LOG_TARGET,
        "sigma_response_blinding = {:?}",
        proof.sigma_response_blinding.value()
    );

    let lhs_com = commit_vector_gadget::<G, GG, FV, N>(
        pedersen_blinding_base,
        pedersen_message_bases,
        &proof.sigma_response_power_permutation_vector,
        &proof.sigma_response_blinding,
    )?;
    let c_bits = challenge_c.to_bits_le()?;
    let power_perm_commitment_scaled = power_perm_commitment.scalar_mul_le(c_bits.iter())?;
    let rhs_com = &proof.blinding_factor_commitment + &power_perm_commitment_scaled;

    tracing::debug!(target: LOG_TARGET, "com(sigma_response_power_permutation_vector; sigma_response_blinding) = {:?}", lhs_com.value().ok());
    tracing::debug!(target: LOG_TARGET, "blinding_factor_commitment + (c · power_perm_commitment): rhs_com = {:?}", rhs_com.value().ok());

    let check1 = lhs_com.is_eq(&rhs_com)?;

    tracing::debug!(target: LOG_TARGET, "check1 = {:?}", check1.value().ok());

    // 2) Group-side equality (V2): E(0; z_ρ) · ∏ (C'_i)^{z_{b,i}} = T_grp · (C^a)^c
    // LHS - compute E_pk(0; z_ρ) · ∏ output_ciphertexts[j]^{z_b[j]}
    // This mirrors native encrypt_one_and_combine (pure rerandomization of zero)

    // Get the generator internally (matching native implementation)
    let generator = GG::constant(G::generator());

    // E_pk(0; z_ρ) = (g^z_ρ, pk^z_ρ)
    // Using direct multiplication with FieldVar
    let enc_one_c1 = generator.clone() * &proof.sigma_response_rerand;
    let enc_one_c2 = public_key.clone() * &proof.sigma_response_rerand;

    // ∏ (C'_i)^{z_b[i]} - note: using OUTPUT ciphertexts to match native
    let msm = msm_ciphertexts_gadget_emulated(
        output_ciphertexts, // Changed from input_ciphertexts to match native
        &proof.sigma_response_power_permutation_vector,
    )?;

    // LHS as ElGamal ciphertext
    let lhs_grp = ElGamalCiphertextVar::new(&enc_one_c1 + &msm.c1, &enc_one_c2 + &msm.c2);

    // RHS - T_grp · (C^a)^c where C^a is the input aggregator
    // This is ElGamal multiplication: T_grp + (C^a) * c
    let input_agg_c1_scaled = input_ciphertext_aggregator
        .c1
        .scalar_mul_le(c_bits.iter())?;
    let input_agg_c2_scaled = input_ciphertext_aggregator
        .c2
        .scalar_mul_le(c_bits.iter())?;

    let rhs_grp = ElGamalCiphertextVar::new(
        &proof.blinding_rerandomization_commitment.c1 + &input_agg_c1_scaled,
        &proof.blinding_rerandomization_commitment.c2 + &input_agg_c2_scaled,
    );

    tracing::debug!(target: LOG_TARGET, "LHS (V2): c1={:?}, c2={:?}", lhs_grp.c1.value().ok(), lhs_grp.c2.value().ok());
    tracing::debug!(target: LOG_TARGET, "RHS (V2): c1={:?}, c2={:?}", rhs_grp.c1.value().ok(), rhs_grp.c2.value().ok());

    // Check both c1 and c2 components separately
    let check2_c1 = lhs_grp.c1.is_eq(&rhs_grp.c1)?;
    let check2_c2 = lhs_grp.c2.is_eq(&rhs_grp.c2)?;
    let check2 = Boolean::kary_and(&[check2_c1, check2_c2])?;
    tracing::debug!(target: LOG_TARGET, "Check2: {:?}", check2.value().ok());

    // Both checks must pass
    let result = Boolean::kary_and(&[check1, check2])?;
    Ok(result)
}

/// MSM over ciphertexts in-circuit using functional fold pattern (generic FieldVar version).
fn msm_ciphertexts_gadget_emulated<G, GG, FV, const N: usize>(
    ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    scalars: &[FV; N],
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    FV: FieldVar<G::ScalarField, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
    for<'a> GG: std::ops::Mul<&'a FV, Output = GG>,
{
    // Use fold to accumulate the scalar multiplication results
    ciphertexts
        .iter()
        .zip(scalars.iter())
        .enumerate()
        .map(|(i, (ct, scalar))| {
            tracing::trace!(
                target: LOG_TARGET,
                "MSM gadget: multiplying ciphertext[{}] by scalar = {:?}",
                i,
                scalar.value()
            );
            tracing::trace!(
                target: LOG_TARGET,
                "MSM gadget: ct[{}].c1 = {:?}",
                i,
                ct.c1.value()
            );
            // Perform scalar multiplication on both components using direct multiplication
            let c1_scaled = ct.c1.clone() * scalar;
            let c2_scaled = ct.c2.clone() * scalar;
            tracing::trace!(
                target: LOG_TARGET,
                "MSM gadget: c1_scaled[{}] = {:?}",
                i,
                c1_scaled.value()
            );
            Ok(ElGamalCiphertextVar::new(c1_scaled, c2_scaled))
        })
        .try_fold(
            // Initialize with zero ciphertext
            ElGamalCiphertextVar::new(GG::zero(), GG::zero()),
            |acc, result| {
                let term = result?;
                // Add the current term to the accumulator
                Ok(ElGamalCiphertextVar::new(
                    &acc.c1 + &term.c1,
                    &acc.c2 + &term.c2,
                ))
            },
        )
}

/// Compute Pedersen commitment to a vector of field elements mirroring pedersen_commit_scalars
/// This directly implements: com(values; randomness) = H^randomness * Π_j G_j^{values[j]}
///
/// Since we can't access the internal params field of ParametersVar, we pass the bases directly
fn commit_vector_gadget<G, GG, FV, const N: usize>(
    blinding_base: &GG,
    message_bases: &[GG; N],
    values: &[FV; N],
    randomness: &FV,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField> + Clone,
    FV: FieldVar<G::ScalarField, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
    for<'a> GG: std::ops::Mul<&'a FV, Output = GG>,
{
    // Compute H^randomness (the blinding term) using direct multiplication
    let blinding_term = blinding_base.clone() * randomness;

    // Compute Π_j G_j^{values[j]} using fold pattern like native implementation
    let message_term =
        message_bases
            .iter()
            .zip(values.iter())
            .try_fold(GG::zero(), |acc, (base, value)| {
                // Compute G_j^{value[j]} using direct multiplication
                let term = base.clone() * value;
                // Add to accumulator
                Ok::<GG, SynthesisError>(&acc + &term)
            })?;

    // Combine: H^randomness + Π_j G_j^{values[j]}
    Ok(&blinding_term + &message_term)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Tests: prove off-circuit, verify in-circuit for N = 4, 8, 10
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::pedersen_commitment::extract_pedersen_bases as native_extract_bases;
    use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
    use crate::shuffling::{generate_random_ciphertexts, shuffle_and_rerandomize_random};
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::pedersen::Commitment as PedersenCommitment;
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_crypto_primitives::sponge::poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge};
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ec::PrimeGroup;
    use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;
    type Pedersen<G> =
        PedersenCommitment<G, crate::pedersen_commitment::bytes_opening::ReencryptionWindow>;

    const TEST_TARGET: &str = "legit_poker";

    fn setup_test_tracing() {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::TRACE)
            .with_target(LOG_TARGET, tracing::Level::TRACE)
            .with_target(
                "legit_poker::shuffling::bayer_groth_permutation::reencryption_protocol",
                tracing::Level::TRACE,
            );

        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_writer(tracing_subscriber::fmt::TestWriter::default()), // This ensures output goes to test stdout
            )
            .with(filter)
            .try_init();
    }

    // Local helper: commit vector natively exactly like the prover
    fn commit_vector_native<const N: usize>(
        params: &ark_crypto_primitives::commitment::pedersen::Parameters<G1Projective>,
        values: &[Fr; N],
        randomness: Fr,
    ) -> G1Projective {
        let (h, bases) = native_extract_bases::<G1Projective, N>(params);
        let mut acc = h * randomness;
        for j in 0..N {
            acc += bases[j] * values[j];
        }
        acc
    }

    fn run_sigma_circuit_test<const N: usize>() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        // Generate a valid ElGamal public key (sk * G, not a random point)
        let sk = Fr::rand(&mut rng);
        let public_key = G1Projective::generator() * sk;
        let pedersen_params = Pedersen::<G1Projective>::setup(&mut rng).unwrap();

        // Inputs: N ciphertexts
        let (c_in, _) = generate_random_ciphertexts::<G1Projective, N>(&public_key, &mut rng);

        // Generate permutation using RS shuffle with a deterministic seed
        // We use 10 levels which is good for up to 1024 elements
        const LEVELS: usize = 10;
        let seed = Fr::from(42u64); // Fixed seed for reproducible testing

        // Create an index array to permute
        let indices: [usize; N] = core::array::from_fn(|i| i);

        // Apply RS shuffle to get the permutation
        let rs_shuffle_trace = run_rs_shuffle_permutation::<Fr, usize, N, LEVELS>(seed, &indices);

        // Convert the permuted indices to a permutation array
        // pi[i] tells us where element i should go
        let mut pi = [0usize; N];
        for (new_pos, &original_idx) in rs_shuffle_trace.permuted_output.iter().enumerate() {
            pi[original_idx] = new_pos;
        }

        let (c_out, rerand) =
            shuffle_and_rerandomize_random::<G1Projective, N>(&c_in, &pi, public_key, &mut rng);

        // FS exponent x and vectors a,b (we only need b and rho here)
        let x = Fr::from(1000u64);

        // NEW algorithm: b[i] = x^{π(i)+1} (output-aligned with 1-based indexing)
        let b = crate::shuffling::bayer_groth_permutation::utils::compute_power_permutation_vector::<
            Fr,
            N,
        >(&pi, x);

        // power_perm_commitment = com(b; power_perm_blinding_factor) with the same vector-Pedersen as native prover
        let power_perm_blinding_factor = Fr::rand(&mut rng);
        let power_perm_commitment =
            commit_vector_native::<N>(&pedersen_params, &b, power_perm_blinding_factor);

        // NEW algorithm: rerandomization scalars are already output-indexed
        let rerandomization_scalars = rerand;

        // Verify the shuffle relation holds before creating the proof
        assert!(
            crate::shuffling::bayer_groth_permutation::utils::verify_shuffle_relation::<
                G1Projective,
                N,
            >(&public_key, &c_in, &c_out, x, &b, &rerandomization_scalars,),
            "Shuffle relation does not hold - cannot create valid proof!"
        );

        // Native proof
        let config_fr = crate::config::poseidon_config::<Fq>();
        tracing::debug!(target: TEST_TARGET, "Creating native prover sponge with Fq config");
        let mut prover_sponge = PoseidonSponge::new(&config_fr);
        let proof = super::super::reencryption_protocol::prove(
            &public_key,
            &pedersen_params,
            &c_in,
            &c_out,
            x,
            &power_perm_commitment,
            &b,
            power_perm_blinding_factor,
            &rerandomization_scalars,
            &mut prover_sponge,
            &mut rng,
        );

        // Verify the proof natively first
        tracing::info!(target: TEST_TARGET, "Starting native verification of proof");
        let mut verifier_sponge = PoseidonSponge::new(&config_fr);
        let native_valid = super::super::reencryption_protocol::verify(
            &public_key,
            &pedersen_params,
            &c_in,
            &c_out,
            x,
            &power_perm_commitment,
            &proof,
            &mut verifier_sponge,
        );
        tracing::info!(target: TEST_TARGET, "Native verification result: {}", native_valid);
        assert!(native_valid, "Native verification failed!");

        // ------------------ Build circuit and verify in-circuit ------------------
        let cs = ConstraintSystem::<Fq>::new_ref();

        // PK as constant
        let pk_var = G1Var::constant(public_key);

        // Allocate ciphertexts as constants
        let mut cin_vars = Vec::with_capacity(N);
        let mut cout_vars = Vec::with_capacity(N);
        for i in 0..N {
            cin_vars.push(ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(c_in[i].clone()),
                AllocationMode::Constant,
            )?);
            cout_vars.push(ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(c_out[i].clone()),
                AllocationMode::Constant,
            )?);
        }
        let c_in_var: [ElGamalCiphertextVar<G1Projective, G1Var>; N] = cin_vars.try_into().unwrap();
        let c_out_var: [ElGamalCiphertextVar<G1Projective, G1Var>; N] =
            cout_vars.try_into().unwrap();

        // x as EmulatedFpVar constant
        let x_var = EmulatedFpVar::<Fr, Fq>::new_constant(cs.clone(), x)?;

        // b_vector_commitment as constant point
        let b_vector_commitment_var = G1Var::constant(power_perm_commitment);

        // Proof as witness (using EmulatedFpVar as the concrete FV implementation)
        let proof_var =
            ReencryptionProofVar::<G1Projective, G1Var, EmulatedFpVar<Fr, Fq>, N>::new_variable(
                cs.clone(),
                || Ok(proof.clone()),
                AllocationMode::Witness,
            )?;

        // Extract Pedersen bases from native parameters and allocate as circuit constants
        // IMPORTANT: Normalize all bases to affine form to ensure consistent representation
        let (blinding_base, message_bases) =
            native_extract_bases::<G1Projective, N>(&pedersen_params);

        tracing::debug!(target: TEST_TARGET, "Extracted {} message bases for N={}", message_bases.len(), N);
        tracing::debug!(target: TEST_TARGET, "Native blinding_base = {:?}", blinding_base);
        for (i, base) in message_bases.iter().enumerate() {
            tracing::debug!(target: TEST_TARGET, "Native message_base[{}] = {:?}", i, base);
        }

        // Convert to affine to ensure consistent coordinate representation
        let blinding_base_affine = blinding_base.into_affine();
        let blinding_base_var = G1Var::constant(blinding_base_affine.into());

        let message_bases_vars: Vec<G1Var> = message_bases
            .iter()
            .map(|base| {
                let base_affine = base.into_affine();
                G1Var::constant(base_affine.into())
            })
            .collect();
        let message_bases_var: [G1Var; N] = message_bases_vars.try_into().unwrap();

        // Create transcript for challenge computation
        let config = crate::config::poseidon_config::<Fq>();
        tracing::debug!(target: TEST_TARGET, "Creating circuit transcript with Fq config");
        let mut transcript = PoseidonSpongeVar::new(cs.clone(), &config);

        // Verify in-circuit
        let ok = verify_gadget::<
            G1Projective,
            G1Var,
            EmulatedFpVar<Fr, Fq>,
            PoseidonSponge<Fq>,
            PoseidonSpongeVar<Fq>,
            N,
        >(
            cs.clone(),
            &mut transcript,
            &pk_var,
            &blinding_base_var,
            &message_bases_var,
            &c_in_var,
            &c_out_var,
            &x_var,
            &b_vector_commitment_var,
            &proof_var,
        )?;

        ok.enforce_equal(&Boolean::constant(true))?;

        // Debug failing constraints
        if !cs.is_satisfied()? {
            tracing::debug!(target = LOG_TARGET, "Circuit is not satisfied!");
            if let Some(unsatisfied_path) = cs.which_is_unsatisfied()? {
                tracing::debug!(
                    target = LOG_TARGET,
                    "First unsatisfied constraint: {}",
                    unsatisfied_path
                );
            }
            tracing::debug!(
                target = LOG_TARGET,
                "Total constraints: {}",
                cs.num_constraints()
            );
            tracing::debug!(
                target = LOG_TARGET,
                "Total witness variables: {}",
                cs.num_witness_variables()
            );
        }

        assert!(cs.is_satisfied()?, "Circuit verification failed");
        Ok(())
    }

    #[test]
    fn test_sigma_circuit_rerand_4() -> Result<(), SynthesisError> {
        setup_test_tracing();
        run_sigma_circuit_test::<4>()
    }

    #[test]
    fn test_sigma_circuit_rerand_8() -> Result<(), SynthesisError> {
        setup_test_tracing();
        run_sigma_circuit_test::<8>()
    }

    #[test]
    fn test_sigma_circuit_rerand_10() -> Result<(), SynthesisError> {
        setup_test_tracing();
        run_sigma_circuit_test::<10>()
    }
}
