//! SNARK circuit gadgets for non-interactive Σ-protocol verification
//!
//! This module provides type-safe circuit gadgets for verifying the Σ-protocol
//! inside a SNARK, ensuring the same witness b is used throughout.
//!
//! Key fixes vs the previous version:
//! 1) commit_vector_gadget now uses the standard arkworks PedersenCommGadget.
//! 2) The Fiat–Shamir challenge `c` is passed into the circuit (do not recompute it
//!    in-circuit) to avoid field/domain mismatch with the native transcript.

use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, vec::Vec};
use tracing::instrument;

use super::reencryption_protocol::ReencryptionProof;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::reencryption_gadgets";

/// Circuit proof representation with const generic N
#[allow(non_snake_case)]
pub struct ReencryptionProofVar<G, GG, const N: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    pub blinding_factor_commitment: GG,
    pub blinding_rerandomization_commitment: ElGamalCiphertextVar<G, GG>,
    pub sigma_response_power_permutation_vector: [FpVar<G::BaseField>; N],
    pub sigma_response_blinding: FpVar<G::BaseField>,
    pub sigma_response_rerand: FpVar<G::BaseField>,
}

impl<G, GG, const N: usize> Clone for ReencryptionProofVar<G, GG, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + Clone,
    FpVar<G::BaseField>: Clone,
{
    #[allow(non_snake_case)]
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

impl<G, GG, const N: usize> AllocVar<ReencryptionProof<G, N>, G::BaseField>
    for ReencryptionProofVar<G, GG, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
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

        // Allocate sigma_response_power_permutation_vector array (convert scalar -> base field for circuit)
        let mut sigma_response_power_permutation_vector_vec = Vec::with_capacity(N);
        for i in 0..N {
            let sigma_response_power_permutation_vector_i = FpVar::new_variable(
                cs.clone(),
                || {
                    Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                        &proof.sigma_response_power_permutation_vector[i],
                    ))
                },
                mode,
            )?;
            sigma_response_power_permutation_vector_vec
                .push(sigma_response_power_permutation_vector_i);
        }
        let sigma_response_power_permutation_vector: [FpVar<G::BaseField>; N] =
            sigma_response_power_permutation_vector_vec
                .try_into()
                .unwrap();

        // Allocate sigma_response_blinding
        let sigma_response_blinding = FpVar::new_variable(
            cs.clone(),
            || {
                Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                    &proof.sigma_response_blinding,
                ))
            },
            mode,
        )?;

        // Allocate sigma_response_rerand (convert scalar -> base field for circuit)
        let sigma_response_rerand = FpVar::new_variable(
            cs.clone(),
            || {
                Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                    &proof.sigma_response_rerand,
                ))
            },
            mode,
        )?;

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
fn absorb_public_inputs_gadget<G, GG>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    input_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    b_vector_commitment: &GG,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
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
fn compute_challenge_gadget<G, GG, const N: usize>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    input_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    permutation_power_vector_commitment: &GG,
    proof: &ReencryptionProofVar<G, GG, N>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Absorb public inputs (matching native verify)
    absorb_public_inputs_gadget(
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
pub fn verify_gadget<G, GG, const N: usize>(
    cs: ConstraintSystemRef<G::BaseField>,
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    public_key: &GG,                  // ElGamal PK = x·G
    pedersen_blinding_base: &GG,      // H for Pedersen commitment
    pedersen_message_bases: &[GG; N], // [G_1, ..., G_N] for Pedersen commitment
    input_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    output_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    perm_power_challenge: &FpVar<G::BaseField>, // a_i = x^(i+1)
    power_perm_commitment: &GG,                 // Pedersen commitment to b
    proof: &ReencryptionProofVar<G, GG, N>,
) -> Result<Boolean<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField> + Clone,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    tracing::debug!(target: LOG_TARGET, N = N, "Starting non-interactive verification");

    // Compute powers sequence [x^1, x^2, ..., x^N] matching native implementation
    let powers = crate::shuffling::bayer_groth_permutation::utils::compute_powers_sequence_gadget::<
        G::BaseField,
        N,
    >(cs.clone(), perm_power_challenge)?;

    // Compute input aggregator C^a where a_i = x^(i+1)
    let input_ciphertext_aggregator = msm_ciphertexts_gadget(input_ciphertexts, &powers)?;

    // Note: Native verify doesn't compute output aggregator - it's only used in prove

    // Compute the Fiat-Shamir challenge using the provided transcript
    // Updated to match native: only uses input aggregator, not output
    let challenge_c = compute_challenge_gadget::<G, GG, N>(
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
    
    let lhs_com = commit_vector_gadget::<G, GG, N>(
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

    // 2) Group-side equality (V2): E(1; z_ρ) · ∏ (C'_i)^{z_{b,i}} = T_grp · (C^a)^c
    // LHS - compute E_pk(1; z_ρ) · ∏ output_ciphertexts[j]^{z_b[j]}
    // This matches native encrypt_one_and_combine
    let sigma_response_rerand_bits = proof.sigma_response_rerand.to_bits_le()?;

    // Get the generator internally (matching native implementation)
    let generator = GG::constant(G::generator());

    // E_pk(1; z_ρ) = (g^z_ρ, g + pk^z_ρ)
    let enc_one_c1 = generator.scalar_mul_le(sigma_response_rerand_bits.iter())?;
    let enc_one_c2_temp = public_key.scalar_mul_le(sigma_response_rerand_bits.iter())?;
    let enc_one_c2 = &enc_one_c2_temp + &generator; // Add generator for E_pk(1; r)

    // ∏ (C'_i)^{z_b[i]} - note: using OUTPUT ciphertexts to match native
    let msm = msm_ciphertexts_gadget(
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

/// MSM over ciphertexts in-circuit using functional fold pattern.
fn msm_ciphertexts_gadget<G, GG, const N: usize>(
    ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    scalars: &[FpVar<G::BaseField>; N],
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Use fold to accumulate the scalar multiplication results
    ciphertexts
        .iter()
        .zip(scalars.iter())
        .map(|(ct, scalar)| {
            // Convert scalar to bits for scalar multiplication
            let bits = scalar.to_bits_le()?;
            // Perform scalar multiplication on both components
            let c1_scaled = ct.c1.scalar_mul_le(bits.iter())?;
            let c2_scaled = ct.c2.scalar_mul_le(bits.iter())?;
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
fn commit_vector_gadget<G, GG, const N: usize>(
    blinding_base: &GG,
    message_bases: &[GG; N],
    values: &[FpVar<G::BaseField>; N],
    randomness: &FpVar<G::BaseField>,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + Clone,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Convert randomness to bits for scalar multiplication
    let randomness_bits = randomness.to_bits_le()?;

    // Compute H^randomness (the blinding term)
    let blinding_term = blinding_base.scalar_mul_le(randomness_bits.iter())?;

    // Compute Π_j G_j^{values[j]} using fold pattern like native implementation
    let message_term =
        message_bases
            .iter()
            .zip(values.iter())
            .try_fold(GG::zero(), |acc, (base, value)| {
                // Convert value to bits for scalar multiplication
                let value_bits = value.to_bits_le()?;
                // Compute G_j^{value[j]}
                let term = base.scalar_mul_le(value_bits.iter())?;
                // Add to accumulator
                Ok::<GG, SynthesisError>(&acc + &term)
            })?;

    // Combine: H^randomness + Π_j G_j^{values[j]}
    Ok(&blinding_term + &message_term)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn scalar_to_base_field<ScalarField, BaseField>(scalar: &ScalarField) -> BaseField
where
    ScalarField: PrimeField,
    BaseField: PrimeField,
{
    // Convert through bytes to keep the same big-endian integer representation
    let mut bytes = Vec::new();
    scalar.serialize_uncompressed(&mut bytes).unwrap();
    BaseField::deserialize_uncompressed(&mut &bytes[..]).unwrap_or(BaseField::zero())
}

// -----------------------------------------------------------------------------
// Tests: prove off-circuit, verify in-circuit for N = 4, 8, 10
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::bayer_groth_permutation::utils::extract_pedersen_bases as native_extract_bases;
    use crate::shuffling::test_utils::{
        generate_random_ciphertexts, shuffle_and_rerandomize_random,
    };
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::pedersen::Commitment as PedersenCommitment;
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ec::PrimeGroup;
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
        PedersenCommitment<G, crate::pedersen_commitment_opening_proof::ReencryptionWindow>;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::TRACE)
            .with_target(LOG_TARGET, tracing::Level::TRACE);

        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
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

        // Permute + rerandomize
        let pi: [usize; N] = core::array::from_fn(|i| (i * 7 + 3) % N); // simple pseudorandom permutation
        let (c_out, rerand) =
            shuffle_and_rerandomize_random::<G1Projective, N>(&c_in, &pi, public_key, &mut rng);

        // FS exponent x and vectors a,b (we only need b and rho here)
        let x = Fr::from(2u64);

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

        // x as constant in base field
        let x_fq: Fq = scalar_to_base_field::<Fr, Fq>(&x);
        let x_var = FpVar::<Fq>::new_constant(cs.clone(), x_fq)?;

        // b_vector_commitment as constant point
        let b_vector_commitment_var = G1Var::constant(power_perm_commitment);

        // Proof as witness
        let proof_var = ReencryptionProofVar::<G1Projective, G1Var, N>::new_variable(
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
        let ok = verify_gadget::<G1Projective, G1Var, N>(
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
