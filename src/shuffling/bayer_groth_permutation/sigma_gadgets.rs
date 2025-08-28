//! SNARK circuit gadgets for non-interactive Σ-protocol verification
//!
//! This module provides type-safe circuit gadgets for verifying the Σ-protocol
//! inside a SNARK, ensuring the same witness b is used throughout.
//!
//! Key fixes vs the previous version:
//! 1) commit_vector_gadget now uses the same per-coordinate Pedersen bases as native code.
//! 2) The Fiat–Shamir challenge `c` is passed into the circuit (do not recompute it
//!    in-circuit) to avoid field/domain mismatch with the native transcript.

use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_crypto_primitives::commitment::pedersen::constraints::ParametersVar;
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

use super::sigma_protocol::SigmaProof;
use ark_crypto_primitives::commitment::pedersen::Parameters;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

const LOG_TARGET: &str = "nexus_nova::shuffling::bayer_groth_permutation::sigma_gadgets";

/// Circuit proof representation with const generic N
#[allow(non_snake_case)]
pub struct SigmaProofVar<G, GG, const N: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    pub blinding_factor_commitment: GG,
    pub blinding_rerandomization_commitment: GG,
    pub sigma_response_b: [FpVar<G::BaseField>; N],
    pub sigma_response_blinding: FpVar<G::BaseField>,
    pub sigma_response_rerand: FpVar<G::BaseField>,
}

impl<G, GG, const N: usize> Clone for SigmaProofVar<G, GG, N>
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
            sigma_response_b: self.sigma_response_b.clone(),
            sigma_response_blinding: self.sigma_response_blinding.clone(),
            sigma_response_rerand: self.sigma_response_rerand.clone(),
        }
    }
}

impl<G, GG, const N: usize> AllocVar<SigmaProof<G, N>, G::BaseField> for SigmaProofVar<G, GG, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    fn new_variable<T: Borrow<SigmaProof<G, N>>>(
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
        let blinding_rerandomization_commitment = GG::new_variable(
            cs.clone(),
            || Ok(proof.blinding_rerandomization_commitment),
            mode,
        )?;

        // Allocate sigma_response_b array (convert scalar -> base field for circuit)
        let mut sigma_response_b_vec = Vec::with_capacity(N);
        for i in 0..N {
            let sigma_response_b_i = FpVar::new_variable(
                cs.clone(),
                || {
                    Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                        &proof.sigma_response_b[i],
                    ))
                },
                mode,
            )?;
            sigma_response_b_vec.push(sigma_response_b_i);
        }
        let sigma_response_b: [FpVar<G::BaseField>; N] = sigma_response_b_vec.try_into().unwrap();

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
            sigma_response_b,
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
    output_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    b_vector_commitment: &GG,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Absorb aggregated input ciphertexts (already computed)
    let input_aggregator_sum = &input_ciphertext_aggregator.c1 + &input_ciphertext_aggregator.c2;
    input_aggregator_sum.curve_absorb_gadget(transcript)?;

    // Absorb aggregated output ciphertexts (already computed)
    let output_aggregator_sum = &output_ciphertext_aggregator.c1 + &output_ciphertext_aggregator.c2;
    output_aggregator_sum.curve_absorb_gadget(transcript)?;

    // Absorb b_vector_commitment
    b_vector_commitment.curve_absorb_gadget(transcript)?;

    Ok(())
}

/// Compute the Fiat-Shamir challenge in-circuit
/// This mirrors the native absorption strategy for efficiency
#[instrument(level = "trace", skip_all, fields(N = N))]
fn compute_challenge_gadget<G, GG, const N: usize>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    input_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    output_ciphertext_aggregator: &ElGamalCiphertextVar<G, GG>,
    b_vector_commitment: &GG,
    proof: &SigmaProofVar<G, GG, N>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Absorb public inputs
    absorb_public_inputs_gadget(
        transcript,
        input_ciphertext_aggregator,
        output_ciphertext_aggregator,
        b_vector_commitment,
    )?;

    tracing::debug!(
        target: LOG_TARGET,
        "prover's input_ciphertext_aggregator: {:?}",
        input_ciphertext_aggregator.value()
    );
    tracing::debug!(
        target: LOG_TARGET,
        "prover's output_ciphertext_aggregator: {:?}",
        output_ciphertext_aggregator.value()
    );
    tracing::debug!(
        target: LOG_TARGET,
        "prover's b_vector_commitment: {:?}",
        b_vector_commitment.value()
    );

    // Absorb proof commitments
    proof
        .blinding_factor_commitment
        .curve_absorb_gadget(transcript)?;
    proof
        .blinding_rerandomization_commitment
        .curve_absorb_gadget(transcript)?;

    // Squeeze the challenge
    Ok(transcript.squeeze_field_elements(1)?[0].clone())
}

/// Verifies the Σ-protocol inside a SNARK circuit, ensuring the same witness is used
/// throughout the entire proof system. Returns a Boolean constraint indicating validity.
///
/// ## Constraints Enforced:
///
/// 1. **Commitment Consistency**: com(sigma_response_b; sigma_response_blinding) = sigma_commitment_T · b_vector_commitment^c
///    - Uses the same Pedersen vector bases as the native verifier.
/// 2. **Shuffle Correctness**: E(1; sigma_response_rerand) · ∏input_ciphertexts[j]^{sigma_response_b[j]} = sigma_ciphertext_T · (output_ciphertext_aggregator)^c
///
/// The challenge is computed using the provided transcript for efficiency.
#[instrument(target = LOG_TARGET, level = "trace", skip_all)]
pub fn verify_sigma_linkage_gadget_ni<G, GG, const N: usize>(
    cs: ConstraintSystemRef<G::BaseField>,
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    generator: &GG,  // curve generator G
    public_key: &GG, // ElGamal PK = x·G
    _pedersen_params: &ParametersVar<G, GG>,
    native_params: &Parameters<G>,
    input_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    output_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    x: &FpVar<G::BaseField>,  // a_i = x^(i+1)
    b_vector_commitment: &GG, // Pedersen commitment to b
    proof: &SigmaProofVar<G, GG, N>,
) -> Result<Boolean<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Compute input aggregator: ∏(input_ciphertexts[i])^{x^(i+1)}
    let input_ciphertext_aggregator =
        compute_output_aggregator_gadget(cs.clone(), input_ciphertexts, x)?;

    // Compute output aggregator: ∏(output_ciphertexts[i])^{x^(i+1)}
    let output_ciphertext_aggregator =
        compute_output_aggregator_gadget(cs.clone(), output_ciphertexts, x)?;

    // Compute the Fiat-Shamir challenge using the provided transcript
    let challenge_c = compute_challenge_gadget::<G, GG, N>(
        transcript,
        &input_ciphertext_aggregator,
        &output_ciphertext_aggregator,
        b_vector_commitment,
        proof,
    )?;

    tracing::debug!(
        target: LOG_TARGET,
        "Computed challenge_c: {:?}",
        challenge_c.value()
    );

    // 1) com(sigma_response_b; sigma_response_blinding) = blinding_factor_commitment + (c · b_vector_commitment)
    let lhs_com = commit_vector_gadget::<G, GG, N>(
        native_params,
        &proof.sigma_response_b,
        &proof.sigma_response_blinding,
        cs.clone(),
    )?;
    let c_bits = challenge_c.to_bits_le()?;
    let b_vector_commitment_scaled = b_vector_commitment.scalar_mul_le(c_bits.iter())?;
    let rhs_com = &proof.blinding_factor_commitment + &b_vector_commitment_scaled;

    tracing::debug!(target: LOG_TARGET, "com(sigma_response_b; sigma_response_blinding) = {:?}", lhs_com.value());
    tracing::debug!(target: LOG_TARGET, "blinding_factor_commitment + (c · b_vector_commitment): rhs_com = {:?}", rhs_com.value());

    let check1 = lhs_com.is_eq(&rhs_com)?;

    tracing::debug!(target: LOG_TARGET, "check1 = {:?}", check1.value());

    // 2) E(1; sigma_response_rerand) · ∏ input_ciphertexts[j]^{sigma_response_b[j]} = blinding_rerandomization_commitment · (output_ciphertext_aggregator)^c
    // LHS - sigma_response_rerand is now a single scalar
    let sigma_response_rerand_bits = proof.sigma_response_rerand.to_bits_le()?;
    let rerand_c1 = generator.scalar_mul_le(sigma_response_rerand_bits.iter())?;
    let rerand_c2_temp = public_key.scalar_mul_le(sigma_response_rerand_bits.iter())?;
    let rerand_c2 = &rerand_c2_temp + generator; // Add generator for E_pk(1; r)
    let msm = msm_ciphertexts_gadget(cs.clone(), input_ciphertexts, &proof.sigma_response_b)?;
    let lhs_c1 = &rerand_c1 + &msm.c1;
    let lhs_c2 = &rerand_c2 + &msm.c2;

    // Compute lhs as single point (c1 + c2)
    let lhs_point = &lhs_c1 + &lhs_c2;

    tracing::debug!(target: LOG_TARGET, "E_pk(1; z_rho) · ∏_{{j=1}}^N C_j^{{z_b,j}}  = {:?}", lhs_point.value());

    // RHS - blinding_rerandomization_commitment + (c1 + c2 of output_aggregator) * c
    let output_aggregator_sum = &output_ciphertext_aggregator.c1 + &output_ciphertext_aggregator.c2;
    let output_aggregator_scaled = output_aggregator_sum.scalar_mul_le(c_bits.iter())?;
    let rhs_point = &proof.blinding_rerandomization_commitment + &output_aggregator_scaled;
    tracing::debug!(target: LOG_TARGET, "T_grp · (C'^a)^c = {:?}", rhs_point.value());

    let check2 = lhs_point.is_eq(&rhs_point)?;
    tracing::debug!(target: LOG_TARGET, "Check2: {:?}", check2.value());

    // Both checks must pass
    let result = Boolean::kary_and(&[check1, check2])?;
    Ok(result)
}

/// Compute C'^a = ∏(C'_i)^{x^(i+1)} inside the circuit.
#[allow(non_snake_case)]
#[instrument(level = "trace", skip_all, fields(N = N))]
pub fn compute_output_aggregator_gadget<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    output_ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    x: &FpVar<G::BaseField>,
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // powers[i] = x^(i+1)
    let mut powers = Vec::with_capacity(N);
    let mut x_power = x.clone();
    for _ in 0..N {
        powers.push(x_power.clone());
        x_power = &x_power * x;
    }
    let powers: [FpVar<G::BaseField>; N] = powers.try_into().unwrap();

    msm_ciphertexts_gadget(_cs, output_ciphertexts, &powers)
}

/// MSM over ciphertexts in-circuit.
#[allow(non_snake_case)]
fn msm_ciphertexts_gadget<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    scalars: &[FpVar<G::BaseField>; N],
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Initialize with first term
    let bits0 = scalars[0].to_bits_le()?;
    let mut acc_c1 = ciphertexts[0].c1.scalar_mul_le(bits0.iter())?;
    let mut acc_c2 = ciphertexts[0].c2.scalar_mul_le(bits0.iter())?;

    // Accumulate
    for i in 1..N {
        let bits = scalars[i].to_bits_le()?;
        let t1 = ciphertexts[i].c1.scalar_mul_le(bits.iter())?;
        let t2 = ciphertexts[i].c2.scalar_mul_le(bits.iter())?;
        acc_c1 = &acc_c1 + &t1;
        acc_c2 = &acc_c2 + &t2;
    }

    Ok(ElGamalCiphertextVar::new(acc_c1, acc_c2))
}

/// Derive the same vector Pedersen bases in-circuit as native code, then
/// compute com(values; randomness) = pedersen_blinding_base^randomness · Π_j bases[j]^{values[j]}.
fn commit_vector_gadget<G, GG, const N: usize>(
    native_params: &Parameters<G>,
    values: &[FpVar<G::BaseField>; N],
    randomness: &FpVar<G::BaseField>,
    cs: impl Into<Namespace<G::BaseField>>,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + CurveAbsorbGadget<G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    let cs = cs.into().cs();

    // Get the bases from native parameters
    let (native_h, native_bases) =
        super::sigma_protocol::vector_commit_bases::<G, N>(native_params);

    // Allocate pedersen_blinding_base and bases as constants in circuit
    let pedersen_blinding_base = GG::new_constant(cs.clone(), native_h)?;
    let mut bases = Vec::with_capacity(N);
    for i in 0..N {
        bases.push(GG::new_constant(cs.clone(), native_bases[i])?);
    }

    // pedersen_blinding_base^randomness
    let r_bits = randomness.to_bits_le()?;
    let mut acc = pedersen_blinding_base.scalar_mul_le(r_bits.iter())?;

    // sum bases[j]^{values[j]}
    for j in 0..N {
        let bits = values[j].to_bits_le()?;
        let term = bases[j].scalar_mul_le(bits.iter())?;
        acc = &acc + &term;
    }
    Ok(acc)
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
    use crate::shuffling::bayer_groth_permutation::sigma_protocol::vector_commit_bases as native_vector_bases;
    use crate::shuffling::test_utils::{
        generate_random_ciphertexts, shuffle_and_rerandomize_random,
    };
    use crate::ElGamalKeys;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_crypto_primitives::commitment::{
        pedersen::Commitment as PedersenCommitment, CommitmentScheme,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use ark_std::Zero;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;
    type Pedersen<G> = PedersenCommitment<G, super::super::sigma_protocol::SigmaWindow>;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG)
            .with_target(LOG_TARGET, tracing::Level::DEBUG);

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
        let (h, bases) = native_vector_bases::<G1Projective, N>(params);
        let mut acc = h * randomness;
        for j in 0..N {
            acc += bases[j] * values[j];
        }
        acc
    }

    fn run_sigma_circuit_test<const N: usize>() -> Result<(), SynthesisError> {
        let mut rng = test_rng();
        // Keys and parameters
        let sk = Fr::rand(&mut rng);
        let keys = ElGamalKeys::new(sk);
        let pedersen_params = Pedersen::<G1Projective>::setup(&mut rng).unwrap();

        // Inputs: N ciphertexts
        let (c_in, _) = generate_random_ciphertexts::<G1Projective, N>(&keys, &mut rng);

        // Permute + rerandomize
        let pi: [usize; N] = core::array::from_fn(|i| (i * 7 + 3) % N); // simple pseudorandom permutation
        let mut pi_inv = [0usize; N];
        for i in 0..N {
            pi_inv[pi[i]] = i;
        }
        let (c_out, rerand) = shuffle_and_rerandomize_random::<G1Projective, N>(
            &c_in,
            &pi,
            keys.public_key,
            &mut rng,
        );

        // FS exponent x and vectors a,b (we only need b and rho here)
        let x = Fr::from(2u64);

        let mut b = [Fr::zero(); N];
        for j in 0..N {
            // b[j] = x^(pi_inv[j]+1) (1-based exponent indexing)
            b[j] = x.pow(&[(pi_inv[j] as u64) + 1]);
        }

        // b_vector_commitment = com(b; b_commitment_blinding_factor) with the same vector-Pedersen as native prover
        let b_commitment_blinding_factor = Fr::rand(&mut rng);
        let b_vector_commitment =
            commit_vector_native::<N>(&pedersen_params, &b, b_commitment_blinding_factor);

        // Compute input-indexed rerandomization scalars: r_j^in = rerand[pi_inv[j]]
        let mut rerandomization_scalars = [Fr::zero(); N];
        for j in 0..N {
            rerandomization_scalars[j] = rerand[pi_inv[j]];
        }

        // Native proof
        let config_fr = crate::config::poseidon_config::<Fq>();
        let mut prover_sponge = PoseidonSponge::new(&config_fr);
        let proof = super::super::sigma_protocol::prove_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &c_in,
            &c_out,
            x,
            &b_vector_commitment,
            &b,
            b_commitment_blinding_factor,
            &rerandomization_scalars,
            &mut prover_sponge,
            &mut rng,
        );

        // Verify the proof natively first
        tracing::info!(target: TEST_TARGET, "Starting native verification of proof");
        let mut verifier_sponge = PoseidonSponge::new(&config_fr);
        let native_valid = super::super::sigma_protocol::verify_sigma_linkage_ni(
            &keys,
            &pedersen_params,
            &c_in,
            &c_out,
            x,
            &b_vector_commitment,
            &proof,
            &mut verifier_sponge,
        );
        tracing::info!(target: TEST_TARGET, "Native verification result: {}", native_valid);
        assert!(native_valid, "Native verification failed!");

        // ------------------ Build circuit and verify in-circuit ------------------
        let cs = ConstraintSystem::<Fq>::new_ref();

        // ParametersVar (constant)
        let params_var =
            ParametersVar::<G1Projective, G1Var>::new_constant(cs.clone(), &pedersen_params)?;

        // Generator and PK as constants
        let gen_var = G1Var::constant(G1Projective::generator());
        let pk_var = G1Var::constant(keys.public_key);

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
        let b_vector_commitment_var = G1Var::constant(b_vector_commitment);

        // Proof as witness
        let proof_var = SigmaProofVar::<G1Projective, G1Var, N>::new_variable(
            cs.clone(),
            || Ok(proof.clone()),
            AllocationMode::Witness,
        )?;

        // Create transcript for challenge computation
        let config = crate::config::poseidon_config::<Fq>();
        let mut transcript = PoseidonSpongeVar::new(cs.clone(), &config);

        // Verify in-circuit
        let ok = verify_sigma_linkage_gadget_ni::<G1Projective, G1Var, N>(
            cs.clone(),
            &mut transcript,
            &gen_var,
            &pk_var,
            &params_var,
            &pedersen_params,
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
                tracing::debug!(target = LOG_TARGET, "First unsatisfied constraint: {}", unsatisfied_path);
            }
            tracing::debug!(target = LOG_TARGET, "Total constraints: {}", cs.num_constraints());
            tracing::debug!(target = LOG_TARGET, "Total witness variables: {}", cs.num_witness_variables());
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
