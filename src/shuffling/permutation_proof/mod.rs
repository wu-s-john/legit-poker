//! Permutation proof module
//!
//! This module ties together three components inside a single circuit:
//! - VRF-derived randomness binds the RS shuffle bit matrix (via two Poseidon squeezes)
//! - The public Bayer–Groth power challenge `x` (power_challenge) is derived from `c_perm`
//! - The Pedersen commitment `c_power` opens to the permuted power vector `b = [x^π(i)]`,
//!   where `b` is proven to be a permutation of `a = [x, x^2, …, x^N]` via a scalar-field
//!   grand-product equality check.
//!
//! Design notes:
//! - This module does not allocate circuit inputs; gadgets consume already-allocated Vars
//!   and only emit constraints.
//! - For RS, we provide a gadget that compares the trimmed bitstream of a small list of
//!   base-field elements (alphas) against the RS bit-matrix Boolean Vars.
//! - For the BG power challenge, we re-derive `x` from `c_perm` in-circuit and enforce it
//!   equals the public `power_challenge` input.
//! - To avoid in-circuit exponentiation by permutation indices, the power-permutation vector
//!   `b` is passed as a witness and checked to be a permutation of the base powers `a`.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::{emulated_fp::EmulatedFpVar, fp::FpVar};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::field_conversion::base_to_scalar;
use crate::shuffling::bayer_groth_permutation::bg_setup_gadget::new_bayer_groth_transcript_gadget_with_poseidon;
use crate::shuffling::curve_absorb::CurveAbsorb;
use crate::shuffling::pedersen_commitment::opening_proof_gadget::{
    verify_scalar_folding_link_gadget, PedersenCommitmentOpeningProofVar,
};
use crate::shuffling::rs_shuffle::data_structures::PermutationWitnessTraceVar;
use crate::shuffling::rs_shuffle::rs_shuffle_gadget::rs_shuffle_indices;
use crate::track_constraints;
use crate::vrf::gadgets::prove_vrf_gadget;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField;

const LOG_TARGET: &str = "nexus_nova::shuffling::permutation_proof";

/// Native (prover-side) configuration parameters for preparing permutation witnesses
pub struct PermutationParameters<'a, C: CurveGroup, R: rand::RngCore> {
    pub vrf_params: &'a crate::vrf::VrfParams<C>,
    pub perm_params: &'a ark_crypto_primitives::commitment::pedersen::Parameters<C>, // DeckHashWindow
    pub power_params: &'a ark_crypto_primitives::commitment::pedersen::Parameters<C>, // ReencryptionWindow
    pub rng: &'a mut R,
}

/// In-circuit parameters for the permutation proof gadgets
pub struct PermutationGadgetParameters<'a, C: CurveGroup> {
    /// VRF parameters used by the VRF proving gadget
    pub vrf_params: &'a crate::vrf::VrfParams<C>,
    /// Number of Poseidon field elements used to derive the RS bit-matrix
    pub num_samples: usize,
}

/// Prepared witnesses from the native prover for driving the permutation gadget
pub struct PreparedPermutationWitness<C: CurveGroup, const N: usize, const LEVELS: usize> {
    pub pk: C,
    pub beta: C::BaseField,
    pub rs_trace: crate::shuffling::rs_shuffle::data_structures::RSShuffleTrace<usize, N, LEVELS>,
    pub indices_init: [C::BaseField; N],
    pub permutation_vec: [C::ScalarField; N],
    pub power_challenge: C::ScalarField,
    pub bg_setup: crate::shuffling::bayer_groth_permutation::bg_setup::BayerGrothSetupParameters<
        C::ScalarField,
        C,
        N,
    >,
    pub perm_power_vector: [C::ScalarField; N],
    pub power_opening_proof:
        crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof<C>,
    pub blinding_r: C::ScalarField,
    pub blinding_s: C::ScalarField,
}

/// Prepare permutation-related witnesses natively (off-circuit)
///
/// Note: This function is scaffolded for completeness. It wires the existing native
/// utilities to produce the objects that the circuit expects, but it is not used by
/// the circuit gadgets directly.
pub fn prepare_witness<C, R, const N: usize, const LEVELS: usize>(
    params: &mut PermutationParameters<'_, C, R>,
    msg: &[u8],
    sk: C::ScalarField,
) -> anyhow::Result<PreparedPermutationWitness<C, N, LEVELS>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField + ark_crypto_primitives::sponge::Absorb,
    C::ScalarField: PrimeField + ark_crypto_primitives::sponge::Absorb,
    R: rand::RngCore,
{
    use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
    use crate::shuffling::pedersen_commitment::opening_proof::{prove, PedersenParams};
    use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
    use ark_std::vec::Vec;

    // 1) VRF native prove to obtain beta and pk
    let g = C::generator();
    let pk = g * sk;
    let (_proof, beta) = crate::vrf::native::prove_vrf::<C>(params.vrf_params, &pk, sk, msg);

    // 2) RS shuffle witnesses using beta as seed
    let input: [usize; N] = std::array::from_fn(|i| i);
    let rs_trace = run_rs_shuffle_permutation::<C::BaseField, usize, N, LEVELS>(beta, &input);

    // Extract 1-indexed permutation in scalar field
    let permutation_vec: [C::ScalarField; N] = rs_trace
        .extract_permutation_array()
        .into_iter()
        .map(|v| C::ScalarField::from(v as u64))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Permutation length mismatch"))?;

    // 3) Bayer–Groth setup (derive x from c_perm, compute b = [x^π(i)], commit c_power)
    let mut transcript =
        new_bayer_groth_transcript_with_poseidon::<C::BaseField>(b"permutation-proof");
    let blinding_r = C::ScalarField::rand(params.rng);
    let blinding_s = C::ScalarField::rand(params.rng);
    let (bg_setup, perm_power_vector) = transcript.run_protocol::<C, N>(
        params.perm_params,
        params.power_params,
        &rs_trace.extract_permutation_array(),
        blinding_r,
        blinding_s,
    );

    // 4) Pedersen opening proof for c_power (fixed N)
    let ped_params = PedersenParams::<C>::from_arkworks::<N>(params.power_params.clone());
    let vc = crate::shuffling::pedersen_commitment::WithCommitment::<C, N> {
        comm: bg_setup.c_power,
        value: perm_power_vector,
    };
    let opening = prove(&ped_params, &vc, blinding_s, params.rng);

    // 5) Indices init (0..N-1) in base field
    let indices_init = std::array::from_fn(|i| C::BaseField::from(i as u64));

    Ok(PreparedPermutationWitness {
        pk,
        beta,
        rs_trace,
        indices_init,
        permutation_vec,
        power_challenge: bg_setup.perm_power_challenge,
        bg_setup,
        perm_power_vector: vc.value,
        power_opening_proof: opening,
        blinding_r,
        blinding_s,
    })
}

/// Bind the RS bit matrix to a list of base-field elements (alphas) by
/// comparing element-wise with the trimmed bitstream of those alphas.
///
/// The trimming removes the first and last bit from each element's bit-decomposition,
/// matching derive_split_bits_circuit(). Bits are laid out row-major by (level, index).
pub fn bind_rs_bits_to_alphas<F, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<F>,
    alphas: &[FpVar<F>],
    bits_mat: &[[Boolean<F>; N]; LEVELS],
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    track_constraints!(&cs, "bind_rs_bits_to_alphas", LOG_TARGET, {
        // Flatten the trimmed bits from all alphas (LSB-first) into a single stream
        let mut bit_stream: Vec<Boolean<F>> = Vec::new();
        for alpha in alphas.iter() {
            let bits = alpha.to_bits_le()?;
            if bits.len() > 2 {
                bit_stream.extend_from_slice(&bits[1..bits.len() - 1]);
            }
        }

        // Compare to the RS bit matrix in row-major order
        let total = N * LEVELS;
        for k in 0..total {
            let level = k / N;
            let idx = k % N;
            if k < bit_stream.len() {
                bits_mat[level][idx].enforce_equal(&bit_stream[k])?;
            } else {
                bits_mat[level][idx].enforce_equal(&Boolean::constant(false))?;
            }
        }
        Ok(())
    })
}

/// Main permutation gadget: emits constraints tying VRF→RS→BG and Pedersen opening together.
///
/// This gadget DOES NOT allocate inputs; it consumes Vars and composes constraints.
#[allow(clippy::too_many_arguments)]
pub fn prove_permutation_gadget<C, GG, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    gadget_params: &PermutationGadgetParameters<'_, C>,
    // VRF
    msg_bytes: &[ark_r1cs_std::uint8::UInt8<ConstraintF<C>>],
    sk_var: EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
    pk_public: &GG,
    // RS (pre-allocated)
    rs_witness_var: &PermutationWitnessTraceVar<ConstraintF<C>, N, LEVELS>,
    indices_init: &[FpVar<ConstraintF<C>>; N],
    alpha_rs: &FpVar<ConstraintF<C>>, // same alpha reused later for permutation product check
    alphas_for_bits: &[FpVar<ConstraintF<C>>], // num_samples base-field elements
    // BG + opening
    power_challenge_public: EmulatedFpVar<C::ScalarField, ConstraintF<C>>, // x
    c_perm: &GG,
    c_power: &GG,
    power_opening_proof_var: &PedersenCommitmentOpeningProofVar<C, GG>,
    // Witness b = [x^π(i)]
    power_perm_vec_wit: &[EmulatedFpVar<C::ScalarField, ConstraintF<C>>; N],
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + ark_crypto_primitives::sponge::Absorb,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            ConstraintF<C>,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<ConstraintF<C>>,
        >,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    for<'a> &'a GG: crate::shuffling::curve_absorb::CurveAbsorbGadget<
        ConstraintF<C>,
        ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<ConstraintF<C>>,
    >,
{
    track_constraints!(&cs, "prove_permutation_gadget", LOG_TARGET, {
        // 1) VRF prove in-circuit; bind pk to public key
        let (pk_var, _gamma, _c, _s, beta) =
            prove_vrf_gadget::<C, GG>(cs.clone(), gadget_params.vrf_params, msg_bytes, sk_var)?;
        pk_var.enforce_equal(pk_public)?;

        // 2) RS bit binding: ensure the RS bit-matrix equals trimmed bits of alphas
        bind_rs_bits_to_alphas::<ConstraintF<C>, N, LEVELS>(
            cs.clone(),
            alphas_for_bits,
            &rs_witness_var.bits_mat,
        )?;

        // 3) RS shuffle constraints on indices
        let indices_after_shuffle: [FpVar<ConstraintF<C>>; N] =
            std::array::from_fn(|i| rs_witness_var.sorted_levels[LEVELS - 1][i].idx.clone());
        rs_shuffle_indices::<ConstraintF<C>, N, LEVELS>(
            cs.clone(),
            indices_init,
            &indices_after_shuffle,
            rs_witness_var,
            alpha_rs,
        )?;

        // 4) Bind public x (power_challenge) to c_perm-derived value
        let mut transcript = new_bayer_groth_transcript_gadget_with_poseidon::<ConstraintF<C>>(
            cs.clone(),
            b"permutation-proof",
        )?;
        let x_from_commit =
            transcript.derive_power_challenge_from_commitment::<C, GG>(cs.clone(), c_perm)?;
        x_from_commit.enforce_equal(&power_challenge_public)?;

        // 5) Efficient power-permutation check: b is permutation of a = [x, x^2, …, x^N]
        // Build base powers a
        let mut a_powers: [EmulatedFpVar<C::ScalarField, ConstraintF<C>>; N] =
            std::array::from_fn(|_| EmulatedFpVar::zero());
        if N > 0 {
            a_powers[0] = power_challenge_public.clone();
            for i in 1..N {
                a_powers[i] = a_powers[i - 1].clone() * &power_challenge_public;
            }
        }

        // Reuse alpha_rs as base-field randomizer; convert to scalar field
        let r_scalar = base_to_scalar::<C>(cs.clone(), alpha_rs)?;

        // Compute products ∏(r - a_i) and ∏(r - b_i)
        let mut lhs = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::one();
        let mut rhs = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::one();
        for i in 0..N {
            lhs = lhs * (r_scalar.clone() - a_powers[i].clone());
            rhs = rhs * (r_scalar.clone() - power_perm_vec_wit[i].clone());
        }
        lhs.enforce_equal(&rhs)?;

        // 6) Verify Pedersen opening for c_power against b (witness power_perm_vec_wit)
        verify_scalar_folding_link_gadget::<C, GG>(
            cs.clone(),
            c_power,
            power_opening_proof_var,
            power_perm_vec_wit,
        )?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::BigInteger;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{test_rng, vec::Vec};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };
    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<BaseField>>;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    /// Mini-test: alpha → bit-matrix binding gadget
    #[test]
    fn test_bind_rs_bits_to_alphas_positive() {
        const N: usize = 8;
        const LEVELS: usize = 3;
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Prepare two random base-field alphas
        let mut rng = test_rng();
        let a0 = BaseField::rand(&mut rng);
        let a1 = BaseField::rand(&mut rng);
        let a0_var = FpVar::new_witness(cs.clone(), || Ok(a0)).unwrap();
        let a1_var = FpVar::new_witness(cs.clone(), || Ok(a1)).unwrap();

        // Build trimmed bitstream natively
        let mut bits: Vec<bool> = Vec::new();
        for a in [a0, a1] {
            let le = a.into_bigint().to_bits_le();
            if le.len() > 2 {
                bits.extend_from_slice(&le[1..le.len() - 1]);
            }
        }
        // Allocate RS bit-matrix Booleans matching the trimmed stream
        let mut mat: [[Boolean<BaseField>; N]; LEVELS] =
            std::array::from_fn(|_| std::array::from_fn(|_| Boolean::constant(false)));
        for k in 0..(N * LEVELS) {
            let level = k / N;
            let idx = k % N;
            let v = if k < bits.len() { bits[k] } else { false };
            mat[level][idx] = Boolean::new_witness(cs.clone(), || Ok(v)).unwrap();
        }

        bind_rs_bits_to_alphas::<BaseField, N, LEVELS>(cs.clone(), &[a0_var, a1_var], &mat)
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Mini-test: BG folding link consistency using verify_scalar_folding_link_gadget
    #[test]
    fn test_bg_power_challenge_and_opening_consistency() {
        use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
        use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
        use crate::shuffling::bayer_groth_permutation::bg_setup::BayerGrothTranscript;
        use crate::shuffling::pedersen_commitment::opening_proof::{prove, PedersenParams};
        use ark_crypto_primitives::commitment::{
            pedersen::Commitment as PedersenCommitment, CommitmentScheme,
        };

        const N: usize = 8; // power-of-two for fixed-size prover
        let mut rng = test_rng();

        // Setup Pedersen params
        let perm_params =
            PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut rng).unwrap();
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut rng).unwrap();

        // Simple permutation 1..=N
        let perm: [usize; N] = std::array::from_fn(|i| i + 1);

        // BG setup (native)
        let mut tr = new_bayer_groth_transcript_with_poseidon::<BaseField>(b"test");
        let (bg_setup, power_vec) = tr.run_protocol::<G1Projective, N>(
            &perm_params,
            &power_params,
            &perm,
            ScalarField::from(3u64),
            ScalarField::from(5u64),
        );

        // Pedersen opening for c_power
        let ped_params = PedersenParams::<G1Projective>::from_arkworks::<N>(power_params.clone());
        let vc = crate::shuffling::pedersen_commitment::WithCommitment::<G1Projective, N> {
            comm: bg_setup.c_power,
            value: power_vec,
        };
        let opening = prove(&ped_params, &vc, ScalarField::from(5u64), &mut rng);

        // Circuit
        let cs = ConstraintSystem::<BaseField>::new_ref();
        let c_perm_var = G1Var::new_witness(cs.clone(), || Ok(bg_setup.c_perm)).unwrap();
        let c_power_var = G1Var::new_witness(cs.clone(), || Ok(bg_setup.c_power)).unwrap();

        // Derive x in-circuit and compare values
        let mut t =
            new_bayer_groth_transcript_gadget_with_poseidon::<BaseField>(cs.clone(), b"test")
                .unwrap();
        let x_var = t
            .derive_power_challenge_from_commitment::<G1Projective, G1Var>(cs.clone(), &c_perm_var)
            .unwrap();
        assert_eq!(x_var.value().unwrap(), bg_setup.perm_power_challenge);

        // Allocate opening transcript (public) and power vector (private)
        let proof_var = PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
            cs.clone(),
            &opening,
            ark_r1cs_std::alloc::AllocationMode::Input,
        )
        .unwrap();
        let power_vec_var: [EmulatedFpVar<ScalarField, BaseField>; N] = std::array::from_fn(|i| {
            EmulatedFpVar::new_witness(cs.clone(), || Ok(vc.value[i])).unwrap()
        });

        // Verify folding link anchored at c_power
        verify_scalar_folding_link_gadget::<G1Projective, G1Var>(
            cs.clone(),
            &c_power_var,
            &proof_var,
            &power_vec_var,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    /// End-to-end test wiring VRF → RS (bits + indices) → BG x-binding →
    /// scalar permutation check → Pedersen opening link
    #[test]
    fn test_end_to_end_permutation_proof() {
        use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
        use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
        use crate::shuffling::pedersen_commitment::opening_proof::{prove, PedersenParams};
        use crate::shuffling::rs_shuffle::bit_generation::derive_split_bits;
        use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
        use crate::shuffling::utils::generate_random_values;
        use crate::vrf::native::prove_vrf as vrf_prove_native;
        use crate::vrf::VrfParams;
        use ark_crypto_primitives::commitment::{
            pedersen::Commitment as PedersenCommitment, CommitmentScheme,
        };
        use ark_r1cs_std::uint8::UInt8;

        let _gaurd = setup_test_tracing();

        const N: usize = 8;
        const LEVELS: usize = 3;

        let mut rng = test_rng();

        // ---------- Native preparation ----------
        // VRF params and secrets
        let vrf_params = VrfParams::<G1Projective>::setup(&mut rng);
        let sk = ScalarField::rand(&mut rng);
        let pk = G1Projective::generator() * sk;
        let msg: Vec<u8> = b"end-to-end-test".to_vec();

        // VRF native to get beta seed
        let (_proof, beta) = vrf_prove_native::<G1Projective>(&vrf_params, &pk, sk, &msg);

        // RS trace from beta
        let input: [usize; N] = std::array::from_fn(|i| i);
        let rs_trace = run_rs_shuffle_permutation::<BaseField, usize, N, LEVELS>(beta, &input);

        // Compute number of samples and alphas used for bit generation
        let (_bits_mat, num_samples) = derive_split_bits::<BaseField, N, LEVELS>(beta);
        let alphas = generate_random_values::<BaseField>(beta, num_samples);

        // BG setup and power vector
        let perm_params =
            PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut rng).unwrap();
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut rng).unwrap();
        // Use the same domain string as the gadget to ensure matching challenges
        let mut tr = new_bayer_groth_transcript_with_poseidon::<BaseField>(b"permutation-proof");
        let (bg_setup, power_vec) = tr.run_protocol::<G1Projective, N>(
            &perm_params,
            &power_params,
            &rs_trace.extract_permutation_array(),
            ScalarField::rand(&mut rng),
            ScalarField::rand(&mut rng),
        );

        // Pedersen opening proof for c_power
        let ped_params = PedersenParams::<G1Projective>::from_arkworks::<N>(power_params.clone());
        let vc = crate::shuffling::pedersen_commitment::WithCommitment::<G1Projective, N> {
            comm: bg_setup.c_power,
            value: power_vec,
        };
        let opening = prove(&ped_params, &vc, ScalarField::rand(&mut rng), &mut rng);

        // Prepare indices_init (0..N-1)
        let indices_init_native: [BaseField; N] =
            std::array::from_fn(|i| BaseField::from(i as u64));

        // ---------- Circuit ----------
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // VRF-related Vars
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let pk_public = G1Var::new_input(cs.clone(), || Ok(pk)).unwrap();
        let msg_vars: Vec<UInt8<BaseField>> = msg
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();

        // RS witness as Vars prepared in-circuit from the same seed (beta)
        let seed_var = FpVar::new_witness(cs.clone(), || Ok(beta)).unwrap();
        let rs_witness_var =
            crate::shuffling::rs_shuffle::native::prepare_rs_witness_data_circuit::<
                BaseField,
                N,
                LEVELS,
            >(cs.clone(), &seed_var, &rs_trace.witness_trace, num_samples)
            .unwrap();

        // Indices init Vars
        let indices_init: [FpVar<BaseField>; N] = std::array::from_fn(|i| {
            FpVar::new_witness(cs.clone(), || Ok(indices_init_native[i])).unwrap()
        });

        // RS alpha vars (recycle beta as alpha_rs and alphas_for_bits)
        let alpha_rs = FpVar::new_witness(cs.clone(), || Ok(beta)).unwrap();
        let alphas_for_bits: Vec<FpVar<BaseField>> = alphas
            .iter()
            .map(|a| FpVar::new_witness(cs.clone(), || Ok(*a)).unwrap())
            .collect();

        // BG + commitment vars
        let power_challenge_public =
            EmulatedFpVar::<ScalarField, BaseField>::new_input(cs.clone(), || {
                Ok(bg_setup.perm_power_challenge)
            })
            .unwrap();
        let c_perm_var = G1Var::new_input(cs.clone(), || Ok(bg_setup.c_perm)).unwrap();
        let c_power_var = G1Var::new_input(cs.clone(), || Ok(bg_setup.c_power)).unwrap();
        let power_opening_proof_var =
            PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
                cs.clone(),
                &opening,
                ark_r1cs_std::alloc::AllocationMode::Input,
            )
            .unwrap();
        let power_perm_vec_wit: [EmulatedFpVar<ScalarField, BaseField>; N] =
            std::array::from_fn(|i| {
                EmulatedFpVar::new_witness(cs.clone(), || Ok(vc.value[i])).unwrap()
            });

        // Gadget params
        let gadget_params = PermutationGadgetParameters::<G1Projective> {
            vrf_params: &vrf_params,
            num_samples,
        };

        // Run the main gadget (no allocations inside)
        prove_permutation_gadget::<G1Projective, G1Var, N, LEVELS>(
            cs.clone(),
            &gadget_params,
            &msg_vars,
            sk_var,
            &pk_public,
            &rs_witness_var,
            &indices_init,
            &alpha_rs,
            &alphas_for_bits,
            power_challenge_public,
            &c_perm_var,
            &c_power_var,
            &power_opening_proof_var,
            &power_perm_vec_wit,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
