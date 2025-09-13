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

use crate::shuffling::bayer_groth_permutation::bg_setup::BGPowerChallengeSetup;
use crate::shuffling::curve_absorb::{CurveAbsorb, CurveAbsorbGadget};
use crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof;
use crate::vrf::simple::prove_simple_vrf;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
// use ark_crypto_primitives::sponge::poseidon::PoseidonSponge; // used in tests
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::{emulated_fp::EmulatedFpVar, fp::FpVar};
use ark_r1cs_std::groups::CurveVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError}; // trait bound needed by BG and opening

use crate::shuffling::bayer_groth_permutation::bg_setup_gadget::new_bayer_groth_transcript_gadget_with_poseidon;
use crate::shuffling::pedersen_commitment::opening_proof_gadget::{
    verify_scalar_folding_link_gadget, PedersenCommitmentOpeningProofVar,
};
use crate::shuffling::rs_shuffle::data_structures::{PermutationWitnessTraceVar, RSShuffleTrace};
use crate::shuffling::rs_shuffle::permutation::{check_grand_product, IndexPositionPair};
use crate::shuffling::rs_shuffle::rs_shuffle_gadget::rs_shuffle_indices;
use crate::track_constraints;
use crate::vrf::simple_gadgets::prove_simple_vrf_gadget;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField;

const LOG_TARGET: &str = "nexus_nova::shuffling::permutation_proof";

// Submodules providing the circuit wrapper and Groth16 proof system
pub mod circuit;
pub mod proof_system;

// Re-exports for ergonomic access to the proof system API
pub use proof_system::{build_public_inputs, PermutationGroth16, PublicData, WitnessData};

/// Native (prover-side) configuration parameters for preparing permutation witnesses
pub struct PermutationParameters<'a, C: CurveGroup, R: rand::RngCore> {
    pub perm_params: &'a ark_crypto_primitives::commitment::pedersen::Parameters<C>, // DeckHashWindow
    pub power_params: &'a ark_crypto_primitives::commitment::pedersen::Parameters<C>, // ReencryptionWindow
    pub rng: &'a mut R,
}

/// In-circuit parameters for the permutation proof gadgets
// Removed PermutationGadgetParameters; its fields are now inlined into function parameters

/// Prepared witnesses from the native prover for driving the permutation gadget
pub struct PreparedPermutationWitness<C: CurveGroup, const N: usize, const LEVELS: usize>
where
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    pub pk: C,
    pub vrf_value: C::BaseField,
    pub rs_trace: RSShuffleTrace<usize, N, LEVELS>,
    pub indices_init: [C::BaseField; N],
    pub permutation_vec: [C::ScalarField; N],
    pub bg_setup: BGPowerChallengeSetup<C::BaseField, C::ScalarField, C>,
    pub perm_power_vector_base: [C::BaseField; N], // Base field version for circuit verification
    pub perm_power_vector_scalar: [C::ScalarField; N], // Scalar field version for Pedersen opening
    pub power_opening_proof: PedersenCommitmentOpeningProof<C>,
    pub blinding_r: C::ScalarField,
    pub blinding_s: C::ScalarField,
}

/// Convenience builder to construct (PublicData, WitnessData) from a prepared bundle
/// and explicit VRF inputs (nonce, secret key).
pub fn construct_perm_io<C, const N: usize, const LEVELS: usize>(
    vrf_nonce: ConstraintF<C>,
    vrf_sk: C::ScalarField,
    prepared: &PreparedPermutationWitness<C, N, LEVELS>,
) -> (PublicData<C, N>, WitnessData<C, N, LEVELS>)
where
    C: CurveGroup,
    C::BaseField: PrimeField,
{
    let public = PublicData::<C, N> {
        nonce: vrf_nonce,
        pk_public: prepared.pk,
        indices_init: prepared.indices_init.map(|x| x.into()),
        power_challenge_public: prepared.bg_setup.power_challenge_base.into(),
        c_perm: prepared.bg_setup.permutation_commitment,
        c_power: prepared.bg_setup.power_permutation_commitment,
        power_opening_proof: prepared.power_opening_proof.clone(),
    };

    let witness = WitnessData::<C, N, LEVELS> {
        sk: vrf_sk,
        rs_witness: prepared.rs_trace.witness_trace.clone(),
        power_perm_vec_wit: prepared.perm_power_vector_base.map(|x| x.into()),
        power_perm_vec_scalar_wit: prepared.perm_power_vector_scalar,
    };

    (public, witness)
}

/// Prepare permutation-related witnesses natively (off-circuit)
///
/// Note: This function is scaffolded for completeness. It wires the existing native
/// utilities to produce the objects that the circuit expects, but it is not used by
/// the circuit gadgets directly.
pub fn prepare_witness<C, R, RO, const N: usize, const LEVELS: usize>(
    params: &mut PermutationParameters<'_, C, R>,
    nonce: C::BaseField,
    sk: C::ScalarField,
    sponge: &mut RO,
) -> anyhow::Result<PreparedPermutationWitness<C, N, LEVELS>>
where
    C: CurveGroup + CurveAbsorb<C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField + Absorb,
    R: rand::RngCore,
    RO: CryptographicSponge,
{
    use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
    use crate::shuffling::pedersen_commitment::opening_proof::{prove, PedersenParams};
    use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
    use ark_std::vec::Vec;

    // 1) Simple VRF native prove to obtain vrf_value and pk
    let g = C::generator();
    let pk = g * sk;
    // Use the provided random oracle sponge
    let vrf_value = prove_simple_vrf::<C, _>(sponge, &nonce, &sk, &pk);

    // 2) RS shuffle witnesses using vrf_value as seed
    let input: [usize; N] = std::array::from_fn(|i| i);
    let rs_trace = run_rs_shuffle_permutation::<C::BaseField, usize, N, LEVELS>(vrf_value, &input);

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
    let (perm_power_vector_base, perm_power_vector_scalar, bg_power_challenge_setup) = transcript
        .compute_power_challenge_setup::<C, N>(
            params.perm_params,
            params.power_params,
            &rs_trace.extract_permutation_array(),
            blinding_r,
            blinding_s,
        );

    // 4) Pedersen opening proof for c_power (fixed N)
    let ped_params = PedersenParams::<C>::from_arkworks::<N>(params.power_params.clone());
    let vc = crate::shuffling::pedersen_commitment::WithCommitment::<C, N> {
        comm: bg_power_challenge_setup.power_permutation_commitment,
        value: perm_power_vector_scalar,
    };
    let opening = prove(&ped_params, &vc, blinding_s, params.rng);

    // 5) Indices init (0..N-1) in base field
    let indices_init = std::array::from_fn(|i| C::BaseField::from(i as u64));

    Ok(PreparedPermutationWitness {
        pk,
        vrf_value,
        rs_trace,
        indices_init,
        permutation_vec,
        bg_setup: bg_power_challenge_setup,
        perm_power_vector_base,
        perm_power_vector_scalar,
        power_opening_proof: opening,
        blinding_r,
        blinding_s,
    })
}

/// Main permutation gadget: emits constraints tying VRF→RS→BG and Pedersen opening together.
#[allow(clippy::too_many_arguments)]
pub fn prove_permutation_gadget<C, GG, RO, ROVar, const N: usize, const LEVELS: usize>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    sponge: &mut ROVar,
    // VRF
    nonce: &FpVar<ConstraintF<C>>,
    sk_var: EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
    pk_public: &GG,
    // RS (pre-allocated)
    rs_witness_var: &PermutationWitnessTraceVar<ConstraintF<C>, N, LEVELS>,
    indices_init: &[FpVar<ConstraintF<C>>; N],
    // alpha/beta are derived in-circuit from a Poseidon transcript bound to public inputs
    num_samples: usize,               // number of base-field elements used to derive RS bits
    // BG + opening
    power_challenge_public: &FpVar<ConstraintF<C>>, // x in base field
    c_perm: &GG,
    c_power: &GG,
    power_opening_proof_var: &PedersenCommitmentOpeningProofVar<C, GG>,
    // Witness b = [x^π(i)] in base field for efficient verification
    power_perm_vec_wit: &[FpVar<ConstraintF<C>>; N],
    // Witness b_scalar = [x^π(i)] in scalar field for Pedersen opening
    power_perm_vec_scalar_wit: &[EmulatedFpVar<C::ScalarField, ConstraintF<C>>; N],
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    ConstraintF<C>: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    for<'a> &'a GG: CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    RO: CryptographicSponge,
    ROVar: CryptographicSpongeVar<ConstraintF<C>, RO>,
{
    track_constraints!(&cs, "prove_permutation_gadget", LOG_TARGET, {
        // 1) Simple VRF gadget in-circuit to derive vrf_value from (nonce, sk)
        let vrf_value =
            prove_simple_vrf_gadget::<C, GG, RO, ROVar>(sponge, nonce, &sk_var, pk_public)?;

        // 2) RS bit binding: derive the RS bit-matrix from vrf_value and enforce equality
        let derived_bits = crate::shuffling::rs_shuffle::bit_generation::derive_split_bits_gadget::<
            ConstraintF<C>,
            N,
            LEVELS,
        >(cs.clone(), &vrf_value, num_samples)?;
        for level in 0..LEVELS {
            for i in 0..N {
                rs_witness_var.bits_mat[level][i].enforce_equal(&derived_bits[level][i])?;
            }
        }

        // 3) Derive alpha and beta from a fresh Poseidon sponge bound to public inputs
        let sponge_cfg = crate::config::poseidon_config::<ConstraintF<C>>();
        let mut chall_sponge = PoseidonSpongeVar::<ConstraintF<C>>::new(cs.clone(), &sponge_cfg);
        // Optional domain separation tag
        // Absorb public inputs in the specified order
        pk_public.curve_absorb_gadget(&mut chall_sponge)?;               // curve
        chall_sponge.absorb(nonce)?;                   // Fp
        chall_sponge.absorb(power_challenge_public)?;  // Fp
        c_perm.curve_absorb_gadget(&mut chall_sponge)?;                  // curve
        c_power.curve_absorb_gadget(&mut chall_sponge)?;                 // curve
        // Squeeze one element for alpha, set beta = alpha^2
        let alpha = chall_sponge.squeeze_field_elements(1)?[0].clone();
        let beta = &alpha * &alpha;

        // 4) RS shuffle constraints on indices
        let indices_after_shuffle: [FpVar<ConstraintF<C>>; N] =
            std::array::from_fn(|i| rs_witness_var.sorted_levels[LEVELS - 1][i].idx.clone());
        rs_shuffle_indices::<ConstraintF<C>, N, LEVELS>(
            cs.clone(),
            indices_init,
            &indices_after_shuffle,
            rs_witness_var,
            &alpha,
            &beta,
        )?;

        // 5) Bind public x (power_challenge) to c_perm-derived value
        let mut transcript = new_bayer_groth_transcript_gadget_with_poseidon::<ConstraintF<C>>(
            cs.clone(),
            b"permutation-proof",
        )?;
        let x_from_commit = transcript
            .derive_power_challenge_from_commitment_base_field::<C, GG>(cs.clone(), c_perm)?;
        x_from_commit.enforce_equal(power_challenge_public)?;

        // 5) Efficient power-permutation check via paired multiset equality.
        // Build base powers a = [x, x^2, ..., x^N] efficiently in base field
        let a_powers: Vec<FpVar<ConstraintF<C>>> = {
            let mut powers = Vec::with_capacity(N);
            if N > 0 {
                let mut current = power_challenge_public.clone();
                powers.push(current.clone());
                for _ in 1..N {
                    current *= power_challenge_public;
                    powers.push(current.clone());
                }
            }
            powers
        };

        // Construct pair lists: left = [(i, x^(i+1))], right = [(π[i], b_i)]
        let left_pairs: Vec<IndexPositionPair<ConstraintF<C>>> = (0..N)
            .map(|i| IndexPositionPair::new(indices_init[i].clone(), a_powers[i].clone()))
            .collect();
        let right_pairs: Vec<IndexPositionPair<ConstraintF<C>>> = (0..N)
            .map(|i| IndexPositionPair::new(indices_after_shuffle[i].clone(), power_perm_vec_wit[i].clone()))
            .collect();

        // Derive challenges for pair encoding by absorbing alpha into the sponge
        // and squeezing three base-field elements: [rho, alpha1, alpha2]
        chall_sponge.absorb(&alpha)?;
        let chals = chall_sponge.squeeze_field_elements(3)?;
        let rho = chals[0].clone();
        let alpha1 = chals[1].clone();
        let alpha2 = chals[2].clone();

        // Check multiset equality of associated pairs using 3-challenge product argument
        check_grand_product::<ConstraintF<C>, IndexPositionPair<ConstraintF<C>>, 3>(
            cs.clone(),
            &left_pairs,
            &right_pairs,
            &[rho, alpha1, alpha2],
        )?;

        // 6) Verify Pedersen opening for c_power against b_scalar (witness power_perm_vec_scalar_wit)
        verify_scalar_folding_link_gadget::<C, GG>(
            cs.clone(),
            c_power,
            power_opening_proof_var,
            power_perm_vec_scalar_wit,
        )?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq as BaseField, Fr as ScalarField, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
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

    // Removed obsolete alpha → bit-matrix binding test

    /// Mini-test: BG folding link consistency using verify_scalar_folding_link_gadget
    #[test]
    fn test_bg_power_challenge_and_opening_consistency() {
    use crate::pedersen_commitment::bytes_opening::{DeckHashWindow, ReencryptionWindow};
        use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
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
        use crate::pedersen_commitment::bytes_opening::{DeckHashWindow, ReencryptionWindow};
        use crate::shuffling::bayer_groth_permutation::bg_setup::new_bayer_groth_transcript_with_poseidon;
        use crate::shuffling::pedersen_commitment::opening_proof::{prove, PedersenParams};
        use crate::shuffling::rs_shuffle::bit_generation::derive_split_bits;
        use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
        use crate::vrf::simple::prove_simple_vrf;
        use ark_crypto_primitives::commitment::{
            pedersen::Commitment as PedersenCommitment, CommitmentScheme,
        };
        use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;

        let _gaurd = setup_test_tracing();

        const N: usize = 8;
        const LEVELS: usize = 3;

        let mut rng = test_rng();

        // ---------- Native preparation ----------
        // Secrets
        let sk = ScalarField::rand(&mut rng);
        let pk = G1Projective::generator() * sk;
        let nonce: BaseField = BaseField::rand(&mut rng);
        // Simple VRF native to get vrf_value (seed)
        let mut sponge_native =
            PoseidonSponge::<BaseField>::new(&crate::config::poseidon_config::<BaseField>());
        let vrf_value = prove_simple_vrf::<G1Projective, _>(&mut sponge_native, &nonce, &sk, &pk);

        // RS trace from vrf_value
        let input: [usize; N] = std::array::from_fn(|i| i);
        let rs_trace = run_rs_shuffle_permutation::<BaseField, usize, N, LEVELS>(vrf_value, &input);

        // Compute number of samples used for bit generation
        let (_bits_mat, num_samples) = derive_split_bits::<BaseField, N, LEVELS>(vrf_value);

        // BG setup and power vector
        let perm_params =
            PedersenCommitment::<G1Projective, DeckHashWindow>::setup(&mut rng).unwrap();
        let power_params =
            PedersenCommitment::<G1Projective, ReencryptionWindow>::setup(&mut rng).unwrap();
        // Use the same domain string as the gadget to ensure matching challenges
        let mut tr = new_bayer_groth_transcript_with_poseidon::<BaseField>(b"permutation-proof");
        let blinding_r = ScalarField::rand(&mut rng);
        let blinding_s = ScalarField::rand(&mut rng);
        let (power_vec_base, power_vec_scalar, bg_setup) = tr
            .compute_power_challenge_setup::<G1Projective, N>(
                &perm_params,
                &power_params,
                &rs_trace.extract_permutation_array(),
                blinding_r,
                blinding_s,
            );

        // Pedersen opening proof for c_power
        let ped_params = PedersenParams::<G1Projective>::from_arkworks::<N>(power_params.clone());
        let vc = crate::shuffling::pedersen_commitment::WithCommitment::<G1Projective, N> {
            comm: bg_setup.power_permutation_commitment,
            value: power_vec_scalar,
        };
        let opening = prove(&ped_params, &vc, blinding_s, &mut rng);

        // Prepare indices_init (0..N-1)
        let indices_init_native: [BaseField; N] =
            std::array::from_fn(|i| BaseField::from(i as u64));

        // ---------- Circuit ----------
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // VRF-related Vars
        let sk_var =
            EmulatedFpVar::<ScalarField, BaseField>::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let pk_public = G1Var::new_input(cs.clone(), || Ok(pk)).unwrap();
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();

        // RS witness as Vars prepared in-circuit from the same seed (vrf_value)
        let seed_var = FpVar::new_witness(cs.clone(), || Ok(vrf_value)).unwrap();
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

        // BG + commitment vars
        let power_challenge_public =
            FpVar::<BaseField>::new_input(cs.clone(), || Ok(bg_setup.power_challenge_base))
                .unwrap();
        let c_perm_var =
            G1Var::new_input(cs.clone(), || Ok(bg_setup.permutation_commitment)).unwrap();
        let c_power_var =
            G1Var::new_input(cs.clone(), || Ok(bg_setup.power_permutation_commitment)).unwrap();
        let power_opening_proof_var =
            PedersenCommitmentOpeningProofVar::<G1Projective, G1Var>::new_variable(
                cs.clone(),
                &opening,
                ark_r1cs_std::alloc::AllocationMode::Input,
            )
            .unwrap();
        // Base field power vector for efficient circuit verification
        let power_perm_vec_wit: [FpVar<BaseField>; N] = std::array::from_fn(|i| {
            FpVar::new_witness(cs.clone(), || Ok(power_vec_base[i])).unwrap()
        });
        // Scalar field power vector for Pedersen opening
        let power_perm_vec_scalar_wit: [EmulatedFpVar<ScalarField, BaseField>; N] =
            std::array::from_fn(|i| {
                EmulatedFpVar::new_witness(cs.clone(), || Ok(vc.value[i])).unwrap()
            });

        // Gadget params
        let sponge_config = crate::config::poseidon_config::<BaseField>();
        // Shared transcript/sponge for VRF (tests use Poseidon)
        let mut sponge_var = PoseidonSpongeVar::<BaseField>::new(cs.clone(), &sponge_config);

        // Run the main gadget (no allocations inside)
        prove_permutation_gadget::<
            G1Projective,
            G1Var,
            PoseidonSponge<BaseField>,
            PoseidonSpongeVar<BaseField>,
            N,
            LEVELS,
        >(
            cs.clone(),
            &mut sponge_var,
            &nonce_var,
            sk_var,
            &pk_public,
            &rs_witness_var,
            &indices_init,
            num_samples,
            &power_challenge_public,
            &c_perm_var,
            &c_power_var,
            &power_opening_proof_var,
            &power_perm_vec_wit,
            &power_perm_vec_scalar_wit,
        )
        .unwrap();

        if !cs.is_satisfied().unwrap() {
            let unsatisfied = cs.which_is_unsatisfied().unwrap();
            if let Some(msg) = unsatisfied {
                panic!("unsatisfied constraint: {}", msg);
            } else {
                panic!("constraint not satisfied but no specific constraint returned");
            }
        }
    }
}
