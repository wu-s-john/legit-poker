use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::{
    emulated_fp::EmulatedFpVar,
    fp::FpVar,
};
use ark_r1cs_std::groups::CurveVar;
use ark_std::marker::PhantomData;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::config::poseidon_config;
use crate::shuffling::pedersen_commitment::opening_proof_gadget::PedersenCommitmentOpeningProofVar;
use crate::shuffling::permutation_proof::prove_permutation_gadget;
use crate::shuffling::rs_shuffle::data_structures::{
    PermutationWitnessTrace, PermutationWitnessTraceVar,
};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField;

/// RS permutation proof circuit that ties together:
/// - VRF-derived randomness (nonce, sk, pk) → RS bit matrix binding
/// - BG power challenge derived from `c_perm` equals `power_challenge_public`
/// - Pedersen opening proof linking `c_power` to the scalar vector b = [x^π(i)]
#[derive(Clone)]
pub struct PermutationProofCircuit<C, GG, const N: usize, const LEVELS: usize>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            ConstraintF<C>,
            PoseidonSpongeVar<ConstraintF<C>>,
        >,
{
    // Parameters
    pub num_samples: usize,

    // Public data
    pub nonce: Option<ConstraintF<C>>,                 // base field
    pub pk_public: Option<C>,                          // curve point
    pub indices_init: Option<[ConstraintF<C>; N]>,     // base field array
    pub alpha_rs: Option<ConstraintF<C>>,              // base field
    pub power_challenge_public: Option<ConstraintF<C>>,// base field
    pub c_perm: Option<C>,                             // curve point
    pub c_power: Option<C>,                            // curve point
    pub power_opening_proof: Option<
        crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof<C>,
    >,

    // Private witnesses
    pub sk: Option<C::ScalarField>,
    pub rs_witness: Option<PermutationWitnessTrace<N, LEVELS>>,
    pub power_perm_vec_wit: Option<[ConstraintF<C>; N]>,
    pub power_perm_vec_scalar_wit: Option<[C::ScalarField; N]>,
    pub(crate) _pd: PhantomData<GG>,
}

impl<C, GG, const N: usize, const LEVELS: usize> PermutationProofCircuit<C, GG, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            ConstraintF<C>,
            PoseidonSpongeVar<ConstraintF<C>>,
        >,
{
    /// Construct a blank circuit with zero/identity public inputs and no witnesses.
    pub fn blank(num_samples: usize) -> Self {
        // Helper defaults
        let zero_f = ConstraintF::<C>::from(0u64);
        let zero_g = C::zero();

        Self {
            num_samples,
            nonce: Some(zero_f),
            pk_public: Some(zero_g),
            indices_init: Some(std::array::from_fn(|_| zero_f)),
            alpha_rs: Some(zero_f),
            power_challenge_public: Some(zero_f),
            c_perm: Some(zero_g),
            c_power: Some(zero_g),
            power_opening_proof: Some(
                crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof {
                    folding_challenge_commitment_rounds: Vec::new(),
                    a_final: C::ScalarField::from(0u64),
                    r_final: C::ScalarField::from(0u64),
                },
            ),
            sk: None,
            rs_witness: None,
            power_perm_vec_wit: None,
            power_perm_vec_scalar_wit: None,
            _pd: PhantomData,
        }
    }
}

impl<C, GG, const N: usize, const LEVELS: usize> ConstraintSynthesizer<ConstraintF<C>>
    for PermutationProofCircuit<C, GG, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField + Absorb,
    ConstraintF<C>: PrimeField + Absorb,
    GG: CurveVar<C, ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorbGadget<
            ConstraintF<C>,
            PoseidonSpongeVar<ConstraintF<C>>,
        >,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    for<'a> &'a GG: crate::shuffling::curve_absorb::CurveAbsorbGadget<
        ConstraintF<C>,
        PoseidonSpongeVar<ConstraintF<C>>,
    >,
{
    #[tracing::instrument(skip_all, target = "r1cs")]
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF<C>>) -> Result<(), SynthesisError> {
        // 1) Instantiate the sponge used by the VRF gadget
        let sponge_cfg = poseidon_config::<ConstraintF<C>>();
        let mut sponge_var = PoseidonSpongeVar::<ConstraintF<C>>::new(cs.clone(), &sponge_cfg);

        // 2) Allocate public inputs in a fixed order
        let pk_public_val = self.pk_public.ok_or(SynthesisError::AssignmentMissing)?;
        let pk_public = GG::new_input(cs.clone(), || Ok(pk_public_val))?;

        let nonce_val = self.nonce.ok_or(SynthesisError::AssignmentMissing)?;
        let nonce = FpVar::<ConstraintF<C>>::new_input(cs.clone(), || Ok(nonce_val))?;

        let indices_init_vals = self.indices_init.ok_or(SynthesisError::AssignmentMissing)?;
        let indices_init: [FpVar<ConstraintF<C>>; N] = std::array::from_fn(|i| {
            FpVar::new_input(cs.clone(), || Ok(indices_init_vals[i]))
                .expect("indices_init input alloc")
        });

        let alpha_rs_val = self.alpha_rs.ok_or(SynthesisError::AssignmentMissing)?;
        let alpha_rs = FpVar::<ConstraintF<C>>::new_input(cs.clone(), || Ok(alpha_rs_val))?;

        let power_challenge_val =
            self.power_challenge_public.ok_or(SynthesisError::AssignmentMissing)?;
        let power_challenge_public =
            FpVar::<ConstraintF<C>>::new_input(cs.clone(), || Ok(power_challenge_val))?;

        let c_perm_val = self.c_perm.ok_or(SynthesisError::AssignmentMissing)?;
        let c_perm = GG::new_input(cs.clone(), || Ok(c_perm_val))?;

        let c_power_val = self.c_power.ok_or(SynthesisError::AssignmentMissing)?;
        let c_power = GG::new_input(cs.clone(), || Ok(c_power_val))?;

        let opening_native = self
            .power_opening_proof
            .ok_or(SynthesisError::AssignmentMissing)?;
        let power_opening_proof_var =
            PedersenCommitmentOpeningProofVar::<C, GG>::new_variable(
                cs.clone(),
                &opening_native,
                ark_r1cs_std::alloc::AllocationMode::Input,
            )?;

        // 3) Allocate witnesses
        let sk_val = self.sk.ok_or(SynthesisError::AssignmentMissing)?;
        let sk_var = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::new_witness(
            cs.clone(),
            || Ok(sk_val),
        )?;

        let rs_witness_native = self
            .rs_witness
            .ok_or(SynthesisError::AssignmentMissing)?;
        let rs_witness_var =
            PermutationWitnessTraceVar::<ConstraintF<C>, N, LEVELS>::new_variable(
                cs.clone(),
                || Ok(&rs_witness_native),
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )?;

        let power_perm_vec_vals = self
            .power_perm_vec_wit
            .ok_or(SynthesisError::AssignmentMissing)?;
        let power_perm_vec_wit: [FpVar<ConstraintF<C>>; N] = std::array::from_fn(|i| {
            FpVar::<ConstraintF<C>>::new_witness(cs.clone(), || Ok(power_perm_vec_vals[i]))
                .expect("power_perm_vec_wit alloc")
        });

        let power_perm_vec_scalar_vals = self
            .power_perm_vec_scalar_wit
            .ok_or(SynthesisError::AssignmentMissing)?;
        let power_perm_vec_scalar_wit: [
            EmulatedFpVar<C::ScalarField, ConstraintF<C>>;
            N
        ] = std::array::from_fn(|i| {
            EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::new_witness(
                cs.clone(),
                || Ok(power_perm_vec_scalar_vals[i]),
            )
            .expect("power_perm_vec_scalar_wit alloc")
        });

        // 4) Invoke the gadget to emit constraints
        prove_permutation_gadget::<
            C,
            GG,
            PoseidonSponge<ConstraintF<C>>,
            PoseidonSpongeVar<ConstraintF<C>>,
            N,
            LEVELS,
        >(
            cs,
            &mut sponge_var,
            &nonce,
            sk_var,
            &pk_public,
            &rs_witness_var,
            &indices_init,
            &alpha_rs,
            self.num_samples,
            &power_challenge_public,
            &c_perm,
            &c_power,
            &power_opening_proof_var,
            &power_perm_vec_wit,
            &power_perm_vec_scalar_wit,
        )
    }
}
