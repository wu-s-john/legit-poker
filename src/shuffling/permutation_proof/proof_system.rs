use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::fields::emulated_fp::{params::OptimizationType, AllocatedEmulatedFpVar};
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_snark::SNARK;
use ark_std::{marker::PhantomData, rand::RngCore, vec::Vec};
use rand::SeedableRng;

use super::circuit::PermutationProofCircuit;
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::pedersen_commitment::opening_proof::PedersenCommitmentOpeningProof;
use crate::shuffling::rs_shuffle::data_structures::PermutationWitnessTrace;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Public data for the permutation proof circuit
pub struct PublicData<C: CurveGroup, const N: usize>
where
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    pub nonce: ConstraintF<C>,
    pub pk_public: C,
    pub indices_init: [ConstraintF<C>; N],
    pub alpha_rs: ConstraintF<C>,
    pub power_challenge_public: ConstraintF<C>, // x
    pub c_perm: C,
    pub c_power: C,
    pub power_opening_proof: PedersenCommitmentOpeningProof<C>,
}

/// Private witness data for the permutation proof circuit
pub struct WitnessData<C: CurveGroup, const N: usize, const LEVELS: usize>
where
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
{
    pub sk: C::ScalarField,
    pub rs_witness: PermutationWitnessTrace<N, LEVELS>,
    pub power_perm_vec_wit: [ConstraintF<C>; N],
    pub power_perm_vec_scalar_wit: [C::ScalarField; N],
}

/// Groth16 wrapper for the permutation proof circuit
pub struct PermutationGroth16<E, C, GG, const N: usize, const LEVELS: usize>
where
    E: Pairing<ScalarField = ConstraintF<C>>,
    C: CurveGroup
        + ToConstraintField<ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorb<ConstraintF<C>>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    for<'a> &'a GG: CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    // Ensure circuit field matches pairing scalar field
    E::ScalarField: PrimeField + Absorb,
    C::ScalarField: Absorb,
{
    pk: ProvingKey<E>,
    pvk: PreparedVerifyingKey<E>,
    _pd: PhantomData<(C, GG)>,
}

impl<E, C, GG, const N: usize, const LEVELS: usize> PermutationGroth16<E, C, GG, N, LEVELS>
where
    E: Pairing<ScalarField = ConstraintF<C>>,
    C: CurveGroup
        + ToConstraintField<ConstraintF<C>>
        + crate::shuffling::curve_absorb::CurveAbsorb<ConstraintF<C>>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>
        + CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    for<'a> &'a GG: CurveAbsorbGadget<ConstraintF<C>, PoseidonSpongeVar<ConstraintF<C>>>,
    E::ScalarField: PrimeField + Absorb,
    C::ScalarField: Absorb,
{
    /// Setup the Groth16 proving and verifying keys for the circuit
    pub fn setup(
        rng: &mut (impl RngCore + rand::CryptoRng),
        num_samples: usize,
    ) -> anyhow::Result<Self> {
        // Build a concrete dummy circuit with consistent public inputs and witnesses
        // using the same flow as native preparation to avoid AssignmentMissing during setup.
        use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};
        use crate::shuffling::permutation_proof::{prepare_witness, PermutationParameters};
        use ark_crypto_primitives::commitment::{
            pedersen::Commitment as PedersenCommitment, CommitmentScheme,
        };
        use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
        use ark_std::UniformRand;

        // Deterministic small setup for params and secrets
        let mut local_rng = rand::rngs::StdRng::seed_from_u64(42);
        let perm_params = PedersenCommitment::<C, DeckHashWindow>::setup(&mut local_rng)
            .map_err(|e| anyhow::anyhow!("pedersen deck params setup: {e}"))?;
        let power_params = PedersenCommitment::<C, ReencryptionWindow>::setup(&mut local_rng)
            .map_err(|e| anyhow::anyhow!("pedersen reencryption params setup: {e}"))?;

        // Prover secrets and nonce
        let sk = C::ScalarField::rand(&mut local_rng);
        let nonce: ConstraintF<C> = ConstraintF::<C>::rand(&mut local_rng);
        let mut sponge = PoseidonSponge::<ConstraintF<C>>::new(&crate::config::poseidon_config::<
            ConstraintF<C>,
        >());

        // Prepare witnesses off-circuit
        let mut prep = PermutationParameters::<C, _> {
            perm_params: &perm_params,
            power_params: &power_params,
            rng: &mut local_rng,
        };
        let prepared = prepare_witness::<C, _, _, N, LEVELS>(&mut prep, nonce, sk, &mut sponge)?;

        // Construct a circuit instance
        let circ = PermutationProofCircuit::<C, GG, N, LEVELS> {
            num_samples,
            // Public
            nonce: Some(nonce),
            pk_public: Some(prepared.pk),
            indices_init: Some(prepared.indices_init),
            alpha_rs: Some(prepared.vrf_value),
            power_challenge_public: Some(prepared.bg_setup.power_challenge_base),
            c_perm: Some(prepared.bg_setup.permutation_commitment),
            c_power: Some(prepared.bg_setup.power_permutation_commitment),
            power_opening_proof: Some(prepared.power_opening_proof.clone()),
            // Witness
            sk: Some(sk),
            rs_witness: Some(prepared.rs_trace.witness_trace.clone()),
            power_perm_vec_wit: Some(prepared.perm_power_vector_base),
            power_perm_vec_scalar_wit: Some(prepared.perm_power_vector_scalar),
            _pd: PhantomData,
        };

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(circ, rng)?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self {
            pk,
            pvk,
            _pd: PhantomData,
        })
    }

    /// Create the Groth16 proof and return the proof along with the serialized public inputs
    pub fn prove(
        &self,
        rng: &mut (impl RngCore + rand::CryptoRng),
        public: &PublicData<C, N>,
        witness: &WitnessData<C, N, LEVELS>,
        num_samples: usize,
    ) -> anyhow::Result<(Proof<E>, Vec<E::ScalarField>)> {
        // Build the circuit instance with assignments
        let circ = PermutationProofCircuit::<C, GG, N, LEVELS> {
            num_samples,
            // Public
            nonce: Some(public.nonce),
            pk_public: Some(public.pk_public),
            indices_init: Some(public.indices_init),
            alpha_rs: Some(public.alpha_rs),
            power_challenge_public: Some(public.power_challenge_public),
            c_perm: Some(public.c_perm),
            c_power: Some(public.c_power),
            power_opening_proof: Some(public.power_opening_proof.clone()),
            // Witness
            sk: Some(witness.sk),
            rs_witness: Some(witness.rs_witness.clone()),
            power_perm_vec_wit: Some(witness.power_perm_vec_wit),
            power_perm_vec_scalar_wit: Some(witness.power_perm_vec_scalar_wit),
            _pd: PhantomData,
        };

        // Prove
        let proof = Groth16::<E>::prove(&self.pk, circ.clone(), rng)?;

        // Build public inputs directly from the synthesized circuit to ensure exact order
        use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
        let cs = ConstraintSystem::<ConstraintF<C>>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: true,
        });
        circ.generate_constraints(cs.clone())?;
        cs.finalize();
        let cs_borrowed = cs.borrow().unwrap();
        let inst = cs_borrowed.instance_assignment().unwrap();
        let public_inputs: Vec<E::ScalarField> = inst[1..].to_vec();
        Ok((proof, public_inputs))
    }

    /// Access the prepared verifying key for external verification orchestration
    pub fn prepared_vk(&self) -> &PreparedVerifyingKey<E> {
        &self.pvk
    }

    /// Verify a proof against the provided public inputs
    pub fn verify(
        &self,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> anyhow::Result<bool> {
        let ok = Groth16::<E>::verify_proof(&self.pvk, proof, public_inputs)?;
        if !ok {
            eprintln!(
                "verification failed: public_inputs={}, vk_inputs={}",
                public_inputs.len(),
                self.pvk.vk.gamma_abc_g1.len() - 1
            );
        }
        Ok(ok)
    }
}

/// Flatten public inputs to base field elements in the exact order of allocation
pub fn build_public_inputs<E, C, const N: usize>(
    public: &PublicData<C, N>,
) -> anyhow::Result<Vec<E::ScalarField>>
where
    E: Pairing,
    C: CurveGroup + ToConstraintField<ConstraintF<C>>,
    C::BaseField: PrimeField,
    C::ScalarField: PrimeField,
    E::ScalarField: PrimeField + From<<C::BaseField as Field>::BasePrimeField>,
{
    let mut v: Vec<E::ScalarField> = Vec::new();

    // 1) pk_public (full point serialization)
    {
        let elems: Vec<ConstraintF<C>> = public
            .pk_public
            .to_field_elements()
            .ok_or_else(|| anyhow::anyhow!("failed to serialize pk_public"))?;
        for e in elems {
            v.push(e.into());
        }
    }

    // 2) nonce (base field)
    v.push(public.nonce.into());

    // 3) indices_init (array of base field)
    for x in public.indices_init.iter() {
        v.push((*x).into());
    }

    // 4) alpha_rs (base field)
    v.push(public.alpha_rs.into());

    // 5) power_challenge_public (base field)
    v.push(public.power_challenge_public.into());

    // 6) c_perm (full point serialization)
    {
        let elems: Vec<ConstraintF<C>> = public
            .c_perm
            .to_field_elements()
            .ok_or_else(|| anyhow::anyhow!("failed to serialize c_perm"))?;
        for e in elems {
            v.push(e.into());
        }
    }

    // 7) c_power (full point serialization)
    {
        let elems: Vec<ConstraintF<C>> = public
            .c_power
            .to_field_elements()
            .ok_or_else(|| anyhow::anyhow!("failed to serialize c_power"))?;
        for e in elems {
            v.push(e.into());
        }
    }

    // 8) power_opening_proof: rounds (L_k, R_k) as points, then a_final, r_final as emulated limbs
    for (l, r) in public
        .power_opening_proof
        .folding_challenge_commitment_rounds
        .iter()
    {
        let le: Vec<ConstraintF<C>> = l
            .to_field_elements()
            .ok_or_else(|| anyhow::anyhow!("failed to serialize L_k"))?;
        for e in le {
            v.push(e.into());
        }
        let re: Vec<ConstraintF<C>> = r
            .to_field_elements()
            .ok_or_else(|| anyhow::anyhow!("failed to serialize R_k"))?;
        for e in re {
            v.push(e.into());
        }
    }

    // Serialize emulated scalars a_final and r_final as limbs using the same
    // representation EmulatedFpVar(Input) uses in ToConstraintFieldGadget (Weight-optimized)
    let limbs_a: Vec<ConstraintF<C>> =
        AllocatedEmulatedFpVar::<C::ScalarField, ConstraintF<C>>::get_limbs_representations(
            &public.power_opening_proof.a_final,
            OptimizationType::Weight,
        )?;
    for e in limbs_a {
        v.push(e.into());
    }

    let limbs_r: Vec<ConstraintF<C>> =
        AllocatedEmulatedFpVar::<C::ScalarField, ConstraintF<C>>::get_limbs_representations(
            &public.power_opening_proof.r_final,
            OptimizationType::Weight,
        )?;
    for e in limbs_r {
        v.push(e.into());
    }

    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::permutation_proof::{prepare_witness, PermutationParameters};
    use ark_bn254::{Bn254, Fr as BaseField};
    use ark_crypto_primitives::commitment::{
        pedersen::Commitment as PedersenCommitment, CommitmentScheme,
    };
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_grumpkin::{Fr as ScalarField, Projective as C};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar as SWVar;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use rand::rngs::StdRng;

    // Curve variable for Grumpkin
    type CVar = SWVar<ark_grumpkin::GrumpkinConfig, FpVar<BaseField>>;

    const N: usize = 8;
    const LEVELS: usize = 3;

    const TEST_TARGET: &str = "nexus_nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::{
            filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
        };
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_end_to_end_permutation_proof_groth16() {
        let _guard = setup_test_tracing();
        let mut rng = StdRng::seed_from_u64(12345);

        // ---------- Native preparation via prepare_witness ----------
        use crate::pedersen_commitment_opening_proof::{DeckHashWindow, ReencryptionWindow};

        // Setup Pedersen parameters (inner curve C=Grumpkin)
        let perm_params = PedersenCommitment::<C, DeckHashWindow>::setup(&mut rng).unwrap();
        let power_params = PedersenCommitment::<C, ReencryptionWindow>::setup(&mut rng).unwrap();

        // Prover secrets
        let sk = ScalarField::rand(&mut rng);
        let nonce: BaseField = BaseField::rand(&mut rng);

        // Poseidon sponge over BaseField (BN254 Fr)
        let mut sponge =
            PoseidonSponge::<BaseField>::new(&crate::config::poseidon_config::<BaseField>());

        // Prepare witnesses off-circuit
        let mut prep_params = PermutationParameters::<C, _> {
            perm_params: &perm_params,
            power_params: &power_params,
            rng: &mut rng,
        };
        let prepared =
            prepare_witness::<C, _, _, N, LEVELS>(&mut prep_params, nonce, sk, &mut sponge)
                .expect("prepare_witness");

        // ---------- Proof system ----------
        let sys: PermutationGroth16<Bn254, C, CVar, N, LEVELS> =
            PermutationGroth16::setup(&mut rng, prepared.rs_trace.num_samples).expect("setup");

        let public = PublicData::<C, N> {
            nonce,
            pk_public: prepared.pk,
            indices_init: prepared.indices_init,
            alpha_rs: prepared.vrf_value,
            power_challenge_public: prepared.bg_setup.power_challenge_base,
            c_perm: prepared.bg_setup.permutation_commitment,
            c_power: prepared.bg_setup.power_permutation_commitment,
            power_opening_proof: prepared.power_opening_proof.clone(),
        };

        let witness = WitnessData::<C, N, LEVELS> {
            sk,
            rs_witness: prepared.rs_trace.witness_trace.clone(),
            power_perm_vec_wit: prepared.perm_power_vector_base,
            power_perm_vec_scalar_wit: prepared.perm_power_vector_scalar,
        };

        let (proof, public_inputs) = sys
            .prove(&mut rng, &public, &witness, prepared.rs_trace.num_samples)
            .expect("prove");

        let ok = sys.verify(&proof, &public_inputs).expect("verify call");
        assert!(ok, "Groth16 proof should verify");
    }
}
