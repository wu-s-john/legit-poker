//! RS shuffle verification circuits for SNARK

use super::data_structures::{PermutationWitnessTrace, PermutationWitnessTraceVar};
use super::rs_shuffle_gadget::{
    rs_shuffle_indices, rs_shuffle_with_bayer_groth_linking_proof, rs_shuffle_with_reencryption,
};
use super::{LEVELS, N};
use crate::bayer_groth_permutation::bg_setup_gadget::new_bayer_groth_transcript_gadget_with_poseidon;
use crate::shuffling::curve_absorb::CurveAbsorbGadget;
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
use crate::track_constraints;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::groups::GroupOpsBounds;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

const LOG_TARGET: &str = "nexus_nova::shuffling::rs_shuffle::circuit";

// Note: RS shuffle gadget functions (rs_shuffle_indices, rs_shuffle, rs_shuffle_with_reencryption)
// have been moved to the rs_shuffle_gadget module for better organization.
// They are now imported and re-exported from this module for backward compatibility.

/// RS Shuffle Circuit - Main circuit for verifying RS shuffle
pub struct RSShuffleCircuit<F, C>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
{
    pub ct_init_pub: Vec<ElGamalCiphertext<C>>,
    pub ct_after_shuffle: Vec<ElGamalCiphertext<C>>,
    pub seed: F,
    pub alpha: F,
    pub beta: F,
    pub witness: PermutationWitnessTrace<N, LEVELS>,
    pub num_samples: usize,
}

/// RS Shuffle with Re-encryption Circuit - Complete circuit for shuffle + re-encryption
pub struct RSShuffleWithReencryptionCircuit<F, C, CV, const N: usize, const LEVELS: usize>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    /// Initial ciphertexts before shuffle (public input)
    pub ct_init_pub: [ElGamalCiphertext<C>; N],
    /// Intermediate ciphertexts after shuffle, before re-encryption (witness)
    pub ct_after_shuffle: [ElGamalCiphertext<C>; N],
    /// Final ciphertexts after shuffle and re-encryption (public input)
    pub ct_final_reencrypted: [ElGamalCiphertext<C>; N],
    /// Seed for deterministic witness generation
    pub seed: F,
    /// Shuffler's public key for re-encryption
    pub shuffler_pk: C,
    /// Re-encryption randomization values (witness)
    pub encryption_randomizations: [F; N],
    /// First Fiat-Shamir challenge
    pub alpha: F,
    /// Second Fiat-Shamir challenge
    pub beta: F,
    /// Witness data for the shuffle
    pub witness: PermutationWitnessTrace<N, LEVELS>,
    /// Number of samples used in bit generation
    pub num_samples: usize,
    /// Precomputed powers of the generator for efficient fixed-base scalar multiplication
    pub generator_powers: Vec<C>,
    _phantom: PhantomData<CV>,
}

impl<F, C, CV, const N: usize, const LEVELS: usize>
    RSShuffleWithReencryptionCircuit<F, C, CV, N, LEVELS>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
{
    /// Create a new RSShuffleWithReencryptionCircuit instance
    pub fn new(
        ct_init_pub: [ElGamalCiphertext<C>; N],
        ct_after_shuffle: [ElGamalCiphertext<C>; N],
        ct_final_reencrypted: [ElGamalCiphertext<C>; N],
        seed: F,
        shuffler_pk: C,
        encryption_randomizations: [F; N],
        alpha: F,
        beta: F,
        witness: PermutationWitnessTrace<N, LEVELS>,
        num_samples: usize,
        generator_powers: Vec<C>,
    ) -> Self {
        Self {
            ct_init_pub,
            ct_after_shuffle,
            ct_final_reencrypted,
            seed,
            shuffler_pk,
            encryption_randomizations,
            alpha,
            beta,
            witness,
            num_samples,
            generator_powers,
            _phantom: PhantomData,
        }
    }
}

/// RS Shuffle Permutation Circuit - Circuit for verifying shuffle of indices only
#[derive(Clone)]
pub struct RSShufflePermutationCircuit<F, const N: usize, const LEVELS: usize>
where
    F: PrimeField,
{
    /// Initial indices (public input) - typically 0..N-1
    pub indices_init: Vec<F>,
    /// Shuffled indices (public input)
    pub indices_after_shuffle: Vec<F>,
    /// Seed for deterministic witness generation (public input)
    pub seed: F,
    /// Fiat-Shamir challenge (public input)
    pub alpha: F,
    /// Witness data for the shuffle
    pub witness: PermutationWitnessTrace<N, LEVELS>,
    /// Number of samples used in bit generation
    pub num_samples: usize,
}

/// RS Shuffle with Bayer-Groth Linking Circuit
///
/// This circuit verifies:
/// 1. RS shuffle correctness (indices are properly shuffled)
/// 2. Bayer-Groth permutation equality proof
/// 3. Linking between the shuffle and permutation proof
pub struct RSShuffleWithBayerGrothLinkCircuit<
    F,
    C,
    CV,
    RO,
    ROVar,
    const N: usize,
    const LEVELS: usize,
> where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
    RO: ark_crypto_primitives::sponge::CryptographicSponge,
    ROVar: ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar<F, RO>,
{
    // ============ Public Inputs ============
    /// RS shuffle challenge alpha
    pub alpha: F,
    /// Commitment to the permutation vector
    pub c_perm: C,
    /// Commitment to the power vector
    pub c_power: C,

    // ============ Private Inputs ============
    /// The actual permutation values (1-indexed)
    pub permutation: [C::ScalarField; N],
    /// RS shuffle witness data
    pub witness: PermutationWitnessTrace<N, LEVELS>,
    /// Initial indices (0..N-1)
    pub indices_init: [F; N],
    /// Shuffled indices
    pub indices_after_shuffle: [F; N],
    /// Blinding factors (r, s) for zero-knowledge
    pub blinding_factors: (C::ScalarField, C::ScalarField),

    // ============ Constants ============
    /// Generator point for commitments
    pub generator: C,
    /// Domain for transcript (Fiat-Shamir)
    pub domain: Vec<u8>,

    _phantom: PhantomData<(CV, RO, ROVar)>,
}

impl<F, C, CV, RO, ROVar, const N: usize, const LEVELS: usize>
    RSShuffleWithBayerGrothLinkCircuit<F, C, CV, RO, ROVar, N, LEVELS>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
    CV: CurveVar<C, F>,
    RO: ark_crypto_primitives::sponge::CryptographicSponge,
    ROVar: ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar<F, RO>,
{
    /// Create a new RSShuffleWithBayerGrothLinkCircuit instance
    pub fn new(
        alpha: F,
        c_perm: C,
        c_power: C,
        permutation: [C::ScalarField; N],
        witness: PermutationWitnessTrace<N, LEVELS>,
        indices_init: [F; N],
        indices_after_shuffle: [F; N],
        blinding_factors: (C::ScalarField, C::ScalarField),
        generator: C,
        domain: Vec<u8>,
    ) -> Self {
        Self {
            alpha,
            c_perm,
            c_power,
            permutation,
            witness,
            indices_init,
            indices_after_shuffle,
            blinding_factors,
            generator,
            domain,
            _phantom: PhantomData,
        }
    }
}

impl<C, CV, const N: usize, const LEVELS: usize> ConstraintSynthesizer<C::BaseField>
    for RSShuffleWithReencryptionCircuit<C::BaseField, C, CV, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle with reencryption and variable allocation",
            LOG_TARGET,
            {
                // Allocate seed as public input
                let seed_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.seed), AllocationMode::Input)?;

                // Use prepare_rs_witness_data_circuit to create witness trace from seed
                let witness_var = super::native::prepare_rs_witness_data_circuit::<
                    C::BaseField,
                    N,
                    LEVELS,
                >(
                    cs.clone(), &seed_var, &self.witness, self.num_samples
                )?;

                // Allocate initial ElGamal ciphertexts as public inputs
                let ct_init_vars: [ElGamalCiphertextVar<C, CV>; N] = self
                    .ct_init_pub
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Input,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate intermediate shuffled ciphertexts as witness
                let ct_after_shuffle_vars: [ElGamalCiphertextVar<C, CV>; N] = self
                    .ct_after_shuffle
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Witness,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate final re-encrypted ciphertexts as public inputs
                let ct_final_reencrypted_vars: Vec<ElGamalCiphertextVar<C, CV>> = self
                    .ct_final_reencrypted
                    .iter()
                    .map(|ct| {
                        ElGamalCiphertextVar::<C, CV>::new_variable(
                            cs.clone(),
                            || Ok(ct),
                            AllocationMode::Input,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate shuffler public key as public input
                let shuffler_pk_var: CV = AllocVar::new_variable(
                    cs.clone(),
                    || Ok(self.shuffler_pk),
                    AllocationMode::Input,
                )?;

                // Allocate re-encryption randomizations as witness
                let encryption_randomizations_vars: [FpVar<C::BaseField>; N] = self
                    .encryption_randomizations
                    .iter()
                    .map(|r| FpVar::new_variable(cs.clone(), || Ok(*r), AllocationMode::Witness))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                // Allocate challenges as public inputs
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;
                let beta_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.beta), AllocationMode::Input)?;

                // Call the main verification function directly with arrays
                let reencrypted_result = rs_shuffle_with_reencryption::<C, _, N, LEVELS>(
                    cs.clone(),
                    &ct_init_vars,
                    &ct_after_shuffle_vars,
                    &witness_var,
                    &encryption_randomizations_vars,
                    &shuffler_pk_var,
                    &alpha_var,
                    &beta_var,
                    &self.generator_powers,
                )?;

                // Verify that the result matches the expected final ciphertexts
                if reencrypted_result.len() != ct_final_reencrypted_vars.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                for (result_ct, expected_ct) in reencrypted_result
                    .iter()
                    .zip(ct_final_reencrypted_vars.iter())
                {
                    result_ct.c1.enforce_equal(&expected_ct.c1)?;
                    result_ct.c2.enforce_equal(&expected_ct.c2)?;
                }

                Ok(())
            }
        )
    }
}

impl<F, const N: usize, const LEVELS: usize> ConstraintSynthesizer<F>
    for RSShufflePermutationCircuit<F, N, LEVELS>
where
    F: PrimeField + Absorb,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle indices with variable allocation",
            LOG_TARGET,
            {
                // Allocate seed as public input
                let seed_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.seed), AllocationMode::Input)?;

                // Use prepare_rs_witness_data_circuit to create witness trace from seed
                let witness_var = super::native::prepare_rs_witness_data_circuit::<F, N, LEVELS>(
                    cs.clone(),
                    &seed_var,
                    &self.witness,
                    self.num_samples,
                )?;

                // Allocate initial indices as public inputs
                let indices_init_vars: Vec<FpVar<F>> = self
                    .indices_init
                    .iter()
                    .map(|idx| FpVar::new_variable(cs.clone(), || Ok(*idx), AllocationMode::Input))
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate shuffled indices as public inputs
                let indices_after_shuffle_vars: Vec<FpVar<F>> = self
                    .indices_after_shuffle
                    .iter()
                    .map(|idx| FpVar::new_variable(cs.clone(), || Ok(*idx), AllocationMode::Input))
                    .collect::<Result<Vec<_>, _>>()?;

                // Allocate challenge as public input
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;

                // Derive beta locally as alpha^2 and call the main verification function
                let beta_var = &alpha_var * &alpha_var;
                rs_shuffle_indices::<F, N, LEVELS>(
                    cs.clone(),
                    &indices_init_vars,
                    &indices_after_shuffle_vars,
                    &witness_var,
                    &alpha_var,
                    &beta_var,
                )
            }
        )
    }
}

impl<C, CV, RO, ROVar, const N: usize, const LEVELS: usize> ConstraintSynthesizer<C::BaseField>
    for RSShuffleWithBayerGrothLinkCircuit<C::BaseField, C, CV, RO, ROVar, N, LEVELS>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::ScalarField: PrimeField,
    RO: ark_crypto_primitives::sponge::CryptographicSponge,
    ROVar: ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar<C::BaseField, RO>,
    CV: CurveVar<C, C::BaseField>
        + CurveAbsorbGadget<
            C::BaseField,
            ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<C::BaseField>,
        > + Clone,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        track_constraints!(
            &cs,
            "rs shuffle with bayer groth linking proof",
            LOG_TARGET,
            {
                // ============ Step 1: Allocate Public Inputs ============
                tracing::debug!(target: LOG_TARGET, "Allocating public inputs");

                // Allocate alpha challenge as public input
                let alpha_var =
                    FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;

                // Allocate commitment to permutation vector as public input
                let c_perm_var =
                    CV::new_variable(cs.clone(), || Ok(self.c_perm), AllocationMode::Input)?;

                // Allocate commitment to power vector as public input
                let c_power_var =
                    CV::new_variable(cs.clone(), || Ok(self.c_power), AllocationMode::Input)?;

                // ============ Step 2: Allocate Private Inputs ============
                tracing::debug!(target: LOG_TARGET, "Allocating private inputs");

                // Allocate permutation as EmulatedFpVar (scalar field in base field circuit)
                let permutation_vars: [EmulatedFpVar<C::ScalarField, C::BaseField>; N] =
                    std::array::from_fn(|i| {
                        EmulatedFpVar::new_variable(
                            cs.clone(),
                            || Ok(self.permutation[i]),
                            AllocationMode::Witness,
                        )
                        .expect("Failed to allocate permutation element")
                    });

                // Allocate witness data
                let witness_var = PermutationWitnessTraceVar::new_variable(
                    cs.clone(),
                    || Ok(&self.witness),
                    AllocationMode::Witness,
                )?;

                // Allocate initial indices
                let indices_init_vars: [FpVar<C::BaseField>; N] = std::array::from_fn(|i| {
                    FpVar::new_variable(
                        cs.clone(),
                        || Ok(self.indices_init[i]),
                        AllocationMode::Witness,
                    )
                    .expect("Failed to allocate initial index")
                });

                // Allocate shuffled indices
                let indices_after_shuffle_vars: [FpVar<C::BaseField>; N] =
                    std::array::from_fn(|i| {
                        FpVar::new_variable(
                            cs.clone(),
                            || Ok(self.indices_after_shuffle[i]),
                            AllocationMode::Witness,
                        )
                        .expect("Failed to allocate shuffled index")
                    });

                // Allocate blinding factors as EmulatedFpVar
                let blinding_r_var = EmulatedFpVar::new_variable(
                    cs.clone(),
                    || Ok(self.blinding_factors.0),
                    AllocationMode::Witness,
                )?;
                let blinding_s_var = EmulatedFpVar::new_variable(
                    cs.clone(),
                    || Ok(self.blinding_factors.1),
                    AllocationMode::Witness,
                )?;
                let blinding_factors_var = (blinding_r_var, blinding_s_var);

                // ============ Step 3: Allocate Constants ============
                tracing::debug!(target: LOG_TARGET, "Allocating constants");

                // Allocate generator as constant
                let generator_var = CV::new_constant(cs.clone(), self.generator)?;

                // ============ Step 4: Create Transcript Gadget ============
                tracing::debug!(target: LOG_TARGET, "Creating transcript gadget");

                // Create transcript gadget using the new_with_poseidon helper
                // Since new_with_poseidon returns a specific type with PoseidonSponge/PoseidonSpongeVar,
                // we need to ensure RO and ROVar match those types
                let mut transcript_gadget = new_bayer_groth_transcript_gadget_with_poseidon::<
                    C::BaseField,
                >(cs.clone(), &self.domain)?;

                // ============ Step 5: Run Combined Protocol ============
                tracing::debug!(target: LOG_TARGET, "Running RS shuffle + Bayer-Groth protocol");

                let (_proof_point, _bg_params) = rs_shuffle_with_bayer_groth_linking_proof::<
                    C::BaseField,
                    C,
                    CV,
                    ark_crypto_primitives::sponge::poseidon::PoseidonSponge<C::BaseField>,
                    ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar<
                        C::BaseField,
                    >,
                    N,
                    LEVELS,
                >(
                    cs.clone(),
                    &alpha_var,
                    &c_perm_var,
                    &c_power_var,
                    &generator_var,
                    &permutation_vars,
                    &witness_var,
                    &indices_init_vars,
                    &indices_after_shuffle_vars,
                    &blinding_factors_var,
                    &mut transcript_gadget,
                )?;

                // The proof_point and bg_params are now constrained by the gadget
                // No additional constraints needed as the gadget handles all verification

                tracing::debug!(
                    target: LOG_TARGET,
                    "Successfully generated constraints for RS shuffle + Bayer-Groth proof"
                );

                // Optionally, we could expose the proof_point as a public output
                // by allocating it as an Input variable and enforcing equality
                // For now, the verification is complete within the circuit

                Ok(())
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rs_shuffle::native::prepare_rs_witness_data_circuit;
    use crate::shuffling::rs_shuffle::rs_shuffle_gadget::rs_shuffle;
    use crate::test_utils::check_cs_satisfied;
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::CurveConfig;
    use ark_ff::AdditiveGroup;
    use ark_grumpkin::GrumpkinConfig;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

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

    #[test]
    fn test_rs_shuffle_ordinary_case() {
        let _guard = setup_test_tracing();
        const N: usize = 52;
        const LEVELS: usize = 5;

        use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
        use crate::shuffling::rs_shuffle::native::prepare_rs_witness_trace;
        use ark_bn254::Fr as BaseField;
        use ark_ec::PrimeGroup;
        use ark_grumpkin::Projective as GrumpkinProjective;
        use ark_std::UniformRand;

        tracing::debug!(target: TEST_TARGET, "Starting test_rs_shuffle_ordinary_case");

        // 1. Create 52 ElGamal ciphertexts using the Grumpkin curve
        let mut rng = ark_std::test_rng();
        let generator = GrumpkinProjective::generator();

        // Generate a public key for encryption
        let private_key = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = generator * private_key;

        // Create 52 ciphertexts with distinct messages
        let ct_init: Vec<ElGamalCiphertext<GrumpkinProjective>> = (0..N)
            .map(|i| {
                let message = <GrumpkinConfig as CurveConfig>::ScalarField::from((i + 1) as u64);
                let randomness = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
                ElGamalCiphertext::encrypt_scalar(message, randomness, public_key)
            })
            .collect();

        // 2. Use a regular seed value to generate witness trace with mixed bits
        let seed = BaseField::from(42u64);
        let (rs_witness_trace, num_samples) = prepare_rs_witness_trace::<BaseField, N, LEVELS>(seed);

        tracing::debug!(
            target: TEST_TARGET,
            "Generated witness trace with {} samples",
            num_samples
        );

        // 3. Prepare witness trace and extract the final permutation
        // The final permutation is encoded in rs_witness_trace.next_levels[LEVELS - 1]
        // where each SortedRow.idx tells us which original element ends up at that position
        let final_sorted = &rs_witness_trace.next_levels[LEVELS - 1];

        // 4. Permute the ciphertexts according to the witness trace's final permutation
        let mut ct_after_shuffle = vec![ct_init[0].clone(); N];
        for (position, sorted_row) in final_sorted.iter().enumerate() {
            // sorted_row.idx is the original index that should be at this position
            ct_after_shuffle[position] = ct_init[sorted_row.idx as usize].clone();
        }

        // 5. Create constraint system and allocate all circuit variables
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate initial ciphertexts as witness
        let ct_init_vars: Vec<ElGamalCiphertextVar<Projective<GrumpkinConfig>, _>> = ct_init
            .iter()
            .map(|ct| {
                ElGamalCiphertextVar::new_variable(cs.clone(), || Ok(ct), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to allocate initial ciphertexts");

        // Allocate shuffled ciphertexts as witness
        let ct_final_vars: Vec<ElGamalCiphertextVar<Projective<GrumpkinConfig>, _>> =
            ct_after_shuffle
                .iter()
                .map(|ct| {
                    ElGamalCiphertextVar::new_variable(
                        cs.clone(),
                        || Ok(ct),
                        AllocationMode::Witness,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("Failed to allocate shuffled ciphertexts");

        track_constraints!(
            &cs,
            "rs_shuffle test - witness preparation and verification",
            TEST_TARGET,
            {
                // Allocate seed as a circuit variable
                let seed_var =
                    FpVar::new_constant(cs.clone(), seed).expect("Failed to allocate seed");

                // Allocate witness trace
                let witness_var = prepare_rs_witness_data_circuit::<BaseField, N, LEVELS>(
                    cs.clone(),
                    &seed_var,
                    &rs_witness_trace,
                    num_samples,
                )
                .expect("Failed to allocate witness data");

                // Create realistic Fiat-Shamir challenges
                let alpha = FpVar::new_constant(cs.clone(), BaseField::from(17u64))
                    .expect("Failed to create alpha");
                let beta = FpVar::new_constant(cs.clone(), BaseField::from(23u64))
                    .expect("Failed to create beta");

                // 6. Run the rs_shuffle verification function
                rs_shuffle::<
                    GrumpkinProjective,
                    ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
                    N,
                    LEVELS,
                >(
                    cs.clone(),
                    &ct_init_vars,
                    &ct_final_vars,
                    &witness_var,
                    &alpha,
                    &beta,
                )
                .expect("rs_shuffle verification failed");
            }
        );

        // 7. Verify the constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid shuffle");

        // 8. Check that the permutation preserves the multiset of ciphertexts
        // Verify that we have exactly N elements and they form a permutation
        let mut index_set: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for sorted_row in final_sorted.iter() {
            assert!(
                index_set.insert(sorted_row.idx),
                "Duplicate index {} in permutation",
                sorted_row.idx
            );
        }
        assert_eq!(index_set.len(), N, "Permutation should contain all indices");

        // Check that the bits across all levels are mixed (not all 0s or all 1s)
        for level in 0..LEVELS {
            let ones_count = rs_witness_trace.bits_mat[level].iter().filter(|&&b| b).count();
            tracing::debug!(
                target: TEST_TARGET,
                "Level {} has {} ones out of {} bits",
                level,
                ones_count,
                N
            );
            // In ordinary case, we expect mixed bits (neither all 0s nor all 1s)
            assert!(ones_count > 0, "Level {} should have some 1s", level);
            assert!(ones_count < N, "Level {} should have some 0s", level);
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: RS shuffle ordinary case");

        // Log ciphertexts before and after permutation for debugging
        tracing::trace!(target: TEST_TARGET, "Ciphertexts before permutation:");
        for (i, ct) in ct_init.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "ct_init[{}]: c1=({:?}, {:?}, {:?}), c2=({:?}, {:?}, {:?})",
                i, ct.c1.x, ct.c1.y, ct.c1.z, ct.c2.x, ct.c2.y, ct.c2.z
            );
        }

        tracing::trace!(target: TEST_TARGET, "Ciphertexts after permutation:");
        for (i, ct) in ct_after_shuffle.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "ct_after_shuffle[{}]: c1=({:?}, {:?}, {:?}), c2=({:?}, {:?}, {:?})",
                i, ct.c1.x, ct.c1.y, ct.c1.z, ct.c2.x, ct.c2.y, ct.c2.z
            );
        }

        tracing::trace!(target: TEST_TARGET, "Permutation mapping:");
        for (position, sorted_row) in final_sorted.iter().enumerate() {
            tracing::trace!(
                target: TEST_TARGET,
                "Position {} <- Original index {}",
                position,
                sorted_row.idx
            );
        }
    }

    #[test]
    fn test_rs_shuffle_with_reencryption() {
        let _guard = setup_test_tracing();
        const N: usize = 52;
        const LEVELS: usize = 5;

        use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
        use crate::shuffling::rs_shuffle::native::run_rs_shuffle_permutation;
        use ark_bn254::Fr as BaseField;
        use ark_ec::PrimeGroup;
        use ark_ff::BigInteger;
        use ark_grumpkin::Projective as GrumpkinProjective;
        use ark_std::UniformRand;

        tracing::debug!(target: TEST_TARGET, "Starting test_rs_shuffle_with_reencryption");

        // 1. Setup: Create ElGamal ciphertexts and keys
        let mut rng = ark_std::test_rng();
        let generator = GrumpkinProjective::generator();

        // Generate shuffler keys
        let shuffler_private_key = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
        let shuffler_public_key = generator * shuffler_private_key;

        // Create N ciphertexts with distinct messages
        let ct_init: [ElGamalCiphertext<GrumpkinProjective>; N] = std::array::from_fn(|i| {
            let message = <GrumpkinConfig as CurveConfig>::ScalarField::from((i + 1) as u64);
            let randomness = <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, shuffler_public_key)
        });

        // 2. Native execution
        let seed = BaseField::from(42u64);

        // Run RS shuffle permutation
        let rs_shuffle_trace =
            run_rs_shuffle_permutation::<BaseField, _, N, LEVELS>(seed, &ct_init);

        tracing::debug!(
            target: TEST_TARGET,
            "Native shuffle completed with {} samples",
            rs_shuffle_trace.num_samples
        );

        // Generate re-encryption randomizations
        let rerandomizations: [<GrumpkinConfig as CurveConfig>::ScalarField; N] =
            crate::shuffling::encryption::generate_randomization_array::<GrumpkinConfig, N>(
                &mut rng,
            );

        // Apply re-encryption natively
        let ct_final_native: [ElGamalCiphertext<GrumpkinProjective>; N] =
            std::array::from_fn(|i| {
                rs_shuffle_trace.permuted_output[i]
                    .add_encryption_layer(rerandomizations[i], shuffler_public_key)
            });

        // 3. SNARK Circuit execution
        let cs = ConstraintSystem::<BaseField>::new_ref();

        // Allocate initial ciphertexts
        let ct_init_vars: [ElGamalCiphertextVar<
            GrumpkinProjective,
            ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
        >; N] = std::array::from_fn(|i| {
            ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(&ct_init[i]),
                AllocationMode::Witness,
            )
            .expect("Failed to allocate initial ciphertext")
        });

        // Allocate shuffled ciphertexts (intermediate state)
        let ct_after_shuffle_vars = std::array::from_fn(|i| {
            ElGamalCiphertextVar::new_variable(
                cs.clone(),
                || Ok(&rs_shuffle_trace.permuted_output[i]),
                AllocationMode::Witness,
            )
            .expect("Failed to allocate shuffled ciphertext")
        });

        // Allocate witness trace
        let seed_var = FpVar::new_constant(cs.clone(), seed).expect("Failed to allocate seed");
        let witness_var = prepare_rs_witness_data_circuit::<BaseField, N, LEVELS>(
            cs.clone(),
            &seed_var,
            &rs_shuffle_trace.witness_trace,
            rs_shuffle_trace.num_samples,
        )
        .expect("Failed to allocate witness data");

        // Allocate re-encryption randomizations
        let rerandomizations_vars: [FpVar<BaseField>; N] = std::array::from_fn(|i| {
            // Convert ScalarField to BaseField
            let scalar_bytes = rerandomizations[i].into_bigint().to_bytes_le();
            let base_field_value = BaseField::from_le_bytes_mod_order(&scalar_bytes);
            FpVar::new_witness(cs.clone(), || Ok(base_field_value))
                .expect("Failed to allocate rerandomization")
        });

        // Allocate shuffler public key
        let shuffler_pk_var: ProjectiveVar<GrumpkinConfig, FpVar<BaseField>> =
            AllocVar::new_witness(cs.clone(), || Ok(shuffler_public_key))
                .expect("Failed to allocate shuffler public key");

        // Allocate Fiat-Shamir challenges
        let alpha = FpVar::new_constant(cs.clone(), BaseField::from(17u64))
            .expect("Failed to create alpha");
        let beta =
            FpVar::new_constant(cs.clone(), BaseField::from(23u64)).expect("Failed to create beta");

        // Generate precomputed generator powers
        let num_bits = BaseField::MODULUS_BIT_SIZE as usize;
        let generator_powers = (0..num_bits)
            .scan(GrumpkinProjective::generator(), |acc, _| {
                let current = *acc;
                *acc = acc.double();
                Some(current)
            })
            .collect::<Vec<_>>();

        // 4. Run the SNARK function
        let ct_final_snark = rs_shuffle_with_reencryption::<
            GrumpkinProjective,
            ProjectiveVar<GrumpkinConfig, FpVar<BaseField>>,
            N,
            LEVELS,
        >(
            cs.clone(),
            &ct_init_vars,
            &ct_after_shuffle_vars,
            &witness_var,
            &rerandomizations_vars,
            &shuffler_pk_var,
            &alpha,
            &beta,
            &generator_powers,
        )
        .expect("rs_shuffle_with_reencryption failed");

        // 5. Verify the constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied");

        // 6. Verify SNARK output matches native execution
        assert_eq!(ct_final_snark.len(), N, "Output size mismatch");

        for i in 0..N {
            // Extract values from SNARK variables
            let snark_c1 = ct_final_snark[i]
                .c1
                .value()
                .expect("Failed to get c1 value");
            let snark_c2 = ct_final_snark[i]
                .c2
                .value()
                .expect("Failed to get c2 value");

            // Compare with native values
            assert_eq!(
                snark_c1, ct_final_native[i].c1,
                "Mismatch in c1 at index {}",
                i
            );
            assert_eq!(
                snark_c2, ct_final_native[i].c2,
                "Mismatch in c2 at index {}",
                i
            );
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: RS shuffle with re-encryption");
    }
}
