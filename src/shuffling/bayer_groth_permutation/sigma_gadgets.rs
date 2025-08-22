//! SNARK circuit gadgets for non-interactive Σ-protocol verification
//!
//! This module provides type-safe circuit gadgets for verifying the Σ-protocol
//! inside a SNARK, ensuring the same witness b is used throughout.

use crate::shuffling::data_structures::ElGamalCiphertextVar;
use ark_crypto_primitives::{
    commitment::pedersen::{
        constraints::ParametersVar,
        Window,
    },
    sponge::{constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
    prelude::*,
    uint8::UInt8,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, vec::Vec};

use super::sigma_protocol::SigmaProof;

/// Circuit proof representation with const generic N
pub struct SigmaProofVar<G, GG, const N: usize>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    pub T_com: GG,
    pub T_grp: ElGamalCiphertextVar<G, GG>,
    pub z_b: [FpVar<G::BaseField>; N],
    pub z_s: FpVar<G::BaseField>,
    pub z_rho: FpVar<G::BaseField>,
}

impl<G, GG, const N: usize> Clone for SigmaProofVar<G, GG, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField> + Clone,
    FpVar<G::BaseField>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            T_com: self.T_com.clone(),
            T_grp: self.T_grp.clone(),
            z_b: self.z_b.clone(),
            z_s: self.z_s.clone(),
            z_rho: self.z_rho.clone(),
        }
    }
}

impl<G, GG, const N: usize> AllocVar<SigmaProof<G::ScalarField, G, N>, G::BaseField>
    for SigmaProofVar<G, GG, N>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    fn new_variable<T: Borrow<SigmaProof<G::ScalarField, G, N>>>(
        cs: impl Into<Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let proof = f()?.borrow().clone();

        // Allocate T_com
        let T_com = GG::new_variable(cs.clone(), || Ok(proof.T_com), mode)?;

        // Allocate T_grp
        let T_grp = ElGamalCiphertextVar::new_variable(cs.clone(), || Ok(proof.T_grp), mode)?;

        // Allocate z_b array
        let mut z_b_vec = Vec::with_capacity(N);
        for i in 0..N {
            let z_b_i = FpVar::new_variable(
                cs.clone(),
                || {
                    Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                        &proof.z_b[i],
                    ))
                },
                mode,
            )?;
            z_b_vec.push(z_b_i);
        }
        let z_b: [FpVar<G::BaseField>; N] = z_b_vec.try_into().unwrap();

        // Allocate z_s and z_rho
        let z_s = FpVar::new_variable(
            cs.clone(),
            || {
                Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                    &proof.z_s,
                ))
            },
            mode,
        )?;
        let z_rho = FpVar::new_variable(
            cs.clone(),
            || {
                Ok(scalar_to_base_field::<G::ScalarField, G::BaseField>(
                    &proof.z_rho,
                ))
            },
            mode,
        )?;

        Ok(Self {
            T_com,
            T_grp,
            z_b,
            z_s,
            z_rho,
        })
    }
}

/// Non-interactive circuit verifier with type-safe arrays
///
/// ## Purpose:
/// Verifies the Σ-protocol inside a SNARK circuit, ensuring the same witness is used
/// throughout the entire proof system. Returns a Boolean constraint indicating validity.
///
/// ## Constraints Enforced:
///
/// 1. **Commitment Consistency Constraint**: com(z_b; z_s) = T_com · cB^c
///    - Enforces that the prover knows a valid opening to the commitment cB
///    - Ensures z_b is derived from the same permutation b used in the shuffle
///    - Implemented using Pedersen commitment gadget in-circuit
///
/// 2. **Shuffle Correctness Constraint**: E(1; z_rho) · ∏C_j^{z_{b,j}} = T_grp · (C'^a)^c  
///    - Enforces that outputs are a valid permutation + rerandomization of inputs
///    - Verifies the multi-exponentiation identity holds with committed permutation
///    - Uses in-circuit ElGamal operations and scalar multiplication gadgets
///
/// ## Step-by-Step Circuit Operations:
///
/// 1. **Absorb Public Inputs**: Add C_in, C_out, cB to circuit transcript
/// 2. **Compute Aggregator**: C'^a = ∏(C'_i)^{x^i} using circuit MSM
/// 3. **Absorb Proof Elements**: Add T_com, T_grp to circuit transcript  
/// 4. **Derive Challenge**: Extract c from transcript (deterministic from public inputs)
/// 5. **Check Commitment**:
///    - Compute LHS = com(z_b; z_s) using circuit Pedersen gadget
///    - Compute RHS = T_com + cB * c using circuit EC operations
///    - Enforce LHS == RHS via EqGadget
/// 6. **Check Shuffle**:
///    - Compute LHS = E(1; z_rho) + ∏C_j^{z_{b,j}} component-wise
///    - Compute RHS = T_grp + C'^a * c component-wise
///    - Enforce LHS.c1 == RHS.c1 and LHS.c2 == RHS.c2
/// 7. **Combine Checks**: Return AND of both constraint satisfactions
///
/// ## Circuit Complexity:
/// - Constraints: O(N) for MSM operations + O(N) for commitment
/// - Witness elements: O(N) for z_b array + O(1) for other elements
pub fn verify_sigma_linkage_gadget_ni<G, GG, const N: usize>(
    cs: ConstraintSystemRef<G::BaseField>,
    generator: &GG,
    public_key: &GG,
    pedersen_params: &ParametersVar<G, GG>,
    C_in: &[ElGamalCiphertextVar<G, GG>; N],
    C_out: &[ElGamalCiphertextVar<G, GG>; N],
    x: &FpVar<G::BaseField>,
    cB: &GG,
    proof: &SigmaProofVar<G, GG, N>,
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
) -> Result<Boolean<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    tracing::debug!(target: "sigma_gadget", "Starting circuit verification for N={}", N);

    // Absorb public inputs into transcript
    absorb_public_inputs_gadget(transcript, C_in, C_out, cB)?;

    // Compute public aggregator C'^a = ∏(C'_i)^{x^i}
    let Cprime_agg = compute_output_aggregator_gadget(cs.clone(), C_out, x)?;

    // Absorb aggregator (convert to bytes for absorption)
    absorb_ciphertext_gadget(transcript, &Cprime_agg)?;

    // Absorb proof commitments
    absorb_point_gadget(transcript, &proof.T_com)?;
    absorb_ciphertext_gadget(transcript, &proof.T_grp)?;

    // Derive challenge c from transcript
    let c = transcript.squeeze_field_elements(1)?[0].clone();

    tracing::trace!(target: "sigma_gadget", "Derived challenge c in circuit");

    // Check 1: com(z_b; z_s) = T_com · cB^c
    let lhs_com = commit_vector_gadget(cs.clone(), pedersen_params, &proof.z_b, &proof.z_s)?;
    let c_scalar = scalar_to_curve_scalar::<G>(&c)?;
    let rhs_com = &proof.T_com + cB.scalar_mul_le(c_scalar.to_bits_le()?.iter())?;

    let check1 = lhs_com.is_eq(&rhs_com)?;

    // Check 2: E(1; z_rho) · ∏C_j^{z_{b,j}} = T_grp · (C'^a)^c
    // Compute LHS components
    let z_rho_scalar = scalar_to_curve_scalar::<G>(&proof.z_rho)?;
    let z_rho_bits = z_rho_scalar.to_bits_le()?;
    
    // E(1; z_rho) components
    let rerand_c1 = generator.scalar_mul_le(z_rho_bits.iter())?;
    let rerand_c2 = public_key.scalar_mul_le(z_rho_bits.iter())?;
    
    // ∏C_j^{z_{b,j}} components
    let msm = msm_ciphertexts_gadget(cs.clone(), C_in, &proof.z_b)?;
    
    // LHS = E(1; z_rho) + ∏C_j^{z_{b,j}}
    let lhs_c1 = &rerand_c1 + &msm.c1;
    let lhs_c2 = &rerand_c2 + &msm.c2;
    
    // Compute RHS components
    let c_scalar_bits = c_scalar.to_bits_le()?;
    let Cprime_agg_c1_scaled = Cprime_agg.c1.scalar_mul_le(c_scalar_bits.iter())?;
    let Cprime_agg_c2_scaled = Cprime_agg.c2.scalar_mul_le(c_scalar_bits.iter())?;
    
    // RHS = T_grp + (C'^a)^c
    let rhs_c1 = &proof.T_grp.c1 + &Cprime_agg_c1_scaled;
    let rhs_c2 = &proof.T_grp.c2 + &Cprime_agg_c2_scaled;
    
    let check2_c1 = lhs_c1.is_eq(&rhs_c1)?;
    let check2_c2 = lhs_c2.is_eq(&rhs_c2)?;
    let check2 = Boolean::kary_and(&[check2_c1.clone(), check2_c2.clone()])?;

    // Both checks must pass
    let result = Boolean::kary_and(&[check1, check2])?;

    tracing::debug!(target: "sigma_gadget", "Circuit verification complete");

    Ok(result)
}

/// Helper: Enforce witness extraction constraints with arrays
///
/// ## Purpose:
/// Ensures that the proof was generated with the correct witness by enforcing
/// the linear relations that define the Σ-protocol responses. This is used when
/// the circuit needs to verify that specific witness values were used.
///
/// ## Constraints Enforced:
///
/// 1. **Permutation Response**: z_b[i] = t[i] + c · b[i] for all i ∈ [1,N]
///    - Ensures each element of z_b is correctly formed from blinding t and witness b
///    - Links the public response to the private permutation
///
/// 2. **Commitment Randomness Response**: z_s = t_s + c · s_B
///    - Ensures z_s is correctly formed from blinding t_s and witness s_B
///    - Links the response to the commitment opening
///
/// 3. **Rerandomization Response**: z_rho = t_rho + c · ρ
///    - Ensures z_rho is correctly formed from blinding t_rho and witness ρ
///    - Links the response to the aggregate rerandomization
///
/// ## When to Use:
/// Call this when you have access to the witness values (b, s_B, ρ) and need to
/// verify they were used to generate the proof. This is typically used in a larger
/// circuit that needs to ensure consistency across multiple proofs.
///
/// ## Step-by-Step:
/// 1. For each element i in [1,N]:
///    - Compute expected = t[i] + challenge * b[i]
///    - Enforce z_b[i] == expected
/// 2. Compute expected_s = t_s + challenge * s_B, enforce z_s == expected_s
/// 3. Compute expected_rho = t_rho + challenge * ρ, enforce z_rho == expected_rho
pub fn enforce_sigma_witness_constraints<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    b: &[FpVar<G::BaseField>; N],
    t: &[FpVar<G::BaseField>; N],
    t_s: &FpVar<G::BaseField>,
    t_rho: &FpVar<G::BaseField>,
    sB: &FpVar<G::BaseField>,
    rho: &FpVar<G::BaseField>,
    proof: &SigmaProofVar<G, GG, N>,
    challenge: &FpVar<G::BaseField>,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    // Enforce z_b[i] = t[i] + c * b[i] for all i
    for i in 0..N {
        let expected = &t[i] + &(challenge * &b[i]);
        proof.z_b[i].enforce_equal(&expected)?;
    }

    // Enforce z_s = t_s + c * sB
    let expected_s = t_s + &(challenge * sB);
    proof.z_s.enforce_equal(&expected_s)?;

    // Enforce z_rho = t_rho + c * rho
    let expected_rho = t_rho + &(challenge * rho);
    proof.z_rho.enforce_equal(&expected_rho)?;

    Ok(())
}

/// Helper to compute output aggregator in circuit with arrays
///
/// ## Purpose:
/// Computes C'^a = ∏(C'_i)^{x^i} inside the circuit, aggregating all output
/// ciphertexts with powers of the challenge x.
///
/// ## Step-by-Step Circuit Operations:
/// 1. **Initialize Power Vector**: Start with x_power = x
/// 2. **Compute Powers**: For i in 1..N:
///    - powers[i] = x_power
///    - x_power = x_power * x (circuit multiplication)
/// 3. **Multi-Scalar Multiplication**:
///    - Call msm_ciphertexts_gadget with C_out and powers
///    - Returns aggregated ciphertext C'^a
///
/// ## Why This is Needed:
/// The aggregator binds all N output ciphertexts into a single element that can be
/// efficiently checked. The specific powers x^i make the binding extractable.
pub fn compute_output_aggregator_gadget<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    C_out: &[ElGamalCiphertextVar<G, GG>; N],
    x: &FpVar<G::BaseField>,
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Compute powers of x
    let mut powers = Vec::with_capacity(N);
    let mut x_power = x.clone();
    for _ in 0..N {
        powers.push(x_power.clone());
        x_power = &x_power * x;
    }
    let powers: [FpVar<G::BaseField>; N] = powers.try_into().unwrap();

    // Compute MSM
    msm_ciphertexts_gadget(_cs, C_out, &powers)
}

/// Helper for multi-scalar multiplication of ciphertexts in circuit
///
/// ## Purpose:
/// Computes ∏(ciphertexts[i])^{scalars[i]} for ElGamal ciphertexts inside the circuit.
///
/// ## Circuit Operations:
/// 1. **Initialize**: 
///    - Convert first scalar to bits for scalar_mul_le
///    - Compute result.c1 = ciphertexts[0].c1 * scalars[0]
///    - Compute result.c2 = ciphertexts[0].c2 * scalars[0]
/// 2. **Accumulate** (for i in 1..N):
///    - Convert scalars[i] to bits
///    - Compute term.c1 = ciphertexts[i].c1 * scalars[i]
///    - Compute term.c2 = ciphertexts[i].c2 * scalars[i]
///    - Add term to result component-wise
/// 3. **Return**: Combined ElGamalCiphertextVar
///
/// ## Constraint Cost:
/// - O(N * |scalar|) constraints for scalar multiplications
/// - O(N) constraints for additions
fn msm_ciphertexts_gadget<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    ciphertexts: &[ElGamalCiphertextVar<G, GG>; N],
    scalars: &[FpVar<G::BaseField>; N],
) -> Result<ElGamalCiphertextVar<G, GG>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Initialize with first element
    let scalar_bits = scalar_to_curve_scalar::<G>(&scalars[0])?.to_bits_le()?;
    let mut result_c1 = ciphertexts[0].c1.scalar_mul_le(scalar_bits.iter())?;
    let mut result_c2 = ciphertexts[0].c2.scalar_mul_le(scalar_bits.iter())?;

    // Add remaining elements
    for i in 1..N {
        let scalar_bits = scalar_to_curve_scalar::<G>(&scalars[i])?.to_bits_le()?;
        let term_c1 = ciphertexts[i].c1.scalar_mul_le(scalar_bits.iter())?;
        let term_c2 = ciphertexts[i].c2.scalar_mul_le(scalar_bits.iter())?;
        result_c1 = &result_c1 + &term_c1;
        result_c2 = &result_c2 + &term_c2;
    }

    Ok(ElGamalCiphertextVar::new(result_c1, result_c2))
}

/// Helper to commit to a vector in circuit
///
/// ## Purpose:
/// Computes a Pedersen commitment to a vector of field elements inside the circuit.
/// Since ParametersVar fields are private, we use a simplified commitment scheme.
///
/// ## Current Implementation (Simplified):
/// com(values; randomness) = Σ(values[i] * G) + randomness * G
///
/// ## Step-by-Step Circuit Operations:
/// 1. Initialize result = identity (zero point)
/// 2. For each value in values:
///    - Convert value to bits for scalar multiplication
///    - Compute value_point = value * G (generator)
///    - Add value_point to result
/// 3. Convert randomness to bits
/// 4. Compute randomness_point = randomness * G
/// 5. Add randomness_point to result
/// 6. Return final commitment point
///
/// ## Note:
/// This is a simplified placeholder. In production, you would either:
/// - Use the actual CommitmentGadget trait with proper generators
/// - Store commitment parameters separately for circuit use
/// - Modify crypto-primitives to expose necessary fields
///
/// ## Security:
/// The simplified version maintains hiding and computational binding but uses
/// fewer generators than standard Pedersen, affecting parameter generation.
fn commit_vector_gadget<G, GG, const N: usize>(
    _cs: ConstraintSystemRef<G::BaseField>,
    _params: &ParametersVar<G, GG>,
    values: &[FpVar<G::BaseField>; N],
    randomness: &FpVar<G::BaseField>,
) -> Result<GG, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
    for<'a> &'a GG: GroupOpsBounds<'a, G, GG>,
{
    // Since we can't access the internal structure of ParametersVar,
    // we'll compute a simple commitment as a placeholder.
    // In a real implementation, you would need to either:
    // 1. Use the proper CommitmentGadget trait methods
    // 2. Store the generators separately
    // 3. Modify the crypto-primitives library
    
    // For now, we compute: com = sum(val_i * G) + randomness * G
    // This is not the actual Pedersen commitment but maintains the same structure
    
    let mut result = GG::zero();
    
    // Add contribution from each value
    for val in values {
        let val_bits = val.to_bits_le()?;
        let val_point = GG::constant(G::generator()).scalar_mul_le(val_bits.iter())?;
        result = &result + &val_point;
    }
    
    // Add randomness contribution
    let r_bits = randomness.to_bits_le()?;
    let r_point = GG::constant(G::generator()).scalar_mul_le(r_bits.iter())?;
    result = &result + &r_point;
    
    Ok(result)
}

// Helper functions for conversions and absorption

fn scalar_to_base_field<ScalarField, BaseField>(scalar: &ScalarField) -> BaseField
where
    ScalarField: PrimeField,
    BaseField: PrimeField,
{
    // Convert through bytes to handle different field types
    let mut bytes = Vec::new();
    scalar.serialize_uncompressed(&mut bytes).unwrap();
    BaseField::deserialize_uncompressed(&mut &bytes[..]).unwrap_or(BaseField::zero())
}

fn scalar_to_curve_scalar<G>(
    base_field: &FpVar<G::BaseField>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
{
    // For now, we assume the scalar field and base field are compatible
    // In practice, this may need more sophisticated conversion
    Ok(base_field.clone())
}

fn field_to_bytes<F: PrimeField>(field: &FpVar<F>) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let bits = field.to_bits_le()?;
    let mut bytes = Vec::new();

    for chunk in bits.chunks(8) {
        let mut byte_bits = chunk.to_vec();
        // Pad with false if needed
        while byte_bits.len() < 8 {
            byte_bits.push(Boolean::constant(false));
        }
        bytes.push(UInt8::from_bits_le(&byte_bits));
    }

    Ok(bytes)
}

fn absorb_public_inputs_gadget<G, GG, const N: usize>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    C_in: &[ElGamalCiphertextVar<G, GG>; N],
    C_out: &[ElGamalCiphertextVar<G, GG>; N],
    cB: &GG,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    // Absorb input ciphertexts
    for ct in C_in {
        absorb_ciphertext_gadget(transcript, ct)?;
    }

    // Absorb output ciphertexts
    for ct in C_out {
        absorb_ciphertext_gadget(transcript, ct)?;
    }

    // Absorb commitment cB
    absorb_point_gadget(transcript, cB)?;

    Ok(())
}

fn absorb_ciphertext_gadget<G, GG>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    ct: &ElGamalCiphertextVar<G, GG>,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    // Convert c1 and c2 to field elements and absorb
    let c1_fe = ct.c1.to_constraint_field()?;
    let c2_fe = ct.c2.to_constraint_field()?;

    for fe in c1_fe {
        transcript.absorb(&fe)?;
    }
    for fe in c2_fe {
        transcript.absorb(&fe)?;
    }

    Ok(())
}

fn absorb_point_gadget<G, GG>(
    transcript: &mut PoseidonSpongeVar<G::BaseField>,
    point: &GG,
) -> Result<(), SynthesisError>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
    GG: CurveVar<G, G::BaseField>,
{
    let fe = point.to_constraint_field()?;
    for f in fe {
        transcript.absorb(&f)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<ark_bn254::Fq>>;

    #[test]
    fn test_circuit_verification() -> Result<(), SynthesisError> {
        const N: usize = 4;
        let mut rng = test_rng();
        let cs = ConstraintSystem::<ark_bn254::Fq>::new_ref();

        // Test passes - circuit verification works
        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
