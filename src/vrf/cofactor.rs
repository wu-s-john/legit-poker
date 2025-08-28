//! Cofactor multiplication utilities for VRF
//!
//! This module provides gadgets for multiplying curve points by the curve's cofactor
//! in SNARK circuits. This is necessary for curves with non-trivial cofactor to ensure
//! points are in the prime-order subgroup.

use ark_ec::{models::CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;

/// Multiply a curve variable by the curve's (constant) cofactor inside the circuit.
///
/// This operation ensures the resulting point is in the prime-order subgroup.
/// For curves with cofactor = 1 (like Grumpkin), this is a no-op.
/// For curves with non-trivial cofactor (like Jubjub with cofactor = 8),
/// this performs the necessary scalar multiplication.
///
/// # Arguments
/// * `p_var` - The curve point variable to multiply by the cofactor
///
/// # Returns
/// * The point multiplied by the cofactor (or unchanged if cofactor = 1)
#[inline]
pub fn mul_by_cofactor_const<C, ConstraintF, V>(p_var: &V) -> Result<V, SynthesisError>
where
    C: CurveGroup,               // the native curve group (e.g., Projective<...>)
    ConstraintF: PrimeField,     // the SNARK constraint field
    V: CurveVar<C, ConstraintF>, // the curve gadget type (e.g., ProjectiveVar<...> or AffineVar<...>)
{
    // If the curve is already prime-order, skip work.
    if <C::Config as CurveConfig>::cofactor_is_one() {
        return Ok(p_var.clone());
    }

    // Build LE bit vector of the cofactor as constant Booleans (no constraints).
    let h_bits: Vec<Boolean<ConstraintF>> = <C::Config as CurveConfig>::COFACTOR
        .iter()
        .flat_map(|&limb| {
            (0..64).map(move |i| Boolean::<ConstraintF>::constant(((limb >> i) & 1) != 0))
        })
        .collect();

    // Compute h * P in-circuit.
    p_var.scalar_mul_le(h_bits.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::UniformRand;

    type GrumpkinVar = ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar<
        ark_grumpkin::GrumpkinConfig,
        FpVar<ark_grumpkin::Fq>,
    >;

    #[test]
    fn test_cofactor_multiplication_grumpkin() {
        // Grumpkin has cofactor = 1, so cofactor multiplication should be identity
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<ark_grumpkin::Fq>::new_ref();

        // Generate a random point
        let point = GrumpkinProjective::rand(&mut rng);
        let point_var = GrumpkinVar::new_witness(cs.clone(), || Ok(point)).unwrap();

        // Apply cofactor multiplication
        let result_var =
            mul_by_cofactor_const::<GrumpkinProjective, ark_grumpkin::Fq, GrumpkinVar>(&point_var)
                .unwrap();

        // Since Grumpkin has cofactor = 1, the result should be the same as input
        assert_eq!(point_var.value().unwrap(), result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
