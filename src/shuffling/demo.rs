use ark_bn254::Fr as CircuitField; // BN254's scalar field = Grumpkin's base field
use ark_ec::PrimeGroup;
use ark_grumpkin::{Fq as GrumpkinScalarField, GrumpkinConfig, Projective as GrumpkinProjective};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::ToBitsGadget,
    fields::fp::FpVar,
    groups::{
        curves::short_weierstrass::{AffineVar, ProjectiveVar},
        CurveVar,
    },
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

fn main() -> Result<(), SynthesisError> {
    demo_non_native_scalar_mul()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo() -> Result<(), SynthesisError> {
        demo_non_native_scalar_mul()
    }
}

pub fn demo_non_native_scalar_mul() -> Result<(), SynthesisError> {
    // Circuit operates in BN254's scalar field (which is Grumpkin's base field)
    let cs = ConstraintSystem::<CircuitField>::new_ref();

    // Grumpkin curve point using AffineVar for optimization
    type GrumpkinAffineVar = AffineVar<GrumpkinConfig, FpVar<CircuitField>>;

    // Allocate affine point as witness using new_variable_omit_on_curve_check
    // First allocate as ProjectiveVar, then convert to AffineVar
    type GrumpkinProjectiveVar = ProjectiveVar<GrumpkinConfig, FpVar<CircuitField>>;
    let p_projective = GrumpkinProjectiveVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || Ok(GrumpkinProjective::generator()),
        AllocationMode::Witness,
    )?;
    let p_var = p_projective.to_affine()?;

    // Non-native scalar k from Grumpkin's scalar field (which is BN254's base field)
    let k = CircuitField::from(0xDEADBEEF_u64);

    // Allocate the non-native scalar using NonNativeFieldVar
    let k_var: FpVar<CircuitField> = FpVar::new_witness(cs.clone(), || Ok(k))?;

    // Convert to bits and multiply
    let bits = k_var.to_bits_le()?;

    let res = p_var.scalar_mul_le(bits.iter())?; // AffineVar result on Grumpkin

    // Now `res` can feed into pairings or other logic.

    println!("Constraint system has {} constraints", cs.num_constraints());
    println!("Is satisfied: {}", cs.is_satisfied()?);

    Ok(())
}
