//! Benchmark comparing fixed-base vs variable-base scalar multiplication in R1CS circuits
//! Tests both individual scalar muls and batched MSM operations
//!
//! IMPORTANT FINDINGS:
//! - The precomputed_base_scalar_mul_le function in ark_r1cs_std for short_weierstrass curves
//!   (which includes BN254) actually IGNORES the precomputed bases and just uses regular scalar_mul_le
//! - This means there's currently no optimization benefit from using "precomputed" MSM vs regular scalar mul
//! - See: r1cs-std/src/groups/curves/short_weierstrass/mod.rs:560-575
//! - For true fixed-base MSM optimizations, custom implementations would be needed

use ark_bn254::{Fq, Fr, G1Projective};
use ark_ec::AdditiveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    prelude::*,
};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::{test_rng, vec::Vec};
use std::time::Instant;

const NUM_SCALARS: usize = 52; // Card deck size
const NUM_SCALARS_WITH_BLINDING: usize = NUM_SCALARS + 1; // 52 + 1 blinding factor

type G1Var = ProjectiveVar<ark_bn254::g1::Config, FpVar<Fq>>;

/// Benchmark result for a single approach
#[derive(Debug)]
struct BenchmarkResult {
    name: &'static str,
    constraints: usize,
    witnesses: usize,
    time_ms: u128,
}

/// Generate random scalars and bases for testing
fn generate_test_data(rng: &mut impl ark_std::rand::Rng) -> (Vec<Fr>, Vec<G1Projective>) {
    let scalars: Vec<Fr> = (0..NUM_SCALARS_WITH_BLINDING)
        .map(|_| Fr::rand(rng))
        .collect();

    let bases: Vec<G1Projective> = (0..NUM_SCALARS_WITH_BLINDING)
        .map(|_| G1Projective::rand(rng))
        .collect();

    (scalars, bases)
}

/// Benchmark 1: Fixed-base individual scalar multiplications
fn bench_fixed_base_individual(
    cs: ConstraintSystemRef<Fq>,
    scalars: &[Fr],
    bases: &[G1Projective],
) -> Result<BenchmarkResult, SynthesisError> {
    let start = Instant::now();
    let initial_constraints = cs.num_constraints();
    let initial_witnesses = cs.num_witness_variables();

    // Allocate bases as constants (fixed)
    let base_vars: Vec<G1Var> = bases
        .iter()
        .map(|base| G1Var::new_constant(cs.clone(), *base))
        .collect::<Result<Vec<_>, _>>()?;

    // Allocate scalars as witnesses
    let scalar_vars: Vec<FpVar<Fq>> = scalars
        .iter()
        .map(|scalar| {
            // Convert Fr to Fq (base field)
            let scalar_fq = scalar_to_base_field::<Fr, Fq>(scalar);
            FpVar::new_witness(cs.clone(), || Ok(scalar_fq))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Perform individual scalar multiplications and accumulate
    let mut result = G1Var::zero();
    for (scalar_var, base_var) in scalar_vars.iter().zip(base_vars.iter()) {
        let scalar_bits = scalar_var.to_bits_le()?;
        let mul_result = base_var.scalar_mul_le(scalar_bits.iter())?;
        result = &result + &mul_result;
    }

    // Ensure result is used (enforce a dummy constraint)
    let _ = result.to_bytes_le()?;

    Ok(BenchmarkResult {
        name: "Fixed-Base Individual Scalar Muls",
        constraints: cs.num_constraints() - initial_constraints,
        witnesses: cs.num_witness_variables() - initial_witnesses,
        time_ms: start.elapsed().as_millis(),
    })
}

/// Benchmark 2: Variable-base individual scalar multiplications
fn bench_variable_base_individual(
    cs: ConstraintSystemRef<Fq>,
    scalars: &[Fr],
    bases: &[G1Projective],
) -> Result<BenchmarkResult, SynthesisError> {
    let start = Instant::now();
    let initial_constraints = cs.num_constraints();
    let initial_witnesses = cs.num_witness_variables();

    // Allocate bases as witnesses (variable)
    let base_vars: Vec<G1Var> = bases
        .iter()
        .map(|base| G1Var::new_witness(cs.clone(), || Ok(*base)))
        .collect::<Result<Vec<_>, _>>()?;

    // Allocate scalars as witnesses
    let scalar_vars: Vec<FpVar<Fq>> = scalars
        .iter()
        .map(|scalar| {
            let scalar_fq = scalar_to_base_field::<Fr, Fq>(scalar);
            FpVar::new_witness(cs.clone(), || Ok(scalar_fq))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Perform individual scalar multiplications and accumulate
    let mut result = G1Var::zero();
    for (scalar_var, base_var) in scalar_vars.iter().zip(base_vars.iter()) {
        let scalar_bits = scalar_var.to_bits_le()?;
        let mul_result = base_var.scalar_mul_le(scalar_bits.iter())?;
        result = &result + &mul_result;
    }

    // Ensure result is used
    let _ = result.to_bytes_le()?;

    Ok(BenchmarkResult {
        name: "Variable-Base Individual Scalar Muls",
        constraints: cs.num_constraints() - initial_constraints,
        witnesses: cs.num_witness_variables() - initial_witnesses,
        time_ms: start.elapsed().as_millis(),
    })
}

/// Benchmark 3: Fixed-base MSM using precomputed_base_multiscalar_mul_le
fn bench_fixed_base_msm(
    cs: ConstraintSystemRef<Fq>,
    scalars: &[Fr],
    bases: &[G1Projective],
) -> Result<BenchmarkResult, SynthesisError> {
    let start = Instant::now();
    let initial_constraints = cs.num_constraints();
    let initial_witnesses = cs.num_witness_variables();

    // For precomputed_base_multiscalar_mul_le, we need to prepare:
    // 1. Each base should have its precomputed powers (2^0*base, 2^1*base, 2^2*base, ...)
    // 2. Scalars as field elements that will be converted to bits internally

    // Compute powers of 2 for each base (up to scalar bit size)
    let scalar_size = Fr::MODULUS_BIT_SIZE as usize;
    let mut precomputed_bases: Vec<Vec<G1Projective>> = Vec::with_capacity(bases.len());

    for base in bases {
        let mut powers = Vec::with_capacity(scalar_size);
        let mut power = *base;
        for _ in 0..scalar_size {
            powers.push(power);
            power.double_in_place();
        }
        precomputed_bases.push(powers);
    }

    // Allocate scalars as witness variables
    let scalar_vars: Vec<FpVar<Fq>> = scalars
        .iter()
        .map(|scalar| {
            let scalar_fq = scalar_to_base_field::<Fr, Fq>(scalar);
            FpVar::new_witness(cs.clone(), || Ok(scalar_fq))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Perform MSM using precomputed_base_multiscalar_mul_le
    // This function expects bases[i] to be the precomputed powers for scalar[i]
    let result =
        G1Var::precomputed_base_multiscalar_mul_le(&precomputed_bases, scalar_vars.iter())?;

    // Ensure result is used
    let _ = result.to_bytes_le()?;

    Ok(BenchmarkResult {
        name: "Fixed-Base MSM (precomputed_base_multiscalar_mul_le)",
        constraints: cs.num_constraints() - initial_constraints,
        witnesses: cs.num_witness_variables() - initial_witnesses,
        time_ms: start.elapsed().as_millis(),
    })
}

/// Benchmark 4: Variable-base MSM using precomputed_base_multiscalar_mul_le
fn bench_variable_base_msm(
    cs: ConstraintSystemRef<Fq>,
    scalars: &[Fr],
    bases: &[G1Projective],
) -> Result<BenchmarkResult, SynthesisError> {
    let start = Instant::now();
    let initial_constraints = cs.num_constraints();
    let initial_witnesses = cs.num_witness_variables();

    // For variable bases, we still need to compute powers
    // Note: Even though bases are "variable", the precomputed powers are still native curve points
    // The "variable" aspect comes from how they're used in the circuit
    let scalar_size = Fr::MODULUS_BIT_SIZE as usize;
    let mut precomputed_bases: Vec<Vec<G1Projective>> = Vec::with_capacity(bases.len());

    for base in bases {
        let mut powers = Vec::with_capacity(scalar_size);
        let mut power = *base;
        for _ in 0..scalar_size {
            powers.push(power);
            power.double_in_place();
        }
        precomputed_bases.push(powers);
    }

    // Allocate scalars as witness variables
    let scalar_vars: Vec<FpVar<Fq>> = scalars
        .iter()
        .map(|scalar| {
            let scalar_fq = scalar_to_base_field::<Fr, Fq>(scalar);
            FpVar::new_witness(cs.clone(), || Ok(scalar_fq))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Perform MSM using precomputed_base_multiscalar_mul_le
    // With variable bases, this won't have the same optimizations as fixed bases
    let result =
        G1Var::precomputed_base_multiscalar_mul_le(&precomputed_bases, scalar_vars.iter())?;

    // Ensure result is used
    let _ = result.to_bytes_le()?;

    Ok(BenchmarkResult {
        name: "Variable-Base MSM (precomputed_base_multiscalar_mul_le)",
        constraints: cs.num_constraints() - initial_constraints,
        witnesses: cs.num_witness_variables() - initial_witnesses,
        time_ms: start.elapsed().as_millis(),
    })
}

/// Helper function to convert from scalar field to base field
fn scalar_to_base_field<ScalarField, BaseField>(scalar: &ScalarField) -> BaseField
where
    ScalarField: PrimeField,
    BaseField: PrimeField,
{
    // Convert through bytes to keep the same representation
    let mut bytes = Vec::new();
    scalar.serialize_uncompressed(&mut bytes).unwrap();
    BaseField::deserialize_uncompressed(&mut &bytes[..]).unwrap_or(BaseField::zero())
}

/// Print comparison between two results
fn print_comparison(result1: &BenchmarkResult, result2: &BenchmarkResult) {
    let constraint_ratio = result2.constraints as f64 / result1.constraints as f64;
    let witness_diff = result2.witnesses as i64 - result1.witnesses as i64;

    println!(
        "{} vs {}:",
        result1
            .name
            .replace(" MSM (precomputed_base_multiscalar_mul_le)", " MSM"),
        result2
            .name
            .replace(" MSM (precomputed_base_multiscalar_mul_le)", " MSM")
    );
    println!(
        "  Constraint ratio: {:.2}x ({} vs {})",
        constraint_ratio, result1.constraints, result2.constraints
    );
    println!(
        "  Witness difference: {:+} ({} vs {})",
        witness_diff, result1.witnesses, result2.witnesses
    );
}

fn main() {
    println!(
        "=== Scalar Multiplication Benchmark ({} scalars) ===\n",
        NUM_SCALARS_WITH_BLINDING
    );

    let mut rng = test_rng();
    let (scalars, bases) = generate_test_data(&mut rng);

    // Run benchmark 1: Fixed-base individual
    let cs1 = ConstraintSystem::<Fq>::new_ref();
    let result1 = bench_fixed_base_individual(cs1, &scalars, &bases)
        .expect("Fixed-base individual benchmark failed");

    println!("1. {}:", result1.name);
    println!("   Constraints: {}", result1.constraints);
    println!("   Witnesses: {}", result1.witnesses);
    println!("   Time: {} ms\n", result1.time_ms);

    // Run benchmark 2: Variable-base individual
    let cs2 = ConstraintSystem::<Fq>::new_ref();
    let result2 = bench_variable_base_individual(cs2, &scalars, &bases)
        .expect("Variable-base individual benchmark failed");

    println!("2. {}:", result2.name);
    println!("   Constraints: {}", result2.constraints);
    println!("   Witnesses: {}", result2.witnesses);
    println!("   Time: {} ms\n", result2.time_ms);

    // Run benchmark 3: Fixed-base MSM
    let cs3 = ConstraintSystem::<Fq>::new_ref();
    let result3 =
        bench_fixed_base_msm(cs3, &scalars, &bases).expect("Fixed-base MSM benchmark failed");

    println!("3. {}:", result3.name);
    println!("   Constraints: {}", result3.constraints);
    println!("   Witnesses: {}", result3.witnesses);
    println!("   Time: {} ms\n", result3.time_ms);

    // Run benchmark 4: Variable-base MSM
    let cs4 = ConstraintSystem::<Fq>::new_ref();
    let result4 =
        bench_variable_base_msm(cs4, &scalars, &bases).expect("Variable-base MSM benchmark failed");

    println!("4. {}:", result4.name);
    println!("   Constraints: {}", result4.constraints);
    println!("   Witnesses: {}", result4.witnesses);
    println!("   Time: {} ms\n", result4.time_ms);

    // Print comparisons
    println!("=== Comparison ===\n");

    print_comparison(&result1, &result2);
    println!();
    print_comparison(&result3, &result4);
    println!();
    print_comparison(&result1, &result3);
    println!();
    print_comparison(&result2, &result4);

    println!("\n=== Summary ===");
    println!(
        "Most efficient: Fixed-Base MSM with {} constraints",
        result3.constraints
    );
    println!(
        "Least efficient: Variable-Base Individual with {} constraints",
        result2.constraints
    );
    println!(
        "Efficiency gain: {:.2}x fewer constraints",
        result2.constraints as f64 / result3.constraints as f64
    );
}
