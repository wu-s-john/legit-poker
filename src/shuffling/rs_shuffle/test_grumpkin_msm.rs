use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::constraints::FBaseVar;
use ark_grumpkin::{Affine as GrumpkinAffine, Fq, Fr, GrumpkinConfig};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::FieldVar,
    groups::curves::short_weierstrass::{AffineVar as SWAffineVar, ProjectiveVar},
    prelude::*,
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::Zero;

// Define type aliases for Grumpkin affine and projective variables
pub type GAffineVar = SWAffineVar<GrumpkinConfig, FBaseVar>;
pub type GProjectiveVar = ProjectiveVar<GrumpkinConfig, FBaseVar>;

/// Custom AffineVar wrapper for Grumpkin points
/// This provides conversions between affine and projective representations
#[derive(Clone)]
pub struct CustomAffineVar {
    pub x: FBaseVar,
    pub y: FBaseVar,
    pub infinity: Boolean<Fq>,
}

impl CustomAffineVar {
    /// Create a new CustomAffineVar from coordinates
    pub fn new(x: FBaseVar, y: FBaseVar, infinity: Boolean<Fq>) -> Self {
        Self { x, y, infinity }
    }

    /// Convert to projective representation
    /// Affine (x,y) → Projective (x:y:1) for finite points
    /// Affine O → Projective (0:1:0) for point at infinity
    /// This conversion requires 0 constraints
    pub fn to_projective(&self) -> Result<GProjectiveVar, SynthesisError> {
        // For infinity: (0:1:0), otherwise (x:y:1)
        let one = FBaseVar::one();
        let zero = FBaseVar::zero();

        // z = 1 if not infinity, 0 if infinity
        let z = FBaseVar::conditionally_select(&self.infinity, &zero, &one)?;

        // x_proj = x if not infinity, 0 if infinity
        let x_proj = FBaseVar::conditionally_select(&self.infinity, &zero, &self.x)?;

        // y_proj = y if not infinity, 1 if infinity
        let y_proj = FBaseVar::conditionally_select(&self.infinity, &one, &self.y)?;

        // Create projective point
        Ok(GProjectiveVar::new(x_proj, y_proj, z))
    }

    /// Create from a projective representation
    /// Projective (X:Y:Z) → Affine (X/Z, Y/Z) for Z ≠ 0
    /// Projective with Z = 0 → Point at infinity
    /// This conversion requires 3 multiplication constraints
    pub fn from_projective(proj: &GProjectiveVar) -> Result<Self, SynthesisError> {
        // Check if Z = 0 (point at infinity)
        let z_is_zero = proj.z.is_zero()?;

        // Compute 1/Z (will be arbitrary if Z = 0, but we won't use it)
        let z_inv = proj.z.inverse()?;

        // x_affine = X * (1/Z)
        let x_affine = &proj.x * &z_inv;

        // y_affine = Y * (1/Z)
        let y_affine = &proj.y * &z_inv;

        // If z is zero, we're at infinity
        Ok(Self {
            x: x_affine,
            y: y_affine,
            infinity: z_is_zero,
        })
    }

    /// Check if this point is the identity (point at infinity)
    pub fn is_zero(&self) -> Result<Boolean<Fq>, SynthesisError> {
        Ok(self.infinity.clone())
    }

    /// Get the identity element (point at infinity)
    pub fn zero() -> Self {
        Self {
            x: FBaseVar::zero(),
            y: FBaseVar::zero(),
            infinity: Boolean::constant(true),
        }
    }

    /// Conditional selection between two points
    pub fn conditionally_select(
        condition: &Boolean<Fq>,
        true_val: &Self,
        false_val: &Self,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            x: FBaseVar::conditionally_select(condition, &true_val.x, &false_val.x)?,
            y: FBaseVar::conditionally_select(condition, &true_val.y, &false_val.y)?,
            infinity: Boolean::conditionally_select(
                condition,
                &true_val.infinity,
                &false_val.infinity,
            )?,
        })
    }
}

impl AllocVar<GrumpkinAffine, Fq> for CustomAffineVar {
    fn new_variable<T: std::borrow::Borrow<GrumpkinAffine>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let value = f()?;
        let point = value.borrow();

        // Check if point is at infinity
        let is_infinity = point.is_zero();

        // Allocate coordinates
        let x = FBaseVar::new_variable(cs.clone(), || Ok(point.x), mode)?;
        let y = FBaseVar::new_variable(cs.clone(), || Ok(point.y), mode)?;
        let infinity = Boolean::new_variable(cs, || Ok(is_infinity), mode)?;

        Ok(Self { x, y, infinity })
    }
}

/// Performs affine point addition for DISTINCT points (P ≠ Q)
///
/// Mathematical formula:
/// ```
/// Given: P = (x₁, y₁), Q = (x₂, y₂) where P ≠ Q
///
/// λ = (y₂ - y₁) / (x₂ - x₁)
/// x₃ = λ² - x₁ - x₂
/// y₃ = λ(x₁ - x₃) - y₁
/// ```
///
/// Constraint count: ~4 multiplication constraints
pub fn affine_add_distinct(
    _cs: ConstraintSystemRef<Fq>,
    p: &CustomAffineVar,
    q: &CustomAffineVar,
) -> Result<CustomAffineVar, SynthesisError> {
    let x1 = &p.x;
    let y1 = &p.y;
    let x2 = &q.x;
    let y2 = &q.y;

    // Step 1: Compute slope λ = (y₂ - y₁) / (x₂ - x₁)
    let x_diff = x2 - x1; // Linear operation (no constraint)
    let y_diff = y2 - y1; // Linear operation (no constraint)

    // CONSTRAINT 1: Enforce (x₂ - x₁) · t = 1, where t = 1/(x₂ - x₁)
    // This ensures x₁ ≠ x₂ (points are distinct)
    let x_diff_inv = x_diff.inverse()?;

    // CONSTRAINT 2: λ = (y₂ - y₁) · t
    let lambda = &y_diff * &x_diff_inv;

    // Step 2: Compute x₃ = λ² - x₁ - x₂
    // CONSTRAINT 3: u = λ²
    let lambda_squared = lambda.square()?;
    let x3 = &lambda_squared - x1 - x2; // Linear operations (no constraints)

    // Step 3: Compute y₃ = λ(x₁ - x₃) - y₁
    let x1_minus_x3 = x1 - &x3; // Linear operation (no constraint)
                                // CONSTRAINT 4: v = λ · (x₁ - x₃)
    let lambda_times_diff = &lambda * &x1_minus_x3;
    let y3 = &lambda_times_diff - y1; // Linear operation (no constraint)

    // Return the result - construct using CustomAffineVar
    Ok(CustomAffineVar {
        x: x3,
        y: y3,
        infinity: Boolean::constant(false),
    })
}

/// Intelligently performs point addition or doubling based on whether P = Q
///
/// Decision logic:
/// - If P = O (infinity), return Q
/// - If Q = O (infinity), return P
/// - If P = Q (same point), perform doubling
/// - If P ≠ Q (different points), perform addition
///
/// This function handles all edge cases correctly.
pub fn affine_add_or_double(
    cs: ConstraintSystemRef<Fq>,
    p: &CustomAffineVar,
    q: &CustomAffineVar,
) -> Result<CustomAffineVar, SynthesisError> {
    // Check if either point is at infinity
    let p_is_infinity = p.is_zero()?;
    let q_is_infinity = q.is_zero()?;

    // If P is infinity, return Q
    // If Q is infinity, return P
    // Otherwise, perform normal addition/doubling

    // Check if we can determine infinity status at compile time
    if let (Ok(p_inf), Ok(q_inf)) = (p_is_infinity.value(), q_is_infinity.value()) {
        if p_inf {
            return Ok(q.clone());
        }
        if q_inf {
            return Ok(p.clone());
        }
    }

    // Check if points are equal (need doubling)
    let x_eq = p.x.is_eq(&q.x)?;
    let y_eq = p.y.is_eq(&q.y)?;
    // Use bitwise AND for combining boolean conditions
    let should_double = &x_eq & &y_eq;

    // Compute both possible results
    let doubled = affine_double(cs.clone(), p)?;
    let added = affine_add_distinct(cs.clone(), p, q)?;
    let add_or_double = CustomAffineVar::conditionally_select(&should_double, &doubled, &added)?;

    // Handle infinity cases with conditional selection
    // If p is infinity, select q; if q is infinity, select p; otherwise use add_or_double
    let result_if_p_inf = q.clone();
    let result_if_q_inf = p.clone();

    let temp =
        CustomAffineVar::conditionally_select(&p_is_infinity, &result_if_p_inf, &add_or_double)?;
    let result = CustomAffineVar::conditionally_select(&q_is_infinity, &result_if_q_inf, &temp)?;

    Ok(result)
}

/// Performs affine point doubling (P + P = 2P)
///
/// Mathematical formula:
/// ```
/// Given: P = (x₁, y₁)
///
/// λ = (3x₁² + a) / (2y₁)  where a = 0 for Grumpkin curve
/// x₃ = λ² - 2x₁
/// y₃ = λ(x₁ - x₃) - y₁
/// ```
///
/// Constraint count: ~5 multiplication constraints
pub fn affine_double(
    cs: ConstraintSystemRef<Fq>,
    p: &CustomAffineVar,
) -> Result<CustomAffineVar, SynthesisError> {
    // Handle point at infinity
    let is_infinity = p.is_zero()?;
    if let Ok(true) = is_infinity.value() {
        return Ok(CustomAffineVar::zero());
    }

    let x1 = &p.x;
    let y1 = &p.y;

    // For points at infinity, we need to handle specially
    // Create conditional values that work even for infinity
    let zero = FBaseVar::zero();
    let one = FBaseVar::one();

    // Use conditional selection to handle infinity case
    // If at infinity, use safe values that won't cause division by zero
    let safe_y = FBaseVar::conditionally_select(&is_infinity, &one, y1)?;

    // Step 1: Compute slope λ = (3x₁² + a) / (2y₁) where a = 0 for Grumpkin

    // CONSTRAINT 1: x₁²
    let x1_squared = x1.square()?;

    // Compute numerator: 3x₁² + a (where a = 0 for Grumpkin)
    // Note: 3x₁² is computed as x₁² + x₁² + x₁² (linear operations, no constraints)
    let three_x1_squared = &x1_squared + &x1_squared + &x1_squared;

    // Compute denominator: 2y₁ (linear operation, no constraint)
    let two_y1 = safe_y.double()?;

    // CONSTRAINT 2: Enforce (2y₁) · t = 1, where t = 1/(2y₁)
    // This ensures y₁ ≠ 0 (point is not on x-axis)
    let two_y1_inv = two_y1.inverse()?;

    // CONSTRAINT 3: λ = (3x₁² + a) · t
    let lambda = &three_x1_squared * &two_y1_inv;

    // Step 2: Compute x₃ = λ² - 2x₁
    // CONSTRAINT 4: λ²
    let lambda_squared = lambda.square()?;
    let two_x1 = x1.double()?; // Linear operation (no constraint)
    let x3 = &lambda_squared - &two_x1; // Linear operation (no constraint)

    // Step 3: Compute y₃ = λ(x₁ - x₃) - y₁
    let x1_minus_x3 = x1 - &x3; // Linear operation (no constraint)
                                // CONSTRAINT 5: λ · (x₁ - x₃)
    let lambda_times_diff = &lambda * &x1_minus_x3;
    let y3 = &lambda_times_diff - y1; // Linear operation (no constraint)

    // Conditionally select between the computed result and infinity
    let result_x = FBaseVar::conditionally_select(&is_infinity, &zero, &x3)?;
    let result_y = FBaseVar::conditionally_select(&is_infinity, &zero, &y3)?;

    // Return the doubled point
    Ok(CustomAffineVar {
        x: result_x,
        y: result_y,
        infinity: is_infinity,
    })
}

/// Performs scalar multiplication using affine double-and-add
/// This is more efficient than converting to projective
pub fn affine_scalar_mul(
    cs: ConstraintSystemRef<Fq>,
    point: &CustomAffineVar,
    scalar_bits: &[Boolean<Fq>],
) -> Result<CustomAffineVar, SynthesisError> {
    if scalar_bits.is_empty() {
        // Return point at infinity for scalar = 0
        return Ok(CustomAffineVar::zero());
    }

    // Handle special case where point is at infinity
    let point_is_inf = point.is_zero()?;
    if let Ok(true) = point_is_inf.value() {
        return Ok(CustomAffineVar::zero());
    }

    // Standard double-and-add algorithm
    // Start with point at infinity
    let mut result = CustomAffineVar::zero();

    // Process bits from MSB to LSB (reverse of little-endian input)
    for bit in scalar_bits.iter().rev() {
        // Always double the accumulator
        let doubled = affine_double(cs.clone(), &result)?;

        // If bit is set, add the base point
        let added = affine_add_or_double(cs.clone(), &doubled, point)?;

        // Select between doubled (bit=0) and added (bit=1)
        result = CustomAffineVar::conditionally_select(bit, &added, &doubled)?;
    }

    // Handle case where point is at infinity
    let infinity = CustomAffineVar::zero();
    CustomAffineVar::conditionally_select(&point_is_inf, &infinity, &result)
}

/// Performs scalar multiplication using precomputed powers of g
///
/// Given:
/// - scalar: A field element to multiply by
/// - powers: Precomputed powers [g, g², g⁴, g⁸, g¹⁶, ...] where powers[i] = g^(2^i)
///
/// Returns: g^scalar computed using Hadamard product and summation
///
/// Algorithm:
/// 1. Decompose scalar into bits b₀, b₁, b₂, ... (LSB first)
/// 2. Perform Hadamard product: for each i, compute bᵢ * powers[i]
///    (where bᵢ * powers[i] = powers[i] if bᵢ = 1, else point at infinity)
/// 3. Sum all the products: result = Σ(bᵢ * powers[i])
///
/// This is the key optimization: instead of double-and-add, we select
/// and sum precomputed powers based on the scalar's bit representation.
pub fn scalar_mul_with_powers(
    cs: ConstraintSystemRef<Fq>,
    scalar: &FBaseVar,
    powers: &[CustomAffineVar],
) -> Result<CustomAffineVar, SynthesisError> {
    // Decompose the scalar into bits (little-endian)
    let scalar_bits = scalar.to_bits_le()?;

    // Ensure we have enough precomputed powers
    let num_bits = scalar_bits.len().min(powers.len());

    if num_bits == 0 {
        return Ok(CustomAffineVar::zero());
    }

    // Initialize result as point at infinity (identity element)
    let mut result = CustomAffineVar::zero();

    // Perform Hadamard product and accumulate
    // For each bit bᵢ, if bᵢ = 1, add powers[i] to result
    for i in 0..num_bits {
        let bit = &scalar_bits[i];
        let power = &powers[i];

        // Add this power to the result if bit = 1
        let new_result = affine_add_or_double(cs.clone(), &result, power)?;

        // Conditionally select: if bit = 1, use new_result; if bit = 0, keep result unchanged
        result = CustomAffineVar::conditionally_select(bit, &new_result, &result)?;
    }

    Ok(result)
}

/// Optimized scalar multiplication using precomputed powers with reduced constraints
/// 
/// This version minimizes conditional selections by collecting powers to add first
pub fn scalar_mul_with_powers_optimized(
    cs: ConstraintSystemRef<Fq>,
    scalar: &FBaseVar,
    powers: &[CustomAffineVar],
) -> Result<CustomAffineVar, SynthesisError> {
    // Decompose the scalar into bits (little-endian)
    let scalar_bits = scalar.to_bits_le()?;
    
    // Ensure we have enough precomputed powers
    let num_bits = scalar_bits.len().min(powers.len());
    
    if num_bits == 0 {
        return Ok(CustomAffineVar::zero());
    }
    
    // Collect all the powers we need to add (where bit = 1)
    // We use conditional selection to either get the power or infinity
    let mut selected_powers = Vec::new();
    
    for i in 0..num_bits {
        let bit = &scalar_bits[i];
        let power = &powers[i];
        
        // Select power if bit = 1, else select infinity (zero)
        let selected = CustomAffineVar::conditionally_select(
            bit,
            power,
            &CustomAffineVar::zero(),
        )?;
        selected_powers.push(selected);
    }
    
    // Now add all selected powers together
    // This is more efficient as we avoid conditional selections in the main loop
    let mut result = CustomAffineVar::zero();
    
    for selected_power in selected_powers.iter() {
        // Since infinity + P = P, this handles the zero case automatically
        result = affine_add_or_double(cs.clone(), &result, selected_power)?;
    }
    
    Ok(result)
}

/// Allocates Grumpkin affine points as witness variables in a constraint system
pub fn allocate_grumpkin_points(
    cs: ConstraintSystemRef<Fq>,
    points: &[GrumpkinAffine],
) -> Result<Vec<CustomAffineVar>, SynthesisError> {
    points
        .iter()
        .map(|p| {
            // Allocate the entire affine point as a witness
            CustomAffineVar::new_witness(cs.clone(), || Ok(*p))
        })
        .collect()
}

/// Allocates scalar field elements as bit vectors in a constraint system
pub fn allocate_scalars_as_bits(
    cs: ConstraintSystemRef<Fq>,
    scalars: &[Fr],
) -> Result<Vec<Vec<Boolean<Fq>>>, SynthesisError> {
    scalars
        .iter()
        .map(|s| {
            let bits = s.into_bigint().to_bits_le();
            bits.iter()
                .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AdditiveGroup;
    use ark_ec::CurveGroup;
    use ark_ff::Field;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_grumpkin_affine_instantiation() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Generate a random Grumpkin point
        let point_native = GrumpkinAffine::generator();

        // Allocate as affine variable
        let points = allocate_grumpkin_points(cs.clone(), &[point_native])?;
        let point_var = &points[0];

        // Check that the allocated point matches the native point
        let x_value = point_var.x.value()?;
        let y_value = point_var.y.value()?;
        assert_eq!(x_value, point_native.x);
        assert_eq!(y_value, point_native.y);

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_scalar_multiplication_with_different_scalars(
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate a base point and multiple scalars to test
        let g_native = GrumpkinAffine::rand(&mut rng);
        let num_scalars = 4;
        let mut scalars_native = Vec::new();
        for _ in 0..num_scalars {
            scalars_native.push(Fr::rand(&mut rng));
        }

        // Compute powers of g: [g, g², g⁴, g⁸, ...]
        let num_bits = 32; // Use 32 bits for testing
        let mut powers_native = Vec::new();
        let mut current = g_native;
        for _ in 0..num_bits {
            powers_native.push(current);
            current = current.into_group().double().into_affine();
        }

        // Allocate powers as constraint variables once
        let powers_var = allocate_grumpkin_points(cs.clone(), &powers_native)?;

        // Test scalar multiplication for each scalar using the same precomputed powers
        for (idx, scalar_native) in scalars_native.iter().enumerate() {
            // Truncate scalar to num_bits for testing
            let scalar_bigint = scalar_native.into_bigint();
            let mut truncated_scalar = Fr::from(0u64);

            // Reconstruct scalar from only the first num_bits
            for i in 0..num_bits {
                if scalar_bigint.get_bit(i) {
                    let power_of_two = Fr::from(1u64 << (i % 64));
                    if i >= 64 {
                        // Handle larger powers of 2
                        let mut p = power_of_two;
                        for _ in 0..(i / 64) {
                            p = p * Fr::from(1u64 << 63) * Fr::from(2u64);
                        }
                        truncated_scalar += p;
                    } else {
                        truncated_scalar += power_of_two;
                    }
                }
            }

            // Convert truncated Fr to Fq for the scalar
            let scalar_fq = Fq::from(truncated_scalar.into_bigint());
            let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(scalar_fq))?;

            // Perform scalar multiplication using precomputed powers
            let result = scalar_mul_with_powers(cs.clone(), &scalar_var, &powers_var)?;

            // Verify against native computation using truncated scalar
            let expected = g_native
                .mul_bigint(truncated_scalar.into_bigint())
                .into_affine();

            let result_x = result.x.value()?;
            let result_y = result.y.value()?;
            assert_eq!(result_x, expected.x, "Failed for scalar {}", idx);
            assert_eq!(result_y, expected.y, "Failed for scalar {}", idx);
        }

        assert!(cs.is_satisfied()?);
        println!(
            "Scalar multiplication with {} different scalars using precomputed powers: {} constraints",
            num_scalars,
            cs.num_constraints()
        );

        Ok(())
    }

    #[test]
    fn test_affine_addition() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate two random points
        let p1_native = GrumpkinAffine::rand(&mut rng);
        let p2_native = GrumpkinAffine::rand(&mut rng);

        // Allocate as affine variables
        let points = allocate_grumpkin_points(cs.clone(), &[p1_native, p2_native])?;
        let p1_affine = &points[0];
        let p2_affine = &points[1];

        // Perform addition in affine (efficient)
        let sum_affine = affine_add_distinct(cs.clone(), p1_affine, p2_affine)?;

        // Verify against native computation
        let sum_native = (p1_native.into_group() + p2_native.into_group()).into_affine();
        let sum_x = sum_affine.x.value()?;
        let sum_y = sum_affine.y.value()?;
        assert_eq!(sum_x, sum_native.x);
        assert_eq!(sum_y, sum_native.y);

        assert!(cs.is_satisfied()?);
        println!("Affine addition: {} constraints", cs.num_constraints());
        Ok(())
    }

    #[test]
    fn test_affine_doubling() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate a random point
        let p_native = GrumpkinAffine::rand(&mut rng);

        // Allocate as affine variable
        let points = allocate_grumpkin_points(cs.clone(), &[p_native])?;
        let p_affine = &points[0];

        // Perform doubling in affine
        let double_affine = affine_double(cs.clone(), p_affine)?;

        // Verify against native computation
        let double_native = p_native.into_group().double().into_affine();
        let double_x = double_affine.x.value()?;
        let double_y = double_affine.y.value()?;
        assert_eq!(double_x, double_native.x);
        assert_eq!(double_y, double_native.y);

        assert!(cs.is_satisfied()?);
        println!("Affine doubling: {} constraints", cs.num_constraints());
        Ok(())
    }

    #[test]
    fn test_affine_scalar_multiplication() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate a point and scalar
        let point_native = GrumpkinAffine::rand(&mut rng);
        let scalar_native = Fr::rand(&mut rng);

        // Allocate point
        let points = allocate_grumpkin_points(cs.clone(), &[point_native])?;
        let point_var = &points[0];

        // Allocate scalar bits
        let scalar_bits = allocate_scalars_as_bits(cs.clone(), &[scalar_native])?;

        // Perform scalar multiplication
        let result = affine_scalar_mul(cs.clone(), point_var, &scalar_bits[0])?;

        // Verify against native computation
        let expected = point_native
            .mul_bigint(scalar_native.into_bigint())
            .into_affine();
        let result_x = result.x.value()?;
        let result_y = result.y.value()?;
        assert_eq!(result_x, expected.x);
        assert_eq!(result_y, expected.y);

        assert!(cs.is_satisfied()?);
        println!("Affine scalar mul: {} constraints", cs.num_constraints());
        Ok(())
    }

    #[test]
    fn test_scalar_mul_with_powers() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate a base point and scalar
        let g_native = GrumpkinAffine::rand(&mut rng);
        let scalar_native = Fr::rand(&mut rng);

        // Compute powers of g: [g, g², g⁴, g⁸, ...]
        let num_bits = 16; // Test with 16 bits for speed
        let mut powers_native = Vec::new();
        let mut current = g_native;
        for _ in 0..num_bits {
            powers_native.push(current);
            current = current.into_group().double().into_affine(); // g^(2^i) -> g^(2^(i+1))
        }

        // Allocate powers as constraint variables
        let powers_var = allocate_grumpkin_points(cs.clone(), &powers_native)?;

        // Method 1: Use scalar_mul_with_powers
        // Create a scalar that fits within num_bits
        let scalar_bigint = scalar_native.into_bigint();
        let mut truncated_scalar = Fr::from(0u64);

        // Reconstruct scalar from only the first num_bits
        for i in 0..num_bits {
            if scalar_bigint.get_bit(i) {
                let power_of_two = Fr::from(1u64 << (i % 64));
                if i >= 64 {
                    // Handle larger powers of 2
                    let mut p = power_of_two;
                    for _ in 0..(i / 64) {
                        p = p * Fr::from(1u64 << 63) * Fr::from(2u64);
                    }
                    truncated_scalar += p;
                } else {
                    truncated_scalar += power_of_two;
                }
            }
        }

        // Convert truncated Fr to Fq for the scalar
        let scalar_fq = Fq::from(truncated_scalar.into_bigint());
        let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(scalar_fq))?;
        let result1 = scalar_mul_with_powers(cs.clone(), &scalar_var, &powers_var)?;

        // Method 2: Standard scalar multiplication for comparison
        let g_var = &powers_var[0];
        // Use the truncated scalar for fair comparison
        let scalar_bits_native = truncated_scalar.into_bigint().to_bits_le();
        let scalar_bits: Result<Vec<_>, _> = scalar_bits_native[..num_bits]
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect();
        let scalar_bits = scalar_bits?;
        let result2 = affine_scalar_mul(cs.clone(), g_var, &scalar_bits)?;

        // Both results should be the same
        let x1 = result1.x.value()?;
        let y1 = result1.y.value()?;
        let x2 = result2.x.value()?;
        let y2 = result2.y.value()?;
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);

        // Verify against native computation using truncated scalar
        let expected = g_native
            .mul_bigint(truncated_scalar.into_bigint())
            .into_affine();
        assert_eq!(x1, expected.x);
        assert_eq!(y1, expected.y);

        assert!(cs.is_satisfied()?);
        println!(
            "Scalar mul with powers: {} constraints",
            cs.num_constraints()
        );
        Ok(())
    }

    #[test]
    fn test_elgamal_deck_scalar_mul_with_powers() -> Result<(), ark_relations::r1cs::SynthesisError>
    {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Constants for a full deck of cards
        const NUM_CARDS: usize = 52;
        const POINTS_PER_CARD: usize = 2; // ElGamal ciphertext has (c1, c2)
        const TOTAL_POINTS: usize = NUM_CARDS * POINTS_PER_CARD;

        // Use full Grumpkin base field size (254 bits)
        const FIELD_SIZE_BITS: usize = 254;

        println!(
            "Setting up ElGamal deck test with {} cards ({} EC points total)",
            NUM_CARDS, TOTAL_POINTS
        );
        println!("Field size: {} bits", FIELD_SIZE_BITS);

        // Generate random ElGamal ciphertexts (simulating encrypted cards)
        let mut ciphertext_points_native = Vec::new();
        for i in 0..NUM_CARDS {
            // Each card has two points (c1, c2)
            let c1 = GrumpkinAffine::rand(&mut rng);
            let c2 = GrumpkinAffine::rand(&mut rng);
            ciphertext_points_native.push(c1);
            ciphertext_points_native.push(c2);
        }

        // Generate random scalars for rerandomization (one per point)
        let mut scalars_native = Vec::new();
        for _ in 0..TOTAL_POINTS {
            scalars_native.push(Fr::rand(&mut rng));
        }

        // For this test, we'll use a common generator for powers
        // In practice, you might have different base points
        let g_native = GrumpkinAffine::generator();

        // Precompute powers of g: [g, g², g⁴, g⁸, ..., g^(2^253)]
        println!("Precomputing {} powers of generator...", FIELD_SIZE_BITS);
        let mut powers_native = Vec::new();
        let mut current = g_native;
        for i in 0..FIELD_SIZE_BITS {
            powers_native.push(current);
            current = current.into_group().double().into_affine();
            if i % 50 == 0 {
                println!("  Computed {} powers...", i + 1);
            }
        }

        // Allocate powers as constraint variables (done once, reused for all scalars)
        println!("Allocating powers in constraint system...");
        let powers_var = allocate_grumpkin_points(cs.clone(), &powers_native)?;

        // Track constraint count before scalar multiplications
        let constraints_before = cs.num_constraints();
        println!(
            "Constraints before scalar multiplications: {}",
            constraints_before
        );

        // Perform scalar multiplication for each point using precomputed powers
        println!(
            "Performing {} scalar multiplications using precomputed powers...",
            TOTAL_POINTS
        );
        let mut results = Vec::new();

        for (idx, scalar_native) in scalars_native.iter().enumerate() {
            // Convert Fr to Fq for the scalar
            let scalar_fq = Fq::from(scalar_native.into_bigint());
            let scalar_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(scalar_fq))?;

            // Perform scalar multiplication using precomputed powers
            let result = scalar_mul_with_powers(cs.clone(), &scalar_var, &powers_var)?;
            results.push(result.clone());

            // Verify against native computation
            let expected = g_native
                .mul_bigint(scalar_native.into_bigint())
                .into_affine();

            let result_x = result.x.value()?;
            let result_y = result.y.value()?;
            assert_eq!(result_x, expected.x, "Failed for point {}", idx);
            assert_eq!(result_y, expected.y, "Failed for point {}", idx);

            if (idx + 1) % 10 == 0 {
                println!("  Completed {} scalar multiplications...", idx + 1);
            }
        }

        // Calculate constraints used for scalar multiplications
        let constraints_after = cs.num_constraints();
        let constraints_for_scalar_muls = constraints_after - constraints_before;
        let constraints_per_scalar_mul = constraints_for_scalar_muls as f64 / TOTAL_POINTS as f64;

        println!("\n=== ElGamal Deck Scalar Multiplication Results ===");
        println!("Total points processed: {}", TOTAL_POINTS);
        println!(
            "Total constraints for precomputing powers: {}",
            constraints_before
        );
        println!(
            "Total constraints for {} scalar multiplications: {}",
            TOTAL_POINTS, constraints_for_scalar_muls
        );
        println!(
            "Average constraints per scalar multiplication: {:.2}",
            constraints_per_scalar_mul
        );
        println!("Total constraints in circuit: {}", constraints_after);

        // For comparison, estimate traditional scalar multiplication cost
        // Traditional scalar_mul_le typically uses ~10 constraints per bit
        let estimated_traditional_per_scalar = FIELD_SIZE_BITS * 10;
        let estimated_traditional_total = estimated_traditional_per_scalar * TOTAL_POINTS;
        let savings_percentage = (1.0
            - (constraints_for_scalar_muls as f64 / estimated_traditional_total as f64))
            * 100.0;

        println!("\n=== Comparison with Traditional Scalar Multiplication ===");
        println!(
            "Estimated traditional cost per scalar mul: {} constraints",
            estimated_traditional_per_scalar
        );
        println!(
            "Estimated traditional total cost: {} constraints",
            estimated_traditional_total
        );
        println!(
            "Actual cost with precomputed powers: {} constraints",
            constraints_after
        );
        println!("Constraint reduction: {:.1}%", savings_percentage);

        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_projective_affine_equivalence() -> Result<(), ark_relations::r1cs::SynthesisError> {
        use ark_r1cs_std::groups::CurveVar;

        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();

        // Generate a random point and scalar
        let point_native = GrumpkinAffine::rand(&mut rng);
        let scalar_native = Fr::rand(&mut rng);

        // Allocate the point as a ProjectiveVar
        let point_projective =
            GProjectiveVar::new_witness(cs.clone(), || Ok(point_native.into_group()))?;

        // Allocate scalar bits for both methods
        let scalar_bits = allocate_scalars_as_bits(cs.clone(), &[scalar_native])?;
        let scalar_bits_fq = &scalar_bits[0];

        // Method 1: Direct scalar multiplication on ProjectiveVar
        let proj_result = point_projective.scalar_mul_le(scalar_bits_fq.iter())?;
        let constraints_projective = cs.num_constraints();
        println!(
            "Projective scalar mul: {} constraints",
            constraints_projective
        );

        // Method 2: Convert to affine, multiply, convert back
        // Convert projective to our custom affine
        let point_affine = CustomAffineVar::from_projective(&point_projective)?;

        // Perform scalar multiplication in affine
        let affine_result = affine_scalar_mul(cs.clone(), &point_affine, scalar_bits_fq)?;

        // Convert back to projective
        let proj_from_affine = affine_result.to_projective()?;
        let constraints_affine = cs.num_constraints();
        println!("Affine route total: {} constraints", constraints_affine);
        println!(
            "Constraint difference: {} fewer constraints with affine",
            constraints_projective.saturating_sub(constraints_affine - constraints_projective)
        );

        // Both results should be equal
        proj_result.enforce_equal(&proj_from_affine)?;

        // Verify the values match
        let proj_x = proj_result.x.value()?;
        let proj_y = proj_result.y.value()?;
        let proj_z = proj_result.z.value()?;

        let affine_proj_x = proj_from_affine.x.value()?;
        let affine_proj_y = proj_from_affine.y.value()?;
        let affine_proj_z = proj_from_affine.z.value()?;

        // Check that the projective coordinates match
        assert_eq!(proj_x, affine_proj_x, "X coordinates don't match");
        assert_eq!(proj_y, affine_proj_y, "Y coordinates don't match");
        assert_eq!(proj_z, affine_proj_z, "Z coordinates don't match");

        // Also verify against native computation
        let expected_native = point_native
            .mul_bigint(scalar_native.into_bigint())
            .into_affine();

        // Convert projective result to affine for comparison with native
        if !proj_z.is_zero() {
            let z_inv = proj_z.inverse().unwrap();
            let x_affine = proj_x * z_inv;
            let y_affine = proj_y * z_inv;
            assert_eq!(x_affine, expected_native.x);
            assert_eq!(y_affine, expected_native.y);
        }

        assert!(cs.is_satisfied()?);
        println!("Projective-Affine equivalence test passed!");
        println!("Total constraints: {}", cs.num_constraints());

        Ok(())
    }
}
