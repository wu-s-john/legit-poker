//! LogUp lookup argument implementation for R1CS
//!
//! This module provides a LogUp-based lookup gadget for proving that a set of query values
//! all belong to a lookup table, using the logarithmic derivative technique.
//!
//! The core identity being proved is:
//! Σ_j 1/(α - y_j) = Σ_i μ_i/(α - x_i)
//! where y_j are query values, x_i are table entries, and μ_i are multiplicities.

use ark_ff::PrimeField;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    cmp::CmpGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
    GR1CSVar,
};

/// Verifies a LogUp lookup argument with a single challenge.
///
/// # Arguments
/// * `cs` - The constraint system
/// * `alpha` - The challenge point
/// * `table_entries` - Distinct table values that are actually used (X_used)
/// * `query_values` - All queried values (Y)
/// * `multiplicities` - Counts for each table entry (MU), must have same length as table_entries
///
/// # Constraints
/// - Enforces table_entries.len() == multiplicities.len()
/// - Enforces Σ multiplicities = query_values.len()
/// - Enforces LogUp equality: Σ 1/(α-y_j) = Σ μ_i/(α-x_i)
pub fn verify_lookup<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    alpha: &FpVar<F>,
    table_entries: &[FpVar<F>],
    query_values: &[FpVar<F>],
    multiplicities: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    // Validate input lengths
    if table_entries.len() != multiplicities.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let n_used = table_entries.len();
    let m = query_values.len();

    if m == 0 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // 1. Range check multiplicities and compute sum
    let m_bound = UInt8::constant(m as u8);
    let mut mu_sum = FpVar::<F>::zero();

    for mu in multiplicities.iter() {
        // Range check: 0 <= mu <= m
        let is_valid = mu.is_le(&m_bound)?;
        is_valid.enforce_equal(&Boolean::constant(true))?;

        // Add to sum
        mu_sum += uint_to_field(mu)?;
    }

    // Enforce sum of multiplicities equals m
    let m_fp = FpVar::<F>::constant(F::from(m as u64));
    mu_sum.enforce_equal(&m_fp)?;

    // 2. Compute denominators and inverses for table entries
    let table_denominators = compute_denominators(alpha, table_entries)?;
    let table_inverses = compute_and_constrain_inverses(cs.clone(), &table_denominators)?;

    // 3. Compute denominators and inverses for query values
    let query_denominators = compute_denominators(alpha, query_values)?;
    let query_inverses = compute_and_constrain_inverses(cs, &query_denominators)?;

    // 4. Compute LogUp sums
    // S_T = Σ_i (μ_i * inv_d_i)
    let mut s_t = FpVar::<F>::zero();
    for i in 0..n_used {
        let mu_fp = uint_to_field(&multiplicities[i])?;
        s_t += mu_fp * &table_inverses[i];
    }

    // S_F = Σ_j inv_e_j
    let mut s_f = FpVar::<F>::zero();
    for inv in query_inverses.iter() {
        s_f += inv;
    }

    // 5. Enforce LogUp equality
    s_t.enforce_equal(&s_f)?;

    Ok(())
}

/// Range check that multiplicity is within bounds [0, max_value].
pub fn range_check_multiplicity<F: PrimeField>(
    mu: &UInt8<F>,
    max_value: u8,
) -> Result<Boolean<F>, SynthesisError> {
    let max_const = UInt8::constant(max_value);
    mu.is_le(&max_const)
}

/// Convert unsigned integer to field element.
pub fn uint_to_field<F: PrimeField>(uint_val: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    // UInt8 has 8 bits, convert via weighted sum
    let mut result = FpVar::<F>::zero();
    let mut power = F::one();

    for bit in uint_val.bits.iter() {
        let bit_fp = FpVar::<F>::from(bit.clone());
        result += bit_fp * power;
        power.double_in_place();
    }

    Ok(result)
}

/// Compute denominators (alpha - x_i) for a set of values.
pub fn compute_denominators<F: PrimeField>(
    alpha: &FpVar<F>,
    values: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut denominators = Vec::with_capacity(values.len());
    for val in values {
        denominators.push(alpha - val);
    }
    Ok(denominators)
}

/// Compute and constrain inverses for denominators.
/// Enforces den * inv = 1 for each denominator.
pub fn compute_and_constrain_inverses<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    denominators: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    denominators
        .iter()
        .map(|den| {
            // Witness the inverse
            let inv = FpVar::new_witness(cs.clone(), || {
                den.value()
                    .map(|d| d.inverse().unwrap_or(F::zero()))
            })?;
            
            // Enforce den * inv = 1
            (den * &inv).enforce_equal(&FpVar::<F>::one())?;
            
            Ok(inv)
        })
        .collect()
}

/// Allocate multiplicities as UInt8 variables.
pub fn new_multiplicity_vars<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    values: &[u8],
    mode: AllocationMode,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut vars = Vec::with_capacity(values.len());
    for &val in values {
        let var = UInt8::new_variable(cs.clone(), || Ok(val), mode)?;
        vars.push(var);
    }
    Ok(vars)
}

/// Allocate table entries as field variables.
pub fn new_table_vars<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    values: &[F],
    mode: AllocationMode,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut vars = Vec::with_capacity(values.len());
    for &val in values {
        let var = FpVar::new_variable(cs.clone(), || Ok(val), mode)?;
        vars.push(var);
    }
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_test_curves::bls12_381::Fr;

    #[test]
    fn test_logup_happy_path() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Table: [2, 7], Queries: [7, 2, 2]
        // MU: [2, 1], alpha: 10
        // Mathematical check: 1/(10-7) + 1/(10-2) + 1/(10-2) = 2/(10-2) + 1/(10-7)
        // = 1/3 + 1/8 + 1/8 = 2/8 + 1/3 = 1/4 + 1/3 = 7/12

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries (X_used)
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values (Y)
        let query_values = vec![
            FpVar::constant(Fr::from(7u64)),
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
        ];

        // Multiplicities (MU)
        let multiplicities = vec![UInt8::constant(2u8), UInt8::constant(1u8)];

        // This should succeed
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_wrong_multiplicity_sum() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values (3 queries)
        let query_values = vec![
            FpVar::constant(Fr::from(7u64)),
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
        ];

        // Wrong multiplicities: [1, 1] sums to 2, not 3
        let multiplicities = vec![UInt8::constant(1u8), UInt8::constant(1u8)];

        // This should fail
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_wrong_multiplicity_distribution() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values
        let query_values = vec![
            FpVar::constant(Fr::from(7u64)),
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
        ];

        // Wrong distribution: [3, 0] sums to 3 but wrong distribution
        let multiplicities = vec![UInt8::constant(3u8), UInt8::constant(0u8)];

        // This should fail the LogUp equality
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_value_not_in_table() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries: [2, 5, 7]
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(5u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values include 9 which is not in table
        let query_values = vec![
            FpVar::constant(Fr::from(7u64)),
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(9u64)), // Not in table!
        ];

        // Any valid multiplicities that sum to 3
        let multiplicities = vec![
            UInt8::constant(1u8),
            UInt8::constant(1u8),
            UInt8::constant(1u8),
        ];

        // This should fail - no way to satisfy LogUp equality
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_zero_denominator_collision() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Set alpha = 7, which will collide with query value 7
        let alpha = FpVar::constant(Fr::from(7u64));

        // Table entries
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values include 7
        let query_values = vec![
            FpVar::constant(Fr::from(7u64)), // alpha - y_0 = 0!
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
        ];

        let multiplicities = vec![UInt8::constant(2u8), UInt8::constant(1u8)];

        // This should fail - inverse constraint fails for zero denominator
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_range_check_overflow() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries
        let table_entries = vec![FpVar::constant(Fr::from(2u64))];

        // 3 query values
        let query_values = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(2u64)),
        ];

        // Multiplicity exceeds m=3
        let multiplicities = vec![UInt8::constant(5u8)]; // 5 > 3

        // This should fail range check
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_empty_table() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Empty table
        let table_entries: Vec<FpVar<Fr>> = vec![];

        // Query values
        let query_values = vec![FpVar::constant(Fr::from(2u64))];

        // Empty multiplicities
        let multiplicities: Vec<UInt8<Fr>> = vec![];

        // This should succeed trivially - no table entries needed if multiplicities is also empty
        // But the sum of multiplicities (0) won't equal query count (1)
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_mismatched_lengths() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Table entries: 2 elements
        let table_entries = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];

        // Query values
        let query_values = vec![FpVar::constant(Fr::from(2u64))];

        // Multiplicities: 3 elements (mismatch!)
        let multiplicities = vec![
            UInt8::constant(1u8),
            UInt8::constant(0u8),
            UInt8::constant(0u8),
        ];

        // This should fail immediately due to length mismatch
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_single_element_lookup() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let alpha = FpVar::constant(Fr::from(10u64));

        // Single table entry
        let table_entries = vec![FpVar::constant(Fr::from(5u64))];

        // Single query
        let query_values = vec![FpVar::constant(Fr::from(5u64))];

        // Multiplicity of 1
        let multiplicities = vec![UInt8::constant(1u8)];

        // This should succeed
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_witness_mode() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Use witness mode for all variables
        let alpha = FpVar::new_witness(cs.clone(), || Ok(Fr::from(10u64))).unwrap();

        // Table entries as witnesses
        let table_entries = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap(),
        ];

        // Query values as witnesses
        let query_values = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
        ];

        // Multiplicities as witnesses
        let multiplicities = vec![
            UInt8::new_witness(cs.clone(), || Ok(2u8)).unwrap(),
            UInt8::new_witness(cs.clone(), || Ok(1u8)).unwrap(),
        ];

        // This should succeed even with witness variables
        let result = verify_lookup(
            cs.clone(),
            &alpha,
            &table_entries,
            &query_values,
            &multiplicities,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_helper_functions() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test range_check_multiplicity
        let mu = UInt8::<Fr>::constant(3u8);
        let in_range = range_check_multiplicity(&mu, 5u8).unwrap();
        assert_eq!(in_range.value().unwrap(), true);

        let out_of_range = range_check_multiplicity(&mu, 2u8).unwrap();
        assert_eq!(out_of_range.value().unwrap(), false);

        // Test uint_to_field
        let uint_val = UInt8::<Fr>::constant(42u8);
        let field_val = uint_to_field(&uint_val).unwrap();
        assert_eq!(field_val.value().unwrap(), Fr::from(42u64));

        // Test compute_denominators
        let alpha = FpVar::constant(Fr::from(10u64));
        let values = vec![
            FpVar::constant(Fr::from(2u64)),
            FpVar::constant(Fr::from(7u64)),
        ];
        let denoms = compute_denominators(&alpha, &values).unwrap();
        assert_eq!(denoms[0].value().unwrap(), Fr::from(8u64)); // 10 - 2
        assert_eq!(denoms[1].value().unwrap(), Fr::from(3u64)); // 10 - 7

        // Test compute_and_constrain_inverses
        let inverses = compute_and_constrain_inverses(cs.clone(), &denoms).unwrap();
        assert_eq!(
            inverses[0].value().unwrap(),
            Fr::from(8u64).inverse().unwrap()
        );
        assert_eq!(
            inverses[1].value().unwrap(),
            Fr::from(3u64).inverse().unwrap()
        );

        assert!(cs.is_satisfied().unwrap());
    }
}