//! Field conversion utilities for converting between base field and scalar field representations
//!
//! This module provides gadgets for converting field elements between the base field
//! (used in circuit constraints) and the scalar field (used for elliptic curve operations).

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    prelude::{ToBitsGadget, ToBytesGadget},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Type alias for the constraint field (base prime field)
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Convert a base field element to a scalar field element with its bit representation
///
/// This function takes a base field element (typically from a Poseidon sponge squeeze),
/// converts it to bytes, then interprets those bytes as a scalar field element modulo
/// the scalar field order. It also returns the bit representation for use in scalar
/// multiplication gadgets.
///
/// # Arguments
/// * `cs` - Constraint system reference
/// * `base_field_elem` - The base field element to convert
///
/// # Returns
/// * Tuple of (scalar_field_var, bits) where:
///   - scalar_field_var is the EmulatedFpVar representing the scalar
///   - bits is the little-endian bit decomposition for scalar multiplication
pub fn base_to_scalar_with_bits<C>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    base_field_elem: &FpVar<ConstraintF<C>>,
) -> Result<
    (
        EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
        Vec<Boolean<ConstraintF<C>>>,
    ),
    SynthesisError,
>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
    ConstraintF<C>: PrimeField,
{
    // Convert base field element to bytes
    let bytes = base_field_elem.to_bytes_le()?;

    // Create scalar field element from bytes (mod scalar field order)
    let scalar = EmulatedFpVar::<C::ScalarField, ConstraintF<C>>::new_witness(cs, || {
        // Extract byte values for witness generation
        let byte_values = bytes
            .iter()
            .map(|b| b.value().unwrap_or_default())
            .collect::<Vec<u8>>();
        Ok(C::ScalarField::from_le_bytes_mod_order(&byte_values))
    })?;

    // Get bit decomposition for scalar multiplication
    let bits = scalar.to_bits_le()?;

    Ok((scalar, bits))
}

/// Convert a base field element to a scalar field element
///
/// This is a simpler version that only returns the scalar field element
/// without the bit decomposition.
///
/// # Arguments
/// * `cs` - Constraint system reference
/// * `base_field_elem` - The base field element to convert
///
/// # Returns
/// * The scalar field element as an EmulatedFpVar
pub fn base_to_scalar<C>(
    cs: ConstraintSystemRef<ConstraintF<C>>,
    base_field_elem: &FpVar<ConstraintF<C>>,
) -> Result<EmulatedFpVar<C::ScalarField, ConstraintF<C>>, SynthesisError>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
    ConstraintF<C>: PrimeField,
{
    let (scalar, _) = base_to_scalar_with_bits::<C>(cs, base_field_elem)?;
    Ok(scalar)
}

/// Convert a scalar field element to base field elements (native version)
///
/// This function converts a scalar field element to a vector of base field elements.
/// It converts via bytes, with each byte becoming a separate field element.
///
/// # Arguments
/// * `scalar` - The scalar field element to convert
///
/// # Returns
/// * Vector of base field elements representing the scalar
pub fn scalar_to_base_field_elements<F: PrimeField, S: PrimeField>(scalar: &S) -> Vec<F> {
    let scalar_bytes = scalar.into_bigint().to_bytes_le();
    scalar_bytes
        .iter()
        .map(|byte| F::from(*byte as u64))
        .collect()
}

/// Convert a scalar field element to base field elements (gadget version)
///
/// This function converts a scalar field element (in EmulatedFpVar form) to
/// a vector of base field elements. It converts via bytes, with each byte
/// becoming a separate field element.
///
/// # Arguments
/// * `scalar` - The scalar field element to convert
///
/// # Returns
/// * Vector of base field elements representing the scalar
pub fn scalar_to_base_field_elements_gadget<C>(
    scalar: &EmulatedFpVar<C::ScalarField, ConstraintF<C>>,
) -> Result<Vec<FpVar<ConstraintF<C>>>, SynthesisError>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
    ConstraintF<C>: PrimeField,
{
    // Convert scalar to bytes
    let scalar_bytes = scalar.to_bytes_le()?;

    // Convert each byte to a field element
    let field_elements = scalar_bytes
        .iter()
        .map(|byte| {
            // Convert UInt8 to field element value
            let bits = byte.to_bits_le()?;
            let mut value = FpVar::zero();
            let mut power = FpVar::one();
            for bit in bits.iter().take(8) {
                let bit_fe = FpVar::from(bit.clone());
                value += &bit_fe * &power;
                power.double_in_place()?;
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(field_elements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr};
    use ark_ff::{BigInteger, UniformRand};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    type TestCurve = ark_bn254::G1Projective;

    #[test]
    fn test_base_to_scalar_conversion() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Create a random base field element
        let base_value = Fq::rand(&mut rng);
        let base_var = FpVar::new_witness(cs.clone(), || Ok(base_value)).unwrap();

        // Convert to scalar field
        let (scalar_var, bits) =
            base_to_scalar_with_bits::<TestCurve>(cs.clone(), &base_var).unwrap();

        // Check that we got bits (the exact number depends on the implementation)
        assert!(!bits.is_empty());

        // Verify the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Check that the scalar value matches expectation
        let scalar_value = scalar_var.value().unwrap();
        let expected = Fr::from_le_bytes_mod_order(&base_value.into_bigint().to_bytes_le());
        assert_eq!(scalar_value, expected);
    }

    #[test]
    fn test_scalar_to_base_native() {
        let mut rng = test_rng();

        // Create a random scalar field element
        let scalar_value = Fr::rand(&mut rng);

        // Convert to base field elements (native)
        let base_elements: Vec<Fq> = scalar_to_base_field_elements(&scalar_value);

        // Check that we got the expected number of field elements (one per byte)
        let scalar_bytes = scalar_value.into_bigint().to_bytes_le();
        assert_eq!(base_elements.len(), scalar_bytes.len());

        // Verify each element matches the corresponding byte
        for (i, elem) in base_elements.iter().enumerate() {
            let expected = Fq::from(scalar_bytes[i] as u64);
            assert_eq!(*elem, expected);
        }
    }

    #[test]
    fn test_scalar_to_base_gadget() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Create a random scalar field element
        let scalar_value = Fr::rand(&mut rng);
        let scalar_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(scalar_value)).unwrap();

        // Convert to base field elements (gadget)
        let base_elements = scalar_to_base_field_elements_gadget::<TestCurve>(&scalar_var).unwrap();

        // Check that we got the expected number of field elements (one per byte)
        let scalar_bytes = scalar_value.into_bigint().to_bytes_le();
        assert_eq!(base_elements.len(), scalar_bytes.len());

        // Verify each element matches the corresponding byte
        for (i, elem) in base_elements.iter().enumerate() {
            let elem_value = elem.value().unwrap();
            let expected = Fq::from(scalar_bytes[i] as u64);
            assert_eq!(elem_value, expected);
        }

        // Verify the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_native_gadget_consistency() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Create a random scalar field element
        let scalar_value = Fr::rand(&mut rng);

        // Native conversion
        let native_elements: Vec<Fq> = scalar_to_base_field_elements(&scalar_value);

        // Gadget conversion
        let scalar_var =
            EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(scalar_value)).unwrap();
        let gadget_elements =
            scalar_to_base_field_elements_gadget::<TestCurve>(&scalar_var).unwrap();

        // Verify they produce the same results
        assert_eq!(native_elements.len(), gadget_elements.len());
        for (native_elem, gadget_elem) in native_elements.iter().zip(gadget_elements.iter()) {
            let gadget_value = gadget_elem.value().unwrap();
            assert_eq!(*native_elem, gadget_value);
        }

        // Verify the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
