//! Common test utilities for SNARK circuit testing

use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSystemRef;

/// Helper function to check if constraint system is satisfied and provide detailed error info
pub fn check_cs_satisfied<F: PrimeField>(cs: &ConstraintSystemRef<F>) -> Result<(), String> {
    match cs.is_satisfied() {
        Ok(true) => Ok(()),
        Ok(false) => {
            // Try to get which constraint is unsatisfied
            match cs.which_is_unsatisfied() {
                Ok(Some(unsatisfied_name)) => {
                    // Find the index if we have constraint names
                    let constraint_names = cs.constraint_names().unwrap_or_default();
                    let index = constraint_names
                        .iter()
                        .position(|name| name == &unsatisfied_name)
                        .map(|i| format!(" at index {}", i))
                        .unwrap_or_default();
                    Err(format!(
                        "Constraint '{}'{} is not satisfied",
                        unsatisfied_name, index
                    ))
                }
                Ok(None) => Err("Constraint system is not satisfied".to_string()),
                Err(e) => Err(format!("Error checking unsatisfied constraint: {:?}", e)),
            }
        }
        Err(e) => Err(format!("Error checking constraint satisfaction: {:?}", e)),
    }
}
