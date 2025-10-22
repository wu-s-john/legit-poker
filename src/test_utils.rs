//! Common test utilities for SNARK circuit testing

use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSystemRef;

/// Helpers shared across test modules.
pub mod serde {
    use std::fmt::Debug;

    /// Assert that a value survives a serde_json round-trip using structural equality.
    pub fn assert_round_trip_eq<T>(value: &T)
    where
        T: ::serde::Serialize + ::serde::de::DeserializeOwned + PartialEq + Debug,
    {
        let json = serde_json::to_string(value)
            .expect("serialization should succeed during round-trip testing");
        let restored: T = serde_json::from_str(&json)
            .expect("deserialization should succeed during round-trip testing");
        assert_eq!(restored, *value, "serde_json round-trip altered the value");
    }

    /// Assert that serde_json emits the same payload before and after round-tripping.
    pub fn assert_round_trip_json<T>(value: &T)
    where
        T: ::serde::Serialize + ::serde::de::DeserializeOwned,
    {
        let json = serde_json::to_value(value)
            .expect("serialization to value should succeed during round-trip testing");
        let restored: T = serde_json::from_value(json.clone())
            .expect("deserialization from value should succeed during round-trip testing");
        let json_after = serde_json::to_value(restored)
            .expect("re-serialization should succeed during round-trip testing");
        assert_eq!(
            json_after, json,
            "serde_json round-trip altered the payload"
        );
    }
}

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
                        .map(|i| format!(" at index {i}"))
                        .unwrap_or_default();
                    Err(format!(
                        "Constraint '{unsatisfied_name}'{index} is not satisfied"
                    ))
                }
                Ok(None) => Err("Constraint system is not satisfied".to_string()),
                Err(e) => Err(format!("Error checking unsatisfied constraint: {e:?}")),
            }
        }
        Err(e) => Err(format!("Error checking constraint satisfaction: {e:?}")),
    }
}
