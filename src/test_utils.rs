//! Common test utilities for SNARK circuit testing

use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSystemRef;
use tracing_subscriber::{filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

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

/// Standardized tracing setup for tests.
///
/// - Writes to the test writer so logs appear with `cargo test`
/// - Includes file and line numbers
/// - Emits `ENTER` span events for better tracing of instrumented functions
/// - Uses an uptime timer for readable timestamps
pub fn setup_test_tracing(log_target: &str) -> tracing::subscriber::DefaultGuard {
    let filter = filter::Targets::new().with_target(log_target, tracing::Level::DEBUG);
    let timer = tracing_subscriber::fmt::time::uptime();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::ENTER)
                .with_test_writer()
                .with_file(true)
                .with_timer(timer)
                .with_line_number(true),
        )
        .with(filter)
        .set_default()
}
