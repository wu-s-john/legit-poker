/// Macro for tracking constraints and witnesses for a code block
#[macro_export]
macro_rules! track_constraints {
    ($cs:expr, $operation_name:expr, $log_target:expr, $code:expr) => {{
        let cs = $cs;
        let initial_constraints = cs.num_constraints();
        let initial_witnesses = cs.num_witness_variables();

        let result = $code;

        let added_constraints = cs.num_constraints() - initial_constraints;
        let added_witnesses = cs.num_witness_variables() - initial_witnesses;

        tracing::info!(
            target: $log_target,
            operation = $operation_name,
            constraints_added = added_constraints,
            witnesses_added = added_witnesses,
            "Constraint tracking"
        );

        result
    }};
}
