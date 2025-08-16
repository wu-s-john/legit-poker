#[cfg(test)]
mod profiling_tests {
    use super::*;
    use std::time::Instant;
    
    // Method 1: Manual timing with spans
    #[test]
    fn profile_with_manual_timing() {
        use std::collections::HashMap;
        let mut timings = HashMap::new();
        
        // Time config generation
        let start = Instant::now();
        let config = poseidon_config::<Fr>();
        timings.insert("poseidon_config", start.elapsed());
        
        // Time constraint system creation
        let start = Instant::now();
        let cs = ConstraintSystem::<Fr>::new_ref();
        timings.insert("cs_creation", start.elapsed());
        
        // Time sponge creation
        let start = Instant::now();
        let sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        timings.insert("sponge_creation", start.elapsed());
        
        // Print sorted timings
        let mut sorted: Vec<_> = timings.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        
        println!("\n=== Timing Results ===");
        for (name, duration) in sorted {
            println!("{}: {:?}", name, duration);
        }
    }
    
    // Method 2: Using tracing spans with timing
    #[tracing::instrument(target = "profile", level = "info")]
    fn expensive_operation() {
        let _span = tracing::info_span!(target: "profile", "poseidon_config").entered();
        let config = poseidon_config::<Fr>();
        drop(_span);
        
        let _span = tracing::info_span!(target: "profile", "sponge_operations").entered();
        // ... operations
    }
    
    // Method 3: Criterion benchmarks (add to Cargo.toml: criterion = "0.5")
    // Create benches/poseidon_bench.rs:
    /*
    use criterion::{black_box, criterion_group, criterion_main, Criterion};
    
    fn bench_poseidon_config(c: &mut Criterion) {
        c.bench_function("poseidon_config", |b| {
            b.iter(|| {
                let config = poseidon_config::<Fr>();
                black_box(config);
            });
        });
    }
    
    criterion_group!(benches, bench_poseidon_config);
    criterion_main!(benches);
    */
    
    // Method 4: Memory profiling with stats
    #[test]
    fn profile_memory_usage() {
        use ark_std::perf_trace::{start_timer, end_timer};
        
        let timer = start_timer!(|| "Total execution");
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        println!("Initial constraints: {}", cs.num_constraints());
        println!("Initial witness vars: {}", cs.num_witness_variables());
        
        // Do operations...
        
        println!("Final constraints: {}", cs.num_constraints());
        println!("Final witness vars: {}", cs.num_witness_variables());
        
        end_timer!(timer);
    }
}

// Method 5: Using cargo flamegraph
// Install: cargo install flamegraph
// Run: cargo flamegraph --test test_name
// This generates flamegraph.svg

// Method 6: Using perf (Linux) or Instruments (macOS)
// macOS: instruments -t "Time Profiler" target/release/test_binary
// Linux: perf record --call-graph=dwarf cargo test test_name
//        perf report

// Method 7: Add custom profiling macros
#[macro_export]
macro_rules! profile_section {
    ($name:expr, $body:expr) => {{
        let start = std::time::Instant::now();
        let result = $body;
        let duration = start.elapsed();
        tracing::info!(
            target: "profile",
            section = $name,
            duration_ms = duration.as_millis(),
            "Section completed"
        );
        result
    }};
}

// Usage:
// let config = profile_section!("poseidon_config", {
//     poseidon_config::<Fr>()
// });