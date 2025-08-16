# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build System
The project uses Cargo with a multi-crate workspace structure:

- `cargo build` - Build all workspace members
- `cargo build --release` - Build optimized release version
- `cargo check --all-features` - Fast compilation check with all features
- `cargo check --all-features --examples` - Check examples
- `cargo test -r --all-features` - Run all tests in release mode
- `cargo fmt --all --check` - Check code formatting
- `cargo clippy --all-targets --all-features` - Run linter

### CLI Commands
The project provides a CLI tool `cargo nexus`:

- `cargo nexus new <project>` - Create new Nexus project
- `cargo nexus run` - Execute program in VM
- `cargo nexus run -v` - Execute with verbose trace output
- `cargo nexus prove` - Generate zero-knowledge proof
- `cargo nexus verify` - Verify proof
- `cargo nexus host <project>` - Create host/guest project structure

### Testing Scripts
- `assets/scripts/smoke.sh <file.rs>` - End-to-end smoke test
- `assets/scripts/test_sdk.sh <file.rs>` - SDK integration test

### RISC-V Target
RISC-V programs require the target:
- `rustup target add riscv32i-unknown-none-elf`
- Check RISC-V code: `cargo check -p example --target=riscv32i-unknown-none-elf`

### Benchmarking
- `cargo bench --bench riscv_machine` - VM benchmarks (requires valgrind + iai-callgrind-runner)
- Nova benchmarks in `nova-benches/`: `cd nova-benches && cargo bench`

## High-Level Architecture

### Core Components

**Nexus zkVM** is a modular, highly-parallelized zero-knowledge virtual machine designed for recursive proof systems. The architecture consists of several key layers:

#### 1. Virtual Machine Layer (`vm/`)
- **RISC-V VM Implementation**: Core 32-bit RISC-V virtual machine with custom instruction evaluation
- **Memory System**: Pluggable memory backends (Paged, Trie-based Merkle, Path-based)
- **Execution Tracing**: Generates execution traces for proof generation
- **ELF Loading**: Parses and loads RISC-V ELF binaries

#### 2. Proof Systems (`nova/`, `spartan/`)
- **Nova Implementation**: Recursive folding schemes (Nova, SuperNova, HyperNova)
- **CycleFold Integration**: Folding over cycle of elliptic curves for efficiency
- **Tree Folding**: Parallel execution with tree-structured proof aggregation
- **Spartan**: Optimized polynomial commitment schemes and SNARKs

#### 3. Folding Schemes Architecture
The system implements multiple folding schemes:

- **Nova**: Basic recursive folding with R1CS constraints
- **SuperNova**: Universal machine execution without universal circuits
- **HyperNova**: Folding for Customizable Constraint Systems (CCS)
- **Mangrove Tree Folding**: Operation-based chunking (SHA-256, ECDSA, aggregation) with reduced copy constraints

Key innovation: Uses CCS arithmetization with operation-based chunking instead of uniform chunking to dramatically reduce copy constraints.

#### 4. SDK Layer (`sdk/`)
Provides high-level interfaces for different proof systems:
- **Nova SDK**: Sequential proving interface
- **HyperNova SDK**: Parallel/tree folding interface
- **Jolt SDK**: Experimental Jolt integration
- **Compilation**: Dynamic guest program compilation and linking

#### 5. Network Layer (`network/`)
- **RPC Interfaces**: Client-server communication for distributed proving
- **PCD (Proof-Carrying Data)**: Network-based proof verification
- **Trait Abstractions**: Common interfaces for network operations

### Proof Generation Flow

1. **Compilation**: Guest Rust code → RISC-V ELF binary
2. **Execution**: ELF loaded into VM, execution traced
3. **Chunking**: Trace split into operation-specific chunks (SHA-256, ECDSA, etc.)
4. **Linearization**: CCS instances transformed to LCCS via sum-check protocol
5. **Tree Folding**: Chunks folded into tree structure with parent aggregation
6. **Final Proof**: Single succinct proof for entire computation

### Memory Architecture
- **Paged Memory** (`memory/paged.rs`): Standard paging with configurable page sizes
- **Merkle Trie** (`memory/trie.rs`): Cryptographically authenticated memory
- **Path Memory** (`memory/path.rs`): Optimized for proof generation paths

### Commitment Schemes
- **Pedersen Commitments**: Homomorphic commitments for witness values
- **Poseidon Hashing**: Merkle tree construction and Fiat-Shamir challenges
- **Two-layer Structure**: Pedersen for efficiency + Poseidon for succinctness

### Runtime System (`runtime/`)
- **Syscall Interface**: RISC-V system calls for guest programs
- **Memory Allocation**: Custom allocator for constrained environments
- **Profiling Macros**: Performance tracking and cycle counting

## Key Implementation Details

### CCS vs R1CS
The system primarily uses CCS (Customizable Constraint Systems) which generalize R1CS:
- More expressive constraint types
- Better suited for operation-specific chunking
- Reduced constraint overhead for cryptographic operations

### Elliptic Curve Choices
- **Primary Curve**: BN254/Grumpkin cycle for main computation
- **Secondary Curve**: Pallas/Vesta for CycleFold operations
- **Curve Cycling**: Enables efficient recursive verification

### Parallelization Strategy
- **Block Pool**: Work-stealing scheduler for parallel proving
- **Tree Structure**: Natural parallelism across tree branches
- **Worker Threads**: Configurable thread pool for folding operations

## Development Notes

### Code Organization Philosophy
- **Prefer Additional Functions**: Even when not explicitly requested, create helper functions to improve code clarity and maintainability
- **Modular Design**: Break complex operations into smaller, well-named functions
- **Separate Files**: Create additional files when it improves code organization, even if not specifically asked for
- **Readability Over Brevity**: Prioritize code that is easy to understand over minimal line counts

### Rust Coding Guidelines
- **Error Handling**: Use `?` operator for Result and Option types instead of explicit pattern matching. For custom errors, specify the error type and provide tracing for error propagation
- **Functional Iteration**: Always prefer functional constructs (`.map()`, `.filter()`, `.fold()`, etc.) over traditional for loops when iterating collections like vectors or hashmaps
- **Logging**: Use structured logging with tracing modules instead of `println!` for output. Always specify the target when using tracing macros (e.g., `tracing::info!(target = "module_name", "message")` or `tracing::debug!(target = "module_name", "debug info")`). Only use `println!` when implementing a custom Debug trait for a struct.

### Testing Approach
- Unit tests throughout individual crates
- Integration tests via smoke testing scripts
- Benchmark-driven performance validation
- CI/CD with multiple validation stages

### Debugging
- Use `cargo nexus run -v` for detailed VM execution traces
- Profiling macros (`nexus_rt::profile!`) for performance analysis
- Cycle counting for proving cost estimation

### R1CS Constraint System Debugging
When working with arkworks R1CS constraints, follow these best practices:

#### 1. Use Namespaces for Debugging
Always wrap constraint logic in descriptive namespaces using `ns!` macro:
```rust
use ark_relations::{ns, r1cs::ConstraintSystemRef};

fn my_gadget<F: Field>(cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
    let cs = ns!(cs, "my_gadget");

    // Nested namespaces for sub-operations
    let cs_hash = ns!(cs, "hash_check");
    cs_hash.enforce_constraint(a, b, c)?;

    Ok(())
}
```

**Important**: The `ns!` macro requires compile-time string constants. Do not use it for simple witness allocations or with dynamic strings:
```rust
// ✅ CORRECT - string literals only
let cs = ns!(cs, "permutation_check");
let cs_inner = ns!(cs, "inner_computation");

// ❌ INCORRECT - dynamic strings not allowed
let name = format!("index_{}", i);
let cs = ns!(cs, name); // Compilation error!

// ❌ INCORRECT - don't use for simple witness allocation
let value = FpVar::new_variable(ns!(cs, "witness"), || Ok(x), mode); // Unnecessary overhead
```

#### 2. Identify Failing Constraints
Use these methods to pinpoint constraint failures:
```rust
if !cs.is_satisfied()? {
    let idx = cs.which_is_unsatisfied()?.unwrap();
    let names = cs.constraint_names().unwrap();
    println!("unsatisfied @{}: {}", idx, names[idx]);
}
```

#### 3. Debugging Best Practices
- **Small Test Harness**: Create minimal tests with `ConstraintSystemRef::new_ref()`
- **Concrete Witness Values**: Use `assigned_value(var)` to inspect field elements
- **Structured Tracing**: Add `#[tracing::instrument(target = "r1cs", skip(cs, ...))]` to functions
- **Keep std Feature**: Use `std` feature during debugging, strip for production
- **Unit Test Gadgets**: Test each gadget in isolation with known inputs
- **Property-Based Testing**: Use randomized inputs to find edge cases
- **In-Circuit Assertions**: Add `assert_eq!` checks during development

#### 4. Example Debug Output
With proper namespacing, failures show clear paths:
```
unsatisfied @42: root/my_gadget/hash/check_padding/enforce( lc_17 * lc_18 = lc_19 )
```

#### 5. Performance Monitoring
- Use `cs.num_constraints()` and `cs.num_witness_variables()` to track circuit size
- Call `to_matrices()` for deeper structural analysis
- Enable `RUST_LOG=r1cs=trace` for detailed constraint tracing

### Adding New Operations
1. Implement CCS constraints for the operation
2. Add to chunking strategy in tree folding
3. Create corresponding gadgets for verification circuits
4. Update SDK interfaces as needed

### Security Considerations
- All commitment schemes are computationally binding
- Random oracle model for Fiat-Shamir transforms
- Proper domain separation for hash functions
- Careful soundness error analysis for finite field operations


# Rust Programming types
- If the return type is under a `Result` or and `Option` type, use the `?` operator to propagate errors.

# SNARK Programming Tips

- When you are allocating variables, you should try to implement by implementing the trait `AllocVar`. Here is an example:

```rust
pub struct ElGamalCiphertextVar<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub c1: ProjectiveVar<G, FpVar<G::BaseField>>,
    pub c2: ProjectiveVar<G, FpVar<G::BaseField>>,
}

impl<G: SWCurveConfig> AllocVar<ElGamalCiphertext<Projective<G>>, G::BaseField>
    for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ElGamalCiphertext<Projective<G>>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let _span =
            tracing::debug_span!(target: "shuffle::alloc", "alloc_elgamal_ciphertext").entered();

        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Allocate as ProjectiveVar directly
        tracing::trace!(target: "shuffle::alloc", "Allocating c1 ProjectiveVar");
        let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c1),
            mode,
        )?;

        tracing::trace!(target: "shuffle::alloc", "Allocating c2 ProjectiveVar");
        let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c2),
            mode,
        )?;

        Ok(Self { c1, c2 })
    }
}

```

- When trying to enforce a constraint, please first write a comment about it expressing the mathematical equation that you are trying to enforce. This will help you understand what you are trying to enforce and will also help you debug any issues that may arise.
- When enforcing a constraint, please use `cs.enforce_constraint` rather than `expression.enforce_equal`. It makes it cleaner what is on the left-hand side of the equation and the right-hand side.
