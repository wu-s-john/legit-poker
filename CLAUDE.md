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
- **Imports**: Place all imports at the top of the file. Do not import within function or block scope, and avoid inserting imports mid-file. Use `use` statements instead of fully qualified paths. If multiple modules export the same symbol, alias to avoid conflicts (e.g., `use foo::Type as FooType;` and `use bar::Type as BarType;`). For TypeScript in the frontend, keep imports at the module top and alias conflicts (`import { Type as FooType } from '...';`).
- **Error Handling**: Use `?` operator for Result and Option types instead of explicit pattern matching. For custom errors, specify the error type and provide tracing for error propagation
- **Functional Iteration**: Always prefer functional constructs (`.map()`, `.filter()`, `.fold()`, etc.) over traditional for loops when iterating collections like vectors or hashmaps
- **Array/Vector Construction**: Strongly prefer functional array construction over mutation. Use `std::array::from_fn()` for arrays or iterator chains with `.collect()` for vectors. Avoid mutable initialization followed by for loops.
  ```rust
  // ❌ AVOID - Mutable array with for loop
  let mut result = [F::zero(); N];
  for i in 0..N {
      result[i] = compute(i);
  }

  // ✅ PREFERRED - Functional array construction
  let result: [F; N] = std::array::from_fn(|i| compute(i));

  // ✅ ALSO GOOD - Iterator chain for arrays (when more complex)
  let result: [F; N] = (0..N)
      .map(|i| compute(i))
      .collect::<Vec<_>>()
      .try_into()
      .unwrap();
  ```
- **Logging**: Use structured logging with tracing modules instead of `println!` for output. Always specify the target when using tracing macros (e.g., `tracing::info!(target = "module_name", "message")` or `tracing::debug!(target = "module_name", "debug info")`). Only use `println!` when implementing a custom Debug trait for a struct.
  - When logging multiple variables, use the `?` operator before variable names to automatically derive Debug formatting, and include descriptive names at the end:
  ```rust
  tracing::debug!(
      target: TEST_TARGET,
      ?blinding_term,
      ?king_blinded_message,
      ?test_recovery,
      points_match,
      "King encryption math verification"
  );
  ```
  This pattern makes logs more readable and allows easy filtering by variable names.

- **Database Queries (Rust)**: Prefer the "seaborn" DSL libraries (SeaORM/SeaQuery) over raw SQL strings for stronger type safety. Avoid building SQL via `format!`/string concatenation; use the ORM/query builder APIs and compile-time checked macros where available.

### Testing Approach
- Unit tests throughout individual crates
- Integration tests via smoke testing scripts
- Benchmark-driven performance validation
- CI/CD with multiple validation stages
- **No Mocking**: Avoid mock objects and mocking frameworks. Instead, use trait-based interfaces with test implementations:
  ```rust
  // ✅ PREFERRED - Trait with test implementation
  trait StorageBackend {
      fn get(&self, key: &str) -> Result<Vec<u8>>;
      fn put(&mut self, key: &str, value: Vec<u8>) -> Result<()>;
  }

  struct TestStorage {
      data: HashMap<String, Vec<u8>>,
  }

  impl StorageBackend for TestStorage {
      fn get(&self, key: &str) -> Result<Vec<u8>> {
          self.data.get(key).cloned().ok_or(Error::NotFound)
      }
      fn put(&mut self, key: &str, value: Vec<u8>) -> Result<()> {
          self.data.insert(key.to_string(), value);
          Ok(())
      }
  }

  // ❌ AVOID - Mock objects
  let mock_storage = MockStorage::new();
  mock_storage.expect_get().returning(|_| Ok(vec![1, 2, 3]));
  ```
  This approach provides better type safety, clearer intent, and easier debugging

### Debugging
- Use `cargo nexus run -v` for detailed VM execution traces
- Profiling macros (`nexus_rt::profile!`) for performance analysis
- Cycle counting for proving cost estimation

### R1CS Constraint System Debugging
When working with arkworks R1CS constraints, follow these best practices:

#### 1. Use Namespaces for Debugging
Always wrap constraint logic in descriptive namespaces using `ns!` macro:
```rust
use ark_relations::{ns, gr1cs::ConstraintSystemRef};

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


# Compiler Error Resolution and Code Context

When fixing compiler errors or searching for code context, **always use the MCP language server tools** first:

## MCP Language Server Tools
The following tools provide efficient, language-aware code analysis:

- **`mcp__language-server__diagnostics`**: Get compiler diagnostics for a specific file
  - Shows all errors, warnings, and hints with line numbers
  - More efficient than running `cargo build` repeatedly

- **`mcp__language-server__definition`**: Find where a symbol is defined
  - Use for resolving "cannot find type" errors
  - Quickly locate struct/trait/function definitions

- **`mcp__language-server__references`**: Find all usages of a symbol
  - Understand how types are used across the codebase
  - Identify all places that need updating when changing a type

- **`mcp__language-server__hover`**: Get type information and documentation
  - Understand what type a variable or expression has
  - View trait implementations and constraints

- **`mcp__language-server__rename_symbol`**: Rename symbols across the codebase
  - Safely rename types, functions, or variables everywhere

- **`mcp__language-server__edit_file`**: Apply precise edits with line numbers
  - More accurate than string-based editing for compiler fixes

### Example Workflow for Compiler Errors:
1. Use `mcp__language-server__diagnostics` to get all errors in a file
2. For "cannot find type" errors, use `mcp__language-server__definition` to locate the type
3. For type mismatch errors, use `mcp__language-server__hover` to understand actual vs expected types
4. Apply fixes using `mcp__language-server__edit_file` with precise line numbers

### Why Use Language Server Tools:
- **Faster**: No need to run full compilation
- **More Accurate**: Language-aware analysis understands Rust semantics
- **Better Context**: Shows related information like trait bounds and implementations
- **Incremental**: Can check single files without building entire project

# Rust Programming types
- If the return type is under a `Result` or and `Option` type, use the `?` operator to propagate errors.

# Domain-Specific Testing Utilities

## Generating Test Data for Card Games

When creating unit tests that require ElGamal ciphertexts for a deck of cards (especially a standard 52-card deck), always use the utility function from `src/shuffling/mod.rs`:

```rust
use crate::shuffling::generate_random_ciphertexts;

// Generate a deck of 52 encrypted cards
let (ciphertexts, randomness) = generate_random_ciphertexts::<G1Projective, 52>(&public_key, &mut rng);
```

This function:
- Creates N ciphertexts with sequential message values (1, 2, ..., N)
- Returns both the ciphertexts and their corresponding randomness values
- Ensures consistent card encoding across all tests (card value = index + 1)
- Is optimized for the poker domain where cards have distinct integer values

**Important**: Never manually create test ciphertexts for card games. Always use this standardized function to ensure:
- Consistent card value encoding
- Proper ElGamal encryption structure
- Reproducible test data when using seeded RNGs

# SNARK Programming Tips

## Elliptic Curve Field Handling

When working with elliptic curve objects, we should make an effort to discern what is scalar field and what is base field. This becomes critically important when working with scalar multiplication on elliptic curves in SNARK circuits.

**Key Principle**: When doing SNARK circuit computations with elliptic curves, we should try to have the scalar fields be base fields. This makes the SNARK circuit cheaper with less constraints and witnesses.

The reason is that we need to break the scalar field value into bits and do scalar multiplication on it. Here's an example of the correct pattern:

```rust
// Convert scalar to bits and perform scalar multiplication
let c_bits = challenge_c.to_bits_le()?;
let b_vector_commitment_scaled = b_vector_commitment.scalar_mul_le(c_bits.iter())?;
```

This approach minimizes circuit complexity by keeping scalar operations in the base field whenever possible.

## AllocVar Implementation

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
        cs: impl Into<gr1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let _span =
            tracing::debug_span!(target: "legit_poker::shuffling::alloc", "alloc_elgamal_ciphertext").entered();

        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Allocate as ProjectiveVar directly
        tracing::trace!(target: "legit_poker::shuffling::alloc", "Allocating c1 ProjectiveVar");
        let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c1),
            mode,
        )?;

        tracing::trace!(target: "legit_poker::shuffling::alloc", "Allocating c2 ProjectiveVar");
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

## Boolean Operations in Circuits

The arkworks `Boolean` type uses trait implementations with standard Rust bitwise operators rather than methods:

```rust
use ark_r1cs_std::boolean::Boolean;

// ✅ CORRECT - Use bitwise operators
let and_result = &bool_a & &bool_b;  // AND operation
let or_result = &bool_a | &bool_b;   // OR operation
let xor_result = &bool_a ^ &bool_b;  // XOR operation
let not_result = !&bool_a;           // NOT operation

// ❌ INCORRECT - These methods don't exist
let and_result = bool_a.and(&bool_b);  // Won't compile
let or_result = bool_a.or(&bool_b);    // Won't compile
```

**Important notes**:
- Always use references with the operators (`&bool_a & &bool_b`)
- These operations generate appropriate constraints automatically
- The operators return `Result<Boolean<F>, SynthesisError>` in constraint contexts
- Use `?` to propagate errors: `let result = (&bool_a & &bool_b)?;`

# SNARK Developer Guidelines: Mirror-First, Safety-First

This section provides comprehensive guidelines for writing SNARK code with native/circuit parity. The core principle: **Write one specification and implement it twice** - a native backend (CPU code) and a circuit backend (constraints). Keep them behaviorally identical and prove they stay in lockstep with tests and logging.

## 0. Scope & Goals

- Produce correct, auditable, and maintainable circuits that exactly mirror the native verifier logic
- Avoid common foot-guns (under-constrained signals, field reinterpretation mistakes, secret-dependent control flow)
- Ship with a robust testing + logging harness so regressions are caught early

## 1. Architecture: "One Spec, Two Backends"

**Rule A1**: Design the verifier once as a pure function over an abstract transcript and abstract group/scalar ops. Then provide:
- **Native backend**: concrete types (PoseidonSponge, G, G::ScalarField)
- **Circuit backend**: gadget types (PoseidonSpongeVar, CurveVar, bit-decomposed scalars or non-native field vars)

This pattern eliminates copy-paste divergence and keeps the native and circuit code literally the same algorithm instantiated over two type families.

## 2. Data Representation & Encoding (Critical)

You will typically have two prime fields:
- **G::ScalarField** (e.g., Fr): used for exponents/scalars (Pedersen, ElGamal, MSMs)
- **G::BaseField** (e.g., Fp): coordinates of curve points, state field of Poseidon sponges, etc.

**Rule D1 (No silent cast)**: Never represent an Fr scalar as an FpVar by "conversion". If Fr != Fp, that is a change of field and can break soundness.

### Preferred Encodings:
- **Scalars (Fr) → bits**: canonical little-endian bit-decomposition with booleanity and exact length checks; feed into scalar_mul_le gadgets
- **Alternative**: Non-native field variables (NonNativeFieldVar<Fr, Fp>) when you truly need field arithmetic over Fr in an Fp circuit (costlier, but sometimes necessary)
- **Points**: affine (x, y) over Fp. Forbid the point at infinity unless explicitly allowed; do subgroup/cofactor checks for public inputs if your curve requires it
- **Transcript**: define one canonical encoding for every absorbed object (point coordinates, scalar bits/limbs, array order, endianness) and use it everywhere

## 3. Constraint Hygiene & Equality Semantics

- Everything you compute must be constrained. Assignments/witness values without constraints are a bug
- **Booleanity & ranges**: enforce `b*(1-b)=0` for bits; for limbs, enforce range via lookups or running sums
- **No secret-dependent branching**: replace `if (secret)` with boolean gating: `out = b*x + (1-b)*y`
- **Equality of points**: use enforce_equal (or constrain both coordinates); do not rely on host-side ==

## 4. Transcript + Challenge Derivation (Determinism)

- Hash the same bytes in the same order on both backends
- Absorb points as (x, y) in an agreed order; absorb scalars as exact bitstrings (or limbs) that the circuit also allocates
- Derive the challenge c identically (same rate/capacity, same squeeze count)
- Add an "audit" mode: log the exact absorbed preimage stream (hex) on both backends and compare byte-for-byte in tests

## 5. Gadget Design Principles

- **Match native function signatures**: e.g., if native does `encrypt_one_and_combine(keys, σ_ρ, C_in, σ_b)`, the gadget should do the same, only with circuit types (points, bits)
- **Expose scalar inputs as bits** (or non-native variables). Provide both fixed-base and variable-base MSM variants with windowing control
- **Use lookups** for small integer and membership checks when your arithmetization supports them

## 6. Testing Strategy (Must-Have)

### Positive Tests
- Random valid instances prove and verify

### Fail-to-Prove (Negative) Tests
For each relation:
- Flip a bit in σ_b[0] → proving must fail
- Swap transcript absorption order → fail
- Alter one ciphertext → fail

### Transcript Snapshot Tests
- Native vs circuit audit logs must match byte-for-byte
- Challenge equality: `c_native == c_circuit.value().unwrap()` for random instances

### Constraint Budget Regression
- Assert constraint counts (per N) to catch accidental bloat

### Property-Based Fuzzing
- Test corner cases (0, 1, max limbs, carries, edge points)

## 7. Performance Guidelines

- Prefer ZK-friendly hashes (Poseidon/Rescue/Griffin) for in-circuit commitments/transcripts
- Minimize public inputs: hash long statements to a short digest inside the circuit; expose only the digest
- Windowed MSMs: configure windows (e.g., 4–6 bits) and reuse decompositions across operations
- Cache shared sub-computations: decompose scalars once, reuse bits across all scalar muls
- If using PLONK-ish stacks, exploit lookups and custom gates for range checks and S-boxes

## 8. Recursion / IVC / Folding (if applicable)

- Keep the step circuit tiny and uniform; expose a compact accumulator/digest in public IO
- Choose recursion-friendly curves (e.g., curve cycles) if you plan to verify proofs inside proofs
- Gate expensive verifier checks carefully and reuse transcript state across steps

## 9. Ops: SRS, Versioning, Domain Separation

- **Groth16**: per-circuit trusted setup; manage keys and toxic waste; re-run if the circuit changes
- **PLONK-ish**: universal SRS; derive per-circuit proving/verifying keys
- **Version everything**: hash circuit sources and keys; include a circuit/version tag as a domain separator in public inputs/transcript

## 10. Example Implementation Patterns

### 10.1 Recommended Allocation (Bits-Based)

```rust
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, prelude::*};

pub struct SigmaProofBitsVar<G, GG, const N: usize>
where
    G: CurveGroup,
    GG: CurveVar<G, G::BaseField>,
{
    pub blinding_factor_commitment: GG,
    pub blinding_rerandomization_commitment: GG,
    pub sigma_response_b_bits: [Vec<Boolean<G::BaseField>>; N],
    pub sigma_response_blinding_bits: Vec<Boolean<G::BaseField>>,
    pub sigma_response_rerand_bits: Vec<Boolean<G::BaseField>>,
}

impl<G, GG, const N: usize> AllocVar<SigmaProof<G, N>, G::BaseField> for SigmaProofBitsVar<G, GG, N>
where
    G: CurveGroup,
    GG: CurveVar<G, G::BaseField>,
{
    fn new_variable<T: Borrow<SigmaProof<G, N>>>(
        cs: impl Into<Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let proof = f()?.borrow().clone();

        let blinding_factor_commitment =
            GG::new_variable(cs.clone(), || Ok(proof.blinding_factor_commitment), mode)?;
        let blinding_rerandomization_commitment =
            GG::new_variable(cs.clone(), || Ok(proof.blinding_rerandomization_commitment), mode)?;

        let alloc_fr_bits = |x: G::ScalarField| -> Result<Vec<Boolean<G::BaseField>>, SynthesisError> {
            let bits_le: Vec<bool> = x.into_bigint().to_bits_le();
            bits_le.into_iter()
                .map(|b| Boolean::new_variable(cs.clone(), || Ok(b), mode))
                .collect()
        };

        let mut tmp: Vec<Vec<Boolean<G::BaseField>>> = Vec::with_capacity(N);
        for i in 0..N {
            tmp.push(alloc_fr_bits(proof.sigma_response_b[i])?);
        }
        let sigma_response_b_bits: [Vec<Boolean<G::BaseField>>; N] = tmp.try_into().unwrap();

        let sigma_response_blinding_bits = alloc_fr_bits(proof.sigma_response_blinding)?;
        let sigma_response_rerand_bits   = alloc_fr_bits(proof.sigma_response_rerand)?;

        Ok(Self {
            blinding_factor_commitment,
            blinding_rerandomization_commitment,
            sigma_response_b_bits,
            sigma_response_blinding_bits,
            sigma_response_rerand_bits,
        })
    }
}
```

### 10.2 Enforcement Pattern

```rust
// 1) Pedersen commitment side:
// Mathematical equation: com(z_b; z_s) = T_com · B^c
let lhs_com = pedersen::commit_bits(&params_var, &sigma_response_b_bits, &sigma_response_blinding_bits)?;
let rhs_com = blinding_factor_commitment.clone()
    + b_vector_commitment.scalar_mul_le(challenge_bits.iter())?;
lhs_com.enforce_equal(&rhs_com)?;

// 2) Group/ciphertext side:
// Mathematical equation: E_pk(1; z_ρ) · ∏ C_j^{z_b[j]} = T_grp · (C'^a)^c
let lhs_grp = elgamal::encrypt_one_and_combine_bits(
    &keys_var,
    &sigma_response_rerand_bits,
    &input_ciphertexts_var,
    &sigma_response_b_bits,
)?;
let rhs_grp = blinding_rerandomization_commitment.clone()
    + (output_agg.c1.clone() + output_agg.c2.clone())
        .scalar_mul_le(challenge_bits.iter())?;
lhs_grp.enforce_equal(&rhs_grp)?;
```

## 11. Logging & Diagnostics (Native/Circuit Sync)

### Log Absorb Events
- Log exactly before every absorb_* call. Emit the preimage encoding (hex) in "audit" builds
- During witness generation, reconstruct the same bytes and log them under the same tag
- Your test harness compares the two logs

### Key Checkpoints
- Log computed aggregators, commitments, derived challenge, and the LHS/RHS of each enforced equality (native side)
- In circuit, expose these as debug witnesses in audit mode if your framework permits

### Example Logging Pattern
```rust
absorb_public_inputs(
    transcript,
    &input_ciphertext_aggregator,
    &output_ciphertext_aggregator,
    b_vector_commitment,
);

tracing::debug!(
    target: LOG_TARGET,
    "Computed input_ciphertext_aggregator: {:?}",
    input_ciphertext_aggregator
);
tracing::debug!(
    target: LOG_TARGET,
    "Computed output_ciphertext_aggregator: {:?}",
    output_ciphertext_aggregator
);
tracing::debug!(
    target: LOG_TARGET,
    "Computed b_vector_commitment: {:?}",
    b_vector_commitment
);
```

## 12. Common Pitfalls & How to Avoid Them

- **Assigned but not constrained** → Always accompany every witness computation with the constraint that forces its value
- **Field confusion (Fr vs Fp)** → Use bits or non-native vars; never "reinterpret cast"
- **Secret-dependent branches** → Replace with boolean selects and gate both branches
- **Unsafe division** → Replace `a/b` with `a * inv(b)` plus a non-zero check gadget
- **Point equality via host ==** → Use gadget equality constraints

## 13. PR & Release Checklists

### PR Checklist
- [ ] No Fr values allocated as FpVar. Scalars are bits or non-native
- [ ] All bits/limbs have boolean/range constraints
- [ ] All equalities are enforced in-circuit (no host comparisons)
- [ ] Transcript encoding documented and used identically in both backends
- [ ] Negative tests cover each enforced relation
- [ ] Constraint counts recorded and compared

### Release Checklist
- [ ] Circuit/key versions bumped and domain-separated
- [ ] Proving/verifying keys re-generated if circuit changed (Groth16)
- [ ] Public input surface area minimized; digests used where possible

## 14. TL;DR (Pin These Rules)

1. **One spec, two backends**
2. **Never cast Fr → FpVar**. Use bits or non-native fields
3. **Fix encodings**. Same byte order and object order for transcript absorption
4. **Constrain everything**. No unconstrained witness values
5. **Test to fail**. Every rule has a negative test
6. **Audit transcripts**. Byte-for-byte logs match across backends
7. **Keep circuits static**. No secret-dependent branches
8. **Minimize public inputs** and version everything

## 15. Transcript and Sponge Usage Guidelines

### Generic Sponge Pattern
When implementing functions that use cryptographic sponges, always use generic type parameters with trait bounds rather than concrete types. This ensures modularity and testability:

```rust
// ✅ CORRECT - Generic sponge with trait bound
fn verify_proof<RO>(
    sponge: &mut RO,
    proof: &Proof,
) -> Result<bool, Error>
where
    RO: CryptographicSponge,
{
    // Implementation
}

// ✅ CORRECT - Circuit version with generic sponge variable
fn verify_proof_gadget<ROVar>(
    sponge: &mut ROVar,
    proof_var: &ProofVar,
) -> Result<Boolean<F>, SynthesisError>
where
    ROVar: CryptographicSpongeVar<F, PoseidonSponge<F>>,
{
    // Circuit implementation
}

// ❌ INCORRECT - Hardcoded concrete type
fn verify_proof(
    sponge: &mut PoseidonSponge<Fr>,
    proof: &Proof,
) -> Result<bool, Error> {
    // Less flexible implementation
}
```

### Curve Absorption
When curve values need to be added to a transcript, use the traits defined in `src/shuffling/curve_absorb.rs`:
- Native: implement `CurveAbsorb` trait
- Circuit: implement `CurveAbsorbGadget` trait

This ensures consistent absorption across native and circuit implementations.
