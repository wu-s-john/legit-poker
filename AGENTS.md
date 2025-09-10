# Repository Guidelines

## Project Structure & Module Organization
- Rust crate at `/` (`Cargo.toml`). Source in `src/`; binaries in `src/bin/*` (e.g., `game_demo`, `bayer_groth_demo`).
- Major modules: `domain/`, `game/`, `shuffling/`, `showdown/`, `vrf/`, `gpu/` (optional GPU support).
- Frontend Next.js app in `zk_poker_frontend/`.
- Infra and tooling: `scripts/` (e.g., GPU setup), `supabase/` (config, migrations).

## Build, Test, and Development Commands
- Rust build: `cargo build` (release: `cargo build --release`). Optional GPU: `cargo build --features gpu`.
- Rust run examples: `RUST_LOG=info cargo run --bin game_demo`.
- Rust tests: `cargo test -- --nocapture` (avoid `--release` for faster compiles).
- Frontend setup: `cd zk_poker_frontend && npm install`.
- Frontend dev: `npm run dev` (build: `npm run build`, start: `npm start`, full preview: `npm run preview`).
- Frontend checks: `npm run check` (lint + typecheck), format: `npm run format:write`.

## Coding Style & Naming Conventions
- Rust: Edition 2021. Format with `cargo fmt --all` (check: `cargo fmt --all -- --check`). Use `snake_case` for files/functions, `CamelCase` for types. Prefer `anyhow::Result` and `?`; avoid `unwrap()` outside tests.
- Imports: Always use proper `use` statements at the top of files instead of fully qualified paths. E.g., `use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;` then reference as `PoseidonSpongeVar`, not the full path.
- Functional Rust: favor iterator chains (`map/filter/fold`) and `std::array::from_fn` over mutable loops.
- Tracing: use `tracing` macros with targets and spans. Example: `tracing::info!(target="shuffling", ?deck_id, "reshuffled");` and annotate hot paths with `#[tracing::instrument(skip(..), target="r1cs")]`.
- Linting: `cargo clippy --all-targets --all-features -D warnings` before PRs.
- Frontend: ESLint + Prettier. Run `npm run check`. Components `PascalCase.tsx`, utilities `camelCase.ts`, shared types in `zk_poker_frontend/src/types/`.

## Testing Guidelines
- Rust: Unit tests are colocated (e.g., `mod tests {}`) and in files like `src/vrf/tests.rs`; E2E in `src/showdown/e2e.rs`. Make tests deterministic (fixed RNG seeds), prefer small fixtures. Run: `RUST_LOG=info cargo test -- --nocapture` and avoid `--release` to keep iteration fast.
- Circuit debugging: use namespaces with `ark_relations::ns!` for clear constraint names; debug with `if !cs.is_satisfied()? { cs.which_is_unsatisfied()?; }`. Track size via `cs.num_constraints()`.
- Frontend: No test runner configured; rely on `npm run check` and manual verification. If adding tests, propose tooling in PR.

## Commit & Pull Request Guidelines
- Commits: short, imperative subject (<=72 chars), explain why + what. Group logical changes; avoid noisy diffs.
- PRs: clear description, linked issues, reproduction steps; include screenshots/GIFs for UI changes. Must pass: `cargo fmt`, `cargo build`, `cargo test` and `zk_poker_frontend` `npm run check`.

## Security & Configuration Tips
- Do not commit secrets. Backend reads env via `.env` (dotenv); frontend via `zk_poker_frontend/.env.local`. Supabase schema in `supabase/migrations/`; coordinate on DB changes.

## SNARK Circuit Notes
- Keep gadgets focused and composable; test in isolation before integrating.
- Use constant-string namespaces only (`ns!(cs, "hash_check")`), not dynamic strings.
- Prefer structured logging over `println!`; enable with `RUST_LOG=r1cs=trace,zk_poker=info` during development.
