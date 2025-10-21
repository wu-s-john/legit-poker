# Legit Poker Backend

This repo hosts the Rust backend for zkPoker, including the ledger operator, coordinator, and supporting binaries.

## Prerequisites

- Rust toolchain (`rustup` recommended)
- Postgres (local Docker `just pg-up` or Supabase dev stack)
- Supabase Realtime credentials when running against the Supabase stack

Before launching any binaries, make sure the environment variables referenced in `.env` are populated. At minimum the server expects:

- `DATABASE_URL` – SeaORM-compatible Postgres connection string
- `SUPABASE_URL` – Supabase REST endpoint (used to derive the realtime URL)
- `SUPABASE_ANON_KEY` – Supabase anon key

## Running the Legit Poker Server

The API server exposes the coordinator via Axum and expects **exactly seven shuffler secrets**. Supply them via the `SERVER_SHUFFLER_SOURCE` environment variable as either:

- JSON array of `{ "id": number, "secret": "0x…" }` entries
- Name of an environment variable containing that JSON (defaults to `SERVER_SHUFFLER_SECRETS`)

If no secrets are provided the binary will deterministically generate seven ephemeral shufflers.

### Using `just`

```bash
just server -- \
  --database-url "$DATABASE_URL" \
  --supabase-url "$SUPABASE_URL" \
  --supabase-anon-key "$SUPABASE_ANON_KEY"
```

Override the bind address with `--bind 0.0.0.0:4000` if needed.

### Using Cargo Directly

```bash
cargo run --bin legit_poker_server -- \
  --database-url "$DATABASE_URL" \
  --supabase-url "$SUPABASE_URL" \
  --supabase-anon-key "$SUPABASE_ANON_KEY" \
  --server-shuffler-source "$SERVER_SHUFFLER_SOURCE"
```

Additional flags:

- `--supabase-realtime-url` – explicit websocket URL (otherwise derived from `SUPABASE_URL`)
- `--server-rng-seed` – seed the RNG for deterministic shuffler sampling
- `--server-log-json` – emit structured JSON logs

On startup the server:

1. Connects to Postgres, wiring SeaORM event/snapshot stores
2. Builds `GameCoordinator<ark_bn254::G1Projective>`
3. Listens on the requested bind address (default `127.0.0.1:4000`)
4. Exposes the snapshot endpoint at `GET /game/{game_id}/hand/{hand_id}/snapshot`

Shutdown is graceful (`Ctrl+C`).
