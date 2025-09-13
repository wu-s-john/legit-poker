# Tasks for zk_poker. Run `just` to list.
# Use bash with strict flags

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Load .env automatically for recipes

set dotenv-load := true

# Default log level for Rust commands if RUST_LOG not set

export RUST_LOG := env_var_or_default("RUST_LOG", "info")

# Database defaults (override via environment)

export DATABASE_URL := env_var_or_default("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:54322/postgres")
export SCHEMA := env_var_or_default("SCHEMA", "public")
export TABLE := env_var_or_default("TABLE", "test")
export PUB := env_var_or_default("PUB", "supabase_realtime")

# Show available tasks
default:
    @just --list

# --- Rust backend ---

# Build Rust (debug)
build:
    cargo build

# Build Rust (release)
build-release:
    cargo build --release

# Build with optional GPU feature
build-gpu:
    cargo build --features gpu

# Run a binary, e.g. `just run game_demo` or `just run bayer_groth_demo`

# Extra args after `--` go to the binary: `just run game_demo -- -vv`
run BIN *ARGS:
    RUST_LOG={{ RUST_LOG }} cargo run --bin {{ BIN }} -- {{ ARGS }}

# Optimized Bayer-Groth demo (release build)
demo:
    echo "Running optimized bayer_groth_demo (release)"
    RUST_LOG={{ RUST_LOG }} cargo run --release --bin bayer_groth_demo

# Tests (no --release; show logs). Pass test filters after `--`.
test *ARGS:
    RUST_LOG={{ RUST_LOG }} cargo test -- --nocapture {{ ARGS }}

# Lint strictly with all targets and features
clippy:
    cargo clippy --all-targets --all-features -D warnings

# Format (check) and format (write)
fmt-check:
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

# One-shot backend dev setup: start Supabase, wait for DB, clear DB, regen Prisma client, apply Prisma+Supabase migrations
# Optional NAME argument forwarded to `migrate` for naming new Prisma migration
backend-setup NAME='':
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Setting up backend dev environment (supabase up, clear DB, prisma migrate, supabase migrate)"
    if ! command -v supabase >/dev/null 2>&1; then
    echo "Supabase CLI not found. Install: https://supabase.com/docs/guides/cli" >&2
    exit 1
    fi
    echo "Ensuring local Supabase stack is running..."
    if ! supabase status -o env >/dev/null 2>&1; then
    supabase start
    else
    echo "Supabase already running."
    fi
    just wait-db
    just prisma-generate
    just db-clean
    just migrate {{ NAME }}

# --- Database / Supabase / Prisma (replaces Makefile) ---

# Start local Supabase stack
supabase-start:
    echo "Starting local Supabase..."
    supabase start

# Show Supabase status and env
supabase-status:
    supabase status -o env

# Generate Prisma client
prisma-generate:
    echo "Generating Prisma client..."
    npx prisma generate

# Run Prisma migrate dev (name overridable). Example: `just prisma-migrate schema_change`
prisma-migrate NAME='init_test':
    echo "Running Prisma migrate dev..."
    echo "Using DATABASE_URL={{ DATABASE_URL }}"
    DATABASE_URL="{{ DATABASE_URL }}" npx prisma migrate dev --name "{{ NAME }}"

# Apply Supabase SQL migrations (local)
supabase-migrate:
    echo "Applying Supabase SQL migrations (local) ..."
    supabase migration up

# Run Prisma migrate, then apply Supabase migrations

# Usage: `just migrate` or `just migrate descriptive_change`
migrate NAME='':
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running Prisma migrate dev (then Supabase migrations)..."
    echo "Using DATABASE_URL={{ DATABASE_URL }}"
    if [[ -n "{{ NAME }}" ]]; then
        DATABASE_URL="{{ DATABASE_URL }}" npx prisma migrate dev --name "{{ NAME }}"
    else
        DATABASE_URL="{{ DATABASE_URL }}" npx prisma migrate dev
    fi
    echo "Applying Supabase SQL migrations..."
    supabase migration up

# Backwards-compat alias
migrate-all NAME='':
    just migrate {{ NAME }}

# Inspect local DB for realtime readiness and applied migrations
inspect-realtime:
    echo "== Publications =="
    psql "{{ DATABASE_URL }}" -At -c 'select pubname, puballtables, pubinsert, pubupdate, pubdelete, pubtruncate from pg_publication;'
    echo "\n== Publication tables (supabase_realtime) =="
    psql "{{ DATABASE_URL }}" -At -c 'select schemaname, tablename from pg_publication_tables where pubname=''supabase_realtime'' order by 1,2;'
    echo "\n== Replica identity (expect f for FULL) =="
    psql "{{ DATABASE_URL }}" -At -c "select c.relname, c.relreplident from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='{{ SCHEMA }}' and c.relkind='r' and c.relname in ('{{ TABLE }}');"
    echo "\n== RLS enabled on {{ SCHEMA }}.{{ TABLE }} =="
    psql "{{ DATABASE_URL }}" -At -c "select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='{{ SCHEMA }}' and c.relname='{{ TABLE }}';"
    echo "\n== Policies on {{ SCHEMA }}.{{ TABLE }} =="
    psql "{{ DATABASE_URL }}" -P pager=off -c "select schemaname, tablename, policyname, cmd, roles, permissive, qual, with_check from pg_policies where schemaname='{{ SCHEMA }}' and tablename='{{ TABLE }}';"
    echo "\n== Prisma migrations (_prisma_migrations) =="
    psql "{{ DATABASE_URL }}" -At -c 'select id, name, to_char(started_at, ''YYYY-MM-DD HH24:MI:SS''), to_char(finished_at, ''YYYY-MM-DD HH24:MI:SS'') from _prisma_migrations order by started_at desc nulls last;' || true
    echo "\n== Supabase migrations registry (if present) =="
    psql "{{ DATABASE_URL }}" -At -c 'select version, name, to_char(applied_at, ''YYYY-MM-DD HH24:MI:SS'') from supabase_migrations.schema_migrations order by applied_at desc;' || true

# Show DB properties for Realtime on a given table
db-props:
    echo "DB URL: {{ DATABASE_URL }}"
    echo "Schema: {{ SCHEMA }}  Table: {{ TABLE }}  Publication: {{ PUB }}"
    echo "\n== Postgres settings =="
    psql "{{ DATABASE_URL }}" -At -c "select 'wal_level='||setting from pg_settings where name='wal_level';"
    echo "\n== Publications =="
    psql "{{ DATABASE_URL }}" -P pager=off -c "select pubname, puballtables, pubinsert, pubupdate, pubdelete, pubtruncate from pg_publication order by pubname;"
    echo "\n== Publication tables ({{ PUB }}) =="
    psql "{{ DATABASE_URL }}" -P pager=off -c "select schemaname, tablename from pg_publication_tables where pubname='{{ PUB }}' order by 1,2;"
    echo "\n== Table replica identity (expect f for FULL) =="
    psql "{{ DATABASE_URL }}" -At -c "select c.relname, c.relreplident from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='{{ SCHEMA }}' and c.relkind='r' and c.relname='{{ TABLE }}';"
    echo "\n== RLS enabled on {{ SCHEMA }}.{{ TABLE }} =="
    psql "{{ DATABASE_URL }}" -At -c "select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='{{ SCHEMA }}' and c.relname='{{ TABLE }}';"
    echo "\n== Policies on {{ SCHEMA }}.{{ TABLE }} =="
    psql "{{ DATABASE_URL }}" -P pager=off -c "select schemaname, tablename, policyname, cmd, roles, permissive, qual, with_check from pg_policies where schemaname='{{ SCHEMA }}' and tablename='{{ TABLE }}';"
    echo "\n== Replication slots (if any) =="
    psql "{{ DATABASE_URL }}" -At -c "select slot_name, plugin, active from pg_replication_slots;" || true

# Run the DB demo (reads .env)
db-demo:
    echo "Running db_demo (ensure .env has DATABASE_URL, SUPABASE_URL, SUPABASE_ANON_KEY)"
    RUST_LOG=db=info cargo run --bin db_demo

# Print DATABASE_URL
print-db-url:
    echo "DATABASE_URL={{ DATABASE_URL }}"

# Clear public.test via SeaORM DSL
db-clean:
    echo "Clearing public.test table via SeaORM DSL..."
    RUST_LOG=db=info cargo run --bin db_clean

# Wait for Postgres to accept connections on DATABASE_URL (timeout seconds)
wait-db TIMEOUT='30':
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Waiting for database at {{ DATABASE_URL }} (timeout: {{ TIMEOUT }}s) ..."
    URL="{{ DATABASE_URL }}"
    URL="${URL#postgresql://}"
    URL="${URL#postgres://}"
    HOSTPORT="${URL#*@}"
    HOSTPORT="${HOSTPORT%%/*}"
    HOST="${HOSTPORT%%:*}"
    PORT="${HOSTPORT##*:}"
    if [[ "${HOSTPORT}" == "${HOST}" ]]; then PORT=5432; fi
    : "${HOST:=127.0.0.1}"
    : "${PORT:=5432}"
    SECS=0
    until (echo > /dev/tcp/${HOST}/${PORT}) >/dev/null 2>&1; do
    sleep 1
    SECS=$((SECS+1))
    if [[ "${SECS}" -ge "{{ TIMEOUT }}" ]]; then
    echo "Database not reachable at ${HOST}:${PORT} after {{ TIMEOUT }}s" >&2
    exit 1
    fi
    done
    echo "Database is up at ${HOST}:${PORT}."



# Lightweight Postgres via Docker for local dev (no Supabase services)
pg-up:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found. Please install Docker Desktop." >&2
    exit 1
    fi
    if docker ps -a --no-trunc | awk 'NR>1{print $NF}' | grep -qx 'zk_poker_pg'; then
    echo "Starting existing container zk_poker_pg..."
    docker start zk_poker_pg >/dev/null
    else
    echo "Launching postgres:15 in container zk_poker_pg on port 54322..."
    docker run -d --name zk_poker_pg -p 54322:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres postgres:15 >/dev/null
    fi
    just wait-db

pg-down:
    #!/usr/bin/env bash
    set -euo pipefail
    if docker ps -a --no-trunc | awk 'NR>1{print $NF}' | grep -qx 'zk_poker_pg'; then
    echo "Stopping and removing zk_poker_pg..."
    docker rm -f zk_poker_pg >/dev/null
    else
    echo "Container zk_poker_pg not found."
    fi

pg-logs:
    #!/usr/bin/env bash
    set -euo pipefail
    if docker ps -a --no-trunc | awk 'NR>1{print $NF}' | grep -qx 'zk_poker_pg'; then
    docker logs -f zk_poker_pg
    else
    echo "Container zk_poker_pg not found. Run 'just pg-up' first." >&2
    exit 1
    fi

# --- Extras ---
# Quick helper for the main game demo
game:
    RUST_LOG={{ RUST_LOG }} cargo run --bin game_demo
