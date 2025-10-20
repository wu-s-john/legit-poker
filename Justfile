# Tasks for zk_poker. Run `just` to list.
# Use bash with strict flags

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Load .env automatically for recipes

set dotenv-load := true

# Default log level for Rust commands if RUST_LOG not set

export RUST_LOG := env_var_or_default("RUST_LOG", "info")

# Database defaults (override via environment)

export DATABASE_URL := env_var_or_default("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:54322/postgres")
export TEST_DATABASE_URL := env_var_or_default(
    "TEST_DATABASE_URL",
    env_var_or_default("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:54322/postgres")
)
export SCHEMA := env_var_or_default("SCHEMA", "public")
export TABLE := env_var_or_default("TABLE", "test")
export PUB := env_var_or_default("PUB", "supabase_realtime")

# SeaORM entity generation defaults
export SEAORM_OUT_DIR := env_var_or_default("SEAORM_OUT_DIR", "src/db/entity")
export SEAORM_SCHEMA := env_var_or_default("SEAORM_SCHEMA", "public")
# Default flags: derive serde on models, use `time` crate for DateTime, expanded format
export SEAORM_FLAGS := env_var_or_default(
    "SEAORM_FLAGS",
    "--with-serde both --date-time-crate time --expanded-format",
)
export SEAORM_IGNORE_TABLES := env_var_or_default("SEAORM_IGNORE_TABLES", "")

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

# One-shot backend dev setup: start Supabase, wait for DB, apply Supabase SQL migrations
backend-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Setting up backend dev environment (supabase up, apply migrations)"
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
    echo "Resetting local database and applying migrations (idempotent)..."
    # Reset ensures local DB matches supabase/migrations even if prior remote-linked versions exist
    # Uses seed configured in supabase/config.toml if present
    supabase db reset --local --yes

# --- Database / Supabase (replaces Makefile) ---

# Start local Supabase stack
supabase-start:
    echo "Starting local Supabase..."
    supabase start

# Show Supabase status and env
supabase-status:
    supabase status -o env

# Apply Supabase SQL migrations (local)
supabase-migrate:
    echo "Applying Supabase SQL migrations (local) ..."
    supabase migration up

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

# Truncate ledger tables to ensure a clean demo run
reset-ledger:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v psql >/dev/null 2>&1; then
        echo "psql not found. Install Postgres client tools." >&2
        exit 1
    fi
    echo "Truncating ledger tables on {{ DATABASE_URL }}"
    psql "{{ DATABASE_URL }}" <<'SQL'
        TRUNCATE TABLE
            public.table_snapshots,
            public.phases,
            public.hand_player,
            public.hand_configs,
            public.events,
            public.hand_shufflers,
            public.hands
        RESTART IDENTITY CASCADE;
    SQL
    echo "Ledger tables truncated."

# Dump schema-only SQL to stdout using a Postgres 17 client container
dump-schema:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker not found. Install Docker Desktop or adjust the dump command." >&2
        exit 1
    fi
    # Resolve DATABASE_URL components
    URL="{{ DATABASE_URL }}"
    URL="${URL#postgresql://}"
    URL="${URL#postgres://}"
    CREDS="${URL%%@*}"
    HOSTPORT_DB="${URL#*@}"
    HOSTPORT="${HOSTPORT_DB%%/*}"
    DBNAME="${HOSTPORT_DB#*/}"
    USER="${CREDS%%:*}"
    PASS="${CREDS#*:}"
    HOST="${HOSTPORT%%:*}"
    PORT="${HOSTPORT##*:}"
    if [[ "${HOSTPORT}" == "${HOST}" ]]; then
        PORT=5432
    fi
    case "${HOST}" in
        127.0.0.1|localhost) HOST_INSIDE="host.docker.internal" ;;
        *) HOST_INSIDE="${HOST}" ;;
    esac
    docker run --rm \
        -e PGPASSWORD="${PASS}" \
        postgres:17 \
        pg_dump -h "${HOST_INSIDE}" -p "${PORT}" -U "${USER}" -d "${DBNAME}" \
        --schema-only --no-owner

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

# Debug helper to dump a game's hand archive
debug-ledger-hand game hand include-events="true" include-snapshots="true":
    #!/usr/bin/env bash
    set -euo pipefail
    cmd=(cargo run --bin debug_ledger_hand -- --game {{ game }} --hand {{ hand }})
    if [[ "{{ include-events }}" != "true" ]]; then
        cmd+=(--no-include-events)
    fi
    if [[ "{{ include-snapshots }}" != "true" ]]; then
        cmd+=(--no-include-snapshots)
    fi
    RUST_LOG={{ RUST_LOG }} "${cmd[@]}"

# --- SeaORM entities ---

# Install SeaORM generator CLI
seaorm-install VERSION='':
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ VERSION }}" ]]; then
        echo "Installing sea-orm-cli version {{ VERSION }} ..."
        cargo install sea-orm-cli --version "{{ VERSION }}"
    else
        echo "Installing sea-orm-cli (latest) ..."
        cargo install sea-orm-cli
    fi

# Show installed sea-orm-cli version
seaorm-version:
    sea-orm-cli --version

# Generate entities from the database schema.
# Uses Supabase DB URL if available; falls back to $DATABASE_URL or default local URL.
gen-entities:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v sea-orm-cli >/dev/null 2>&1; then
        echo "sea-orm-cli not found. Install it with: just seaorm-install" >&2
        exit 1
    fi
    # Resolve DATABASE_URL from Supabase status when available
    if command -v supabase >/dev/null 2>&1 && supabase status >/dev/null 2>&1; then
        # Extract DB_URL line and export as DATABASE_URL (keeps surrounding quotes)
        eval "$(supabase status -o env | awk -F= '/^DB_URL=/{print "export DATABASE_URL=" $2}')"
    else
        : "${DATABASE_URL:=${DATABASE_URL:-postgresql://postgres:postgres@127.0.0.1:54322/postgres}}"
    fi
    mkdir -p "{{ SEAORM_OUT_DIR }}"
    echo "Generating SeaORM entities from $DATABASE_URL (schema={{ SEAORM_SCHEMA }}) -> {{ SEAORM_OUT_DIR }}"
    EXTRA=""
    if [[ -n "{{ SEAORM_IGNORE_TABLES }}" ]]; then
        EXTRA="--ignore-tables {{ SEAORM_IGNORE_TABLES }}"
    fi
    sea-orm-cli generate entity \
        -u "$DATABASE_URL" \
        -s "{{ SEAORM_SCHEMA }}" \
        -o "{{ SEAORM_OUT_DIR }}" \
        {{ SEAORM_FLAGS }} \
        $EXTRA
    echo "✓ SeaORM entities regenerated at {{ SEAORM_OUT_DIR }}"

# Clean and regenerate entities (removes existing generated files first)
gen-entities-fresh:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -d "{{ SEAORM_OUT_DIR }}" ]]; then
        echo "Removing existing entities at {{ SEAORM_OUT_DIR }} ..."
        rm -rf "{{ SEAORM_OUT_DIR }}"/*
    fi
    just gen-entities
