Local DB + Supabase Migrations + Realtime (Rust)

Prereqs
- Docker and Supabase CLI installed
- Rust toolchain

1) Start Supabase locally
  supabase init
  supabase start
  supabase status -o env   # note DB URL, API URL, ANON/SERVICE keys

2) Configure environment
  # .env (repo root)
  DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"
  SUPABASE_URL="http://127.0.0.1:54321"
  SUPABASE_ANON_KEY="<from supabase status -o env>"

3) Apply schema via Supabase migrations
  # Single migration creates public.test and enables Realtime on it:
  #   supabase/migrations/20250914090000_init_schema.sql
  # For a clean, idempotent local setup, reset the DB to match local migrations:
  supabase db reset  # WARNING: resets local DB and runs all SQL in supabase/migrations

4) (Optional) Re-apply migrations without reset (not recommended when linked to remote)
  supabase migration up

5) Run the Rust demo
  RUST_LOG=db=info cargo run --bin db_demo

What the demo does
- Inserts one row (foo=1, bar=10, baz=100)
- Updates foo from 1->2 using SeaORM DSL
- Updates bar to 11
- Prints INSERT/UPDATE events with before/after via Supabase Realtime WS

Notes
- All database writes use SeaORM’s type-safe DSL. No raw SQL is used in Rust.
- Supabase migrations own both DDL for the test table and Realtime configuration (publication + replica identity).
