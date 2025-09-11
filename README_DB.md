Local DB + Prisma + Realtime (Rust)

Prereqs
- Docker and Supabase CLI installed
- Node (for Prisma CLI), Rust toolchain

1) Start Supabase locally
  supabase init
  supabase start
  supabase status -o env   # note DB URL, API URL, ANON/SERVICE keys

2) Configure environment
  # .env (repo root)
  DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"
  SUPABASE_URL="http://127.0.0.1:54321"
  SUPABASE_ANON_KEY="<from supabase status -o env>"

3) Apply Prisma schema
  npm i -D prisma && npm i @prisma/client
  npx prisma generate
  npx prisma migrate dev --name init_test

4) Enable Realtime on the table
This repo includes a Supabase migration:
  supabase/migrations/20250911115900_enable_realtime_test.sql
Run it via Supabase SQL editor or:
  supabase db reset   # WARNING: resets local DB and runs migrations in supabase/migrations

5) Run the Rust demo
  RUST_LOG=db=info cargo run --bin db_demo

What the demo does
- Inserts one row (foo=1, bar=10, baz=100)
- Updates foo from 1->2 using SeaORM DSL
- Updates bar to 11
- Prints INSERT/UPDATE events with before/after via Supabase Realtime WS

Notes
- All database writes use SeaORM’s type-safe DSL. No raw SQL is used in Rust.
- Prisma owns DDL for the test table; Supabase migration only configures Realtime publication + replica identity.

