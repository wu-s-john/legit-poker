-- Initial schema and Realtime setup (Supabase-only migrations)
-- This migration replaces prior Prisma-managed DDL.
-- Applies cleanly on a fresh Supabase local instance.

BEGIN;

-- Core demo table used by src/bin/db_demo.rs and SeaORM entity src/db/entity/test.rs
-- Keep definition in sync with Rust model: foo (PK), bar, baz as integers.
create table if not exists public.test (
  foo integer primary key,
  bar integer not null,
  baz integer not null
);

-- Enable Realtime on public.test and include previous values on updates
-- Supabase local provides the publication `supabase_realtime`.
alter publication supabase_realtime add table public.test;
alter table public.test replica identity full;

COMMIT;

