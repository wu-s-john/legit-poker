-- Enable Realtime for public.test and include previous values on updates
alter publication supabase_realtime add table public.test;
alter table public.test replica identity full;
