-- Musaed: fix for "permission denied for table ..." on a new clinic.
-- Run ONCE in that clinic's Supabase SQL editor. It only gives the server's key access to the
-- clinic's own tables. It does not change or delete any data. Safe to run again.
grant usage on schema public to service_role;
grant all on all tables in schema public to service_role;
grant all on all sequences in schema public to service_role;
grant execute on all functions in schema public to service_role;
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;
notify pgrst, 'reload schema';
