-- Doctors can close part of a day ("not available Saturday after 5"). One-off blocks, one row each.
-- Run ONCE in the clinic's Supabase SQL editor. Safe to re-run. Adds a new table only; nothing existing is touched.
-- Until this is run, the calendar's "Close part of the day" shows a clear message and nothing is blocked.
create table if not exists public.doctor_time_blocks (
  id uuid not null default gen_random_uuid() primary key,
  doctor_name text not null,
  date date not null,
  from_time text not null,
  to_time text not null,
  note text,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists doctor_time_blocks_date_idx on public.doctor_time_blocks (date);
alter table public.doctor_time_blocks enable row level security;
grant all on public.doctor_time_blocks to service_role;
notify pgrst, 'reload schema';
select 'doctor_time_blocks ready' as result;
