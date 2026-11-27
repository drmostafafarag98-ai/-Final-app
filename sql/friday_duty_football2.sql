-- Second doctor for the American football match (one male + one female doctor): same columns as friday_duty_football.
-- Run ONCE in the clinic's Supabase SQL editor. Safe to re-run. Adds a new table only; nothing existing is touched.
-- Until this is run, the football match shows just one doctor.
create table if not exists public.friday_duty_football2 (
  duty_date date not null primary key,
  doctor_email text not null,
  doctor_name text,
  reminder_sent_at timestamptz,
  reminder_error text,
  created_at timestamptz default now(),
  whatsapp_sent_at timestamptz,
  owner_nudged_at timestamptz
);
alter table public.friday_duty_football2 enable row level security;
grant all on public.friday_duty_football2 to service_role;
notify pgrst, 'reload schema';
select 'friday_duty_football2 ready';
