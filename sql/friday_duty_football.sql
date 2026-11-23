-- Second Friday event (American football): one doctor per Friday, same columns as friday_duty.
-- Run ONCE in the clinic's Supabase SQL editor. Safe to re-run. Adds a new table only; nothing existing is touched.
-- Until this is run, the Friday event duty page shows just the first event.
create table if not exists public.friday_duty_football (
  duty_date date not null primary key,
  doctor_email text not null,
  doctor_name text,
  reminder_sent_at timestamptz,
  reminder_error text,
  created_at timestamptz default now(),
  whatsapp_sent_at timestamptz,
  owner_nudged_at timestamptz
);
alter table public.friday_duty_football enable row level security;
grant all on public.friday_duty_football to service_role;

-- Empower's four football Fridays (doctors matched by first name; skipped if already there).
insert into public.friday_duty_football (duty_date, doctor_email, doctor_name)
select v.d::date, doc.email, doc.name
from (values ('2026-11-20','menna'),('2026-11-27','omnia'),('2026-12-04','youssef'),('2026-12-11','zeinab')) as v(d,k)
join lateral (
  select email, name from public.doctors
  where status = 'approved' and name ilike '%' || v.k || '%'
  order by id limit 1
) doc on true
on conflict (duty_date) do nothing;

notify pgrst, 'reload schema';

select duty_date, doctor_name from public.friday_duty_football order by duty_date;
