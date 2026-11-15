-- Musaed: base database for a NEW clinic (run ONCE in the clinic's own Supabase SQL editor).
-- Safe to re-run: every statement uses "if not exists". It creates structure only, no data.
-- Taken from the live Empower schema (Nov 2026). Keep server.js identical across clinics.

create table if not exists public.app_sessions (
  token text not null primary key,
  email text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists app_sessions_email_idx on public.app_sessions (email);
create index if not exists app_sessions_expires_at_idx on public.app_sessions (expires_at);

create table if not exists public.appointments (
  id bigint generated always as identity primary key,
  patient_name text not null,
  start_time timestamptz not null,
  end_time timestamptz not null,
  doctor_color text,
  doctor_name text,
  created_at timestamptz default now(),
  notes jsonb default '[]'::jsonb,
  patient_phone text,
  status text not null default 'confirmed',
  paid boolean not null default false,
  visit_type text not null default 'session',
  is_free boolean not null default false,
  cancelled_at timestamptz,
  deleted_at timestamptz,
  arrived_at timestamptz,
  own_patient boolean not null default false
);
create index if not exists appointments_deleted_at_idx on public.appointments (deleted_at);

create table if not exists public.attendance (
  id uuid not null default gen_random_uuid() primary key,
  person_email text not null,
  person_name text,
  day date not null,
  check_in timestamptz not null,
  check_out timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists attendance_day_idx on public.attendance (day);

create table if not exists public.booking_deposits (
  id uuid not null default gen_random_uuid() primary key,
  created_at timestamptz default now(),
  appointment_id text,
  patient_name text,
  phone text,
  doctor_name text,
  visit_label text,
  start_time timestamptz,
  amount integer default 0,
  package_booking boolean default false,
  screenshot_path text,
  status text default 'pending',
  reviewed_at timestamptz
);

create table if not exists public.booking_leads (
  id uuid not null default gen_random_uuid() primary key,
  created_at timestamptz default now(),
  last_seen timestamptz default now(),
  phone_key text unique,
  name text,
  phone text,
  completed boolean default false
);

create table if not exists public.booking_settings (
  id integer not null primary key,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz default now()
);

create table if not exists public.clinic_onboarding (
  id uuid not null default gen_random_uuid() primary key,
  created_at timestamptz not null default now(),
  clinic_name text not null,
  data jsonb not null default '{}'::jsonb
);

create table if not exists public.clinic_settings (
  key text not null primary key,
  value text,
  updated_at timestamptz default now()
);

create table if not exists public.day_reminders (
  id uuid not null default gen_random_uuid() primary key,
  patient_name text not null,
  patient_phone text,
  reminder_date date not null,
  note text,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists day_reminders_date_idx on public.day_reminders (reminder_date);

create table if not exists public.doctor_leaves (
  id uuid not null default gen_random_uuid() primary key,
  doctor_name text not null,
  date date not null,
  kind text not null default 'leave',
  note text,
  created_by text,
  created_at timestamptz not null default now(),
  hours numeric,
  unique (doctor_name, date)
);

create table if not exists public.doctor_unavailability (
  id uuid not null default gen_random_uuid() primary key,
  doctor_name text not null,
  date date not null,
  created_at timestamptz not null default now(),
  unique (doctor_name, date)
);
create index if not exists doctor_unavailability_date_idx on public.doctor_unavailability (date);

create table if not exists public.doctor_withdrawals (
  id uuid not null default gen_random_uuid() primary key,
  doctor_name text not null,
  amount numeric not null,
  payment_method text not null default 'cash',
  withdrawal_date date not null default current_date,
  note text,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists doctor_withdrawals_date_idx on public.doctor_withdrawals (withdrawal_date);

create table if not exists public.doctors (
  id bigint generated always as identity primary key,
  email text not null unique,
  name text,
  role text default 'doctor',
  color text,
  status text default 'pending',
  requested_at timestamptz default now(),
  approved_at timestamptz,
  approved_by text,
  google_refresh_token text,
  password_hash text,
  can_view_dashboard boolean not null default false,
  permissions jsonb not null default '{}'::jsonb,
  phone text,
  telegram_chat_id bigint
);

create table if not exists public.expenses (
  id uuid not null default gen_random_uuid() primary key,
  description text not null,
  amount numeric not null,
  expense_date date not null default current_date,
  created_by text,
  created_at timestamptz not null default now(),
  payment_method text not null default 'cash'
);
create index if not exists expenses_date_idx on public.expenses (expense_date);

create table if not exists public.friday_duty (
  duty_date date not null primary key,
  doctor_email text not null,
  doctor_name text,
  reminder_sent_at timestamptz,
  reminder_error text,
  created_at timestamptz default now(),
  whatsapp_sent_at timestamptz,
  owner_nudged_at timestamptz
);

create table if not exists public.login_log (
  id bigint generated by default as identity primary key,
  created_at timestamptz default now(),
  event text,
  email text,
  ip text,
  device text,
  detail text
);
create index if not exists login_log_created_idx on public.login_log (created_at desc);

create table if not exists public.other_income (
  id uuid not null default gen_random_uuid() primary key,
  description text not null,
  amount numeric not null,
  income_date date not null default current_date,
  payment_method text not null default 'cash',
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists other_income_date_idx on public.other_income (income_date);

create table if not exists public.packages (
  id uuid not null default gen_random_uuid() primary key,
  patient_name text not null,
  total_sessions integer not null,
  used_sessions integer not null default 0,
  created_by text,
  created_at timestamptz not null default now(),
  total_price numeric,
  amount_paid numeric not null default 0,
  policy_sent_at timestamptz,
  followup_status text,
  followup_note text,
  followup_at timestamptz,
  share_token text,
  share_sent_at timestamptz,
  start_date date
);
create unique index if not exists packages_share_token_idx on public.packages (share_token);
create index if not exists packages_patient_name_idx on public.packages (patient_name);

create table if not exists public.patient_intake_forms (
  id uuid not null default gen_random_uuid() primary key,
  patient_name text not null,
  patient_phone text not null,
  chief_complaint text,
  referral_source text,
  matched boolean not null default false,
  submitted_at timestamptz not null default now()
);
create index if not exists patient_intake_forms_name_idx on public.patient_intake_forms (patient_name);

create table if not exists public.payroll_adjustments (
  id uuid not null default gen_random_uuid() primary key,
  doctor_name text not null,
  amount numeric not null,
  adj_date date not null,
  note text,
  created_by text,
  created_at timestamptz not null default now()
);

create table if not exists public.push_subscriptions (
  endpoint text not null primary key,
  email text not null,
  subscription jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists push_subscriptions_email_idx on public.push_subscriptions (email);

create table if not exists public.sessions (
  id text not null primary key,
  patient_name text not null,
  session_date text,
  session_type text,
  transcript jsonb,
  note text,
  doctor_name text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  delete_requested boolean default false,
  delete_requested_by text,
  delete_requested_at timestamptz
);

create table if not exists public.training_applicants (
  id uuid not null default gen_random_uuid() primary key,
  created_at timestamptz not null default now(),
  full_name text not null,
  phone text not null,
  graduation_year integer not null,
  university text,
  area text not null,
  area_other text,
  commute text,
  can_commit_6_days boolean,
  works_elsewhere boolean not null default false,
  works_details text,
  experience text,
  availability text,
  courses text,
  cv_path text,
  cv_name text,
  status text not null default 'new',
  rating integer,
  owner_notes text,
  train_start date,
  train_end date,
  train_shift text,
  confirm_sent_at timestamptz,
  remind_for date,
  train_days text
);

create table if not exists public.transfers (
  id uuid not null default gen_random_uuid() primary key,
  amount numeric not null,
  from_method text not null,
  to_method text not null,
  transfer_date date not null default current_date,
  note text,
  created_by text,
  created_at timestamptz not null default now(),
  doctor_name text
);
create index if not exists transfers_date_idx on public.transfers (transfer_date);

-- Lock every table: only the clinic's own server (service key) can read/write. No public access.
alter table public.app_sessions enable row level security;
alter table public.appointments enable row level security;
alter table public.attendance enable row level security;
alter table public.booking_deposits enable row level security;
alter table public.booking_leads enable row level security;
alter table public.booking_settings enable row level security;
alter table public.clinic_onboarding enable row level security;
alter table public.clinic_settings enable row level security;
alter table public.day_reminders enable row level security;
alter table public.doctor_leaves enable row level security;
alter table public.doctor_unavailability enable row level security;
alter table public.doctor_withdrawals enable row level security;
alter table public.doctors enable row level security;
alter table public.expenses enable row level security;
alter table public.friday_duty enable row level security;
alter table public.login_log enable row level security;
alter table public.other_income enable row level security;
alter table public.packages enable row level security;
alter table public.patient_intake_forms enable row level security;
alter table public.payroll_adjustments enable row level security;
alter table public.push_subscriptions enable row level security;
alter table public.sessions enable row level security;
alter table public.training_applicants enable row level security;
alter table public.transfers enable row level security;

-- Private storage buckets used by the server (images/videos, CVs, deposit screenshots).
insert into storage.buckets (id, name, public) values
  ('session-images', 'session-images', false),
  ('applicant-cvs', 'applicant-cvs', false),
  ('booking-deposits', 'booking-deposits', false)
on conflict (id) do nothing;

-- The server uses the service_role key. New Supabase projects do NOT give service_role rights on
-- tables made in the SQL editor, so without this every request fails with
-- "permission denied for table ...". anon/authenticated get nothing (the app only talks to server.js).
grant usage on schema public to service_role;
grant all on all tables in schema public to service_role;
grant all on all sequences in schema public to service_role;
grant execute on all functions in schema public to service_role;
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;

notify pgrst, 'reload schema';
