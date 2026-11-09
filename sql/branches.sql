-- Branches (multi-branch clinics). Safe: only ADDS one optional column, changes no data.
-- Run once in the clinic's Supabase SQL editor. Clinics with one branch can skip it.
alter table public.doctors add column if not exists branch text;
