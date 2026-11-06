-- Musaed Support — run once in the OWNER's own Supabase project (musaed-support),
-- never in a clinic's project. Holds problem reports sent from the shared app by
-- doctors of every clinic. Contains no patient records by design.
--
-- Security model:
--   * The table has RLS on and NO policies, and anon/authenticated have no table
--     grants: nobody can read or edit reports through the public API.
--   * The app (publishable key) can only call two functions:
--       submit_support_report  -> adds a report, returns its id
--       support_report_status  -> returns status/reply for ids the device already holds
--   * The owner / Claude read and answer reports from the dashboard or connector.

create table if not exists public.support_reports (
  id             uuid primary key default gen_random_uuid(),
  created_at     timestamptz not null default now(),
  clinic_code    text,
  clinic_name    text,
  doctor_email   text,
  doctor_name    text,
  message        text not null,
  page           text,
  user_agent     text,
  app_lang       text,
  app_version    text,
  recent_errors  jsonb,
  status         text not null default 'new'
                 check (status in ('new', 'in_progress', 'answered', 'fixed', 'needs_owner', 'closed')),
  reply          text,
  replied_at     timestamptz,
  internal_notes text,
  fix_pr_url     text
);

create index if not exists support_reports_status_idx  on public.support_reports (status, created_at);
create index if not exists support_reports_created_idx on public.support_reports (created_at);

alter table public.support_reports enable row level security;
revoke all on table public.support_reports from anon, authenticated;

create or replace function public.submit_support_report(
  p_message       text,
  p_clinic_code   text  default null,
  p_clinic_name   text  default null,
  p_doctor_email  text  default null,
  p_doctor_name   text  default null,
  p_page          text  default null,
  p_user_agent    text  default null,
  p_app_lang      text  default null,
  p_app_version   text  default null,
  p_recent_errors jsonb default null
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
  v_msg text := trim(coalesce(p_message, ''));
begin
  if length(v_msg) < 3 then raise exception 'message too short'; end if;
  if length(v_msg) > 4000 then raise exception 'message too long'; end if;

  -- Flood guards: per sender, and overall.
  if (select count(*) from support_reports
        where created_at > now() - interval '1 hour'
          and coalesce(doctor_email, '') = coalesce(p_doctor_email, '')) >= 10 then
    raise exception 'too many reports, try again later';
  end if;
  if (select count(*) from support_reports where created_at > now() - interval '10 minutes') >= 100 then
    raise exception 'support is busy, try again later';
  end if;

  insert into support_reports
    (message, clinic_code, clinic_name, doctor_email, doctor_name, page, user_agent, app_lang, app_version, recent_errors)
  values
    (v_msg,
     left(p_clinic_code, 40), left(p_clinic_name, 120), left(p_doctor_email, 200), left(p_doctor_name, 120),
     left(p_page, 200), left(p_user_agent, 400), left(p_app_lang, 10), left(p_app_version, 40),
     case when p_recent_errors is null or pg_column_size(p_recent_errors) > 20000 then null else p_recent_errors end)
  returning id into v_id;

  return v_id;
end;
$$;

-- Lets a device see the answers to ITS OWN reports (it keeps the ids it got back).
create or replace function public.support_report_status(p_ids uuid[])
returns table (id uuid, created_at timestamptz, message text, status text, reply text, replied_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select r.id, r.created_at, left(r.message, 300), r.status, r.reply, r.replied_at
  from support_reports r
  where r.id = any (p_ids[1:50])
  order by r.created_at desc;
$$;

revoke all on function public.submit_support_report(text, text, text, text, text, text, text, text, text, jsonb) from public;
revoke all on function public.support_report_status(uuid[]) from public;
grant execute on function public.submit_support_report(text, text, text, text, text, text, text, text, text, jsonb) to anon, authenticated;
grant execute on function public.support_report_status(uuid[]) to anon, authenticated;
