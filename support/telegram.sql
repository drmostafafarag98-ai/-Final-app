-- Musaed Support — Telegram alert on each new report (applied in musaed-support).
-- The DB trigger calls the Edge Function support-telegram (support/functions/support-telegram),
-- which reads the bot token from the Edge Function secret TELEGRAM_BOT_TOKEN.
create extension if not exists pg_net;

alter table public.support_reports add column if not exists notified_at timestamptz;

create table if not exists public.support_config (
  key   text primary key,
  value text
);
alter table public.support_config enable row level security;
revoke all on table public.support_config from anon, authenticated;

create or replace function public.support_notify_new_report()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform net.http_post(
    url := 'https://qprxyvvtqhtdzidzrcwi.supabase.co/functions/v1/support-telegram',
    body := jsonb_build_object('id', new.id),
    headers := '{"Content-Type":"application/json"}'::jsonb,
    timeout_milliseconds := 10000
  );
  return new;
end;
$$;
revoke all on function public.support_notify_new_report() from public, anon, authenticated;

create trigger support_reports_notify
  after insert on public.support_reports
  for each row execute function public.support_notify_new_report();

-- The Edge Function uses the service_role key; new projects do not grant it table rights by default.
grant select, insert, update on table public.support_reports to service_role;
grant select, insert, update on table public.support_config to service_role;

-- Daily Telegram nudge at 21:00 Cairo if reports are still waiting (no Claude usage).
-- Runs at 18:00 and 19:00 UTC; only the run that lands at 21:00 Cairo calls the function.
create extension if not exists pg_cron;
select cron.schedule(
  'support-daily-reminder',
  '0 18,19 * * *',
  $$
  select net.http_post(
    url := 'https://qprxyvvtqhtdzidzrcwi.supabase.co/functions/v1/support-telegram',
    body := '{"remind":true}'::jsonb,
    headers := '{"Content-Type":"application/json"}'::jsonb,
    timeout_milliseconds := 15000
  )
  where extract(hour from now() at time zone 'Africa/Cairo') = 21;
  $$
);
