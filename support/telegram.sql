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
