# مُسَاعِد (Musaed) — notes for Claude

## Working with the owner
- Talk to the owner in Egyptian Arabic, simply — they are a physiotherapist, not a developer.
- **Ship changes yourself.** When the owner asks for a change: make it, check it, open a PR, and
  merge it into `main` yourself — do not wait for the owner to press Merge. Then tell them it is
  live and how to test it.
- Still ask first before anything that could delete or corrupt real clinic data
  (database migrations that drop/alter data, bulk deletes, payment/accounting logic rewrites).
- After merging, give the owner a short, safe way to test that does not create fake revenue
  (e.g. open WhatsApp but don't press send).

## How the system is laid out
- This repo is the **frontend shared by all clinics**, served by GitHub Pages at
  `app.musaedapp.com`. Merging to `main` makes a change live for **every** clinic within minutes.
- `clinics.json` maps a clinic code to that clinic's backend URL.
- Each clinic has its own backend (copy of `server.js` on its own Render), its own Supabase and
  its own accounts under the clinic's email. Keep `server.js` identical across clinics.
- Per-clinic differences (booking / HR / team / docs) are feature flags stored in each clinic's
  Supabase `booking_settings.data.features` — not code differences.
- `demo.html` is a separate demo copy with fake data; it is not kept in sync with `index.html`.

## Support system ("عندي مشكلة") — plan and status
Goal: a doctor at any clinic hits a problem while the owner is away, writes it in the app, and
Claude reads it, answers or fixes it, and the doctor sees the reply in the app.

Design (decided with the owner):
- Reports live in the **owner's own Supabase account**, project `musaed-support` — never in a
  clinic's Supabase, so Claude never needs access to patient data. Connect Claude's Supabase
  connector to that account only (not to Empower's).
- The shared frontend talks to it directly with the project's **publishable key** (public by
  design). No `server.js` / Render change is needed, and every clinic gets it automatically.
- `support/schema.sql`: table `support_reports` (RLS on, no policies, no grants to anon) plus two
  security-definer functions the app may call: `submit_support_report` and
  `support_report_status` (a device sees only the replies to the report ids it holds).
- Frontend: `#supportWidget` script at the end of `index.html` — floating "?" button (only when
  signed in), form, list of the doctor's own reports with replies, red dot on new replies; it
  attaches clinic code/name, doctor email/name, current page, user agent and the last 10 JS
  errors. It stays hidden while `SUPPORT_URL` / `SUPPORT_KEY` in that script are empty.

Steps:
1. [done] Schema file + widget code (hidden).
2. [done] Create Supabase account with own email, project `musaed-support`, connect it to Claude.
3. [done] Run `support/schema.sql` in `musaed-support`, put its URL + publishable key in the
   widget, test, merge. Project ref: `qprxyvvtqhtdzidzrcwi` (eu-central-1).
4. [in progress] Telegram alert to the owner on each new report: `support/telegram.sql` (trigger →
   pg_net) → Edge Function `support/functions/support-telegram` (deployed, verify_jwt off, does its
   own checks). Bot `@musaed_support2_bot`; token is the Edge Function secret `TELEGRAM_BOT_TOKEN`
   (never in the repo); owner's chat id is learned from their first message and kept in
   `support_config`.
5. [done, needs Supabase connector added to it by the owner] Scheduled task "Musaed support triage",
   once a day 20:51 Cairo (owner chose: Telegram alert + owner tells Claude "شوف الشكاوى" when busy,
   daily run as a safety net): read `status = 'new'` reports, triage —
   usage question → write `reply`, status `answered`; code bug → fix, PR, merge, write `reply`,
   status `fixed`, `fix_pr_url`; data problem in a clinic / anything risky → status
   `needs_owner` and tell the owner. Reply to doctors in simple Egyptian Arabic.

## Checks before merging
- Extract the inline `<script>` blocks from `index.html` and run `node --check` on each.
- `node --check server.js` if the backend changed.
