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

## Checks before merging
- Extract the inline `<script>` blocks from `index.html` and run `node --check` on each.
- `node --check server.js` if the backend changed.
