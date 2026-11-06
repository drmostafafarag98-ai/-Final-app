// Musaed support: sends the owner a Telegram message for each new report.
// Called by the support_reports_notify DB trigger (pg_net) with {"id": "<report id>"}.
// Needs the Edge Function secret TELEGRAM_BOT_TOKEN. The owner's chat id is learned
// once from the first private message sent to the bot and kept in support_config.
// It does its own checking (no JWT): it only announces a real report that was created
// in the last hour and not announced yet, so calling it by hand cannot spam anyone.

const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const TG = Deno.env.get("TELEGRAM_BOT_TOKEN") || "";

const db = (path: string, init: RequestInit = {}) =>
  fetch(`${SB_URL}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json", ...(init.headers || {}) },
  });
const tg = (method: string, body?: unknown) =>
  fetch(`https://api.telegram.org/bot${TG}/${method}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
  }).then((r) => r.json());
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json" } });

async function chatId(): Promise<string | null> {
  const rows = await (await db("support_config?key=eq.telegram_chat_id&select=value")).json();
  if (rows?.[0]?.value) return rows[0].value;
  const upd = await tg("getUpdates", { allowed_updates: ["message"] });
  const msg = (upd.result || []).map((u: any) => u.message).find((m: any) => m?.chat?.type === "private");
  if (!msg) return null;
  const id = String(msg.chat.id);
  await db("support_config", { method: "POST", headers: { Prefer: "resolution=merge-duplicates" },
    body: JSON.stringify({ key: "telegram_chat_id", value: id }) });
  return id;
}

Deno.serve(async (req) => {
  if (!TG) return json({ ok: false, error: "TELEGRAM_BOT_TOKEN missing" }, 500);
  const body = await req.json().catch(() => ({}));

  if (body.setup) {
    const me = await tg("getMe");
    const chat = me.ok ? await chatId() : null;
    return json({ ok: !!me.ok, bot: me.result?.username || null, chat_linked: !!chat });
  }

  if (body.remind) {
    // Daily nudge (pg_cron): only if reports are waiting, and at most once every 20 hours,
    // so calling it by hand cannot spam the owner.
    const last = await (await db("support_config?key=eq.last_reminder&select=value")).json();
    if (last?.[0]?.value && Date.now() - Date.parse(last[0].value) < 20 * 3600_000) return json({ ok: true, skipped: "recent" });
    const rows = await (await db("support_reports?status=in.(new,in_progress,needs_owner)&select=status")).json();
    if (!Array.isArray(rows)) return json({ ok: false, error: rows }, 500);
    const waiting = rows.filter((r: any) => r.status !== "needs_owner").length;
    const owner = rows.length - waiting;
    if (!waiting && !owner) return json({ ok: true, skipped: "none" });
    const chat = await chatId();
    if (!chat) return json({ ok: false, error: "no chat" }, 500);
    let text = "📋 تذكير الشكاوى\n\n";
    if (waiting) text += `• ${waiting} شكوى لسه مستنية رد.\n`;
    if (owner) text += `• ${owner} شكوى محتاجاك انت.\n`;
    text += `\nافتح Claude واكتب "شوف الشكاوى".`;
    const sent = await tg("sendMessage", { chat_id: chat, text });
    if (!sent.ok) return json({ ok: false, error: sent.description }, 502);
    await db("support_config", { method: "POST", headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ key: "last_reminder", value: new Date().toISOString() }) });
    return json({ ok: true, waiting, owner });
  }

  const id = String(body.id || "");
  if (!/^[0-9a-f-]{36}$/.test(id)) return json({ ok: false, error: "bad id" }, 400);
  const since = new Date(Date.now() - 3600_000).toISOString();
  // Claim the report atomically so it is announced once.
  const claimed = await (await db(
    `support_reports?id=eq.${id}&notified_at=is.null&created_at=gte.${since}` +
      "&select=id,clinic_name,clinic_code,doctor_name,doctor_email,page,message",
    { method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify({ notified_at: new Date().toISOString() }) },
  )).json();
  const r = claimed?.[0];
  if (!r) return json({ ok: true, skipped: true });

  const chat = await chatId();
  if (!chat) return json({ ok: false, error: "no chat yet: send the bot a message" }, 500);
  const text =
    `🆘 شكوى جديدة في مُساعِد\n\n` +
    `🏥 ${r.clinic_name || r.clinic_code || "—"}\n` +
    `👤 ${r.doctor_name || "—"}${r.doctor_email ? " (" + r.doctor_email + ")" : ""}\n` +
    `📄 الصفحة: ${r.page || "—"}\n\n` +
    `${String(r.message).slice(0, 3000)}\n\n` +
    `عشان Claude يشتغل عليها: افتح Claude واكتب "شوف الشكاوى".`;
  const sent = await tg("sendMessage", { chat_id: chat, text });
  if (!sent.ok) {
    await db(`support_reports?id=eq.${id}`, { method: "PATCH", body: JSON.stringify({ notified_at: null }) });
    return json({ ok: false, error: sent.description }, 502);
  }
  return json({ ok: true });
});
