// Musaed push gateway — lives in the owner's musaed-support project, NOT on any clinic server.
// Clinic servers call it with the shared secret (header x-push-secret):
//   {action:"subscribe", clinic, email, subscription}
//   {action:"notify", clinic, emails:[...], title, body, tag?}
//   {action:"unsubscribe", endpoint}
// GET returns the public VAPID key. VAPID keys are generated on first use and kept in support_config.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import webpush from "npm:web-push@3.6.7";

const URL_ = Deno.env.get("SUPABASE_URL")!;
const KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const H = { apikey: KEY, Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" };
const json = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });

async function cfg(key: string): Promise<string | null> {
  const r = await fetch(`${URL_}/rest/v1/support_config?key=eq.${key}&select=value`, { headers: H });
  const j = await r.json().catch(() => []);
  return Array.isArray(j) && j[0] ? j[0].value : null;
}
async function setCfg(key: string, value: string) {
  await fetch(`${URL_}/rest/v1/support_config`, { method: "POST", headers: { ...H, Prefer: "resolution=ignore-duplicates" }, body: JSON.stringify({ key, value }) });
}
async function vapid() {
  let pub = await cfg("vapid_public"), priv = await cfg("vapid_private");
  if (!pub || !priv) {
    const k = webpush.generateVAPIDKeys();
    await setCfg("vapid_public", k.publicKey); await setCfg("vapid_private", k.privateKey);
    pub = await cfg("vapid_public"); priv = await cfg("vapid_private");
  }
  return { pub: pub!, priv: priv! };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*" } });
  try {
    if (req.method === "GET") return json({ publicKey: (await vapid()).pub });
    const secret = await cfg("push_secret");
    if (!secret || req.headers.get("x-push-secret") !== secret) return json({ error: "forbidden" }, 403);
    const b = await req.json();
    if (b.action === "subscribe") {
      const s = b.subscription;
      if (!b.clinic || !b.email || !s || !s.endpoint) return json({ error: "bad request" }, 400);
      await fetch(`${URL_}/rest/v1/push_subscriptions`, { method: "POST", headers: { ...H, Prefer: "resolution=merge-duplicates" },
        body: JSON.stringify({ endpoint: s.endpoint, clinic: String(b.clinic), email: String(b.email).toLowerCase(), subscription: s, fail_count: 0 }) });
      return json({ ok: true });
    }
    if (b.action === "unsubscribe") {
      await fetch(`${URL_}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(b.endpoint || "")}`, { method: "DELETE", headers: H });
      return json({ ok: true });
    }
    if (b.action === "notify") {
      const emails: string[] = (b.emails || []).map((e: string) => String(e).toLowerCase());
      if (!b.clinic || emails.length === 0) return json({ ok: true, sent: 0 });
      const list = emails.map((e) => `"${e.replace(/"/g, "")}"`).join(",");
      const r = await fetch(`${URL_}/rest/v1/push_subscriptions?clinic=eq.${encodeURIComponent(b.clinic)}&email=in.(${encodeURIComponent(list)})&select=endpoint,subscription`, { headers: H });
      const subs = await r.json();
      if (!Array.isArray(subs) || subs.length === 0) return json({ ok: true, sent: 0 });
      const v = await vapid();
      webpush.setVapidDetails("mailto:support@musaedapp.com", v.pub, v.priv);
      const payload = JSON.stringify({ title: b.title || "Musaed", body: b.body || "", tag: b.tag || "musaed-appointment" });
      let sent = 0;
      await Promise.all(subs.map(async (row: any) => {
        try {
          await webpush.sendNotification(row.subscription, payload, { TTL: 3600 });
          sent++;
          await fetch(`${URL_}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(row.endpoint)}`, { method: "PATCH", headers: H, body: JSON.stringify({ last_ok_at: new Date().toISOString(), fail_count: 0 }) });
        } catch (e: any) {
          if (e && (e.statusCode === 404 || e.statusCode === 410))
            await fetch(`${URL_}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(row.endpoint)}`, { method: "DELETE", headers: H });
        }
      }));
      return json({ ok: true, sent });
    }
    return json({ error: "unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error).message || e) }, 500);
  }
});
