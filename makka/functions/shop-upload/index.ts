// shop-upload: the shop owner's page sends {pass, image: "data:image/jpeg;base64,..."}.
// Checks the shop password (shop_admin_login, which also counts wrong tries), then stores the
// photo in the public "shop-products" bucket and returns its URL. verify_jwt is off: it does its own check.
import { createClient } from "jsr:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  try {
    const { pass, image } = await req.json();
    if (typeof pass !== "string" || typeof image !== "string") return json({ error: "بيانات ناقصة" }, 400);
    const m = image.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
    if (!m) return json({ error: "نوع الصورة مش مدعوم" }, 400);
    const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
    if (bytes.length > 1024 * 1024) return json({ error: "الصورة كبيرة أوي" }, 400);

    const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data: ok, error: aerr } = await sb.rpc("shop_admin_login", { p_pass: pass });
    if (aerr) return json({ error: "مشكلة في السيرفر" }, 500);
    if (!ok) return json({ error: "كلمة السر غلط" }, 401);

    const ext = m[1] === "jpeg" ? "jpg" : m[1];
    const path = `p/${Date.now()}-${crypto.randomUUID().slice(0, 8)}.${ext}`;
    const { error } = await sb.storage.from("shop-products").upload(path, bytes, {
      contentType: `image/${m[1]}`, cacheControl: "31536000", upsert: false,
    });
    if (error) return json({ error: "الصورة متحفظتش" }, 500);
    const { data } = sb.storage.from("shop-products").getPublicUrl(path);
    return json({ url: data.publicUrl });
  } catch (_e) {
    return json({ error: "حصلت مشكلة" }, 500);
  }
});
