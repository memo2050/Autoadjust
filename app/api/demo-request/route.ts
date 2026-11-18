import { parseDemoRequest } from "../../../lib/demo/request";

// Public endpoint: stores a "Request a Demo" form. Writes only to public.demo_requests with the server-side service key; the browser never sees a key.
const hits = new Map<string, { t: number; n: number }>();
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
  const now = Date.now(), h = hits.get(ip);
  const n = h && now - h.t < 3600_000 ? h.n : 0;
  if (n >= 5) return json({ error: "Too many requests. Please try again later." }, 429);
  hits.set(ip, { t: h && now - h.t < 3600_000 ? h.t : now, n: n + 1 });
  if (hits.size > 5000) hits.clear();
  let body: unknown;
  try { body = await req.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const p = parseDemoRequest(body);
  if (!p.ok) return json({ error: p.error }, 400);
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return json({ error: "Demo requests are not enabled on this site yet." }, 503);
  try {
    const r = await fetch(url.replace(/\/$/, "") + "/rest/v1/demo_requests", {
      method: "POST",
      headers: { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ ...p.value, source: "website" }),
    });
    if (!r.ok) return json({ error: "Could not save your request. Please try again." }, 502);
    return json({ ok: true });
  } catch { return json({ error: "Could not save your request. Please try again." }, 502); }
}
