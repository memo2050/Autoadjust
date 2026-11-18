import { parseDemoRequest, storeBlockReason, makeLimiter } from "../../../lib/demo/request";

// Public endpoint: stores a "Request a Demo" form in public.demo_requests.
// Everything is enforced HERE on the server: same-origin check, size cap, validation + honeypot, per-IP and global rate limits,
// environment-isolation guard, and the service-role key (server env only; never sent to the browser, never in a response or log).
export const dynamic = "force-dynamic";
const allow = makeLimiter(5, 200, 3600_000);
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

export async function POST(req: Request) {
  const origin = req.headers.get("origin"), host = req.headers.get("host");
  if (origin) { let ok = false; try { ok = !!host && new URL(origin).host === host; } catch {} if (!ok) return json({ error: "Forbidden." }, 403); }
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) return json({ error: "Invalid request." }, 415);
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "anon";
  if (!allow(ip)) return json({ error: "Too many requests. Please try again later." }, 429);
  let text = ""; try { text = await req.text(); } catch { return json({ error: "Invalid request." }, 400); }
  if (text.length > 8192) return json({ error: "Request too large." }, 413);
  let body: unknown; try { body = JSON.parse(text); } catch { return json({ error: "Invalid request." }, 400); }
  const p = parseDemoRequest(body);
  if (!p.ok) return json({ error: p.error }, 400);
  if (storeBlockReason(process.env)) return json({ error: "Demo requests are not enabled on this site yet." }, 503);
  const url = process.env.SUPABASE_URL!, key = process.env.SUPABASE_SERVICE_ROLE_KEY!;
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
