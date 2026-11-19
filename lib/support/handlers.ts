import { answer } from "./kb";
import { parseTicket, newRef, newToken, hashToken, tokenMatches, validRef, validToken, ticketBlockReason, supabaseStore, type TicketStore } from "./tickets";
import { makeLimiter } from "../demo/request";
import { clientIp, sameOrigin } from "../analyze/guard";
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
export interface Deps { env: NodeJS.ProcessEnv; store?: TicketStore; userId?: (req: Request) => Promise<string | null> }
async function body(req: Request, max: number): Promise<{ b?: unknown; err?: Response }> {
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) return { err: json({ error: "invalid" }, 415) };
  let t = ""; try { t = await req.text(); } catch { return { err: json({ error: "invalid" }, 400) }; }
  if (t.length > max) return { err: json({ error: "too_large" }, 413) };
  try { return { b: JSON.parse(t) }; } catch { return { err: json({ error: "invalid" }, 400) }; }
}
export function createSupportHandlers(d: Deps) {
  const hops = Math.max(1, Number(d.env.TRUSTED_PROXY_HOPS) || 1);
  const chatLim = makeLimiter(30, 2000, 3600_000), mkLim = makeLimiter(5, 200, 3600_000), readLim = makeLimiter(30, 2000, 3600_000);
  const store = () => d.store ?? supabaseStore(d.env);
  const gate = (req: Request) => (sameOrigin(req.headers) ? null : json({ error: "forbidden" }, 403));
  return {
    async chat(req: Request) {
      const g = gate(req); if (g) return g; if (!chatLim(clientIp(req.headers, hops))) return json({ error: "rate_limited" }, 429);
      const r = await body(req, 2048); if (r.err) return r.err; const q = (r.b as any)?.message;
      if (typeof q !== "string" || !q.trim() || q.length > 500) return json({ error: "invalid" }, 400);
      return json({ ...answer(q, (r.b as any)?.lang === "ar" ? "ar" : (r.b as any)?.lang === "en" ? "en" : undefined), ticketsEnabled: ticketBlockReason(d.env) === null });
    },
    async create(req: Request) {
      const g = gate(req); if (g) return g; if (!mkLim(clientIp(req.headers, hops))) return json({ error: "rate_limited" }, 429);
      const r = await body(req, 8192); if (r.err) return r.err;
      const p = parseTicket(r.b); if (!p.ok) return json({ error: p.error }, 400);
      if (ticketBlockReason(d.env)) return json({ error: "not_enabled" }, 503);
      const ref = newRef(), token = newToken();
      try { await store().create(p.value, ref, hashToken(token), d.userId ? await d.userId(req) : null); } catch { return json({ error: "store_failed" }, 502); }
      return json({ ok: true, ref, token, status: "open" }, 201);   // the token is shown ONCE; only its hash is stored
    },
    /** body: { ref, token, reply? } — view a ticket; with `reply`, add a customer message. */
    async track(req: Request) {
      const g = gate(req); if (g) return g; if (!readLim(clientIp(req.headers, hops))) return json({ error: "rate_limited" }, 429);
      const r = await body(req, 8192); if (r.err) return r.err; const { ref, token, reply } = (r.b ?? {}) as any;
      if (!validRef(ref) || !validToken(token)) return json({ error: "not_found" }, 404);   // same answer for bad format, unknown ref and wrong token
      if (ticketBlockReason(d.env)) return json({ error: "not_enabled" }, 503);
      try {
        const t = await store().find(ref);
        if (!t || !tokenMatches(token, t.token_hash)) return json({ error: "not_found" }, 404);
        if (reply !== undefined) { if (typeof reply !== "string" || reply.trim().length < 2 || reply.length > 4000) return json({ error: "invalid" }, 400); if (t.status === "closed") return json({ error: "closed" }, 409); await store().addMessage(ref, "customer", reply.trim()); }
        const pub = { ref: t.ref, status: t.status, subject: t.subject, category: t.category, created_at: t.created_at, updated_at: t.updated_at }; return json({ ticket: pub, messages: await store().messages(ref) });
      } catch { return json({ error: "store_failed" }, 502); }
    },
  };
}
