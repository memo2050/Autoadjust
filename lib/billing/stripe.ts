// Minimal Stripe client over the REST API (no SDK dependency => nothing to pin or audit). TEST MODE ONLY unless BILLING_MODE=live is set deliberately
// (that is a production decision and is NOT enabled anywhere in development). Secrets are read from env only and never logged or returned.
import { createHmac, timingSafeEqual } from "node:crypto";
import { HttpError } from "../soc/pipeline";

export function stripeMode(env: Record<string, string | undefined> = process.env): "test" | "live" | null {
  const k = env.STRIPE_SECRET_KEY ?? ""; if (/^(sk|rk)_test_[A-Za-z0-9]{8,}$/.test(k)) return "test"; if (/^(sk|rk)_live_[A-Za-z0-9]{8,}$/.test(k)) return "live"; return null;
}
function apiBase(env: Record<string, string | undefined>): string {
  const o = env.STRIPE_API_BASE; if (!o) return "https://api.stripe.com";
  const u = new URL(o); if (!["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) throw new HttpError(500, "STRIPE_API_BASE may only point at localhost (tests).");   // never send the key to another host
  return u.origin;
}
export function assertConfigured(env: Record<string, string | undefined> = process.env) {
  const m = stripeMode(env); if (!m) throw new HttpError(503, "Billing is not configured on this server.");
  if (m === "live" && env.BILLING_MODE !== "live") throw new HttpError(503, "A live Stripe key is present but live billing has not been enabled (BILLING_MODE=live). Development uses test mode only.");
  return m;
}
const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
export async function stripePost(path: string, body: Record<string, string>, idempotencyKey?: string, env: Record<string, string | undefined> = process.env): Promise<any> {
  assertConfigured(env);
  const r = await fetch(apiBase(env) + path, { method: "POST", headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded", ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}) }, body: form(body) });
  const j: any = await r.json().catch(() => ({}));
  if (!r.ok) throw new HttpError(502, "The payment provider rejected the request" + (j?.error?.code ? ` (${String(j.error.code).slice(0, 60)})` : "") + ".");
  return j;
}
export async function stripeGet(path: string, env: Record<string, string | undefined> = process.env): Promise<any> {
  assertConfigured(env);
  const r = await fetch(apiBase(env) + path, { method: "GET", headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY } }); const j: any = await r.json().catch(() => ({}));
  if (!r.ok) throw new HttpError(502, "The payment provider rejected the request" + (j?.error?.code ? ` (${String(j.error.code).slice(0, 60)})` : "") + "."); return j;
}
/** Verifies a Stripe-Signature header against the RAW body. Constant-time; rejects stale timestamps and any malformed header. */
export function verifyWebhook(raw: string, header: string | null, secret: string | undefined, now = Date.now(), toleranceSec = 300): boolean {
  if (!secret || !header) return false;
  const parts = header.split(",").map((p) => p.trim().split("=")); const t = parts.find((p) => p[0] === "t")?.[1]; const sigs = parts.filter((p) => p[0] === "v1" && p[1]).map((p) => p[1]);
  if (!t || !/^\d{9,12}$/.test(t) || !sigs.length) return false; if (Math.abs(now / 1000 - Number(t)) > toleranceSec) return false;
  const want = createHmac("sha256", secret).update(`${t}.${raw}`).digest();
  return sigs.some((s) => /^[0-9a-f]{64}$/.test(s) && timingSafeEqual(Buffer.from(s, "hex"), want));
}
