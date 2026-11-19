// Abuse and cost protection for the public /api/analyze endpoint (real AI calls cost money).
//  - Two tiers: anonymous visitors (tight) and signed-in users (higher). Tier is decided by a VERIFIED Supabase token, never by a client claim.
//  - Per-client hourly and daily quotas, plus a global daily budget so one attacker (or a bug) can never run up an unbounded bill.
//  - Same-origin requirement for anonymous callers (stops other websites and naive scripts), input and output size caps, mode allowlist, image analysis only when signed in.
//  - The client IP is the entry added by the OUR proxy (TRUSTED_PROXY_HOPS from the right of x-forwarded-for, default 1), so a visitor cannot dodge limits by inventing the left-most entries.
// Counters are in memory (per server instance, reset on restart); the global cap bounds the damage either way.
export type Tier = "anon" | "user";
export const MODES = ["chat", "team", "solution", "analyst", "describe"] as const;
export interface GuardConfig { anonHour: number; anonDay: number; userHour: number; userDay: number; globalDay: number; anonChars: number; userChars: number; anonTokens: number; userTokens: number; hops: number }
export const configFrom = (env: NodeJS.ProcessEnv): GuardConfig => {
  const n = (k: string, d: number) => { const v = Number(env[k]); return Number.isFinite(v) && v > 0 ? v : d; };
  return { anonHour: n("ANALYZE_ANON_HOUR", 4), anonDay: n("ANALYZE_ANON_DAY", n("FREE_DAILY_LIMIT", 8)), userHour: n("ANALYZE_USER_HOUR", 40), userDay: n("ANALYZE_USER_DAY", 150), globalDay: n("ANALYZE_GLOBAL_DAILY", 400),
    anonChars: n("ANALYZE_ANON_CHARS", 6000), userChars: n("ANALYZE_USER_CHARS", 30000), anonTokens: n("ANALYZE_ANON_TOKENS", 1200), userTokens: n("ANALYZE_USER_TOKENS", 3000), hops: Math.floor(n("TRUSTED_PROXY_HOPS", 1)) };
};
export function clientIp(h: Headers, hops: number): string {
  const xs = (h.get("x-forwarded-for") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const ip = xs.length ? xs[Math.max(0, xs.length - hops)] : (h.get("x-real-ip") ?? "").trim();
  return ip && ip.length <= 64 ? ip : "unknown";
}
export function sameOrigin(h: Headers): boolean {
  const host = h.get("host"), o = h.get("origin");
  if (o) { try { return !!host && new URL(o).host === host; } catch { return false; } }
  return h.get("sec-fetch-site") === "same-origin";
}
type Win = { start: number; n: number };
export function makeGuard(cfg: GuardConfig, now: () => number = Date.now) {
  const hour = new Map<string, Win>(), day = new Map<string, Win>(); let g: Win = { start: now(), n: 0 };
  const bump = (m: Map<string, Win>, k: string, span: number, max: number, t: number) => { const w = m.get(k); const cur = w && t - w.start < span ? w : { start: t, n: 0 }; if (cur.n >= max) return Math.ceil((cur.start + span - t) / 1000); return 0; };
  const add = (m: Map<string, Win>, k: string, span: number, t: number) => { const w = m.get(k); const cur = w && t - w.start < span ? w : { start: t, n: 0 }; cur.n++; m.set(k, cur); if (m.size > 20000) m.clear(); };
  return {
    /** Returns null if allowed (and counts it), else { status, error, retryAfter? }. */
    check(tier: Tier, key: string, chars: number, mode: string | undefined, hasImage: boolean) {
      const t = now(), user = tier === "user";
      if (mode !== undefined && !(MODES as readonly string[]).includes(mode)) return { status: 400, error: "Bad request" };
      if (hasImage && !user) return { status: 401, error: "Please sign in to analyse diagrams." };
      if (chars > (user ? cfg.userChars : cfg.anonChars)) return { status: 413, error: "That message is too long." };
      if (t - g.start >= 86_400_000) g = { start: t, n: 0 };
      if (g.n >= cfg.globalDay) return { status: 503, error: "The AI assistant has reached today's capacity. Please try again tomorrow." };
      const k = tier + ":" + key, rh = bump(hour, k, 3_600_000, user ? cfg.userHour : cfg.anonHour, t), rd = bump(day, k, 86_400_000, user ? cfg.userDay : cfg.anonDay, t);
      if (rh || rd) return { status: 429, error: user ? "Usage limit reached. Please try again later." : "Free usage limit reached. Sign in or try again later.", retryAfter: Math.max(rh, rd) };
      add(hour, k, 3_600_000, t); add(day, k, 86_400_000, t); g.n++; return null;
    },
    globalCount: () => g.n,
  };
}
