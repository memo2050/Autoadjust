// Shared, persistent rate limiting on the existing rate_limit_hit RPC (migration 0112; 24 h windows need 0117). Optional: RATE_LIMIT_STORE=supabase. Otherwise (or if the store is unreachable) it behaves exactly like the in-memory limiter, so nothing changes until the migration is approved and applied.
import { createHash } from "crypto";
import { makeLimiter } from "../demo/request";

export type RateLimiterFactory = (scope: string, perKey: number, total: number, windowMs: number) => (key: string) => Promise<boolean>;
export interface RlDeps { env: NodeJS.ProcessEnv; fetch?: typeof fetch; now?: () => number }
const sha = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 32);

export function sharedEnabled(env: NodeJS.ProcessEnv): boolean {
  return (env.RATE_LIMIT_STORE ?? "").toLowerCase() === "supabase" && !!(env.SUPABASE_URL ?? "").trim() && !!(env.SUPABASE_SERVICE_ROLE_KEY ?? "").trim();
}
export function createRateLimiters(d: RlDeps): RateLimiterFactory & { mode: () => "shared" | "memory"; sharedFailures: () => number } {
  const f = d.fetch ?? fetch, on = sharedEnabled(d.env), base = (d.env.SUPABASE_URL ?? "").replace(/\/$/, ""), sk = d.env.SUPABASE_SERVICE_ROLE_KEY ?? ""; let failures = 0;
  const hit = async (scope: string, key: string, limit: number, windowMs: number): Promise<boolean> => {
    const r = await f(base + "/rest/v1/rpc/rate_limit_hit", { method: "POST", headers: { apikey: sk, Authorization: "Bearer " + sk, "Content-Type": "application/json" }, body: JSON.stringify({ p_key: scope + ":" + sha(key), p_window: Math.round(windowMs / 1000) }), signal: AbortSignal.timeout(2500) });
    if (!r.ok) throw new Error("rl " + r.status); const n = await r.json(); if (typeof n !== "number") throw new Error("rl shape"); return n <= limit;
  };
  const make = ((scope, perKey, total, windowMs) => {
    const mem = makeLimiter(perKey, total, windowMs, d.now);   // always the fallback: a store outage never removes the limit
    return async (key: string): Promise<boolean> => {
      if (!on) return mem(key);
      try {
        if (perKey < 1e9 && !(await hit(scope, key, perKey, windowMs))) return false;
        if (total < 1e9 && !(await hit(scope + ":all", "all", total, windowMs))) return false;
        return true;
      } catch { failures++; return mem(key); }
    };
  }) as RateLimiterFactory & { mode: () => "shared" | "memory"; sharedFailures: () => number };
  make.mode = () => (on ? "shared" : "memory"); make.sharedFailures = () => failures; return make;
}
