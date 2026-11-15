import type { Store } from "./store";
import { HttpError } from "./pipeline";

/** Ingest paths must keep flowing if the shared counter is briefly unavailable (collectors would otherwise drop data); every other route fails closed. */
const FAIL_OPEN = /:(telemetry|wazuh|alerts|push|xpoll|xres|scanp|windows)$/;
const local = new Map<string, number[]>();
const warned = new Map<string, number>();
function localHit(key: string, perMin: number) {
  const now = Date.now(), a = (local.get(key) ?? []).filter((t) => now - t < 60000);
  a.push(now); local.set(key, a); if (local.size > 5000) for (const [k, v] of local) if (!v.some((t) => now - t < 60000)) local.delete(k);
  return a.length;
}
/** Allow at most `perMin` calls per minute for `key`. Uses the shared database counter when the store has one. Throws 429 (with retryAfter) or, if the counter is unavailable on a sensitive route, 503. */
export async function limit(store: Store, key: string, perMin: number): Promise<void> {
  let n: number;
  try { n = store.hit ? await store.hit(key, 60) : localHit(key, perMin); }
  catch (e) {
    if (!FAIL_OPEN.test(key)) throw new HttpError(503, "The service is temporarily unable to verify request limits. Please retry shortly.", { code: "rate_limiter_unavailable", retryAfter: 5 });
    const now = Date.now(); if (now - (warned.get("w") ?? 0) > 60000) { warned.set("w", now); console.error("rate limiter unavailable; ingest continues with a per-process limit", (e as Error).message); }
    n = localHit(key, perMin);
  }
  if (n > perMin) { const retry = 60 - (Math.floor(Date.now() / 1000) % 60); throw new HttpError(429, "Too many requests. Slow down and retry in a minute.", { code: "rate_limited", retryAfter: retry }); }
}
