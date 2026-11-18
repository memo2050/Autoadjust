export type DemoRequest = { name: string; email: string; company: string; message: string };
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[^\s@<>]{2,}$/;
const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : "");
/** Validates the public "Request a Demo" form. Returns the cleaned request or an error string. Honeypot field `website` must be empty. */
export function parseDemoRequest(b: unknown): { ok: true; value: DemoRequest } | { ok: false; error: string } {
  if (!b || typeof b !== "object") return { ok: false, error: "Invalid request." };
  const o = b as Record<string, unknown>;
  if (typeof o.website === "string" && o.website.length > 0) return { ok: false, error: "Invalid request." };
  const name = clean(o.name, 120), email = clean(o.email, 200).toLowerCase(), company = clean(o.company, 160), message = clean(o.message, 2000);
  if (!name) return { ok: false, error: "Please enter your name." };
  if (!EMAIL.test(email)) return { ok: false, error: "Please enter a valid email address." };
  return { ok: true, value: { name, email, company, message } };
}

import { envViolations } from "../tenant/env-isolation";
/** Fail-closed environment check for the demo-request writer. Returns a reason (never a secret) when this server must NOT write, else null.
 *  Refuses when the runtime isolation guard reports a violation, when the Supabase URL is the production project but this is not production,
 *  and when SUPABASE_URL / the service key are missing. */
export function storeBlockReason(env: NodeJS.ProcessEnv): string | null {
  if ((env.DEMO_REQUESTS_ENABLED ?? "").toLowerCase() !== "on") return "storage not enabled";   // off by default: no database call is attempted until the owner approves migration 0114 and sets DEMO_REQUESTS_ENABLED=on
  const v = envViolations(env);
  if (v.length) return "environment isolation check failed";
  const ref = /^https:\/\/([a-z0-9]{15,30})\.supabase\.co/i.exec(env.SUPABASE_URL ?? "")?.[1]?.toLowerCase();
  const prod = (env.PRODUCTION_PROJECT_REF ?? "").toLowerCase();
  if (prod && ref === prod && (env.APP_ENV ?? "").toLowerCase() !== "production") return "refusing to write to the production project from a non-production app";
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) return "not configured";
  return null;
}

/** Fixed-window limiter: `perKey` hits per key and `total` hits overall per window. In memory (per server instance). */
export function makeLimiter(perKey: number, total: number, windowMs: number, now: () => number = Date.now) {
  let start = now(), all = 0; const m = new Map<string, number>();
  return (key: string): boolean => {
    const t = now(); if (t - start >= windowMs) { start = t; all = 0; m.clear(); }
    const n = m.get(key) ?? 0;
    if (n >= perKey || all >= total) return false;
    if (m.size > 5000) m.clear();
    m.set(key, n + 1); all++; return true;
  };
}
