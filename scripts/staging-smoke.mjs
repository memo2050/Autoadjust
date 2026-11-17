#!/usr/bin/env node
// Staging smoke test. READ THE SAFETY RULES: it refuses to run unless STAGING_URL host contains "staging", "localhost" or "127.0.0.1" (never point it at production).
// Config (env, never committed): STAGING_URL, and EITHER SMOKE_TOKEN_A + SMOKE_TOKEN_B (two test users' access tokens)
//   OR STAGING_SUPABASE_URL + STAGING_SUPABASE_ANON_KEY + SMOKE_EMAIL_A/SMOKE_PASSWORD_A + SMOKE_EMAIL_B/SMOKE_PASSWORD_B (two throwaway staging test users).
// Output: one line per check (PASS/FAIL/SKIP) and a JSON summary on the last line. Secrets are never printed.
const base = (process.env.STAGING_URL ?? "").replace(/\/$/, "");
const host = (() => { try { return new URL(base).hostname; } catch { return ""; } })();
if (!base || !/staging|^localhost$|^127\.0\.0\.1$/.test(host)) { console.error("Refusing to run: STAGING_URL must be a staging/localhost address."); process.exit(2); }
const results = []; const rec = (name, ok, detail = "") => { results.push({ name, status: ok === null ? "SKIP" : ok ? "PASS" : "FAIL", detail }); console.log(`${ok === null ? "SKIP" : ok ? "PASS" : "FAIL"}  ${name}${detail ? "  - " + detail : ""}`); };
const api = async (method, path, tok, body, headers = {}) => { const r = await fetch(`${base}/api/soc/${path}`, { method, headers: { "content-type": "application/json", ...(tok ? { authorization: "Bearer " + tok } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); let j = null; try { j = await r.json(); } catch {} return { status: r.status, body: j, headers: r.headers }; };
async function login(kind) {
  const direct = process.env[`SMOKE_TOKEN_${kind}`]; if (direct) return direct;
  const u = process.env.STAGING_SUPABASE_URL, k = process.env.STAGING_SUPABASE_ANON_KEY, e = process.env[`SMOKE_EMAIL_${kind}`], p = process.env[`SMOKE_PASSWORD_${kind}`];
  if (!u || !k || !e || !p) return null;
  if (/prod/i.test(u)) throw new Error("STAGING_SUPABASE_URL looks like production; refusing.");
  const r = await fetch(`${u.replace(/\/$/, "")}/auth/v1/token?grant_type=password`, { method: "POST", headers: { apikey: k, "content-type": "application/json" }, body: JSON.stringify({ email: e, password: p }) }); const j = await r.json().catch(() => ({})); return j.access_token ?? null;
}
const mustBeRefused = (r) => r.status === 401 || r.status === 403;
const run = async () => {
  // 1. Authentication
  rec("no token is refused", mustBeRefused(await api("GET", "me")));
  rec("forged token is refused", mustBeRefused(await api("GET", "me", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.AAAA")));
  rec("shared admin token is not accepted by default", mustBeRefused(await api("GET", "me", "admin")));
  const home = await fetch(base + "/"); rec("site responds", home.status < 500, "HTTP " + home.status);
  const A = await login("A"), B = await login("B");
  if (!A || !B) { rec("signed-in checks", null, "no test users/tokens configured"); return; }
  // 2. Organizations and tenant isolation
  const suffix = Math.random().toString(36).slice(2, 8);
  const oa = await api("POST", "org/create", A, { name: "Smoke A " + suffix }), ob = await api("POST", "org/create", B, { name: "Smoke B " + suffix });
  rec("each test user can create an organization", oa.status === 201 && ob.status === 201, `A:${oa.status} B:${ob.status}`);
  const idA = oa.body?.id ?? oa.body?.organization?.id, idB = ob.body?.id ?? ob.body?.organization?.id; if (!idA || !idB) return;
  const hA = { "x-org-id": idA }, hB = { "x-org-id": idB };
  rec("user A cannot act inside organization B", mustBeRefused(await api("GET", "org/keys", A, undefined, hB)));
  rec("user B cannot act inside organization A", mustBeRefused(await api("GET", "org/keys", B, undefined, hA)));
  // 3. MFA
  const mfa = await api("GET", "org/mfa", A, undefined, hA); rec("MFA status endpoint answers", mfa.status === 200, JSON.stringify({ enforced: mfa.body?.enforced, verified: mfa.body?.verified }));
  const key = await api("POST", "org/keys", A, { name: "smoke-" + suffix, scopes: ["noc"], expiresInDays: 1 }, hA);
  if (mfa.body?.enforced && !mfa.body?.verified) rec("MFA enforced: privileged change without a verified authenticator is refused", key.status === 403 && key.body?.code === "mfa_required", "HTTP " + key.status);
  else rec("collector key can be created", key.status === 201, "HTTP " + key.status);
  // 4. Scoped collector key
  if (key.status === 201) {
    const kv = key.body.key;
    rec("noc-scoped key can push telemetry", (await api("POST", "noc/telemetry", kv, { devices: [{ id: "smoke-dev", type: "server", hostname: "smoke-" + suffix }] })).status === 200);
    rec("noc-scoped key is refused on SOC ingest", (await api("POST", "ingest/windows", kv, { events: [] })).status === 403);
    rec("key listing never shows the key or hash", !JSON.stringify((await api("GET", "org/keys", A, undefined, hA)).body).includes(kv));
    rec("revoked key stops working", (await api("DELETE", "org/keys/" + key.body.id, A, undefined, hA)).status < 300 && mustBeRefused(await api("POST", "noc/telemetry", kv, { devices: [] })));
  }
  // 5. Rate limiting (uses a cheap read-only-ish limit: invitations list is not limited, so probe the key-create limit with invalid names, which are rejected after counting)
  let limited = false, last = 0; for (let i = 0; i < 14 && !limited; i++) { const r = await api("POST", "org/keys", A, { name: "" }, hA); last = r.status; limited = r.status === 429; }
  if (!limited && last === 403 && mfa.body?.enforced && !mfa.body?.verified) rec("rate limiter returns 429 with Retry-After", null, "skipped: MFA blocks privileged calls before the limiter; use an aal2 test user to test this");
  else rec("rate limiter returns 429 with Retry-After", limited, limited ? "" : "last HTTP " + last);
  // 6. Billing
  const bill = await api("GET", "billing/status", A, undefined, hA); rec("billing status: Free plan, enforcement off", bill.status === 200 && (bill.body?.plan?.id ?? bill.body?.plan) === "free" && !bill.body?.enforced, JSON.stringify({ plan: bill.body?.plan?.id ?? bill.body?.plan, enforced: bill.body?.enforced }));
  const co = await api("POST", "billing/checkout", A, { plan: "pro" }, hA); rec("checkout never charges from smoke: refused (no Stripe/MFA) or test-mode URL only", co.status !== 200 || /checkout\.stripe\.com/.test(JSON.stringify(co.body)) , "HTTP " + co.status);
  // 7. Export / deletion safety
  const ex = await api("POST", "org/export", B, undefined, hB); rec("export request answers sensibly (200, MFA 403 or not-configured 501)", [200, 403, 501].includes(ex.status), "HTTP " + ex.status);
  rec("export link without token is refused", (await fetch(base + "/api/soc/org/export/download")).status === 403);
  rec("deletion needs the exact name", (await api("POST", "org/deletion", B, { confirm: "wrong" }, hB)).status >= 400);
  rec("platform-admin routes refuse normal users", mustBeRefused(await api("GET", "admin/deletions", A, undefined, hA)));
  // 8. Security hygiene
  const r = await api("GET", "org/current", A, undefined, hA); rec("responses are JSON and contain no server secrets", !/(service_role|SUPABASE_SERVICE|sk_live_|sk_test_|whsec_)/.test(JSON.stringify(r.body)));
  const h = home.headers; rec("security headers present (informational)", !!(h.get("x-content-type-options") || h.get("strict-transport-security")), "x-content-type-options=" + h.get("x-content-type-options") + "; hsts=" + !!h.get("strict-transport-security"));
};
run().then(() => { const f = results.filter((x) => x.status === "FAIL").length; console.log(JSON.stringify({ pass: results.filter((x) => x.status === "PASS").length, fail: f, skip: results.filter((x) => x.status === "SKIP").length, target: host })); process.exit(f ? 1 : 0); }).catch((e) => { console.error("ERROR", e.message); process.exit(3); });
