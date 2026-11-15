// T4: MFA enforcement at the API (aal2) and the shared rate limiter (429 + Retry-After, fail-closed / fail-open).
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, aal?: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: sub.slice(0, 6) + "@x.io", role: "authenticated", aud: "authenticated", aal, exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG = "c0000000-0000-4000-8000-0000000000c1";
async function world(env: Record<string, string> = {}, store?: TestStore) {
  const s = store ?? new TestStore(), owner = randomUUID(), analyst = randomUUID(), viewer = randomUUID();
  await s.upsert("organizations", [{ id: ORG, name: "C", slug: "cc", plan: "free", settings: {} }] as any);
  await s.upsert("org_members", [{ orgId: ORG, userId: owner, role: "owner" }, { orgId: ORG, userId: analyst, role: "security_analyst" }, { orgId: ORG, userId: viewer, role: "executive_readonly" }] as any, "org_id,user_id");
  const call = async (method: string, p: string, tok: string, body?: unknown) => { const r = await handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { authorization: "Bearer " + tok, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), p.split("/"), { store: s, model: null, env } as any); return { status: r.status, headers: r.headers, body: (await r.json().catch(() => ({}))) as any }; };
  return { s, call, owner, analyst, viewer };
}

test("MFA off by default: nothing changes for existing deployments", async () => {
  const w = await world(); assert.equal((await w.call("POST", "org/keys", jwt(w.owner), { name: "key-one" })).status, 201);
});
test("MFA on: owner without aal2 can read but not change; aal2 can; error is a clear mfa_required", async () => {
  const w = await world({ MFA_ENFORCE: "on" });
  assert.equal((await w.call("GET", "org/members", jwt(w.owner))).status, 200, "reads still work so the page can show the enrolment prompt");
  const r = await w.call("POST", "org/keys", jwt(w.owner, "aal1"), { name: "key-one" }); assert.equal(r.status, 403); assert.equal(r.body.code, "mfa_required");
  assert.equal((await w.call("POST", "org/keys", jwt(w.owner), { name: "key-one" })).status, 403, "no aal claim = not verified");
  assert.equal((await w.call("POST", "org/keys", jwt(w.owner, "aal2"), { name: "key-one" })).status, 201);
  const st = (await w.call("GET", "org/mfa", jwt(w.owner, "aal1"))).body; assert.deepEqual([st.enforced, st.verified, st.required], [true, false, true]);
});
test("MFA on: non-privileged roles are not forced unless the organization requires it", async () => {
  const w = await world({ MFA_ENFORCE: "on" });
  assert.notEqual((await w.call("POST", "incidents", jwt(w.analyst), {})).body?.code, "mfa_required");
  assert.equal((await w.call("POST", "org/mfa", jwt(w.owner, "aal1"), { requireMfa: true })).status, 403, "changing the policy itself needs aal2");
  assert.equal((await w.call("POST", "org/mfa", jwt(w.analyst, "aal2"), { requireMfa: true })).status, 403, "analysts cannot change it");
  assert.equal((await w.call("POST", "org/mfa", jwt(w.owner, "aal2"), { requireMfa: "yes" })).status, 400);
  const on = await w.call("POST", "org/mfa", jwt(w.owner, "aal2"), { requireMfa: true }); assert.equal(on.status, 200); assert.equal(on.body.orgRequiresMfa, true);
  const blocked = await w.call("POST", "incidents", jwt(w.analyst, "aal1"), {}); assert.equal(blocked.body.code, "mfa_required", "now analysts need aal2 to change things");
  assert.notEqual((await w.call("POST", "incidents", jwt(w.analyst, "aal2"), {})).body?.code, "mfa_required");
  assert.equal((await w.call("GET", "org/mfa", jwt(w.analyst))).body.required, true);
  const audit = await w.s.select<any>("soc_audit", {}); assert.ok(audit.some((a) => a.action === "org.mfa_policy"));
});
test("MFA never applies to collector API keys (they are not people) and does not block them", async () => {
  const w = await world({ MFA_ENFORCE: "on" }); const k = (await w.call("POST", "org/keys", jwt(w.owner, "aal2"), { name: "coll-one", scopes: ["noc"] })).body;
  assert.equal((await w.call("POST", "noc/telemetry", k.key, { devices: [{ id: "d1", type: "server" }] })).status, 200);
});

test("rate limiter: 429 with Retry-After after the limit; separate keys are independent", async () => {
  const w = await world(); const t = jwt(w.owner); let last: any;
  for (let i = 0; i < 10; i++) { last = await w.call("POST", "org/keys", t, { name: "key-" + i }); assert.equal(last.status, 201, "call " + i); }
  last = await w.call("POST", "org/keys", t, { name: "key-11" }); assert.equal(last.status, 429); assert.equal(last.body.code, "rate_limited");
  const ra = Number(last.headers.get("retry-after")); assert.ok(ra >= 1 && ra <= 60);
  assert.equal((await w.call("POST", "org/invitations", t, { email: "a@b.io", role: "noc_operator" })).status === 429, false, "a different limit key is unaffected");
});
test("rate limiter is shared through the store: two server instances on the same database see one counter", async () => {
  const s = new TestStore(); const a = await world({}, s), b = await world({}, s); const t = jwt(a.owner);
  for (let i = 0; i < 6; i++) assert.equal((await a.call("POST", "org/keys", t, { name: "xkey-" + i })).status, 201);
  for (let i = 6; i < 10; i++) assert.equal((await b.call("POST", "org/keys", t, { name: "ykey-" + i })).status, 201);
  assert.equal((await b.call("POST", "org/keys", t, { name: "zkey-1" })).status, 429, "instance B counted instance A's calls");
});
test("rate limiter failure: sensitive routes fail closed (503 + Retry-After); collector ingest fails open", async () => {
  const s = new TestStore(); (s as any).hit = async () => { throw new Error("db down"); }; const w = await world({}, s);
  const key = (await (async () => { (s as any).hit = undefined; const x = await w.call("POST", "org/keys", jwt(w.owner), { name: "coll-one", scopes: ["noc"] }); (s as any).hit = async () => { throw new Error("db down"); }; return x.body; })());
  const closed = await w.call("POST", "org/keys", jwt(w.owner), { name: "key-one" }); assert.equal(closed.status, 503); assert.equal(closed.body.code, "rate_limiter_unavailable"); assert.ok(closed.headers.get("retry-after"));
  assert.equal((await w.call("POST", "noc/telemetry", key.key, { devices: [{ id: "d1", type: "server" }] })).status, 200, "data keeps flowing");
});
