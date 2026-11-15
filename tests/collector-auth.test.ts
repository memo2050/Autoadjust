// T3: individual collector authentication. Scoped keys, expiry, rotation with overlap, IP allowlist, revocation, org isolation, legacy tokens off.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { ipMatches, validIpEntry } from "../lib/tenant/auth";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: sub.slice(0, 6) + "@x.io", role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const A = "a0000000-0000-4000-8000-0000000000a1", B = "b0000000-0000-4000-8000-0000000000b1";
async function world(env: Record<string, string> = {}) {
  const s = new TestStore(), uA = randomUUID(), uB = randomUUID();
  await s.upsert("organizations", [{ id: A, name: "A", slug: "a", plan: "free" }, { id: B, name: "B", slug: "b", plan: "free" }] as any);
  await s.upsert("org_members", [{ orgId: A, userId: uA, role: "owner" }, { orgId: B, userId: uB, role: "owner" }] as any, "org_id,user_id");
  const call = async (method: string, p: string, tok: string, body?: unknown, headers: Record<string, string> = {}) => { const r = await handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { authorization: "Bearer " + tok, "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }), p.split("/"), { store: s, model: null, env } as any); return { status: r.status, body: (await r.json().catch(() => ({}))) as any }; };
  return { s, call, ownerA: jwt(uA), ownerB: jwt(uB) };
}
const mk = async (w: any, body: any) => (await w.call("POST", "org/keys", w.ownerA, body)).body;
const TEL = { devices: [{ id: "d1", type: "server" }] };

test("scopes: a key only reaches the routes of its scopes; unscoped keys keep full collector access (compatibility)", async () => {
  const w = await world(); try {
    const soc = await mk(w, { name: "soc-only", scopes: ["soc"] }), noc = await mk(w, { name: "noc-only", scopes: ["noc"] }), all = await mk(w, { name: "legacy-style" });
    assert.deepEqual(all.scopes, ["soc", "noc", "executor", "discovery"]);
    assert.equal((await w.call("POST", "noc/telemetry", soc.key, TEL)).status, 403, "soc key cannot send NOC telemetry");
    assert.equal((await w.call("POST", "noc/telemetry", noc.key, TEL)).status, 200); assert.equal((await w.call("POST", "noc/telemetry", all.key, TEL)).status, 200);
    assert.notEqual((await w.call("POST", "ingest/windows", soc.key, {})).status, 403, "soc key reaches the SOC ingest route (body errors are not scope errors)");
    assert.equal((await w.call("POST", "ingest/windows", noc.key, {})).status, 403, "noc key cannot ingest SOC events");
    assert.equal((await w.call("GET", "noc/executor/jobs?host=h1", noc.key)).status, 403, "noc key cannot poll executor jobs");
    assert.equal((await w.call("GET", "noc/scans/pending", noc.key)).status, 403);
    assert.equal((await w.call("GET", "noc/changes/pending", noc.key)).status, 403);
    assert.equal((await w.call("POST", "org/keys", noc.key, { name: "escalate" })).status, 403, "a collector key can never manage keys");
    assert.equal((await w.call("POST", "org/keys", w.ownerA, { name: "bad", scopes: ["admin"] })).status, 400, "unknown scope refused");
    assert.equal((await w.call("POST", "org/keys", w.ownerA, { name: "bad2", scopes: [] })).status, 400);
  } finally { /* none */ }
});
test("org isolation: org A's key writes only to org A", async () => {
  const w = await world(); const a = await mk(w, { name: "a-key", scopes: ["noc"] });
  await w.call("POST", "noc/telemetry", a.key, TEL); const rows = await w.s.select<any>("noc_devices", {}); assert.ok(rows.length && rows.every((r) => r.orgId === A));
  const bKey = (await w.call("POST", "org/keys", w.ownerB, { name: "b-key", scopes: ["noc"] })).body; await w.call("POST", "noc/telemetry", bKey.key, { devices: [{ id: "d1", type: "server" }] });
  assert.equal((await w.s.select<any>("noc_devices", {})).length, 2, "same device id in two orgs = two rows"); assert.equal((await w.s.select<any>("noc_devices", { where: { orgId: B } })).length, 1);
});
test("expiry and revocation", async () => {
  const w = await world(); const k = await mk(w, { name: "exp", scopes: ["noc"], expiresInDays: 30 }); assert.ok(k.expiresAt);
  assert.equal((await w.call("POST", "noc/telemetry", k.key, TEL)).status, 200);
  const row = (await w.s.select<any>("org_api_keys", { where: { id: k.id } }))[0]; await w.s.upsert("org_api_keys", [{ ...row, expiresAt: new Date(Date.now() - 1000).toISOString() }]);
  assert.equal((await w.call("POST", "noc/telemetry", k.key, TEL)).status, 401, "expired key refused");
  const k2 = await mk(w, { name: "rev", scopes: ["noc"] }); assert.equal((await w.call("DELETE", "org/keys/" + k2.id, w.ownerA)).status, 200); assert.equal((await w.call("POST", "noc/telemetry", k2.key, TEL)).status, 401, "revoked key refused at once");
  assert.equal((await w.call("POST", "org/keys", w.ownerA, { name: "x", expiresInDays: 0 })).status, 400);
});
test("rotation: new key works at once, old key works only during the overlap, then stops; overlap 0 cuts the old key immediately; another org cannot rotate it", async () => {
  const w = await world(); const old = await mk(w, { name: "collector-1", scopes: ["noc"], allowedIps: ["10.0.0.0/8"] });
  const hdr = { "x-forwarded-for": "10.1.2.3" };
  const r = await w.call("POST", `org/keys/${old.id}/rotate`, w.ownerA, { overlapHours: 2 }); assert.equal(r.status, 201); assert.deepEqual(r.body.scopes, ["noc"]);
  assert.equal((await w.call("POST", "noc/telemetry", r.body.key, TEL, hdr)).status, 200, "new key works immediately and inherited the IP allowlist");
  assert.equal((await w.call("POST", "noc/telemetry", r.body.key, TEL, { "x-forwarded-for": "8.8.8.8" })).status, 401);
  assert.equal((await w.call("POST", "noc/telemetry", old.key, TEL, hdr)).status, 200, "old key still valid during overlap");
  const row = (await w.s.select<any>("org_api_keys", { where: { id: old.id } }))[0]; await w.s.upsert("org_api_keys", [{ ...row, expiresAt: new Date(Date.now() - 1000).toISOString() }]);
  assert.equal((await w.call("POST", "noc/telemetry", old.key, TEL, hdr)).status, 401, "old key dead after overlap");
  const r0 = await w.call("POST", `org/keys/${r.body.id}/rotate`, w.ownerA, { overlapHours: 0 }); assert.equal((await w.call("POST", "noc/telemetry", r.body.key, TEL, hdr)).status, 401, "overlap 0 = immediate");
  assert.equal((await w.call("POST", `org/keys/${r0.body.id}/rotate`, w.ownerB, {})).status, 404, "other org cannot rotate it");
  assert.equal((await w.call("POST", `org/keys/${r0.body.id}/rotate`, w.ownerA, { overlapHours: 999 })).status, 400);
});
test("IP allowlist: exact and CIDR; no header or wrong address is refused; unrestricted keys unaffected", async () => {
  const w = await world(); const k = await mk(w, { name: "ip", scopes: ["noc"], allowedIps: ["203.0.113.7", "192.168.10.0/24"] }), free = await mk(w, { name: "free", scopes: ["noc"] });
  const t = (key: string, ip?: string) => w.call("POST", "noc/telemetry", key, TEL, ip ? { "x-forwarded-for": ip + ", 1.1.1.1" } : {});
  assert.equal((await t(k.key, "203.0.113.7")).status, 200); assert.equal((await t(k.key, "192.168.10.99")).status, 200);
  assert.equal((await t(k.key, "192.168.11.1")).status, 401); assert.equal((await t(k.key)).status, 401, "no address = refused"); assert.equal((await t(free.key)).status, 200);
  assert.equal((await w.call("POST", "org/keys", w.ownerA, { name: "bad", allowedIps: ["not-an-ip"] })).status, 400); assert.equal((await w.call("POST", "org/keys", w.ownerA, { name: "bad", allowedIps: ["10.0.0.0/33"] })).status, 400);
  assert.ok(ipMatches("10.2.3.4", "10.0.0.0/8") && !ipMatches("11.2.3.4", "10.0.0.0/8") && ipMatches("::1", "::1") && !validIpEntry("999.1.1.1"));
});
test("listing shows scopes/expiry/allowlist and never the key or its hash", async () => {
  const w = await world(); const k = await mk(w, { name: "list", scopes: ["soc"], allowedIps: ["10.0.0.1"], expiresInDays: 10 });
  const l = (await w.call("GET", "org/keys", w.ownerA)).body.keys.find((x: any) => x.id === k.id); assert.deepEqual([l.scopes, l.allowedIps], [["soc"], ["10.0.0.1"]]); assert.ok(l.expiresAt);
  assert.ok(!JSON.stringify(l).includes(k.key) && !("keyHash" in l));
});
test("legacy tokens: work only while SOC_LEGACY_TOKENS is on and leave an audit warning; with it off they are refused everywhere", async () => {
  const TOK = "legacy-shared-ingest-token-0123456789";
  const on = await world({ SOC_INGEST_TOKEN: TOK }); assert.equal((await on.call("POST", "noc/telemetry", TOK, TEL)).status, 200);
  await new Promise((r) => setTimeout(r, 20)); assert.ok((await on.s.select<any>("soc_audit", {})).some((e) => String(e.action).includes("legacy_token_used")), "warning recorded so you know a collector still uses it");
  const off = await world({ SOC_INGEST_TOKEN: TOK, SOC_LEGACY_TOKENS: "off" });
  for (const [m, p, b] of [["POST", "noc/telemetry", TEL], ["POST", "ingest/windows", {}], ["GET", "noc/executor/jobs?host=h", undefined], ["POST", "ingest/wazuh", {}]] as const) assert.equal((await off.call(m, p, TOK, b)).status, 401, `${p} refuses the shared token`);
  const k = await mk(off, { name: "own", scopes: ["noc"] }); assert.equal((await off.call("POST", "noc/telemetry", k.key, TEL)).status, 200, "individual key still works with legacy off");
});
