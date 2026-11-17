// Phase 6: authorization matrix on the COMBINED application (PR #1 + PR #2). Every sensitive route is called as each kind of caller; the expected outcome is asserted.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, aal = "aal2") => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: sub.slice(0, 6) + "@x.io", role: "authenticated", aud: "authenticated", aal, exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const A = "a2000000-0000-4000-8000-0000000000a1", B = "b2000000-0000-4000-8000-0000000000b1";
const ROUTES: [string, string, unknown?][] = [
  ["POST", "org/keys", { name: "key-x" }], ["GET", "org/keys"], ["DELETE", "org/keys/c2000000-0000-4000-8000-0000000000c1"], ["POST", "org/keys/c2000000-0000-4000-8000-0000000000c1/rotate", {}], ["POST", "org/invitations", { email: "a@b.io", role: "noc_operator" }], ["GET", "org/invitations"],
  ["PATCH", "org/members/d2000000-0000-4000-8000-0000000000d1", { role: "owner" }], ["DELETE", "org/members/d2000000-0000-4000-8000-0000000000d1"], ["POST", "org/mfa", { requireMfa: true }], ["POST", "org/export"], ["POST", "org/deletion", { confirm: "A" }], ["DELETE", "org/deletion"],
  ["GET", "admin/deletions"], ["POST", "admin/deletions/x/approve"], ["GET", "billing/admin/plans"], ["PUT", "billing/admin/settings", {}], ["POST", "billing/admin/orgs/" + A + "/refund", {}], ["GET", "billing/admin/stats"],
  ["POST", "billing/checkout", { plan: "pro" }], ["POST", "billing/change", { plan: "pro" }], ["POST", "billing/cancel"],
];
const MIN: Record<string, string[]> = {   // roles that may legitimately get past authorization (anything else must be refused with 401/403)
  "POST org/keys": ["owner", "it_admin"], "DELETE org/keys/c2000000-0000-4000-8000-0000000000c1": ["owner", "it_admin"], "POST org/keys/c2000000-0000-4000-8000-0000000000c1/rotate": ["owner", "it_admin"], "POST org/invitations": ["owner", "it_admin"],
  "PATCH org/members/d2000000-0000-4000-8000-0000000000d1": ["owner", "it_admin"], "DELETE org/members/d2000000-0000-4000-8000-0000000000d1": ["owner", "it_admin"], "POST org/mfa": ["owner", "it_admin"], "POST org/export": ["owner"], "POST org/deletion": ["owner"], "DELETE org/deletion": ["owner"],
  "POST billing/checkout": ["owner", "it_admin"], "POST billing/change": ["owner", "it_admin"], "POST billing/cancel": ["owner", "it_admin"],
};
const PLATFORM = ["GET admin/deletions", "POST admin/deletions/x/approve", "GET billing/admin/plans", "PUT billing/admin/settings", "POST billing/admin/orgs/" + A + "/refund", "GET billing/admin/stats"];
async function world() {
  const s = new TestStore(), id = { owner: randomUUID(), it_admin: randomUUID(), noc_operator: randomUUID(), security_analyst: randomUUID(), executive_readonly: randomUUID(), outsider: randomUUID() };
  await s.upsert("organizations", [{ id: A, name: "A", slug: "a", plan: "free", settings: {} }, { id: B, name: "B", slug: "b", plan: "free", settings: {} }] as any);
  await s.upsert("org_members", [...(["owner", "it_admin", "noc_operator", "security_analyst", "executive_readonly"] as const).map((r) => ({ orgId: A, userId: id[r], role: r })), { orgId: B, userId: id.outsider, role: "owner" }] as any, "org_id,user_id");
  const env = { EXPORT_SIGNING_SECRET: "e".repeat(40), MFA_ENFORCE: "on" };
  const call = async (method: string, p: string, tok: string | null, body?: unknown, h: Record<string, string> = {}) => { const r = await handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { ...(tok ? { authorization: "Bearer " + tok } : {}), "content-type": "application/json", ...h }, body: body === undefined ? undefined : JSON.stringify(body) }), p.split("/"), { store: s, model: null, env } as any); return r.status; };
  return { s, id, call };
}
test("unauthenticated and forged callers are refused on every sensitive route (401/403, never 2xx/5xx)", async () => {
  const w = await world();
  for (const [m, p, b] of ROUTES) for (const tok of [null, "garbage", jwt(w.id.owner).slice(0, -3) + "abc"]) { const st = await w.call(m, p, tok, b); assert.ok(st === 401 || st === 403, `${m} ${p} with ${tok ? "bad token" : "no token"} -> ${st}`); }
});
test("each role may only do what its role allows; platform-only routes refuse every organization role", async () => {
  const w = await world();
  for (const [m, p, b] of ROUTES) { const k = `${m} ${p}`;
    for (const role of ["owner", "it_admin", "noc_operator", "security_analyst", "executive_readonly"] as const) {
      const st = await w.call(m, p, jwt(w.id[role]), b);
      if (PLATFORM.includes(k)) assert.equal(st, 403, `${k} as ${role} must be refused (platform admin only) -> ${st}`);
      else if (MIN[k] && !MIN[k].includes(role)) assert.ok(st === 403, `${k} as ${role} must be refused -> ${st}`);
      assert.ok(st < 500 || (st === 503 && p.startsWith("billing")), `${k} as ${role} must not crash (503 allowed only for "Stripe not configured") -> ${st}`);
    } }
});
test("without MFA, privileged users cannot change anything (aal1) but can still read", async () => {
  const w = await world();
  for (const [m, p, b] of ROUTES.filter((r) => r[0] !== "GET" && (MIN[`${r[0]} ${r[1]}`] ?? []).includes("owner"))) { const st = await w.call(m, p, jwt(w.id.owner, "aal1"), b); assert.equal(st, 403, `${m} ${p} as owner/aal1 -> ${st}`); }
  assert.equal(await w.call("GET", "org/keys", jwt(w.id.owner, "aal1")), 200);
});
test("tenant isolation: an owner of another organization cannot act on this organization's keys/members/invitations", async () => {
  const w = await world(); const k = await handleSoc(new Request("http://x/api/soc/org/keys", { method: "POST", headers: { authorization: "Bearer " + jwt(w.id.owner), "content-type": "application/json" }, body: JSON.stringify({ name: "keyA" }) }), ["org", "keys"], { store: w.s, model: null, env: { MFA_ENFORCE: "on" } } as any); const key = ((await k.json()) as any).id;
  assert.ok(key);
  const out = jwt(w.id.outsider); for (const [m, p, b] of [["DELETE", `org/keys/${key}`], ["POST", `org/keys/${key}/rotate`, {}], ["DELETE", `org/members/${w.id.executive_readonly}`], ["PATCH", `org/members/${w.id.executive_readonly}`, { role: "viewer" }]] as [string, string, unknown?][]) {
    const st = await w.call(m, p, out, b, { "x-org-id": A }); assert.ok(st === 403 || st === 404, `${m} ${p} by other org -> ${st}`); }
  assert.equal((await w.s.select<any>("org_api_keys", { where: { orgId: A } })).filter((x) => !x.revokedAt).length, 1, "org A key still active");
  assert.equal((await w.s.select<any>("org_members", { where: { orgId: A } })).length, 5);
});
