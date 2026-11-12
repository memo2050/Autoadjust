// Phase 4: multi-organization isolation, authentication and permissions. Run: npx tsx --test tests/tenant.test.ts
// Two real organizations (A, B) with several users each; synthetic data only.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { TestStore } from "./test-store";
import { T } from "../lib/soc/store";
import { handleSoc } from "../lib/soc/api";
import { ScopedStore, DEFAULT_ORG_ID } from "../lib/tenant/scoped-store";
import { verifyJwtHs256 } from "../lib/tenant/auth";
import { sha256 } from "../lib/soc/util";

const SECRET = "test-jwt-secret-test-jwt-secret-1234567890";
process.env.SUPABASE_JWT_SECRET = SECRET;
process.env.SOC_ADMIN_TOKEN = "legacy-admin-token-1234567890";
process.env.PLATFORM_ADMIN_USER_IDS = "";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string, o: Record<string, unknown> = {}, secret = SECRET) => {
  const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600, ...o });
  return `${h}.${p}.${createHmac("sha256", secret).update(h + "." + p).digest("base64url")}`;
};
const U = { alice: "aaaaaaaa-0000-4000-8000-00000000000a", bob: "bbbbbbbb-0000-4000-8000-00000000000b", carol: "cccccccc-0000-4000-8000-00000000000c", dave: "dddddddd-0000-4000-8000-00000000000d", erin: "eeeeeeee-0000-4000-8000-00000000000e", nina: "99999999-0000-4000-8000-000000000009", frank: "ffffffff-0000-4000-8000-00000000000f" };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const tokens: Record<string, string> = {};
for (const [n, id] of Object.entries(U)) tokens[n] = jwt(id, `${n}@example.com`);

async function world() {
  const s = new TestStore();
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a" }, { id: ORG_B, name: "Org B", slug: "org-b" }] as any);
  const mem = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await mem(ORG_A, U.alice, "owner"); await mem(ORG_A, U.carol, "security_analyst"); await mem(ORG_A, U.dave, "executive_readonly"); await mem(ORG_A, U.nina, "noc_operator");
  await mem(ORG_B, U.bob, "owner"); await mem(ORG_B, U.erin, "security_analyst"); await mem(ORG_A, U.frank, "it_admin"); await mem(ORG_B, U.frank, "executive_readonly");
  return s;
}
const call = (s: TestStore, method: string, path: string, tok?: string, body?: unknown, org?: string) =>
  handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { ...(tok ? { authorization: "Bearer " + tok } : {}), ...(org ? { "x-org-id": org } : {}), "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store: s, model: null });
const j = async (r: Response) => r.json() as Promise<any>;

let rec = 1; const t0 = Math.floor(Date.now() / 60000) * 60000 - 3 * 3600_000; const iso = (m: number) => new Date(t0 + m * 60_000).toISOString();
const w = (host: string, id: number, min: number, data: Record<string, string>) => ({ Id: id, RecordId: rec++, TimeCreated: iso(min), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: host, Data: data });
const attack = (host: string) => { const e: unknown[] = []; for (let i = 0; i < 6; i++) e.push(w(host, 4625, i, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" })); e.push(w(host, 4624, 7, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "10" })); e.push(w(host, 1102, 10, { SubjectUserName: "administrator" })); return { host, events: e }; };
async function newKey(s: TestStore, tok: string, name = "collector-1") { const r = await call(s, "POST", "org/keys", tok, { name }); assert.equal(r.status, 201); return (await j(r)).key as string; }

test("JWT verification: signature, expiry, algorithm, audience and role are all enforced", () => {
  const ok = jwt(U.alice, "a@x.io"); assert.ok(verifyJwtHs256(ok, SECRET));
  assert.equal(verifyJwtHs256(ok, "another-secret-another-secret-123456"), null, "wrong secret");
  assert.equal(verifyJwtHs256(jwt(U.alice, "a@x.io", { exp: Math.floor(Date.now() / 1000) - 5 }), SECRET), null, "expired");
  assert.equal(verifyJwtHs256(jwt(U.alice, "a@x.io", { role: "service_role" }), SECRET), null, "service_role key is not a user");
  assert.equal(verifyJwtHs256(jwt(U.alice, "a@x.io", { role: "anon" }), SECRET), null, "anon key is not a user");
  assert.equal(verifyJwtHs256(jwt(U.alice, "a@x.io", { aud: "other" }), SECRET), null, "wrong audience");
  const none = `${b64({ alg: "none", typ: "JWT" })}.${ok.split(".")[1]}.`; assert.equal(verifyJwtHs256(none, SECRET), null, "alg none");
  const [h, p] = ok.split("."); const forged = `${h}.${b64({ sub: U.bob, role: "authenticated", aud: "authenticated", exp: 9999999999 })}.${ok.split(".")[2]}`; assert.equal(verifyJwtHs256(forged, SECRET), null, "tampered payload");
  assert.ok(p);
});

test("authentication: no token, garbage, forged and expired tokens are rejected; user without organization gets a clear 403", async () => {
  const s = await world();
  assert.equal((await call(s, "GET", "me")).status, 401);
  assert.equal((await call(s, "GET", "me", "x".repeat(40))).status, 401);
  assert.equal((await call(s, "GET", "me", jwt(U.alice, "alice@example.com", {}, "wrong-secret-wrong-secret-wrong-1234"))).status, 401);
  assert.equal((await call(s, "GET", "me", jwt(U.alice, "alice@example.com", { exp: 1 }))).status, 401);
  const lone = jwt("12121212-0000-4000-8000-000000000012", "lone@example.com");
  const r = await call(s, "GET", "overview", lone); assert.equal(r.status, 403); assert.equal((await j(r)).code, "no_organization");
  const me = await j(await call(s, "GET", "me", tokens.alice)); assert.equal(me.organization.id, ORG_A); assert.equal(me.orgRole, "owner"); assert.equal(me.auth, "user");
});

test("organization choice: several memberships need x-org-id; a non-member org id is refused; role comes from the database", async () => {
  const s = await world();
  const r = await call(s, "GET", "me", tokens.frank); assert.equal(r.status, 409); assert.equal((await j(r)).organizations.length, 2);
  assert.equal((await call(s, "GET", "me", tokens.frank, undefined, ORG_A)).status, 200);
  assert.equal((await j(await call(s, "GET", "me", tokens.frank, undefined, ORG_A))).orgRole, "it_admin");
  assert.equal((await j(await call(s, "GET", "me", tokens.frank, undefined, ORG_B))).orgRole, "executive_readonly");
  // stored preference (what the account page sets) is honoured only for real memberships
  assert.equal((await j(await call(s, "GET", "me", jwt(U.frank, "frank@example.com", { user_metadata: { active_org: ORG_B } })))).organization.id, ORG_B);
  assert.equal((await call(s, "GET", "me", jwt(U.bob, "bob@example.com", { user_metadata: { active_org: ORG_A } }))).status, 200, "bob has one org; a bogus preference is ignored");
  assert.equal((await j(await call(s, "GET", "me", jwt(U.bob, "bob@example.com", { user_metadata: { active_org: ORG_A } })))).organization.id, ORG_B);
  assert.equal((await call(s, "GET", "me", jwt(U.frank, "frank@example.com", { user_metadata: { active_org: "a0000000-0000-4000-8000-0000000000ff" } }))).status, 409, "preference for a non-member org is ignored");
  assert.equal((await call(s, "GET", "me", tokens.bob, undefined, ORG_A)).status, 403, "bob is not in A");
  assert.equal((await call(s, "GET", "me", tokens.bob, undefined, "not-a-uuid")).status, 400);
  // demotion takes effect immediately (no stale role inside a still-valid token)
  await s.upsert("org_members", [{ orgId: ORG_A, userId: U.carol, role: "executive_readonly" }] as any, "org_id,user_id");
  assert.equal((await j(await call(s, "GET", "me", tokens.carol))).orgRole, "executive_readonly");
  // a disabled organization locks everyone out
  await s.upsert("organizations", [{ id: ORG_B, name: "Org B", slug: "org-b", disabledAt: new Date().toISOString() }] as any);
  assert.equal((await call(s, "GET", "me", tokens.bob)).status, 403);
});

test("ISOLATION: data ingested for org A is invisible to org B on every read path, and same-named hosts do not collide", async () => {
  const s = await world();
  const keyA = await newKey(s, tokens.alice), keyB = await newKey(s, tokens.bob);
  // the SAME host name ("WS01") in both organizations: bare ids would collide
  const ra = await call(s, "POST", "ingest/windows", keyA, attack("WS01")); assert.equal(ra.status, 200); assert.ok((await j(ra)).accepted > 0);
  const aEvents = (await j(await call(s, "GET", "events?limit=1000", tokens.alice))).length; assert.ok(aEvents >= 8);
  for (const p of ["events", "alerts", "incidents", "hunt?q=administrator", "audit"]) { const x = await j(await call(s, "GET", p, tokens.bob)); const rows = Array.isArray(x) ? x : x.rows; assert.equal(rows.filter((e: any) => p === "audit" ? !/org\./.test(e.action) : true).length, 0, `B sees nothing at /${p}`); }
  const ovB = await j(await call(s, "GET", "overview", tokens.bob)); assert.equal(ovB.counts?.events ?? ovB.events ?? 0, 0);
  const bIn = await call(s, "POST", "ingest/windows", keyB, attack("WS01")); assert.equal(bIn.status, 200);
  // A's data is intact after B wrote the same host/record ids
  assert.equal((await j(await call(s, "GET", "events?limit=1000", tokens.alice))).length, aEvents);
  assert.equal((await j(await call(s, "GET", "events?limit=1000", tokens.bob))).length, aEvents);
  const aAlerts = await j(await call(s, "GET", "alerts", tokens.alice)), bAlerts = await j(await call(s, "GET", "alerts", tokens.bob));
  assert.ok(aAlerts.length > 0 && bAlerts.length === aAlerts.length);
  // every raw row carries its own organization key; no row belongs to the Default organization
  const raw = (await s.select<any>("soc_events", { limit: 5000 })); assert.ok(raw.every((r) => r.orgId === ORG_A || r.orgId === ORG_B));
  assert.equal(raw.filter((r) => r.orgId === ORG_A).length, aEvents);
  assert.ok(raw.filter((r) => r.orgId === ORG_B).every((r) => String(r.id).startsWith(ORG_B + ":")));
});

test("ISOLATION: addressing another organization's object by id returns 404 and changes nothing", async () => {
  const s = await world();
  await call(s, "POST", "ingest/windows", await newKey(s, tokens.alice), attack("WS01"));
  const inc = (await j(await call(s, "GET", "incidents", tokens.alice)))[0]; assert.ok(inc, "A has an incident");
  assert.equal((await call(s, "GET", `incidents/${inc.id}`, tokens.bob)).status, 404);
  assert.equal((await call(s, "PATCH", `incidents/${inc.id}`, tokens.bob, { owner: "mallory" })).status, 404);
  assert.equal((await call(s, "POST", `incidents/${inc.id}/status`, tokens.bob, { status: "closed" })).status, 404);
  assert.equal((await j(await call(s, "GET", `incidents/${inc.id}`, tokens.alice))).incident.owner ?? null, null, "A's incident untouched");
  // a request body can not smuggle an organization id
  const evil = await call(s, "POST", "ingest/windows", await newKey(s, tokens.bob), { ...attack("WS99"), orgId: ORG_A, org_id: ORG_A });
  assert.equal(evil.status, 200);
  assert.equal((await s.select<any>("soc_events", { where: { assetId: "ws99" } as any })).filter((r) => r.orgId === ORG_A).length, 0);
});

test("ScopedStore: cannot write a row for another org, cannot widen a query, cannot read shared tables it should not touch", async () => {
  const s = await world(); const a = new ScopedStore(s, ORG_A), b = new ScopedStore(s, ORG_B);
  await a.upsert(T.assets, [{ id: "h1", name: "a-host" } as any]);
  await assert.rejects(() => b.upsert(T.assets, [{ id: "h2", orgId: ORG_A } as any]), /different organization/);
  assert.equal((await b.select(T.assets, { where: { orgId: ORG_A } as any })).length, 0, "caller-supplied orgId is overridden");
  assert.equal(await b.get(T.assets, "h1"), null);
  await b.remove(T.assets, { id: "h1" }); assert.ok(await a.get(T.assets, "h1"), "B's delete did not touch A");
  await assert.rejects(() => a.select("org_members"), /not available/); await assert.rejects(() => a.upsert("organizations", [{ id: "x" } as any]), /not available/);
  await assert.rejects(() => a.select(T.meta, {}), /by id/);
  // shared CISA reference data: everyone reads, only platform admins write
  await assert.rejects(() => a.upsert(T.kev, [{ id: "CVE-2024-0001" } as any]), /platform/);
  await new ScopedStore(s, ORG_A, { platformAdmin: true }).upsert(T.kev, [{ id: "CVE-2024-0001" } as any]);
  assert.equal((await b.select(T.kev, {})).length, 1);
  // per-integration state (soc_meta) is separate per organization
  await a.upsert(T.meta, [{ id: "wazuh", data: { alertsReceived: 5 } } as any]); assert.equal(await b.get(T.meta, "wazuh"), null);
  assert.throws(() => new ScopedStore(s, "x' or 1=1 --"), /Invalid organization/);
});

test("PERMISSIONS: viewer reads only; analysts write only in their domain; only admins approve; collectors cannot read", async () => {
  const s = await world();
  const key = await newKey(s, tokens.alice);
  await call(s, "POST", "ingest/windows", key, attack("WS01"));
  const inc = (await j(await call(s, "GET", "incidents", tokens.alice)))[0];
  assert.equal((await call(s, "GET", "incidents", tokens.dave)).status, 200, "executive reads");
  assert.equal((await call(s, "PATCH", `incidents/${inc.id}`, tokens.dave, { owner: "x" })).status, 403, "executive cannot write");
  assert.equal((await call(s, "PATCH", `incidents/${inc.id}`, tokens.carol, { owner: "carol" })).status, 200, "security analyst writes SOC");
  assert.equal((await call(s, "POST", "noc/maps", tokens.carol, { name: "m" })).status, 403, "security analyst cannot write NOC");
  assert.equal((await call(s, "PATCH", `incidents/${inc.id}`, tokens.nina, { owner: "nina" })).status, 403, "NOC operator cannot write SOC");
  assert.notEqual((await call(s, "POST", "noc/maps", tokens.nina, { name: "m" })).status, 403, "NOC operator writes NOC");
  assert.equal((await call(s, "POST", "noc/sources", tokens.carol, { name: "z", type: "zabbix", mode: "push" })).status, 403, "analyst cannot approve/configure");
  assert.equal((await call(s, "GET", "overview", key)).status, 403, "collector key cannot read");
  assert.equal((await call(s, "GET", "audit", tokens.dave)).status, 403, "viewer cannot read audit");
  assert.equal((await call(s, "GET", "audit", tokens.carol)).status, 200);
});

test("collector API keys: per organization, hashed at rest, revocable; cannot be replayed across organizations", async () => {
  const s = await world();
  const keyA = await newKey(s, tokens.alice, "ws-fleet");
  const stored = await s.select<any>("org_api_keys", {}); assert.equal(stored.length, 1);
  assert.ok(!JSON.stringify(stored).includes(keyA), "plaintext key never stored"); assert.equal(stored[0].keyHash.length, 64); assert.equal(stored[0].orgId, ORG_A);
  assert.equal((await call(s, "POST", "ingest/windows", keyA, attack("H1"))).status, 200);
  assert.equal((await call(s, "GET", "events", tokens.bob)).status, 200); assert.equal((await j(await call(s, "GET", "events", tokens.bob))).length, 0);
  assert.equal((await call(s, "POST", "ingest/windows", keyA.slice(0, -2) + "xx", attack("H1"))).status, 401, "altered key");
  assert.equal((await call(s, "POST", "org/keys", tokens.carol, { name: "nope" })).status, 403, "analyst cannot mint keys");
  assert.equal((await call(s, "POST", "org/keys", keyA, { name: "self" })).status, 403, "a key cannot mint keys");
  assert.equal((await j(await call(s, "GET", "org/keys", tokens.alice))).keys[0].prefix, keyA.slice(0, 12));
  assert.equal((await call(s, "GET", "org/keys", tokens.bob)).status, 200); assert.equal((await j(await call(s, "GET", "org/keys", tokens.bob))).keys.length, 0);
  assert.equal((await call(s, "DELETE", `org/keys/${stored[0].id}`, tokens.bob)).status, 404, "B cannot revoke A's key");
  assert.equal((await call(s, "DELETE", `org/keys/${stored[0].id}`, tokens.alice)).status, 200);
  assert.equal((await call(s, "POST", "ingest/windows", keyA, attack("H2"))).status, 401, "revoked key");
});

test("legacy shared tokens only reach the Default organization and can be switched off", async () => {
  const s = await world(); const L = "legacy-admin-token-1234567890";
  await call(s, "POST", "ingest/windows", await newKey(s, tokens.alice), attack("WS01"));
  const me = await j(await call(s, "GET", "me", L)); assert.equal(me.organization.id, DEFAULT_ORG_ID); assert.equal(me.auth, "legacy");
  assert.equal((await j(await call(s, "GET", "events", L))).length, 0, "legacy token cannot see org A");
  assert.equal((await call(s, "GET", "org/members", L)).status, 200);
  assert.equal((await call(s, "POST", "org/keys", L, { name: "legacy-key" })).status, 201);
  process.env.SOC_LEGACY_TOKENS = "off";
  try { assert.equal((await call(s, "GET", "me", L)).status, 401); } finally { delete process.env.SOC_LEGACY_TOKENS; }
  // non-platform org admins cannot rewrite the shared KEV catalogue
  assert.equal((await call(s, "POST", "import/kev", tokens.alice, { vulnerabilities: [{ cveID: "CVE-2024-1111" }] })).status, 403);
});

test("organizations: create, slug rules, per-user limit, members, roles, last-owner protection", async () => {
  const s = await world(); const newbie = jwt("13131313-0000-4000-8000-000000000013", "newbie@example.com");
  assert.equal((await call(s, "POST", "org/create", undefined, { name: "X" })).status, 401);
  assert.equal((await call(s, "POST", "org/create", newbie, { name: "A" })).status, 400, "name too short");
  assert.equal((await call(s, "POST", "org/create", newbie, { name: "Org A", slug: "org-a" })).status, 409, "slug taken");
  assert.equal((await call(s, "POST", "org/create", newbie, { name: "Evil", slug: "bad slug!" })).status, 400);
  const r = await call(s, "POST", "org/create", newbie, { name: "Newbie Co", slug: "newbie-co" }); assert.equal(r.status, 201);
  const o = await j(r); assert.equal(o.role, "owner");
  assert.equal((await j(await call(s, "GET", "org/mine", newbie))).organizations[0].id, o.id);
  assert.equal((await j(await call(s, "GET", "me", newbie))).organization.id, o.id);
  assert.equal((await j(await call(s, "GET", "events", newbie))).length, 0, "a new organization starts empty");
  for (let i = 0; i < 4; i++) assert.equal((await call(s, "POST", "org/create", newbie, { name: "Extra " + i, slug: "extra-" + i })).status, 201);
  assert.equal((await call(s, "POST", "org/create", newbie, { name: "One too many", slug: "too-many" })).status, 429);
  // roles
  const m = await j(await call(s, "GET", "org/members", tokens.alice)); assert.equal(m.members.length, 5);
  assert.equal((await call(s, "PATCH", `org/members/${U.dave}`, tokens.carol, { role: "owner" })).status, 403, "analyst cannot change roles");
  assert.equal((await call(s, "PATCH", `org/members/${U.dave}`, tokens.frank, { role: "owner" }, ORG_A)).status, 403, "it_admin cannot make owners");
  assert.equal((await call(s, "PATCH", `org/members/${U.bob}`, tokens.alice, { role: "owner" })).status, 404, "alice cannot touch B's member");
  assert.equal((await call(s, "PATCH", `org/members/${U.alice}`, tokens.alice, { role: "viewer" })).status, 400, "unknown role");
  assert.equal((await call(s, "PATCH", `org/members/${U.alice}`, tokens.alice, { role: "it_admin" })).status, 409, "last owner cannot demote");
  assert.equal((await call(s, "DELETE", `org/members/${U.alice}`, tokens.alice)).status, 409, "last owner cannot leave");
  assert.equal((await call(s, "PATCH", `org/members/${U.dave}`, tokens.alice, { role: "security_analyst" })).status, 200);
  assert.equal((await call(s, "DELETE", `org/members/${U.dave}`, tokens.carol)).status, 403);
  assert.equal((await call(s, "DELETE", `org/members/${U.dave}`, tokens.alice)).status, 200);
  assert.equal((await call(s, "GET", "me", tokens.dave)).status, 403, "removed member is locked out at once");
});

test("invitations: right email only, single use, expiry, token never stored, other org cannot see or revoke", async () => {
  const s = await world(); const newbie = jwt("14141414-0000-4000-8000-000000000014", "invitee@example.com"), other = jwt("15151515-0000-4000-8000-000000000015", "other@example.com");
  assert.equal((await call(s, "POST", "org/invitations", tokens.carol, { email: "invitee@example.com", role: "executive_readonly" })).status, 403);
  assert.equal((await call(s, "POST", "org/invitations", tokens.alice, { email: "invitee@example.com", role: "owner" })).status, 400);
  const r = await call(s, "POST", "org/invitations", tokens.alice, { email: "Invitee@Example.com", role: "executive_readonly" }); assert.equal(r.status, 201);
  const inv = await j(r); assert.ok(inv.token.startsWith("inv_"));
  const stored = JSON.stringify(await s.select("org_invitations", {})); assert.ok(!stored.includes(inv.token)); assert.ok(stored.includes(sha256(inv.token)));
  assert.equal((await call(s, "GET", "org/invitations", tokens.bob)).status, 200); assert.equal((await j(await call(s, "GET", "org/invitations", tokens.bob))).invitations.length, 0);
  assert.equal((await call(s, "DELETE", `org/invitations/${inv.id}`, tokens.bob)).status, 404);
  assert.equal((await call(s, "POST", "org/invitations/accept", other, { token: inv.token })).status, 403, "wrong email");
  assert.equal((await call(s, "POST", "org/invitations/accept", newbie, { token: "inv_" + "z".repeat(43) })).status, 400, "unknown token");
  const ok = await call(s, "POST", "org/invitations/accept", newbie, { token: inv.token }); assert.equal(ok.status, 200); assert.equal((await j(ok)).role, "executive_readonly");
  assert.equal((await call(s, "POST", "org/invitations/accept", newbie, { token: inv.token })).status, 400, "single use");
  assert.equal((await j(await call(s, "GET", "me", newbie))).organization.id, ORG_A);
  assert.equal((await call(s, "PATCH", "incidents/x", newbie, { owner: "z" })).status, 403, "invited as read-only");
  const r2 = await j(await call(s, "POST", "org/invitations", tokens.alice, { email: "late@example.com", role: "security_analyst" }));
  const rows = await s.select<any>("org_invitations", { where: { id: r2.id } }); await s.upsert("org_invitations", [{ ...rows[0], expiresAt: new Date(Date.now() - 1000).toISOString() }] as any);
  assert.equal((await call(s, "POST", "org/invitations/accept", jwt("16161616-0000-4000-8000-000000000016", "late@example.com"), { token: r2.token })).status, 400, "expired");
});

test("AUDIT: each organization has its own hash chain that verifies; membership changes are recorded in the right organization only", async () => {
  const s = await world();
  await call(s, "POST", "ingest/windows", await newKey(s, tokens.alice), attack("WS01")); await call(s, "POST", "ingest/windows", await newKey(s, tokens.bob), attack("WS01"));
  await call(s, "PATCH", `org/members/${U.carol}`, tokens.alice, { role: "executive_readonly" });
  const va = await j(await call(s, "GET", "audit/verify", tokens.alice)), vb = await j(await call(s, "GET", "audit/verify", tokens.bob)); assert.equal(va.ok, true); assert.equal(vb.ok, true);
  const aa = await j(await call(s, "GET", "audit", tokens.alice)), ab = await j(await call(s, "GET", "audit", tokens.bob));
  assert.ok(aa.some((e: any) => e.action === "org.member.role")); assert.ok(!ab.some((e: any) => e.action === "org.member.role"));
  assert.ok(aa.length > 0 && ab.length > 0 && aa.every((e: any) => !JSON.stringify(e).includes(ORG_B)) && ab.every((e: any) => !JSON.stringify(e).includes(ORG_A)));
  const sa = (await s.select<any>("soc_audit", { limit: 1000 })); assert.ok(sa.filter((e) => e.orgId === ORG_A).length && sa.filter((e) => e.orgId === ORG_B).length);
});
