// Phase 3: real-time NOC telemetry -> events/incidents, stale detection, history/availability, and two-organization isolation.
// Everything here runs the real code paths (handleSoc, ScopedStore, workflow); only the database is in-memory. Run: npx tsx --test tests/noc-org.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { ScopedStore } from "../lib/tenant/scoped-store";
import * as RT from "../lib/noc/realtime";
import { NT } from "../lib/noc/types";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40);
delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const U = { a: "aaaaaaaa-0000-4000-8000-00000000000a", ro: "cccccccc-0000-4000-8000-00000000000c", b: "bbbbbbbb-0000-4000-8000-00000000000b" };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const tok = { a: jwt(U.a, "a@x.io"), ro: jwt(U.ro, "ro@x.io"), b: jwt(U.b, "b@x.io") };
const J = async (r: Response) => r.json() as Promise<any>;

async function world() {
  const s = new TestStore();
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a" }, { id: ORG_B, name: "Org B", slug: "org-b" }] as any);
  const m = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await m(ORG_A, U.a, "owner"); await m(ORG_A, U.ro, "executive_readonly"); await m(ORG_B, U.b, "owner");
  const deps = { store: s, model: null } as any;
  const call = (m: string, p: string, t: string, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: m, headers: { authorization: "Bearer " + t, "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), deps);
  const scoped = (org: string, now?: () => number) => ({ store: new ScopedStore(s, org), actor: { name: "test", role: "admin" } as any, model: null, now });
  return { s, call, scoped };
}
const srv = (cpu: number, extra: any = {}) => ({ source: "linux-agent", devices: [{ id: "web01", name: "web01", type: "server", ip: "10.0.0.5", up: true, metrics: { cpu, mem: 40, disk: 50, ...extra } }] });

test("critical CPU opens ONE event + incident; repeated samples do not duplicate; recovery resolves from fresh data", async () => {
  const { call, scoped } = await world();
  let r = await call("POST", "noc/telemetry", tok.a, srv(97)); assert.equal(r.status, 200); let b = await J(r); assert.equal(b.eventsOpened, 1);
  await call("POST", "noc/telemetry", tok.a, srv(98)); r = await call("POST", "noc/telemetry", tok.a, srv(96)); b = await J(r); assert.equal(b.eventsOpened, 0, "no duplicate while the problem persists");
  const c = scoped(ORG_A); const ev = await c.store.select<any>(NT.events, {}), inc = await c.store.select<any>(NT.incidents, {});
  assert.equal(ev.length, 1); assert.equal(ev[0].status, "problem"); assert.equal(ev[0].severity, "critical"); assert.equal(inc.length, 1); assert.match(inc[0].title, /High CPU/);
  b = await J(await call("POST", "noc/telemetry", tok.a, srv(20))); assert.equal(b.eventsResolved, 1);
  const ev2 = await c.store.select<any>(NT.events, {}), inc2 = await c.store.select<any>(NT.incidents, {});
  assert.equal(ev2[0].status, "resolved"); assert.equal(inc2[0].status, "Resolved", "incident closed because fresh telemetry shows recovery");
});

test("a warning-level metric is shown but does not raise an incident; a down device does", async () => {
  const { call, scoped } = await world();
  await call("POST", "noc/telemetry", tok.a, srv(82)); // between warning and degraded
  assert.equal((await scoped(ORG_A).store.select<any>(NT.incidents, {})).length, 0);
  await call("POST", "noc/telemetry", tok.a, { source: "probe", devices: [{ id: "web01", name: "web01", type: "server", up: false, metrics: {} }] });
  const inc = await scoped(ORG_A).store.select<any>(NT.incidents, {}); assert.equal(inc.length, 1); assert.match(inc[0].title, /is down/);
  await call("POST", "noc/telemetry", tok.a, srv(10)); assert.equal((await scoped(ORG_A).store.select<any>(NT.incidents, {}))[0].status, "Resolved");
});

test("a silent device is detected by the sweep, and clears when data returns", async () => {
  const { call, scoped } = await world(); await call("POST", "noc/telemetry", tok.a, srv(10));
  const later = Date.now() + 20 * 60_000, c = scoped(ORG_A, () => later);
  assert.deepEqual(await RT.sweepDevices(c), ["web01"]); assert.deepEqual(await RT.sweepDevices(c), [], "not raised twice");
  assert.match((await c.store.select<any>(NT.incidents, {}))[0].title, /No data from web01/);
  const b = await J(await call("POST", "noc/telemetry", tok.a, srv(10))); assert.equal(b.eventsResolved, 1);
});

test("history and availability are computed from stored samples only", async () => {
  const { call, scoped } = await world();
  for (let i = 0; i < 3; i++) await call("POST", "noc/telemetry", tok.a, srv(10 + i));
  await call("POST", "noc/telemetry", tok.a, { source: "probe", devices: [{ id: "web01", name: "web01", type: "server", up: false, metrics: {} }] });
  const av = await RT.availability(scoped(ORG_A), 24), d = av.devices[0]; assert.equal(d.samples, 4); assert.equal(d.upSamples, 3); assert.equal(d.availabilityPct, 75);
  const h = await RT.history(scoped(ORG_A), "web01", "cpu", 24); assert.deepEqual(h.points.map((p) => p.v), [10, 11, 12]);
  assert.deepEqual((await RT.history(scoped(ORG_A), "web01", "cpu; drop", 24)).points, []);
  const api = await J(await call("GET", "noc/availability?hours=24", tok.a)); assert.equal(api.devices[0].availabilityPct, 75);
});

test("organization isolation: B sees none of A's devices, events, incidents, metrics or availability", async () => {
  const { call, scoped } = await world();
  await call("POST", "noc/telemetry", tok.a, srv(99));
  await call("POST", "noc/telemetry", tok.b, { source: "x", devices: [{ id: "web01", name: "web01", type: "server", up: true, metrics: { cpu: 5 } }] });   // same device id in B on purpose
  assert.equal((await scoped(ORG_B).store.select<any>(NT.incidents, {})).length, 0, "B's healthy device raised nothing");
  assert.equal((await scoped(ORG_A).store.select<any>(NT.incidents, {})).length, 1);
  const bd = await J(await call("GET", "noc/devices", tok.b)); assert.equal(bd.length, 1); assert.equal(bd[0].metrics.cpu, 5);
  const bav = await RT.availability(scoped(ORG_B), 24); assert.equal(bav.devices[0].samples, 1);
  assert.deepEqual((await RT.history(scoped(ORG_B), "web01", "cpu", 24)).points.map((p) => p.v), [5]);
  const bov = await call("GET", "noc/overview", tok.b); assert.equal(bov.status, 200);
});

test("read-only members cannot push telemetry; unauthenticated is rejected; bad payloads are 400", async () => {
  const { call } = await world();
  assert.equal((await call("POST", "noc/telemetry", tok.ro, srv(10))).status, 403);
  assert.equal((await call("POST", "noc/telemetry", "nope", srv(10))).status, 401);
  assert.equal((await call("POST", "noc/telemetry", tok.a, { devices: [] })).status, 400);
  assert.equal((await call("POST", "noc/telemetry", tok.a, { devices: [{ id: "x", type: "server", metrics: { cpu: 500 } }] })).status, 400);
});

test("long windows are read in pages, so a 1000-row database cap cannot silently truncate availability", async () => {
  const { s, scoped } = await world(); const base = Date.parse("2026-11-10T00:00:00Z"), rows: any[] = [];
  for (let i = 0; i < 2500; i++) rows.push({ id: "m" + i, deviceId: "web01", sourceId: "native", key: "up", value: i % 10 === 0 ? 0 : 1, t: new Date(base + i * 1000).toISOString() });
  await new ScopedStore(s, ORG_A).upsert(NT.metrics, rows);
  const capped = { ...s, select: (t: string, q: any = {}) => s.select(t, { ...q, limit: Math.min(q.limit ?? 1000, 1000) }) } as any;   // emulate the Supabase row cap
  const c: any = { store: new ScopedStore(Object.assign(Object.create(s), { select: capped.select }), ORG_A), actor: { name: "t", role: "admin" }, now: () => base + 3000 * 1000 };
  const d = (await RT.availability(c, 24)).devices[0]; assert.equal(d.samples, 2500); assert.equal(d.availabilityPct, 90);
});
