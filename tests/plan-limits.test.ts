// Device limits and data retention. Proves: nothing is restricted or deleted unless BILLING_ENFORCE=1; existing devices keep working above the limit;
// only NEW devices are refused; retention is dry-run by default, prunes only old noc_metrics, and is isolated per organization.
import test from "node:test";
import assert from "node:assert/strict";
import { TestStore } from "./test-store";
import { getEntitlements, status, deviceLimit } from "../lib/billing/service";
import { PLAN_LIMITS } from "../lib/billing/plans";
import { admitDevices, pruneMetrics } from "../lib/noc/limits";
import { ingestAndEvaluate } from "../lib/noc/realtime";
import { ScopedStore } from "../lib/tenant/scoped-store";

const A = "11111111-1111-4111-8111-111111111111", B = "22222222-2222-4222-8222-222222222222", ON = { BILLING_ENFORCE: "1" }, OFF = {};
const dev = (n: number, extra = {}) => ({ id: "dev" + n, type: "server", metrics: { cpu: 10 }, ...extra });
const ctx = (raw: TestStore, org: string, deviceMax: number | null) => ({ store: new ScopedStore(raw, org), actor: { name: "t", role: "admin" }, model: null, deviceMax } as any);

test("limits table matches the approved recommendation", () => {
  assert.deepEqual([PLAN_LIMITS.free.maxApiKeys, PLAN_LIMITS.pro.maxApiKeys], [25, 100]); assert.deepEqual([PLAN_LIMITS.free.maxExecutors, PLAN_LIMITS.pro.maxExecutors], [3, 50]);
  assert.deepEqual([PLAN_LIMITS.free.maxDevices, PLAN_LIMITS.pro.maxDevices], [25, 500]); assert.deepEqual([PLAN_LIMITS.free.retentionDays, PLAN_LIMITS.pro.retentionDays], [7, 30]);
});
test("flag off (default): every limit is null, status says not enforced, existing orgs unaffected", async () => {
  const s = new TestStore(), e = await getEntitlements(s, A, Date.now(), OFF);
  assert.deepEqual([e.enforced, e.maxDevices, e.maxExecutors, e.maxApiKeys, e.retentionDays], [false, null, null, null, null]); assert.equal(await deviceLimit(s, A, OFF), null);
  assert.equal((await status(s, A, OFF) as any).enforced, false);
  const on = await getEntitlements(s, A, Date.now(), ON); assert.deepEqual([on.enforced, on.maxDevices, on.retentionDays], [true, 25, 7]);
});
test("telemetry with no limit stores every device (not enforced)", async () => {
  const s = new TestStore(); const r: any = await ingestAndEvaluate(ctx(s, A, null), { devices: Array.from({ length: 40 }, (_, i) => dev(i)) });
  assert.equal(r.received, 40); assert.equal(r.deviceLimitSkipped, undefined);
});
test("limit on: only NEW devices beyond the limit are skipped and reported; existing devices above the limit still update; nothing is deleted", async () => {
  const s = new TestStore(); await ingestAndEvaluate(ctx(s, A, null), { devices: Array.from({ length: 6 }, (_, i) => dev(i)) });   // org already has 6 devices
  const r: any = await ingestAndEvaluate(ctx(s, A, 5), { devices: [dev(0, { metrics: { cpu: 55 } }), dev(100), dev(101)] });         // limit now 5 (already exceeded)
  assert.equal(r.received, 1, "existing dev0 updated"); assert.equal(r.deviceLimitSkipped, 2); assert.deepEqual(r.skippedDevices.sort(), ["dev100", "dev101"]);
  const all = await new ScopedStore(s, A).select<any>("noc_devices", {}); assert.equal(all.length, 6, "no device removed, none added");
  assert.equal(all.find((d: any) => d.id === "dev0").metrics.cpu, 55);
  const none: any = await ingestAndEvaluate(ctx(s, A, 5), { devices: [dev(200)] }); assert.equal(none.received, 0); assert.equal(none.deviceLimitSkipped, 1);
});
test("room left: admits new devices up to the limit exactly", async () => {
  const s = new TestStore(); await ingestAndEvaluate(ctx(s, A, null), { devices: [dev(1), dev(2)] });
  const a = await admitDevices(new ScopedStore(s, A), ["dev1", "dev3", "dev4", "dev5"], 4); assert.deepEqual([...a.allowed].sort(), ["dev1", "dev3", "dev4"]); assert.deepEqual(a.skipped, ["dev5"]);
});
test("device counts are per organization", async () => {
  const s = new TestStore(); await ingestAndEvaluate(ctx(s, A, null), { devices: Array.from({ length: 5 }, (_, i) => dev(i)) });
  const r: any = await ingestAndEvaluate(ctx(s, B, 5), { devices: Array.from({ length: 5 }, (_, i) => dev(i)) }); assert.equal(r.received, 5, "org B has its own room");
});
test("retention: no limit = nothing eligible; dry run reports but deletes nothing; apply removes only old noc_metrics of this org", async () => {
  const s = new TestStore(), now = Date.now(), d = 86400000;
  for (const org of [A, B]) await s.upsert("noc_metrics", [{ id: org + ":old1", orgId: org, t: now - 40 * d }, { id: org + ":old2", orgId: org, t: new Date(now - 10 * d).toISOString() }, { id: org + ":new", orgId: org, t: now - d }] as any);
  await s.upsert("audit_log", [{ id: A + ":a1", orgId: A, t: now - 400 * d }] as any);
  const sa = new ScopedStore(s, A);
  assert.equal((await pruneMetrics(sa, null, { apply: true, now })).deleted, 0);
  const dry: any = await pruneMetrics(sa, 7, { now }); assert.deepEqual([dry.eligible, dry.deleted, dry.applied], [2, 0, false]); assert.equal((await sa.select("noc_metrics", {})).length, 3);
  const real: any = await pruneMetrics(sa, 7, { apply: true, now }); assert.equal(real.deleted, 2);
  assert.deepEqual((await sa.select<any>("noc_metrics", {})).map((r: any) => r.id), ["new"]);
  assert.equal((await new ScopedStore(s, B).select("noc_metrics", {})).length, 3, "other org untouched"); assert.equal((await s.select("audit_log", {})).length, 1, "audit log untouched");
});
