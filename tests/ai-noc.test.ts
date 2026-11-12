// Phase 5 – AI NOC analyst. Deterministic analysis over stored org data; model narrative is a stub (no live model key in this environment) run through the REAL validation.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { ScopedStore } from "../lib/tenant/scoped-store";
import { analyzeNoc, detect } from "../lib/noc/ai-analyst";
import { CATALOG } from "../lib/noc/exec/catalog";
import { NT } from "../lib/noc/types";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const J = async (r: Response) => r.json() as Promise<any>;
let n = 0;
async function world() {
  n++; const u = { owner: randomUUID(), ro: randomUUID(), noc: randomUUID(), bOwner: randomUUID() }; const tok = { owner: jwt(u.owner, `o${n}@x`), ro: jwt(u.ro, `r${n}@x`), noc: jwt(u.noc, `n${n}@x`), bOwner: jwt(u.bOwner, `b${n}@x`) };
  const s = new TestStore(); await s.upsert("organizations", [{ id: ORG_A, name: "A", slug: "a" }, { id: ORG_B, name: "B", slug: "b" }] as any);
  const m = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await m(ORG_A, u.owner, "owner"); await m(ORG_A, u.ro, "executive_readonly"); await m(ORG_A, u.noc, "noc_operator"); await m(ORG_B, u.bOwner, "owner");
  let model: any = null; const deps: any = { store: s, get model() { return model; } };
  const call = (mth: string, p: string, t: string, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: mth, headers: { authorization: "Bearer " + t, "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), deps);
  const A = new ScopedStore(s, ORG_A), B = new ScopedStore(s, ORG_B), NOW = Date.parse("2026-11-10T20:00:00Z");
  const dev = (id: string, o: any = {}) => ({ id, name: id, type: "server", ip: o.ip ?? "10.0.0." + (10 + (id.charCodeAt(id.length - 1) % 50)), source: "live", up: o.up ?? true, metrics: o.metrics ?? { cpu: 10, mem: 30, disk: 40 }, links: o.links ?? [], history: [], receivedAt: new Date(NOW - 30_000).toISOString(), collector: "t" });
  const series = async (store: ScopedStore, deviceId: string, key: string, vals: number[], stepMin = 5) => { const rows = vals.map((value, i) => ({ id: `nmt_${deviceId}${key}${i}`.replace(/[^a-z0-9_]/gi, "") + "aa00bb", deviceId, sourceId: "native", key, value, t: new Date(NOW - (vals.length - i) * stepMin * 60_000).toISOString() })); await store.upsert(NT.metrics, rows as any); return rows; };
  const ctx = (store: ScopedStore, name = "tester") => ({ store, actor: { name, role: "admin" }, now: () => NOW }) as any;
  return { s, call, A, B, NOW, tok, dev, series, ctx, setModel: (f: any) => { model = f; } };
}
const base = (n: number, v: number, j = 1) => Array.from({ length: n }, (_, i) => v + ((i * 7) % (2 * j + 1)) - j);

test("detect(): level shift is flagged with real sample ids; stable noise, short history and small changes are not", () => {
  const rows = (vals: number[]) => vals.map((value, i) => ({ id: "r" + i, value, t: new Date(Date.parse("2026-11-10T00:00:00Z") + i * 300_000).toISOString() }));
  const up = detect(rows([...base(40, 20), 95, 96, 94, 97]), "cpu", "d"); assert.ok(up.anomaly); assert.equal(up.anomaly!.direction, "up"); assert.ok(up.anomaly!.baseline < 25 && up.anomaly!.current > 90); assert.ok(up.anomaly!.evidence.every((e) => e.startsWith("r")));
  assert.equal(detect(rows(base(44, 20, 2)), "cpu", "d").anomaly, undefined, "noise around a stable level");
  assert.ok(detect(rows([1, 2, 3, 90, 91]), "cpu", "d").insufficient, "too little history is reported, not guessed");
  assert.equal(detect(rows([...base(40, 20), 24, 25, 24, 26]), "cpu", "d").anomaly, undefined, "a small change below the minimum delta is ignored");
  const disk = detect(rows(Array.from({ length: 48 }, (_, i) => 50 + i * 0.5)), "disk", "d"); assert.ok(disk.trend); assert.ok(disk.trend!.etaHoursTo100! > 0 && disk.trend!.r2 > 0.9);
  assert.equal(detect(rows(Array.from({ length: 48 }, (_, i) => 50 + ((i * 37) % 11))), "disk", "d").trend, undefined, "no trend claim from random data");
});

test("CPU spike: root cause names a CPU-bound workload; every cited evidence id exists in this organization's data; recommendations are not executed", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("web01", { metrics: { cpu: 96, mem: 35, disk: 40 } })] as any);
  const rows = await w.series(w.A, "web01", "cpu", [...base(40, 20), 95, 96, 94, 97]);
  const r = await analyzeNoc(w.ctx(w.A), { deviceId: "web01" }); const a = r.analyses[0];
  assert.match(a.rootCauses[0].cause, /CPU-bound workload on web01/); assert.ok(["medium", "high"].includes(a.rootCauses[0].confidence)); assert.ok(a.rootCauses[0].contradicts.some((x: string) => /Memory is normal/.test(x)));
  const all = new Set((await w.A.select<any>(NT.metrics, {})).map((x: any) => x.id).concat(["web01"])); for (const id of a.rootCauses.flatMap((c: any) => c.evidence)) assert.ok(all.has(id) || id.startsWith("rec:"), "unknown evidence " + id);
  assert.ok(r.anomalies.some((x: any) => x.metric === "cpu" && rows.some((row) => x.evidence.includes(row.id))));
  assert.ok(r.recommendations.length >= 1 && r.recommendations.every((x: any) => x.kind === "recommendation" && x.status === "not_executed" && x.requiresHuman === true));
  assert.ok(r.recommendations.some((x: any) => x.changesSystem && /cannot do this/.test(x.action)), "system-changing advice is labelled as a human task");
  assert.match(r.contract, /Nothing in this result was executed/); assert.ok(r.suggestedDiagnostics.some((d: any) => d.template === "sys.cpu_top" && d.status === "suggested_not_requested"));
});

test("a recent read-only diagnostic result becomes cited evidence and raises confidence; an old one is ignored", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("web01", { metrics: { cpu: 96, mem: 35, disk: 40 } })] as any); await w.series(w.A, "web01", "cpu", [...base(40, 20), 95, 96, 94, 97]);
  const job = (id: string, endedAt: string) => ({ id, hostId: "web01", os: "linux", template: "sys.cpu_top", tier: "R0", params: {}, status: "succeeded", dryRun: false, requestedBy: "u", requestedByKind: "user", requestedAt: endedAt, endedAt, nonce: "n", argvPreview: "", policy: [], note: "", output: "  PID %CPU %MEM COMMAND\n 4242 93.0  1.2 ffmpeg\n" });
  await w.A.upsert("noc_diag_jobs", [job("njb_recent01", new Date(w.NOW - 600_000).toISOString())] as any);
  let r = await analyzeNoc(w.ctx(w.A), { deviceId: "web01" }); let top = r.analyses[0].rootCauses[0]; assert.equal(top.confidence, "high"); assert.ok(top.evidence.includes("njb_recent01")); assert.ok(top.supports.some((x: string) => /ffmpeg/.test(x) && /read-only/.test(x)));
  const w2 = await world(); await w2.A.upsert("noc_devices", [w2.dev("web01", { metrics: { cpu: 96, mem: 35, disk: 40 } })] as any); await w2.series(w2.A, "web01", "cpu", [...base(40, 20), 95, 96, 94, 97]); await w2.A.upsert("noc_diag_jobs", [job("njb_old00001", new Date(w2.NOW - 10 * 3600_000).toISOString())] as any);
  r = await analyzeNoc(w2.ctx(w2.A), { deviceId: "web01" }); top = r.analyses[0].rootCauses[0]; assert.ok(!top.evidence.includes("njb_old00001")); assert.ok(top.nextChecks.some((x: string) => /sys\.cpu_top/.test(x)));
});

test("offline device: upstream cause when a linked neighbour is also down; local cause when neighbours are healthy; low confidence and a caveat when topology is unknown", async () => {
  const w = await world();
  await w.A.upsert("noc_devices", [w.dev("sw1", { up: false }), w.dev("srv1", { up: false, links: [{ to: "sw1" }] }), w.dev("srv2", { up: true, links: [{ to: "sw1" }] }), w.dev("alone", { up: false }), w.dev("lone-with-friend", { up: false, links: [{ to: "friend" }] }), w.dev("friend", { up: true })] as any);
  const up = await analyzeNoc(w.ctx(w.A), { deviceId: "srv1" }); assert.match(up.analyses[0].rootCauses[0].cause, /Upstream or shared-dependency failure involving sw1/); assert.ok(up.analyses[0].rootCauses[0].evidence.includes("sw1"));
  const loc = await analyzeNoc(w.ctx(w.A), { deviceId: "lone-with-friend" }); assert.match(loc.analyses[0].rootCauses[0].cause, /itself is down/); assert.ok(loc.analyses[0].rootCauses[0].contradicts.some((x: string) => /silent agent/.test(x)));
  const unk = await analyzeNoc(w.ctx(w.A), { deviceId: "alone" }); assert.equal(unk.analyses[0].rootCauses[0].confidence, "low"); assert.ok(unk.analyses[0].rootCauses[0].contradicts.some((x: string) => /No link data/.test(x)));
});

test("disk growth: trend + ETA to full is computed from stored samples and recommended as a human task", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("db01", { metrics: { cpu: 5, mem: 30, disk: 88 } })] as any); await w.series(w.A, "db01", "disk", Array.from({ length: 48 }, (_, i) => 70 + i * 0.4), 30);
  const r = await analyzeNoc(w.ctx(w.A), { deviceId: "db01", hours: 48 }); const t = r.trends.find((x: any) => x.metric === "disk"); assert.ok(t && t.etaHoursTo100! > 0, "ETA computed"); assert.match(r.analyses[0].rootCauses[0].cause, /Disk space exhaustion/);
  assert.ok(r.recommendations.some((x: any) => /Plan cleanup or expansion/.test(x.action) && x.requiresHuman)); assert.ok(r.suggestedDiagnostics.some((d: any) => d.template === "sys.disk"));
});

test("latency/loss with a saturated link points at link saturation; without saturation it says the path (and why)", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("edge1", { metrics: { latencyMs: 420, lossPct: 6, bwInMbps: 950, bwCapMbps: 1000 } }), w.dev("p2", { metrics: { latencyMs: 400, lossPct: 5 } })] as any);
  const sat = await analyzeNoc(w.ctx(w.A), { deviceId: "edge1" }); assert.match(sat.analyses[0].rootCauses[0].cause, /Link saturation/);
  const path = await analyzeNoc(w.ctx(w.A), { deviceId: "p2" }); assert.match(path.analyses[0].rootCauses[0].cause, /path problem/); assert.ok(path.analyses[0].rootCauses[0].contradicts.some((x: string) => /No link is saturated/.test(x)));
});

test("flapping devices and linked devices that change together are surfaced", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("a1", { links: [{ to: "a2" }] }), w.dev("a2", { links: [{ to: "a1" }] })] as any);
  await w.series(w.A, "a1", "up", [1, 1, 0, 1, 0, 1, 1, 0, 1, 1]); await w.series(w.A, "a1", "cpu", [...base(40, 20), 95, 96, 94, 97]); await w.series(w.A, "a2", "cpu", [...base(40, 20), 93, 95, 94, 96]);
  const r = await analyzeNoc(w.ctx(w.A), { deviceId: "a1" }); assert.ok(r.analyses[0].rootCauses.some((c: any) => /flapping/.test(c.cause))); assert.ok(r.correlations.some((c: any) => c.kind === "linked_devices_changed_together" && c.deviceIds.includes("a2")));
});

test("no data and unknown targets are handled honestly; other organizations' devices and incidents are invisible", async () => {
  const w = await world(); const empty = await analyzeNoc(w.ctx(w.A)); assert.ok(empty.limitations.some((x: string) => /No devices have reported/.test(x))); assert.equal(empty.analyses.length, 0);
  await w.A.upsert("noc_devices", [w.dev("web01", { metrics: { cpu: 99 } })] as any); await w.A.upsert(NT.incidents, [{ id: "inc1", title: "x", severity: "high", status: "Investigating", host: "web01", sourceId: "n", eventIds: [], executionIds: [], assignedAgent: "server", category: "server", createdAt: "t", updatedAt: "t" }] as any);
  const thin = await analyzeNoc(w.ctx(w.A), { deviceId: "web01" }); assert.ok(thin.limitations.some((x: string) => /at least 12 samples/.test(x)), "says why anomaly detection did not run");
  assert.equal((await w.call("POST", "noc/ai/analyze", w.tok.bOwner, { deviceId: "web01" })).status, 404, "B cannot analyze A's device");
  assert.equal((await w.call("POST", "noc/ai/analyze", w.tok.bOwner, { incidentId: "inc1" })).status, 404, "B cannot analyze A's incident");
  const b = await J(await w.call("POST", "noc/ai/analyze", w.tok.bOwner, {})); assert.equal(b.dataUsed.devices, 0); assert.ok(!JSON.stringify(b).includes("web01"));
  const a = await J(await w.call("POST", "noc/ai/analyze", w.tok.ro, { incidentId: "inc1" })); assert.equal(a.analyses[0].deviceId, "web01", "read-only roles can read analysis");
});

test("model narrative: kept only when every cited id is real; invented ids, claimed actions and a failing model are discarded with a visible reason", async () => {
  const w = await world(); await w.A.upsert("noc_devices", [w.dev("web01", { metrics: { cpu: 96 } })] as any); const rows = await w.series(w.A, "web01", "cpu", [...base(40, 20), 95, 96, 94, 97]);
  const ask = (f: any) => analyzeNoc(w.ctx(w.A), { deviceId: "web01" }, f);
  let r = await ask(async () => ({ text: `CPU on web01 shifted; see ${rows[rows.length - 1].id}.`, model: "stub-model" })); assert.equal(r.method, "rules+ai"); assert.ok(r.narrative); assert.match(r.narrativeNote!, /computed from your data/);
  r = await ask(async () => ({ text: "Cause confirmed by nmt_deadbeefcafe0001 on web01.", model: "stub" })); assert.equal(r.narrative, null); assert.equal(r.method, "rules"); assert.ok(r.limitations.some((x: string) => /do not exist in this organization/.test(x)));
  r = await ask(async () => ({ text: "I have restarted nginx and the problem was resolved.", model: "stub" })); assert.equal(r.narrative, null); assert.ok(r.limitations.some((x: string) => /claimed an action/.test(x)));
  r = await ask(async () => { throw new Error("service down"); }); assert.equal(r.narrative, null); assert.ok(r.analyses[0].rootCauses.length >= 1, "analysis still returned"); assert.ok(r.limitations.some((x: string) => /AI service unavailable/.test(x)));
});

test("analysis never executes: no jobs are created by default; with explicit proposal flag the agent only PROPOSES (human must confirm), and only catalog templates appear", async () => {
  const w = await world(); const key = await J(await w.call("POST", "org/keys", w.tok.owner, { name: "analyst-key" }));
  const tr = await w.call("POST", "noc/telemetry", key.key, { source: "t", devices: [{ id: "web01", name: "web01", type: "server", ip: "10.0.0.5", up: true, metrics: { cpu: 96 } }] }); assert.equal(tr.status, 200, JSON.stringify([key, await tr.text()]));
  await w.series(w.A, "web01", "cpu", [...base(40, 20), 95, 96, 94, 97]);
  const r0 = await w.call("POST", "noc/ai/analyze", w.tok.noc, { deviceId: "web01" }); let r = await J(r0); assert.equal(r0.status, 200, JSON.stringify(r)); assert.equal((await w.A.select<any>("noc_diag_jobs", {})).length, 0, "plain analysis creates nothing");
  for (const d of r.suggestedDiagnostics) assert.ok(CATALOG.some((t) => t.id === d.template), d.template);
  assert.equal((await w.call("POST", "noc/ai/analyze", w.tok.ro, { deviceId: "web01", proposeDiagnostics: true })).status, 403, "read-only role cannot trigger proposals");
  r = await J(await w.call("POST", "noc/ai/analyze", w.tok.noc, { deviceId: "web01", proposeDiagnostics: true })); assert.ok(r.suggestedDiagnostics.every((d: any) => d.status === "suggested_not_requested") && r.suggestedDiagnostics.some((d: any) => /not proposed/.test(d.why)), "execution off / no executor -> nothing proposed, and it says why");
  await w.call("POST", "noc/exec/executors", w.tok.owner, { hostId: "web01", keyId: key.id, os: "linux" }); await w.call("PUT", "noc/exec/settings", w.tok.owner, { enabled: true });
  r = await J(await w.call("POST", "noc/ai/analyze", w.tok.noc, { deviceId: "web01", proposeDiagnostics: true })); const prop = r.suggestedDiagnostics.find((d: any) => d.status === "proposed_awaiting_human"); assert.ok(prop?.jobId);
  const job = await J(await w.call("GET", `noc/diag/${prop.jobId}`, w.tok.noc)); assert.equal(job.status, "proposed"); assert.equal(job.requestedBy, "agent:noc-analyst");
  assert.equal((await J(await w.call("GET", "noc/executor/jobs?host=web01", key.key))).jobs.length, 0, "an AI proposal is never delivered to a host");
  assert.equal((await w.call("POST", `noc/diag/${prop.jobId}/approve`, w.tok.ro, {})).status, 403);
  assert.equal((await J(await w.call("POST", `noc/diag/${prop.jobId}/approve`, w.tok.noc, {}))).status, "queued", "only a human confirmation queues it");
});
