// Phase 5 – AI SOC analyst: prioritization, correlation, investigation and evidence-based recommendations over stored organization data. Model narrative is a stub run through the REAL validation.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { ScopedStore } from "../lib/tenant/scoped-store";
import { analyzeSoc } from "../lib/soc/ai-analyst";
import { T } from "../lib/soc/store";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1", J = async (r: Response) => r.json() as Promise<any>;
const NOW = Date.parse("2026-11-10T20:00:00Z"), ago = (min: number) => new Date(NOW - min * 60_000).toISOString();
let n = 0;
async function world() {
  n++; const u = { owner: randomUUID(), ro: randomUUID(), sec: randomUUID(), bOwner: randomUUID() }; const tok = { owner: jwt(u.owner, `o${n}@x`), ro: jwt(u.ro, `r${n}@x`), sec: jwt(u.sec, `s${n}@x`), bOwner: jwt(u.bOwner, `b${n}@x`) };
  const s = new TestStore(); await s.upsert("organizations", [{ id: ORG_A, name: "A", slug: "a" }, { id: ORG_B, name: "B", slug: "b" }] as any);
  const m = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await m(ORG_A, u.owner, "owner"); await m(ORG_A, u.ro, "executive_readonly"); await m(ORG_A, u.sec, "security_analyst"); await m(ORG_B, u.bOwner, "owner");
  const deps: any = { store: s, model: null };
  const call = (mth: string, p: string, t: string, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: mth, headers: { authorization: "Bearer " + t, "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), deps);
  const A = new ScopedStore(s, ORG_A), B = new ScopedStore(s, ORG_B);
  return { s, call, A, B, tok, deps };
}
const asset = (host: string, crit: number) => ({ id: host, hostname: host, ips: ["10.0.0.1"], criticality: crit, authorized: false, source: "live", firstSeen: ago(9999), lastSeen: ago(1) });
const alert = (id: string, host: string, o: any = {}) => ({ id, source: "live", ruleId: o.rule ?? "r1", key: id, title: o.title ?? `Alert ${id}`, severity: o.sev ?? "high", confidence: o.conf ?? 0.8, mitre: o.mitre ?? [], assetId: host, host, eventIds: o.events ?? [], firstSeen: o.first ?? ago(30), lastSeen: o.last ?? ago(10), reasoning: "because", entities: { users: o.users ?? [], ips: o.ips ?? [] }, incidentId: o.inc, createdAt: ago(30) });
const inc = (id: string, host: string, alerts: string[], o: any = {}) => ({ id, source: "live", title: o.title ?? `Incident ${id}`, severity: o.sev ?? "high", confidence: o.conf ?? 0.8, status: o.status ?? "open", assetId: host, host, alertIds: alerts, tactics: o.tactics ?? [], firstSeen: o.first ?? ago(30), lastSeen: o.last ?? ago(10), reasoning: "r", statusChangedAt: ago(30), createdAt: ago(30), updatedAt: ago(10) });
const ev = (id: string, host: string, t: string) => ({ id, source: "live", collector: "c", assetId: host, host, time: t, channel: "Security", provider: "p", eventId: 4625, summary: `failed logon on ${host}`, data: {}, fingerprint: id, ingestedAt: t });
async function seed(A: ScopedStore) {
  await A.upsert(T.assets, [asset("dc01", 5), asset("ws07", 2), asset("print1", 1)] as any);
  await A.upsert(T.events, [ev("evt_aaaaaa01", "dc01", ago(25)), ev("evt_aaaaaa02", "dc01", ago(20)), ev("evt_aaaaaa03", "ws07", ago(15))] as any);
  await A.upsert(T.alerts, [alert("alt_a0000001", "dc01", { sev: "critical", rule: "brute", mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }], events: ["evt_aaaaaa01", "evt_aaaaaa02"], ips: ["203.0.113.9"], users: ["administrator"], inc: "inc_a0000001" }),
    alert("alt_a0000002", "dc01", { rule: "newsvc", mitre: [{ id: "T1543", name: "Create Service", tactic: "Persistence" }], ips: ["203.0.113.9"], inc: "inc_a0000001" }), alert("alt_a0000003", "dc01", { rule: "ps", mitre: [{ id: "T1059", name: "PowerShell", tactic: "Execution" }], inc: "inc_a0000001" }),
    alert("alt_a0000004", "ws07", { sev: "medium", rule: "brute", mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }], events: ["evt_aaaaaa03"], ips: ["203.0.113.9"], inc: "inc_a0000002", last: ago(300) }),
    alert("alt_a0000005", "print1", { sev: "low", rule: "x", inc: "inc_a0000003", last: ago(3000), conf: 0.3 })] as any);
  await A.upsert(T.incidents, [inc("inc_a0000001", "dc01", ["alt_a0000001", "alt_a0000002", "alt_a0000003"], { sev: "critical", tactics: ["Credential Access", "Persistence", "Execution"] }), inc("inc_a0000002", "ws07", ["alt_a0000004"], { sev: "medium", tactics: ["Credential Access"], last: ago(300) }), inc("inc_a0000003", "print1", ["alt_a0000005"], { sev: "low", conf: 0.3, last: ago(3000) }), inc("inc_a0000004", "dc01", [], { status: "closed" })] as any);
}

test("prioritization: order follows severity x asset criticality x evidence x recency; every point is explained; closed incidents are excluded", async () => {
  const w = await world(); await seed(w.A); const r = await analyzeSoc(w.A, { now: NOW }, { name: "t", role: "admin" });
  assert.deepEqual(r.priorities.map((p) => p.incidentId), ["inc_a0000001", "inc_a0000002", "inc_a0000003"]); assert.ok(!r.priorities.some((p) => p.incidentId === "inc_a0000004"));
  const top = r.priorities[0]; assert.equal(top.level, "critical"); assert.equal(top.score, Math.min(100, top.factors.reduce((s, f) => s + f.points, 0)), "score is exactly the sum of its stated factors");
  for (const name of ["severity", "asset criticality", "evidence strength", "recency", "correlation", "attack progression"]) assert.ok(top.factors.some((f) => f.name === name), name);
  assert.match(top.explanation, /Score \d+\/100 = /); assert.ok(top.factors.find((f) => f.name === "asset criticality")!.why.includes("5/5"));
  assert.ok(r.priorities[0].score > r.priorities[1].score && r.priorities[1].score > r.priorities[2].score);
  assert.equal(r.priorities[2].level, "low"); assert.equal(r.priorities[0].confidence, "medium", "3 alerts, 2 rules, but only 2 supporting events: medium, not high"); assert.equal(r.priorities[2].confidence, "low");
});

test("correlation: shared IP across incidents, same technique on several hosts, multi-stage progression", async () => {
  const w = await world(); await seed(w.A); const r = await analyzeSoc(w.A, { now: NOW }, { name: "t", role: "admin" });
  const ip = r.correlations.find((c) => c.kind === "shared_ip" && c.entity === "ip:203.0.113.9")!; assert.ok(ip.incidentIds.includes("inc_a0000001") && ip.incidentIds.includes("inc_a0000002")); assert.match(ip.why, /lead, not proof/);
  assert.ok(r.correlations.some((c) => c.kind === "same_technique_multi_host" && /T1110/.test(c.summary) && /2 hosts/.test(c.summary)));
  assert.ok(r.correlations.some((c) => c.kind === "kill_chain_progression" && c.incidentIds[0] === "inc_a0000001"));
});

test("investigation: timeline, entities, tactics in kill-chain order; recommendations cite real alert/incident ids and are human-only", async () => {
  const w = await world(); await seed(w.A); const r = await analyzeSoc(w.A, { incidentId: "inc_a0000001", now: NOW }, { name: "t", role: "admin" }); const inv = r.investigation!;
  assert.deepEqual(inv.tactics, ["Execution", "Persistence", "Credential Access"], "kill-chain order");
  assert.ok(inv.timeline.length >= 5 && inv.timeline.every((x: any, i: number, a: any[]) => i === 0 || a[i - 1].time <= x.time)); assert.deepEqual(inv.entities.users, ["administrator"]); assert.ok(inv.entities.ips.includes("203.0.113.9")); assert.ok(inv.relatedIncidents.includes("inc_a0000002"));
  const real = new Set([...(await w.A.select<any>(T.incidents, {})).map((x: any) => x.id), ...(await w.A.select<any>(T.alerts, {})).map((x: any) => x.id)]);
  assert.ok(r.recommendations.length >= 2); for (const rec of r.recommendations) { assert.equal(rec.kind, "recommendation"); assert.equal(rec.status, "not_executed"); assert.equal(rec.requiresHuman, true); for (const id of rec.evidenceIds) assert.ok(real.has(id), "unknown evidence " + id); }
  assert.ok(r.recommendations.some((x) => /password reset/.test(x.action) && x.changesSystem && /cannot change accounts/.test(x.action)));
  assert.ok(r.suggestedDiagnostics.every((d) => d.status === "suggested_not_requested" && d.template === "sys.cpu_top"));
  assert.match(r.contract, /Nothing in this result was executed/);
});

test("honesty: no data is said plainly; missing events/assets are listed as limitations; unknown incident is 404", async () => {
  const w = await world(); const empty = await analyzeSoc(w.A, { now: NOW }, { name: "t", role: "admin" }); assert.equal(empty.priorities.length, 0); assert.ok(empty.limitations.some((x) => /No data is not the same as no threats/.test(x)));
  await w.A.upsert(T.alerts, [alert("alt_b0000001", "ghost", { inc: "inc_b0000001" })] as any); await w.A.upsert(T.incidents, [inc("inc_b0000001", "ghost", ["alt_b0000001"])] as any);
  const r = await analyzeSoc(w.A, { incidentId: "inc_b0000001", now: NOW }, { name: "t", role: "admin" }); assert.ok(r.limitations.some((x) => /No asset record for ghost/.test(x))); assert.ok(r.limitations.some((x) => /No raw events/.test(x))); assert.ok(r.recommendations.some((x) => /Register ghost as an asset/.test(x.action)));
  await assert.rejects(() => analyzeSoc(w.A, { incidentId: "inc_nope" }, { name: "t", role: "admin" }), /not found/);
});

test("organization isolation: B's analysis never contains A's data; B cannot investigate A's incident; roles", async () => {
  const w = await world(); await seed(w.A); await w.B.upsert(T.incidents, [inc("inc_c0000001", "bhost", [], { sev: "low" })] as any);
  const b = await J(await w.call("POST", "ai/analyze", w.tok.bOwner, {})); assert.deepEqual(b.priorities.map((p: any) => p.incidentId), ["inc_c0000001"]); const text = JSON.stringify(b); for (const leak of ["inc_a0000001", "alt_a0000001", "dc01", "203.0.113.9", "administrator"]) assert.ok(!text.includes(leak), "leaked " + leak);
  assert.equal((await w.call("POST", "ai/analyze", w.tok.bOwner, { incidentId: "inc_a0000001" })).status, 404);
  assert.equal((await w.call("POST", "ai/analyze", w.tok.ro, {})).status, 200, "read-only can view analysis"); assert.equal((await w.call("POST", "ai/analyze", w.tok.ro, { proposeDiagnostics: true })).status, 403); assert.equal((await w.call("POST", "ai/analyze", "bad", {})).status, 401);
  const a = await J(await w.call("POST", "ai/analyze", w.tok.sec, {})); assert.equal(a.dataUsed.openIncidents, 3);
  const audits = (await w.s.select<any>("soc_audit", {})).filter((x: any) => x.action === "soc.ai.analyze"); assert.ok(audits.length >= 3, "every analysis is audited");
});

test("model narrative: kept only if all cited ids are real; invented ids, claimed actions and failures are discarded visibly", async () => {
  const w = await world(); await seed(w.A); const ask = (f: any) => analyzeSoc(w.A, { now: NOW }, { name: "t", role: "admin" }, f);
  let r = await ask(async () => ({ text: "inc_a0000001 on dc01 is the priority; see alt_a0000001.", model: "stub" })); assert.equal(r.method, "rules+ai"); assert.ok(r.narrative); assert.match(r.narrativeNote!, /computed from your data, not by the model/);
  r = await ask(async () => ({ text: "Attacker moved to inc_deadbeef99 and alt_feedface11.", model: "stub" })); assert.equal(r.narrative, null); assert.ok(r.limitations.some((x) => /do not exist in this organization/.test(x)));
  r = await ask(async () => ({ text: "I have blocked the address and the incident was resolved.", model: "stub" })); assert.equal(r.narrative, null); assert.ok(r.limitations.some((x) => /claimed an action/.test(x)));
  r = await ask(async () => { throw new Error("boom"); }); assert.equal(r.narrative, null); assert.equal(r.priorities.length, 3);
});

test("SOC analysis never executes anything; with the explicit flag it only PROPOSES a read-only diagnostic for a human to confirm", async () => {
  const w = await world(); await seed(w.A); const key = await J(await w.call("POST", "org/keys", w.tok.owner, { name: "exec-key-soc" }));
  await w.call("POST", "noc/telemetry", key.key, { source: "t", devices: [{ id: "dc01", name: "dc01", type: "server", ip: "10.0.0.1", up: true, metrics: { cpu: 5 } }] });
  await J(await w.call("POST", "ai/analyze", w.tok.sec, { incidentId: "inc_a0000001" })); assert.equal((await w.A.select<any>("noc_diag_jobs", {})).length, 0);
  await w.call("POST", "noc/exec/executors", w.tok.owner, { hostId: "dc01", keyId: key.id, os: "linux" }); await w.call("PUT", "noc/exec/settings", w.tok.owner, { enabled: true });
  const r = await J(await w.call("POST", "ai/analyze", w.tok.sec, { incidentId: "inc_a0000001", proposeDiagnostics: true })); const p = r.suggestedDiagnostics.find((d: any) => d.status === "proposed_awaiting_human"); assert.ok(p?.jobId);
  const job = await J(await w.call("GET", `noc/diag/${p.jobId}`, w.tok.sec)); assert.equal(job.status, "proposed"); assert.equal(job.requestedBy, "agent:soc-analyst"); assert.equal(job.template, "sys.cpu_top");
  assert.equal((await J(await w.call("GET", "noc/executor/jobs?host=dc01", key.key))).jobs.length, 0, "not delivered until a human confirms");
});
