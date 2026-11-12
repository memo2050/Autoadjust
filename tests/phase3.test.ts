import { TestStore } from "./test-store";
// Run: npx tsx --test tests/phase3.test.ts   (synthetic TEST FIXTURES only; nothing here is real security data)
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore, T } from "../lib/soc/store";
import { normalizeWindows } from "../lib/soc/windows";
import { runRules } from "../lib/soc/rules";
import { ingestWindows } from "../lib/soc/pipeline";
import { handleSoc, collectors } from "../lib/soc/api";
import type { SocEvent } from "../lib/soc/types";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890" });
const actor = { name: "tester", role: "admin" };
const t0 = Date.now() - 3600_000;
const iso = (sec: number) => new Date(t0 + sec * 1000).toISOString();
let rec = 1;
const sys = (id: number, sec: number, data: Record<string, string>, host = "WS09") => ({ Id: id, RecordId: rec++, TimeCreated: iso(sec), ProviderName: "Microsoft-Windows-Sysmon", LogName: "Microsoft-Windows-Sysmon/Operational", MachineName: host, Data: data });
const secEv = (id: number, sec: number, data: Record<string, string>, host = "WS09") => ({ Id: id, RecordId: rec++, TimeCreated: iso(sec), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: host, Data: data });
const norm = (raw: any) => { const e = normalizeWindows(raw, { source: "live", collector: "t" }); if ("error" in e) throw new Error(e.error); return e as SocEvent; };
const H = (tok: string, extra: Record<string, string> = {}) => ({ authorization: `Bearer ${tok}`, "content-type": "application/json", ...extra });
const call = (store: TestStore, method: string, path: string, tok = "admin-token-1234567890", body?: unknown) => handleSoc(new Request("http://x/api/soc/" + path, { method, headers: H(tok), body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store, model: null });

test("Sysmon events normalize with process, remote address, summary and severity", () => {
  const e = norm(sys(3, 0, { Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", User: "CORP\\alice", DestinationIp: "198.51.100.7", DestinationPort: "4444" }));
  assert.equal(e.srcIp, "198.51.100.7"); assert.equal(e.user, "CORP\\alice"); assert.match(e.summary, /network connection to 198\.51\.100\.7:4444/); assert.ok(e.severity);
  const p = norm(sys(1, 1, { Image: "C:\\x\\a.exe", ParentImage: "C:\\Windows\\explorer.exe", CommandLine: "a.exe -x" }));
  assert.equal(p.process, "C:\\x\\a.exe"); assert.equal(p.parentProcess, "C:\\Windows\\explorer.exe"); assert.match(p.summary, /process created/);
  const app = norm({ Id: 1000, RecordId: 9, TimeCreated: iso(2), ProviderName: "Application Error", LogName: "Application", MachineName: "WS09", LevelDisplayName: "Error", Data: {} });
  assert.equal(app.summary, "Application error (crash)"); assert.equal(app.severity, "high");
  assert.equal(norm(secEv(1102, 3, {})).severity, "high");
});

test("SYS-NET-001: script host to public IP on a odd port is high; private IP is ignored", () => {
  const ev = [norm(sys(3, 0, { Image: "C:\\Windows\\System32\\mshta.exe", User: "a", DestinationIp: "203.0.113.50", DestinationPort: "4444" })), norm(sys(3, 1, { Image: "C:\\Windows\\System32\\mshta.exe", User: "a", DestinationIp: "10.0.0.5", DestinationPort: "4444" })), norm(sys(3, 2, { Image: "C:\\Program Files\\App\\app.exe", User: "a", DestinationIp: "203.0.113.50", DestinationPort: "443" }))];
  const a = runRules(ev).filter((x) => x.ruleId === "SYS-NET-001");
  assert.equal(a.length, 1); assert.equal(a[0].severity, "high"); assert.match(a[0].reasoning, /not a common web port/); assert.equal(a[0].eventIds.length, 1);
});

test("SYS-CRED-001: non-system process reading LSASS memory is critical; Defender is ignored", () => {
  const bad = norm(sys(10, 0, { SourceImage: "C:\\Users\\Public\\tool.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" }));
  const ok = norm(sys(10, 1, { SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" }));
  const a = runRules([bad, ok]).filter((x) => x.ruleId === "SYS-CRED-001");
  assert.equal(a.length, 1); assert.equal(a[0].severity, "critical"); assert.deepEqual(a[0].eventIds, [bad.id]);
});

test("SYS-RANSOM-001: 120 files with one new extension in 60s is critical; normal doc saves are not", () => {
  const mass = Array.from({ length: 120 }, (_, i) => norm(sys(11, i * 0.4, { Image: "C:\\Users\\bob\\AppData\\Local\\Temp\\enc.exe", TargetFilename: `C:\\Users\\bob\\Documents\\file${i}.docx.locked7` })));
  const a = runRules(mass).filter((x) => x.ruleId === "SYS-RANSOM-001");
  assert.equal(a.length, 1); assert.equal(a[0].severity, "critical"); assert.match(a[0].reasoning, /locked7/);
  const normal = Array.from({ length: 120 }, (_, i) => norm(sys(11, i * 0.4, { Image: "C:\\Program Files\\Office\\WINWORD.EXE", TargetFilename: `C:\\Users\\bob\\Documents\\file${i}.docx` })));
  assert.equal(runRules(normal).filter((x) => x.ruleId === "SYS-RANSOM-001").length, 0);
});

test("Sysmon process creation feeds the existing command-line rules", () => {
  const ev = [norm(sys(1, 0, { Image: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin delete shadows /all /quiet", User: "x" })), norm(sys(1, 1, { Image: "C:\\Windows\\System32\\powershell.exe", CommandLine: "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", User: "x" }))];
  const ids = runRules(ev).map((x) => x.ruleId); assert.ok(ids.includes("WIN-IMPACT-001")); assert.ok(ids.includes("WIN-EXEC-001"));
});

test("WIN-BEHAV-001: one account from 4 addresses within 30 minutes", () => {
  const ev = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"].map((ip, i) => norm(secEv(4624, i * 120, { TargetUserName: "svc_backup", IpAddress: ip, LogonType: "3" })));
  const a = runRules(ev).filter((x) => x.ruleId === "WIN-BEHAV-001"); assert.equal(a.length, 1); assert.match(a[0].reasoning, /4 distinct addresses/);
  assert.equal(runRules(ev.slice(0, 3)).filter((x) => x.ruleId === "WIN-BEHAV-001").length, 0);
});

test("collector heartbeat: an empty batch records contact; status derives from the real contact time", async () => {
  const store = new TestStore();
  let r = await call(store, "POST", "ingest/windows", "ingest-token-1234567890", { host: "WS77", collector: "Send-SecurityEvents.ps1", version: "2.0", events: [] }); assert.equal(r.status, 200);
  const list = await collectors(store); assert.equal(list.length, 1); assert.equal(list[0].status, "connected"); assert.equal(list[0].version, "2.0"); assert.equal(list[0].lastBatch, 0);
  assert.equal((await collectors(store, Date.now() + 20 * 60_000))[0].status, "stale"); assert.equal((await collectors(store, Date.now() + 3 * 3600_000))[0].status, "offline");
  r = await call(store, "GET", "collectors", "viewer-token-1234567890"); assert.equal(r.status, 200); assert.equal((await r.json()).length, 1);
  r = await call(store, "GET", "collectors", "ingest-token-1234567890"); assert.equal(r.status, 403, "a collector token cannot read the console");
});

test("live view: /events?since returns only newly ingested events", async () => {
  const store = new TestStore();
  await ingestWindows(store, { host: "WS10", events: [secEv(4625, 0, { TargetUserName: "a", IpAddress: "203.0.113.1", LogonType: "3" }, "WS10")] }, "live", actor);
  const first = await (await call(store, "GET", "events?limit=10")).json() as SocEvent[]; assert.equal(first.length, 1);
  const cursor = first[0].ingestedAt; await new Promise((r) => setTimeout(r, 5));
  await ingestWindows(store, { host: "WS10", events: [secEv(4625, 5, { TargetUserName: "b", IpAddress: "203.0.113.1", LogonType: "3" }, "WS10")] }, "live", actor);
  const next = await (await call(store, "GET", "events?since=" + encodeURIComponent(cursor))).json() as SocEvent[]; assert.equal(next.length, 1); assert.equal(next[0].targetUser ?? next[0].user, "b");
  assert.equal((await (await call(store, "GET", "events?since=" + encodeURIComponent(next[0].ingestedAt))).json() as SocEvent[]).length, 0);
});

// ---------------------------------------------------------------- server-side agent tasks
import type { Alert, SocAction } from "../lib/soc/types";
async function seedAttack(store: TestStore) {
  const ev: any[] = []; for (let i = 0; i < 9; i++) ev.push(secEv(4625, i, { TargetUserName: i % 3 ? "administrator" : "bob", IpAddress: "203.0.113.77", LogonType: "3" }, "SRV01"));
  ev.push(secEv(4624, 20, { TargetUserName: "administrator", IpAddress: "203.0.113.77", LogonType: "3" }, "SRV01"), secEv(4672, 21, { SubjectUserName: "administrator" }, "SRV01"));
  ev.push(sys(1, 30, { Image: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin delete shadows /all /quiet", User: "administrator" }, "SRV01"));
  await ingestWindows(store, { host: "SRV01", events: ev }, "live", actor);
}
async function runTask(store: TestStore, body: any) {
  let r = await call(store, "POST", "tasks", "analyst-token-1234567890", body); assert.equal(r.status, 201); let run = await r.json(); const seen: number[] = [run.progress];
  for (let i = 0; i < 60 && run.status === "running"; i++) { r = await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890"); run = await r.json(); seen.push(run.progress); }
  return { run, seen };
}
test("every role runs real steps; progress is stepsDone/stepsTotal and strictly increases once per executed step", async () => {
  const store = new TestStore(); await seedAttack(store);
  for (const role of ["siem", "analyst", "hunter", "engineer", "responder", "ciso"]) {
    const { run, seen } = await runTask(store, { role, task: role === "siem" ? "Find repeated failed logons" : "Investigate suspicious login attempts." });
    assert.equal(run.status, "completed", role + " " + (run.error ?? "")); assert.equal(run.stepsDone, run.stepsTotal); assert.equal(run.progress, 100);
    assert.equal(seen.length, run.stepsTotal + 1, role + ": one request per step"); for (let i = 1; i < seen.length; i++) assert.ok(seen[i] > seen[i - 1], role + " progress must rise");
    assert.ok(run.steps.every((s: any) => s.status === "done" && s.startedAt && s.endedAt && typeof s.durationMs === "number" && s.detail), role + " steps carry real timing and detail");
    assert.ok(run.result.head && run.result.limits.length, role + " has a result"); assert.equal(run.state, undefined, "scratch state is not exposed");
  }
});
test("agents produce DIFFERENT results, use handoff context, and the analyst finds the compromise", async () => {
  const store = new TestStore(); await seedAttack(store);
  const siem = (await runTask(store, { role: "siem", task: "Find repeated failed logons" })).run;
  assert.ok(siem.result.pivots.ips.includes("203.0.113.77")); assert.match(siem.result.handoff, /203\.0\.113\.77/);
  const analyst = (await runTask(store, { role: "analyst", task: "x", context: { ips: siem.result.pivots.ips, hosts: siem.result.pivots.hosts, from: "siem", message: siem.result.handoff } })).run;
  assert.equal(analyst.result.severity, "critical"); assert.match(analyst.result.findings[0].t, /SUCCESSFUL logon/); assert.match(analyst.steps[1].detail, /checked first/);
  const hunter = (await runTask(store, { role: "hunter", task: "x", context: { ips: ["203.0.113.77"], from: "analyst" } })).run;
  assert.ok(hunter.steps.some((s: any) => s.id === "pivot"), "pivot step exists only when earlier agents supplied an address"); assert.match(hunter.result.findings.map((f: any) => f.t).join(" "), /Related activity for 203\.0\.113\.77/);
  const solo = await runTask(store, { role: "hunter", task: "x" }); assert.ok(!solo.run.steps.some((s: any) => s.id === "pivot"));
  const heads = new Set([siem, analyst, hunter].map((r: any) => r.result.head)); assert.equal(heads.size, 3);
});
test("disruptive recommendations become PROPOSED actions only; nothing is executed; duplicates are not re-created", async () => {
  const store = new TestStore(); await seedAttack(store);
  const a1 = (await runTask(store, { role: "analyst", task: "x" })).run; assert.ok(a1.result.actionIds.length >= 2);
  const acts = await store.select<SocAction>(T.actions, {}); assert.ok(acts.length >= 2); assert.ok(acts.every((a) => a.status === "proposed" && a.requiresApproval && a.proposedBy === "agent:analyst"));
  assert.ok(acts.some((a) => a.type === "block_ip" && a.target === "203.0.113.77"));
  const n = acts.length; await runTask(store, { role: "analyst", task: "again" }); assert.equal((await store.select<SocAction>(T.actions, {})).length, n, "same proposal is not duplicated");
  const r = await call(store, "POST", `tasks`, "viewer-token-1234567890", { role: "analyst" }); assert.equal(r.status, 403);
});
test("cancel stops a run; a failed step can be retried and completed steps are kept", async () => {
  const store = new TestStore(); await seedAttack(store);
  let r = await call(store, "POST", "tasks", "analyst-token-1234567890", { role: "analyst", task: "x" }); let run = await r.json();
  r = await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890"); run = await r.json(); assert.equal(run.stepsDone, 1);
  r = await call(store, "POST", `tasks/${run.id}/cancel`, "analyst-token-1234567890"); run = await r.json(); assert.equal(run.status, "cancelled");
  r = await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890"); run = await r.json(); assert.equal(run.stepsDone, 1, "a cancelled run does not advance");
  // failure injection: break the store read used by step 2 of a new run
  r = await call(store, "POST", "tasks", "analyst-token-1234567890", { role: "analyst", task: "y" }); run = await r.json(); await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890");
  const real = store.select.bind(store); let boom = true; (store as any).select = async (t: string, q: any) => { if (boom && t === T.events) throw new Error("database timeout"); return real(t, q); };
  r = await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890"); run = await r.json(); assert.equal(run.status, "failed"); assert.match(run.error, /database timeout/); assert.equal(run.steps[1].status, "failed"); assert.equal(run.stepsDone, 1);
  boom = false; r = await call(store, "POST", `tasks/${run.id}/retry`, "analyst-token-1234567890"); run = await r.json(); assert.equal(run.status, "running");
  for (let i = 0; i < 10 && run.status === "running"; i++) run = await (await call(store, "POST", `tasks/${run.id}/next`, "analyst-token-1234567890")).json();
  assert.equal(run.status, "completed"); assert.equal(run.progress, 100);
  const r2 = await call(store, "POST", `tasks/${run.id}/retry`, "analyst-token-1234567890"); assert.equal(r2.status, 409);
});
test("responder picks the incident for the handoff host and reports real stages", async () => {
  const store = new TestStore(); await seedAttack(store);
  const { run } = await runTask(store, { role: "responder", task: "Respond", context: { hosts: ["SRV01"], from: "hunter" } });
  assert.equal(run.status, "completed"); assert.ok(run.result.incidentId); assert.equal(run.result.stages.length, 5); assert.ok(run.result.recs.some((x: any) => x.dis && x.type === "isolate_host"));
  const empty = new TestStore(); const e = (await runTask(empty, { role: "responder", task: "x" })).run; assert.equal(e.status, "completed"); assert.match(e.result.head, /no active incidents/);
});

// ---------------------------------------------------------------- approvals, audit chain, incident management
import { verifyAuditChain } from "../lib/soc/pipeline";
test("approvals view: risk, affected device/user, evidence, then approve/reject history with identity and time", async () => {
  const store = new TestStore(); await seedAttack(store); await runTask(store, { role: "analyst", task: "x" }); await runTask(store, { role: "responder", task: "x" });
  let r = await call(store, "GET", "approvals", "viewer-token-1234567890"); assert.equal(r.status, 200); const ap = await r.json();
  assert.ok(ap.pending.length >= 3); assert.equal(ap.executor.configured, false);
  const iso = ap.pending.find((x: any) => x.type === "isolate_host"), blk = ap.pending.find((x: any) => x.type === "block_ip");
  assert.equal(iso.risk.level, "high"); assert.ok(iso.affected.host && iso.affected.incident && iso.evidence.alerts.length > 0 && iso.evidence.events.length > 0); assert.equal(iso.byAgent, true);
  assert.equal(blk.affected.ip, "203.0.113.77"); assert.ok(blk.risk.reasons.length && blk.risk.ifApproved);
  r = await call(store, "POST", `actions/${iso.id}/approve`, "analyst-token-1234567890", {}); assert.equal(r.status, 403, "only an approver may decide");
  r = await call(store, "POST", `actions/${iso.id}/approve`, "admin-token-1234567890", { note: "confirmed with owner" }); assert.equal(r.status, 200);
  r = await call(store, "POST", `actions/${blk.id}/reject`, "admin-token-1234567890", { note: "shared NAT" }); assert.equal(r.status, 200);
  const after = await (await call(store, "GET", "approvals")).json(); assert.equal(after.history.length, 2);
  const h = after.history.find((x: any) => x.id === iso.id); assert.equal(h.status, "approved"); assert.equal(h.decidedBy, "admin-token"); assert.ok(h.decidedAt); assert.equal(h.decisionNote, "confirmed with owner");
  r = await call(store, "POST", `actions/${iso.id}/approve`, "admin-token-1234567890", {}); assert.equal(r.status, 409, "cannot decide twice");
});
test("audit log is a hash chain: verification passes, then fails if a record is edited or removed", async () => {
  const store = new TestStore(); await seedAttack(store); await runTask(store, { role: "siem", task: "x" });
  let v = await verifyAuditChain(store); assert.equal(v.ok, true); assert.ok(v.checked >= 3);
  const rows = (await store.select<any>(T.audit, {})).sort((a, b) => a.seq - b.seq); assert.equal(rows[0].prevHash, "genesis"); assert.equal(rows[1].prevHash, rows[0].hash);
  const r = await call(store, "GET", "audit/verify", "viewer-token-1234567890"); assert.equal(r.status, 403, "viewers cannot read the audit log");
  assert.equal((await (await call(store, "GET", "audit/verify", "analyst-token-1234567890")).json()).ok, true);
  const tampered = structuredClone(rows[2]); tampered.actor = "someone-else"; await store.upsert(T.audit, [tampered]);
  v = await verifyAuditChain(store); assert.equal(v.ok, false); assert.equal(v.brokenAt!.seq, rows[2].seq); assert.match(v.brokenAt!.reason, /changed/);
  await store.upsert(T.audit, [rows[2]]); assert.equal((await verifyAuditChain(store)).ok, true);
  await store.remove(T.audit, { id: rows[1].id }); v = await verifyAuditChain(store); assert.equal(v.ok, false); assert.match(v.brokenAt!.reason, /missing|duplicated/);
});
test("concurrent audit writes do not fork the chain", async () => {
  const store = new TestStore(); const { audit } = await import("../lib/soc/pipeline");
  await Promise.all(Array.from({ length: 25 }, (_, i) => audit(store, actor, "test.event", "t" + i, { i }))); const v = await verifyAuditChain(store); assert.equal(v.ok, true); assert.equal(v.checked, 25);
});
test("incident center: display status, owner, assigned agents and audit of assignment", async () => {
  const store = new TestStore(); await seedAttack(store);
  let list = await (await call(store, "GET", "incidents")).json() as any[]; assert.ok(list.length >= 1); const inc = list[0]; assert.equal(inc.displayStatus, "New");
  await runTask(store, { role: "responder", task: "x" });
  list = await (await call(store, "GET", "incidents")).json(); const i2 = list.find((x: any) => x.id === inc.id); assert.equal(i2.displayStatus, "Pending Approval"); assert.ok(i2.pendingApprovals >= 1); assert.ok(i2.assignedAgents.includes("responder"));
  let r = await call(store, "PATCH", `incidents/${inc.id}`, "analyst-token-1234567890", { owner: "Dana (SOC lead)" }); assert.equal(r.status, 200); assert.equal((await r.json()).owner, "Dana (SOC lead)");
  r = await call(store, "PATCH", `incidents/${inc.id}`, "viewer-token-1234567890", { owner: "x" }); assert.equal(r.status, 403);
  const d = await (await call(store, "GET", `incidents/${inc.id}`)).json(); assert.equal(d.incident.owner, "Dana (SOC lead)"); assert.equal(d.incident.displayStatus, "Pending Approval");
  assert.ok((await store.select<any>(T.audit, {})).some((x: any) => x.action === "incident.assign" && x.target === inc.id));
  r = await call(store, "PATCH", `incidents/${inc.id}`, "analyst-token-1234567890", { status: "investigating" }); assert.equal(r.status, 200);
  const approvals = await (await call(store, "GET", "approvals")).json(); for (const a of approvals.pending.filter((x: any) => x.incidentId === inc.id)) await call(store, "POST", `actions/${a.id}/reject`, "admin-token-1234567890", {});
  list = await (await call(store, "GET", "incidents")).json(); assert.equal(list.find((x: any) => x.id === inc.id).displayStatus, "Investigating");
});
