import { TestStore } from "./test-store";
// Run: npx tsx --test tests/soc.test.ts   (uses synthetic TEST FIXTURES only; none of this is real security data)
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore, SupabaseStore, T } from "../lib/soc/store";
import { normalizeWindows } from "../lib/soc/windows";
import { runRules } from "../lib/soc/rules";
import { ingestWindows, importScan, setIncidentStatus, verifyIncident, importKev, HttpError } from "../lib/soc/pipeline";
import { parseGreenboneCsv, parseGreenboneXml } from "../lib/soc/greenbone";
import { parseXml } from "../lib/soc/xml";
import { runAnalyst, validateOutput, decideAction } from "../lib/soc/agents";
import { handleSoc, overview } from "../lib/soc/api";
import type { Alert, Asset, Incident, SocAction, SocEvent, Vuln } from "../lib/soc/types";

const actor = { name: "tester", role: "admin" };
const t0 = Math.floor(Date.now() / 60000) * 60000 - 6 * 3600_000; // relative to now so the 7-day recurrence window never makes tests flaky
const iso = (min: number) => new Date(t0 + min * 60_000).toISOString();
let rec = 1000;
const win = (id: number, min: number, data: Record<string, string>, o: Record<string, unknown> = {}) => ({ Id: id, RecordId: rec++, TimeCreated: iso(min), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: "WS01.corp.local", Data: data, ...o });
const fail = (min: number, ip = "203.0.113.9", user = "administrator") => win(4625, min, { TargetUserName: user, IpAddress: ip, LogonType: "3" });
const norm = (raw: any) => { const e = normalizeWindows(raw, { source: "live", collector: "t" }); if ("error" in e) throw new Error(e.error); return e as SocEvent; };

test("normalizer maps fields, builds stable ids, rejects junk", () => {
  const e = norm(win(4624, 0, { TargetUserName: "alice", IpAddress: "10.0.0.5", LogonType: "10" }));
  assert.equal(e.host, "WS01"); assert.equal(e.assetId, "ws01"); assert.equal(e.user, "alice"); assert.equal(e.logonType, 10); assert.equal(e.srcIp, "10.0.0.5");
  const again = norm({ ...win(4624, 0, { TargetUserName: "alice", IpAddress: "10.0.0.5", LogonType: "10" }), RecordId: (e.recordId as number) });
  assert.equal(again.id, e.id, "same record gives the same id (dedupe)");
  assert.ok("error" in normalizeWindows({ foo: 1 }, { source: "live", collector: "t" }));
  assert.ok("error" in normalizeWindows({ Id: 4624, TimeCreated: "nope", MachineName: "x" }, { source: "live", collector: "t" }));
  assert.equal(norm(win(4624, 0, { TargetUserName: "-", IpAddress: "-" })).srcIp, undefined);
});

test("brute force then success then privileges => critical alert with evidence", () => {
  const ev = [...Array.from({ length: 8 }, (_, i) => fail(i)), win(4624, 9, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" }), win(4672, 9.5, { SubjectUserName: "administrator" })].map(norm);
  const a = runRules(ev);
  const brute = a.find((x) => x.ruleId === "WIN-AUTH-001")!, succ = a.find((x) => x.ruleId === "WIN-AUTH-002")!;
  assert.ok(brute && brute.eventIds.length === 8);
  assert.equal(succ.severity, "critical"); assert.ok(succ.confidence >= 0.9); assert.equal(succ.eventIds.length, 10);
  assert.match(succ.reasoning, /could also be a user who mistyped/);
});

test("4 failures is not enough; spraying is detected across users", () => {
  assert.equal(runRules([0, 1, 2, 3].map((i) => norm(fail(i)))).length, 0);
  const spray = runRules(["a", "b", "c", "d", "e", "f"].map((u, i) => norm(fail(i, "198.51.100.7", u))));
  assert.equal(spray[0].mitre[0].id, "T1110.003"); assert.equal(spray[0].severity, "high");
});

test("other rules fire on the right events and stay quiet on benign ones", () => {
  const ev = [
    win(4624, 0, { TargetUserName: "bob", IpAddress: "8.8.4.4", LogonType: "10" }),
    win(4624, 1, { TargetUserName: "bob", IpAddress: "192.168.1.20", LogonType: "10" }),
    win(4732, 2, { TargetUserName: "Administrators", MemberName: "CN=mallory", SubjectUserName: "bob" }),
    win(4732, 2, { TargetUserName: "Print Operators", MemberName: "CN=x", SubjectUserName: "bob" }),
    win(4698, 3, { TaskName: "\\Updater", TaskContent: "<Command>powershell.exe -nop -w hidden</Command>", SubjectUserName: "bob" }),
    win(4698, 3, { TaskName: "\\Backup", TaskContent: "<Command>C:\\Program Files\\Backup\\run.exe</Command>", SubjectUserName: "bob" }),
    win(1102, 4, { SubjectUserName: "bob" }),
    win(4688, 5, { SubjectUserName: "bob", NewProcessName: "C:\\Windows\\System32\\powershell.exe", CommandLine: "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" }),
    win(4688, 6, { SubjectUserName: "bob", NewProcessName: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin delete shadows /all /quiet" }),
    win(4688, 7, { SubjectUserName: "bob", NewProcessName: "C:\\Windows\\notepad.exe", CommandLine: "notepad.exe notes.txt" }),
    win(1116, 8, { "Threat Name": "Trojan:Win32/Test", "Severity Name": "Severe", Path: "C:\\Users\\bob\\x.exe" }, { LogName: "Microsoft-Windows-Windows Defender/Operational" }),
    win(7045, 9, { ServiceName: "Evil", ImagePath: "C:\\Users\\Public\\e.exe" }, { LogName: "System", ProviderName: "Service Control Manager" }),
  ].map(norm);
  const a = runRules(ev), by = (r: string) => a.filter((x) => x.ruleId === r);
  assert.equal(by("WIN-AUTH-003").length, 1, "only the public IP RDP logon");
  assert.equal(by("WIN-PRIV-001").length, 1);
  assert.deepEqual(by("WIN-PERSIST-001").map((x) => x.severity).sort(), ["high", "low"]);
  assert.equal(by("WIN-EVASION-001").length, 1);
  assert.equal(by("WIN-EXEC-001").length, 1, "notepad is not flagged");
  assert.equal(by("WIN-IMPACT-001")[0].severity, "critical");
  assert.equal(by("WIN-MAL-001")[0].severity, "critical");
  assert.equal(by("WIN-PERSIST-002")[0].severity, "high");
});

const attackPayload = () => ({ host: "WS01", ips: ["10.0.0.5"], events: [...Array.from({ length: 6 }, (_, i) => fail(i)), win(4624, 8, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" }), win(4698, 20, { TaskName: "\\Upd", TaskContent: "<Command>powershell -enc AAAA</Command>", SubjectUserName: "administrator" }), win(4720, 25, { TargetUserName: "support$$", SubjectUserName: "administrator" }), win(4732, 26, { TargetUserName: "Administrators", MemberName: "CN=support$$", SubjectUserName: "administrator" })] });

test("ingest is idempotent, creates one correlated incident, escalates on kill-chain progression", async () => {
  const s = new TestStore();
  const payload = attackPayload() as any;
  const r1 = await ingestWindows(s, payload, "live", actor);
  assert.equal(r1.accepted, 10); assert.ok(r1.newAlerts >= 4);
  const evCount = (await s.select(T.events)).length;
  const alertCount = (await s.select(T.alerts)).length;
  const r2 = await ingestWindows(s, payload, "live", actor);
  assert.equal((await s.select(T.events)).length, evCount, "no duplicate events"); assert.equal((await s.select(T.alerts)).length, alertCount, "no duplicate alerts"); assert.equal(r2.newAlerts, 0);
  const incs = await s.select<Incident>(T.incidents);
  assert.equal(incs.length, 1, "all alerts are within 2h on one host");
  assert.equal(incs[0].severity, "critical"); assert.ok(incs[0].tactics.length >= 3); assert.match(incs[0].reasoning, /Rules fired/);
  const asset = (await s.get<Asset>(T.assets, "ws01"))!; assert.deepEqual(asset.ips, ["10.0.0.5"]); assert.equal(asset.authorized, false);
});

test("rejects bad events but keeps good ones", async () => {
  const s = new TestStore();
  const r = await ingestWindows(s, { host: "WS02", events: [fail(0), { nope: true }] as any }, "live", actor);
  assert.equal(r.accepted, 1); assert.equal(r.rejected.length, 1);
});

test("incident workflow: transitions, verification gates, recurrence", async () => {
  const s = new TestStore();
  await ingestWindows(s, attackPayload() as any, "live", actor);
  const inc = (await s.select<Incident>(T.incidents))[0];
  await assert.rejects(() => setIncidentStatus(s, inc.id, "closed", actor), (e: any) => e instanceof HttpError && e.status === 409);
  await setIncidentStatus(s, inc.id, "investigating", actor); await setIncidentStatus(s, inc.id, "contained", actor);
  await assert.rejects(() => verifyIncident(s, inc.id, actor), (e: any) => e.status === 409, "verify only after remediated");
  await setIncidentStatus(s, inc.id, "remediated", actor);
  const rem = new Date((await s.get<Incident>(T.incidents, inc.id))!.remediatedAt!).getTime();
  // no telemetry after remediation => inconclusive (never "passed")
  assert.equal((await verifyIncident(s, inc.id, actor)).verification!.status, "inconclusive");
  await assert.rejects(() => setIncidentStatus(s, inc.id, "closed", actor, undefined, true), (e: any) => e.status === 400, "forced close needs a note");
  // telemetry continues 30 min later with no recurrence => passed
  const later = new Date(rem + 30 * 60_000).toISOString();
  await ingestWindows(s, { host: "WS01", events: [{ ...win(4624, 0, { TargetUserName: "alice", IpAddress: "10.0.0.9", LogonType: "2" }), TimeCreated: later }] }, "live", actor);
  assert.equal((await verifyIncident(s, inc.id, actor)).verification!.status, "passed");
  const closed = await setIncidentStatus(s, inc.id, "closed", actor);
  assert.equal(closed.closedWithoutVerification, undefined);
  // same attack again after closure => failed-style recurrence is a NEW incident linked to the old one
  const again = { host: "WS01", events: Array.from({ length: 6 }, (_, i) => ({ ...fail(i, "203.0.113.50"), TimeCreated: new Date(rem + 3 * 3600_000 + i * 60_000).toISOString() })) };
  await ingestWindows(s, again as any, "live", actor);
  const all = await s.select<Incident>(T.incidents);
  assert.equal(all.length, 2); assert.equal(all.find((i) => i.id !== inc.id)!.recurrenceOf, inc.id);
});

test("verification fails when the same rule fires again after remediation", async () => {
  const s = new TestStore();
  await ingestWindows(s, { host: "WS03", events: Array.from({ length: 6 }, (_, i) => fail(i)) } as any, "live", actor);
  const inc = (await s.select<Incident>(T.incidents))[0];
  for (const st of ["investigating", "contained", "remediated"] as const) await setIncidentStatus(s, inc.id, st, actor);
  const rem = new Date((await s.get<Incident>(T.incidents, inc.id))!.remediatedAt!).getTime();
  await ingestWindows(s, { host: "WS03", events: Array.from({ length: 6 }, (_, i) => ({ ...fail(i), TimeCreated: new Date(rem + 20 * 60_000 + i * 1000).toISOString() })) } as any, "live", actor);
  const v = await verifyIncident(s, inc.id, actor);
  assert.equal(v.verification!.status, "failed");
});

const GB = (extra = "", scanEnd = "2026-10-20T12:00:00Z") => `<?xml version="1.0"?><get_reports_response><report><report><scan_end>${scanEnd}</scan_end><results>
<result id="r1"><host>10.0.0.5<hostname>ws01</hostname></host><port>445/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>SMBv1 enabled &amp; vulnerable</name><refs><ref type="cve" id="CVE-2017-0144"/></refs><solution type="VendorFix">Disable SMBv1</solution><tags>summary=Remote code execution|solution_type=VendorFix</tags></nvt><severity>9.3</severity><threat>Critical</threat><qod><value>95</value></qod></result>
<result id="r2"><host>10.0.0.5<hostname>ws01</hostname></host><port>3389/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.2"><name>TLS 1.0 enabled</name></nvt><severity>4.3</severity><threat>Medium</threat><qod><value>80</value></qod></result>
<result id="r3"><host>10.0.0.5</host><port>general/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.3"><name>OS detection</name></nvt><severity>0.0</severity><threat>Log</threat></result>
${extra}</results></report></report></get_reports_response>`;

test("Greenbone XML and CSV parse; log results skipped; XXE-style input rejected", () => {
  const r = parseGreenboneXml(GB());
  assert.equal(r.findings.length, 2); assert.equal(r.logResultsSkipped, 1); assert.equal(r.scanTime, "2026-10-20T12:00:00.000Z");
  assert.deepEqual(r.findings[0].cves, ["CVE-2017-0144"]); assert.equal(r.findings[0].name, "SMBv1 enabled & vulnerable"); assert.equal(r.findings[0].host, "ws01");
  const csv = 'IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Timestamp\n10.0.0.7,srv1,22,tcp,7.5,High,80,VendorFix,"OpenSSH, old","Summary, with comma",x,1.2.3,"CVE-2023-38408, CVE-2023-1234",2026-10-20T11:00:00Z\n10.0.0.7,srv1,,,0.0,Log,0,,Info,,,1.2.4,,2026-10-20T11:00:00Z\n';
  const c = parseGreenboneCsv(csv);
  assert.equal(c.findings.length, 1); assert.equal(c.findings[0].port, "22/tcp"); assert.equal(c.findings[0].cves.length, 2); assert.equal(c.findings[0].name, "OpenSSH, old");
  assert.throws(() => parseXml('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'), /entity/i);
  assert.throws(() => parseGreenboneXml("<a><b/></a>"), /No <result>/);
});

test("scan import: refuses unauthorized hosts until attested, tracks fixed/reappeared, flags KEV", async () => {
  const s = new TestStore();
  await ingestWindows(s, { host: "WS01", ips: ["10.0.0.5"], events: [fail(0)] } as any, "live", actor);
  await assert.rejects(() => importScan(s, GB(), { attest: false, source: "imported" }, actor), (e: any) => e.status === 409 && e.extra.unauthorizedHosts.length === 1);
  assert.equal((await s.select(T.vulns)).length, 0, "nothing stored before authorization");
  await importKev(s, { catalogVersion: "t", vulnerabilities: [{ cveID: "CVE-2017-0144" }, { cveID: "bad" }] }, actor);
  const imp = await importScan(s, GB(), { attest: true, attestNote: "my lab PC", source: "imported" }, actor);
  assert.equal(imp.findings, 2); assert.equal(imp.newFindings, 2);
  const vs = await s.select<Vuln>(T.vulns);
  const smb = vs.find((v) => v.cves.includes("CVE-2017-0144"))!;
  assert.equal(smb.severity, "critical"); assert.equal(smb.kev, true); assert.ok(smb.priority > vs.find((v) => v.name.startsWith("TLS"))!.priority); assert.equal(vs[0].assetId, "ws01", "linked to the collector asset by IP/hostname");
  assert.equal((await s.get<Asset>(T.assets, "ws01"))!.authorized, true);
  // later scan without the SMB finding => fixed_verified
  const later = GB("", "2026-10-21T12:00:00Z").replace(/<result id="r1">[\s\S]*?<\/result>/, "");
  const imp2 = await importScan(s, later, { attest: false, source: "imported" }, actor);
  assert.equal(imp2.fixedVerified, 1);
  assert.equal((await s.get<Vuln>(T.vulns, smb.id))!.status, "fixed_verified");
  // a stale (older) report must not mark anything fixed
  const old = await importScan(s, GB("", "2026-10-19T12:00:00Z").replace(/<result id="r2">[\s\S]*?<\/result>/, ""), { attest: false, source: "imported" }, actor);
  assert.equal(old.fixedVerified, 0);
  // reappears in a newer scan
  const imp3 = await importScan(s, GB("", "2026-10-22T12:00:00Z"), { attest: false, source: "imported" }, actor);
  assert.equal(imp3.reappeared, 1); assert.equal((await s.get<Vuln>(T.vulns, smb.id))!.status, "reappeared");
});

test("agent output validation drops invented evidence ids and flags unsupported claims", () => {
  const out = JSON.stringify({ summary: "s", analysis: "## A", findings: [{ claim: "real", evidence_ids: ["evt_1", "evt_FAKE"], confidence: "high" }, { claim: "made up", evidence_ids: ["evt_FAKE"], confidence: "high" }],
    recommendations: [{ action: "Isolate host", priority: "P1", action_type: "isolate_host", target: "ws01", rationale: "r", evidence_ids: ["evt_1"] }, { action: "Review logs", priority: "P3", action_type: "investigate", disruptive: false }], limitations: [] });
  const { out: v, invalid } = validateOutput("```json\n" + out + "\n```", new Set(["evt_1"]));
  assert.deepEqual(invalid, ["evt_FAKE"]); assert.equal(v.findings[0].supported, true); assert.deepEqual(v.findings[0].evidenceIds, ["evt_1"]);
  assert.equal(v.findings[1].supported, false); assert.equal(v.findings[1].confidence, "low");
  assert.equal(v.recommendations[0].disruptive, true); assert.equal(v.recommendations[1].disruptive, false);
  assert.match(validateOutput("not json", new Set()).out.summary, /could not be parsed/);
});

test("AI analyst: unavailable without a key (no fake answer); with a model it audits, validates, and queues approvals", async () => {
  const s = new TestStore();
  await ingestWindows(s, attackPayload() as any, "live", actor);
  const alert = (await s.select<Alert>(T.alerts)).find((a) => a.ruleId === "WIN-AUTH-002")!;
  const none = await runAnalyst(s, { kind: "investigate_alert", alertId: alert.id }, actor, null);
  assert.equal(none.status, "unavailable"); assert.equal(none.output, null); assert.ok(none.evidenceIds.length > 5);
  let seen = "";
  const model = async (_sys: string, user: string) => { seen = user; return { model: "mock", text: JSON.stringify({ summary: "Likely password guessing then login.", analysis: "## Assessment\n- hypothesis", findings: [{ claim: "Login after failures", evidence_ids: [alert.eventIds[0], "evt_nope"], confidence: "medium" }],
    recommendations: [{ action: "Disable the account pending review", priority: "P1", action_type: "disable_account", target: "administrator", rationale: "x", evidence_ids: [alert.eventIds[0]] }], limitations: ["No firewall logs"] }) }; };
  const run = await runAnalyst(s, { kind: "investigate_alert", alertId: alert.id, focus: "is this an attack?" }, actor, model);
  assert.equal(run.status, "ok"); assert.deepEqual(run.invalidEvidenceIds, ["evt_nope"]); assert.match(seen, /<evidence>/); assert.match(seen, /is this an attack\?/);
  const acts = await s.select<SocAction>(T.actions); assert.equal(acts.length, 1); assert.equal(acts[0].status, "proposed"); assert.equal(acts[0].requiresApproval, true);
  await assert.rejects(() => decideAction(s, acts[0].id, "done", actor), (e: any) => e.status === 409, "cannot mark done before approval");
  assert.equal((await decideAction(s, acts[0].id, "approved", actor, "ok")).status, "approved");
  assert.equal((await decideAction(s, acts[0].id, "done", actor)).status, "done");
  const failing = await runAnalyst(s, { kind: "report" }, actor, async () => { throw new Error("boom"); });
  assert.equal(failing.status, "error"); assert.equal(failing.output, null);
  const aud = await s.select<any>(T.audit); assert.ok(aud.some((a) => a.action === "agent.run") && aud.some((a) => a.action === "action.approved"));
});

const call = (s: TestStore, method: string, path: string, token?: string, body?: unknown, ct = "application/json") =>
  handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), "content-type": ct }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) }), path.split("?")[0].split("/"), { store: s, model: null });

test("API: auth, roles, ingest token separation, workspace endpoints", async () => {
  Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890" }); delete process.env.SOC_DEV_AUTH;
  const s = new TestStore();
  assert.equal((await call(s, "GET", "me")).status, 401);
  assert.equal((await call(s, "GET", "me", "short")).status, 401);
  assert.equal((await call(s, "GET", "me", "wrong-token-1234567890")).status, 401);
  assert.equal((await call(s, "GET", "overview", "ingest-token-1234567890")).status, 403, "collector token cannot read");
  assert.equal((await call(s, "POST", "ingest/windows", "viewer-token-1234567890", attackPayload())).status, 403, "viewer cannot ingest");
  const ing = await call(s, "POST", "ingest/windows", "ingest-token-1234567890", attackPayload()); assert.equal(ing.status, 200);
  const me = await (await call(s, "GET", "me", "admin-token-1234567890")).json(); assert.equal(me.role, "admin"); assert.equal(me.aiConfigured, false);
  const ov = await (await call(s, "GET", "overview", "viewer-token-1234567890")).json();
  assert.equal(ov.present.live.events, 10); assert.equal(ov.present.demo.events, 0); assert.ok(ov.activeIncidents.length === 1 && ov.recentAlerts.length >= 4 && typeof ov.posture === "number");
  const incId = ov.activeIncidents[0].id;
  const det = await (await call(s, "GET", "incidents/" + incId, "viewer-token-1234567890")).json(); assert.ok(det.timeline.length > 10 && det.events.length === 10);
  assert.equal((await call(s, "PATCH", "incidents/" + incId, "viewer-token-1234567890", { status: "investigating" })).status, 403);
  assert.equal((await call(s, "PATCH", "incidents/" + incId, "analyst-token-1234567890", { status: "investigating" })).status, 200);
  assert.equal((await call(s, "PATCH", "incidents/" + incId, "analyst-token-1234567890", { status: "closed" })).status, 409);
  const run = await (await call(s, "POST", "agents/run", "analyst-token-1234567890", { agent: "soc_analyst", target: incId, question: "" })).json(); assert.equal(run.run.status, "unavailable");
  assert.equal((await call(s, "POST", "agents/run", "analyst-token-1234567890", { agent: "soc_analyst", target: "", question: "" })).status, 400);
  const ask = await (await call(s, "POST", "agents/run", "analyst-token-1234567890", { agent: "soc_analyst", target: "", question: "any backdoor? administrator" })).json(); assert.equal(ask.run.status, "unavailable");
  const imp = await call(s, "POST", "import/greenbone", "analyst-token-1234567890", GB(), "application/xml"); assert.equal(imp.status, 409);
  assert.equal((await call(s, "POST", "import/greenbone?attest=true", "analyst-token-1234567890", GB(), "application/xml")).status, 200);
  const integ = (await (await call(s, "GET", "integrations", "viewer-token-1234567890")).json()).integrations;
  assert.equal(integ.find((i: any) => i.id === "windows").status, "healthy", "health follows the collector's last CONTACT (it just sent these events), not the age of the events themselves"); assert.equal(integ.find((i: any) => i.id === "ai").status, "not_configured"); assert.equal(integ.find((i: any) => i.id === "siem").status, "not_implemented");
  assert.equal((await call(s, "GET", "audit", "viewer-token-1234567890")).status, 403);
  assert.equal((await call(s, "GET", "audit", "analyst-token-1234567890")).status, 200);
  assert.equal((await call(s, "POST", "ingest/windows", "ingest-token-1234567890", { events: new Array(5001).fill({}) })).status, 413);
  assert.equal((await call(s, "POST", "actions/x/approve", "analyst-token-1234567890", {})).status, 403, "approval is admin-only");
  assert.equal((await call(s, "GET", "nothing", "admin-token-1234567890")).status, 404);
  const o2 = await overview(s); assert.equal(o2.vulnCounts.critical, 1);
});

test("dev auth is ignored in production", async () => {
  Object.assign(process.env, { SOC_DEV_AUTH: "true", NODE_ENV: "production" });
  assert.equal((await call(new TestStore(), "GET", "me")).status, 401);
  Object.assign(process.env, { NODE_ENV: "test" });
  assert.equal((await call(new TestStore(), "GET", "me")).status, 200);
  delete process.env.SOC_DEV_AUTH;
});

test("Supabase store builds correct REST requests (mocked fetch; real database not exercised)", async () => {
  const calls: { url: string; init: any }[] = [];
  const f = (async (url: string, init: any) => { calls.push({ url, init }); return new Response(init?.method === "POST" || init?.method === "DELETE" ? "" : JSON.stringify([{ asset_id: "ws01", last_seen: "x", id: "a" }]), { status: 200 }); }) as any;
  const s = new SupabaseStore("https://p.supabase.co", "svc", f);
  await s.upsert(T.alerts, [{ id: "a", assetId: "ws01", lastSeen: "t" } as any]);
  await s.upsert(T.incidents, [{ id: "i1", verification: undefined, status: "open" } as any, { id: "i2", verification: { status: "passed" }, status: "open" } as any]);
  const sent = JSON.parse(calls[1].init.body); assert.equal(sent[0].verification, null, "undefined becomes NULL so stale values are cleared"); assert.equal(sent[1].verification.status, "passed");
  assert.match(calls[0].url, /soc_alerts\?on_conflict=id$/); assert.equal(JSON.parse(calls[0].init.body)[0].asset_id, "ws01"); assert.equal(calls[0].init.headers.apikey, "svc");
  const rows = await s.select<any>(T.alerts, { where: { assetId: "ws01" }, order: ["lastSeen", "desc"], limit: 5, gte: ["time", "2026"] });
  assert.match(calls[2].url, /asset_id=eq\.ws01/); assert.match(calls[2].url, /order=last_seen\.desc/); assert.match(calls[2].url, /limit=5/); assert.match(calls[2].url, /time=gte\.2026/); assert.equal(rows[0].assetId, "ws01");
  const bad = new SupabaseStore("https://p.supabase.co", "svc", (async () => new Response("nope", { status: 401 })) as any);
  await assert.rejects(() => bad.select(T.alerts), /Database error 401/);
});
