import { TestStore } from "./test-store";
// Run: npx tsx --test tests/roles.test.ts  (synthetic fixtures only)
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore, T } from "../lib/soc/store";
import { ingestWindows, importScan } from "../lib/soc/pipeline";
import { handleSoc, overview, incidentDetail } from "../lib/soc/api";
import { runAnalyst, PERSONA } from "../lib/soc/agents";
import { HUNTS, analyzeLogs, csvCell, eventStats, execSummaryMd, hardeningFor, huntEvents, incidentReportMd, parseEventInput, planToCsv, playbookFor, remediationPlan, ruleCatalog, topRisks, validateManualAction } from "../lib/soc/roles";
import type { SocAction, SocEvent } from "../lib/soc/types";

const actor = { name: "tester", role: "admin" };
const t0 = Math.floor(Date.now() / 60000) * 60000 - 3 * 3600_000;
const iso = (m: number) => new Date(t0 + m * 60_000).toISOString();
let rec = 1;
const w = (host: string, id: number, min: number, data: Record<string, string>, o: Record<string, unknown> = {}) => ({ Id: id, RecordId: rec++, TimeCreated: iso(min), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: host, Data: data, ...o });
function payload() {
  const e: unknown[] = [];
  for (let i = 0; i < 6; i++) e.push(w("WS01", 4625, i, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" }));
  e.push(w("WS01", 4624, 7, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "10" }));
  e.push(w("WS01", 4688, 8, { SubjectUserName: "administrator", NewProcessName: "C:\\Windows\\System32\\powershell.exe", CommandLine: "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" }));
  e.push(w("WS01", 4688, 9, { SubjectUserName: "bob", NewProcessName: "C:\\Windows\\notepad.exe", CommandLine: "notepad.exe a.txt" }));
  e.push(w("WS01", 1102, 10, { SubjectUserName: "administrator" }));
  return { host: "WS01", events: e as any };
}
async function seeded() { const s = new TestStore(); await ingestWindows(s, payload(), "live", actor); return s; }
const events = async (s: TestStore) => s.select<SocEvent>(T.events, { limit: 1000 });

test("huntEvents: every filter must match; free text searches raw data; limit respected", async () => {
  const ev = await events(await seeded());
  assert.equal(huntEvents(ev, { eventIds: [4625] }).total, 6);
  assert.equal(huntEvents(ev, { eventIds: [4625], ip: "203.0.113" }).total, 6);
  assert.equal(huntEvents(ev, { eventIds: [4625], user: "bob" }).total, 0);
  assert.equal(huntEvents(ev, { q: "notepad" }).total, 1);
  assert.equal(huntEvents(ev, { q: "NOTEPAD", host: "ws" }).total, 1);
  assert.equal(huntEvents(ev, { host: "other" }).total, 0);
  assert.equal(huntEvents(ev, { from: iso(8), to: iso(9) }).total, 2);
  const r = huntEvents(ev, {}, 3); assert.equal(r.rows.length, 3); assert.equal(r.total, ev.length);
  assert.ok(r.rows[0].time >= r.rows[1].time, "newest first");
});

test("hunt presets find the planted behavior and stay quiet on benign events", async () => {
  const ev = await events(await seeded()); const h = (id: string) => HUNTS.find((x) => x.id === id)!.run(ev);
  assert.equal(h("failed-sources").matches.length, 6); assert.match(h("failed-sources").note, /203\.0\.113\.9 \(6\)/);
  assert.equal(h("encoded-cmd").matches.length, 1);
  assert.equal(h("log-tamper").matches.length, 1);
  assert.equal(h("public-rdp").matches.length, 1);
  assert.equal(h("persistence").matches.length, 0); assert.equal(h("recovery-inhibit").matches.length, 0); assert.match(h("recovery-inhibit").note, /None/);
  const st = eventStats(ev); assert.equal(st.total, ev.length); assert.equal(st.bySource[0][0], "203.0.113.9");
});

test("parseEventInput: JSON array, {events}, NDJSON and wevtutil XML; rejects junk and oversize", () => {
  const one = { Id: 4625, TimeCreated: iso(0), MachineName: "A", LogName: "Security", Data: { TargetUserName: "x", IpAddress: "1.2.3.4" } };
  assert.equal(parseEventInput(JSON.stringify([one, one])).raw.length, 2);
  assert.equal(parseEventInput(JSON.stringify({ events: [one] })).format, "json");
  assert.equal(parseEventInput(JSON.stringify(one) + "\n" + JSON.stringify(one)).format, "ndjson");
  const xml = `<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><EventRecordID>77</EventRecordID><TimeCreated SystemTime="${iso(1)}"/><Channel>Security</Channel><Computer>WS09.corp.local</Computer></System><EventData><Data Name="TargetUserName">eve</Data><Data Name="IpAddress">198.51.100.4</Data><Data Name="LogonType">3</Data></EventData></Event></Events>`;
  const p = parseEventInput(xml); assert.equal(p.format, "xml"); assert.equal(p.raw.length, 1);
  const a = analyzeLogs(xml); assert.equal(a.accepted.length, 1); assert.equal(a.accepted[0].host, "WS09"); assert.equal(a.accepted[0].user, "eve"); assert.equal(a.accepted[0].srcIp, "198.51.100.4");
  assert.ok(parseEventInput("hello").error); assert.ok(parseEventInput("").error); assert.ok(parseEventInput("<a>").error);
  assert.ok(parseEventInput("<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>").error, "entity declarations rejected");
  assert.ok(parseEventInput("x".repeat(6_100_000)).error);
});

test("analyzeLogs runs the real normalizer and rules, reports rejects, dedupes, stores nothing", () => {
  const evs = payload().events as any[];
  const a = analyzeLogs(JSON.stringify([...evs, evs[0], { junk: true }, 5]));
  assert.equal(a.received, evs.length + 3); assert.equal(a.accepted.length, evs.length); assert.equal(a.rejected.length, 2);
  assert.ok(a.alerts.some((x) => x.ruleId === "WIN-AUTH-001") && a.alerts.some((x) => x.ruleId === "WIN-EXEC-001") && a.alerts.every((x) => x.preview));
  assert.ok(a.alerts[0].severity === "critical" || a.alerts[0].severity === "high", "sorted by severity");
  assert.ok(ruleCatalog().length >= 14 && ruleCatalog()[0].mitre.length > 0);
});

test("remediation plan orders hosts and fixes by priority, skips fixed/accepted, CSV neutralizes formulas", async () => {
  const s = new TestStore();
  const r = (ip: string, host: string, oid: string, name: string, sev: number, sol: string) => `<result><host>${ip}<hostname>${host}</hostname></host><port>445/tcp</port><nvt oid="${oid}"><name>${name}</name><solution type="VendorFix">${sol}</solution></nvt><severity>${sev}</severity><threat>x</threat><qod><value>90</value></qod></result>`;
  const xml = `<report><scan_end>${iso(0)}</scan_end><results>${r("10.0.0.2", "a", "1", "=HYPERLINK(\"http://x\")", 9.5, "Patch it")}${r("10.0.0.2", "a", "2", "Other", 5, "Patch it")}${r("10.0.0.3", "b", "3", "Low one", 2, "Meh")}</results></report>`;
  await importScan(s, xml, { attest: true, source: "imported" }, actor);
  const o = await overview(s); const plan = remediationPlan(await s.select<any>(T.vulns, { limit: 100 }), o.assets);
  assert.equal(plan.items[0].host, "a"); assert.equal(plan.totals.findings, 3); assert.equal(plan.items[0].steps.length, 1, "same fix grouped"); assert.equal(plan.items[0].steps[0].fixes.length, 2);
  const csv = planToCsv(plan); assert.match(csv, /"'=HYPERLINK/); assert.equal(csv.split("\r\n").length, 4);
  assert.equal(csvCell('a"b'), '"a""b"'); assert.equal(csvCell("@x"), `"'@x"`);
  const vs = await s.select<any>(T.vulns, { limit: 100 }); vs[0].status = "accepted_risk"; assert.equal(remediationPlan(vs).totals.findings, 2);
});

test("hardening guidance and playbooks follow the alerts of the incident", async () => {
  const s = await seeded(); const o = await overview(s);
  const h = hardeningFor(o.recentAlerts); assert.ok(h.some((x) => x.ruleId === "WIN-AUTH-001" && x.advice.length > 0 && x.hosts.includes("WS01")));
  assert.equal(hardeningFor([{ ruleId: "X", title: "t", host: "h" }])[0].advice[0].startsWith("No hardening"), true);
  const inc = o.activeIncidents[0]; const d = await incidentDetail(s, inc.id);
  const pb = playbookFor(inc, d.alerts.map((a) => a.ruleId)); assert.equal(pb.length, 5);
  const contain = pb[1].steps; assert.ok(contain.length >= 3 && contain.every((x) => x.needsApproval), "containment steps all need approval");
  assert.ok(new Set(pb.flatMap((p) => p.steps.map((x) => x.id))).size === pb.flatMap((p) => p.steps).length, "step ids unique");
  const md = incidentReportMd({ incident: d.incident, timeline: d.timeline, actions: d.actions, notes: ["called owner"] });
  assert.match(md, /# Incident report/); assert.match(md, /called owner/); assert.match(md, /rule-based hypotheses/);
  assert.match(incidentReportMd({ incident: { ...d.incident, source: "demo" } as any }), /SAMPLE \(simulated\)/);
});

test("executive summary: honest labels, ranked risks, decisions", async () => {
  const s = await seeded(); const o = await overview(s);
  const x = { posture: o.posture, vulnCounts: o.vulnCounts, activeIncidents: o.activeIncidents, kevVulns: 2, assets: o.assets, topVulns: [{ name: "SMBv1", host: "A", severity: "critical" as const, kev: true, priority: 95 }, { name: "TLS1.0", host: "A", severity: "medium" as const, kev: false, priority: 30 }], pendingActions: 3, mode: "connected" as const };
  const md = execSummaryMd(x); assert.match(md, /Active incidents: \*\*1\*\*/); assert.match(md, /Approve emergency patching for 2/); assert.match(md, /Approve or reject 3/); assert.match(md, /no history is stored/i); assert.doesNotMatch(md, /SAMPLE DATA/);
  assert.match(execSummaryMd({ ...x, mode: "sample" }), /SAMPLE DATA/);
  const t = topRisks(x); assert.equal(t[0].rank, 1); assert.match(t[0].risk, /incident|SMBv1/i);
  assert.match(execSummaryMd({ ...x, posture: null, activeIncidents: [], topVulns: [], kevVulns: 0, pendingActions: 0 }), /None right now/);
});

test("validateManualAction accepts only known types and bounded text", () => {
  assert.equal(validateManualAction({ type: "block_ip", target: "1.2.3.4", description: "block" }).ok, true);
  for (const bad of [{ type: "format_disk", target: "x", description: "y" }, { type: "block_ip", target: "", description: "y" }, { type: "block_ip", target: "x", description: "" }, { type: "block_ip", target: "x".repeat(201), description: "y" }, { type: "block_ip", target: "x", description: "y", rationale: "z".repeat(1001) }, null]) assert.equal(validateManualAction(bad as any).ok, false);
});

const call = (s: TestStore, method: string, path: string, token?: string, body?: unknown) =>
  handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store: s, model: null });
const AN = "analyst-token-1234567890", VI = "viewer-token-1234567890", AD = "admin-token-1234567890";

test("API: /hunt search, manual action proposal (roles, validation, never executed), approval flow", async () => {
  Object.assign(process.env, { SOC_ADMIN_TOKEN: AD, SOC_VIEWER_TOKEN: VI, SOC_ANALYST_TOKEN: AN }); delete process.env.SOC_DEV_AUTH;
  const s = await seeded(); const o = await overview(s); const incId = o.activeIncidents[0].id;
  const h = await (await call(s, "GET", "hunt?eventIds=4625&ip=203.0.113", VI)).json(); assert.equal(h.total, 6); assert.equal(h.searched, 10);
  assert.equal((await (await call(s, "GET", "hunt?q=notepad", VI)).json()).total, 1);
  assert.equal((await call(s, "GET", "hunt")).status, 401);
  const body = { type: "block_ip", target: "203.0.113.9", description: "Block the brute-force source", rationale: "6 failed logons", incidentId: incId };
  assert.equal((await call(s, "POST", "actions", VI, body)).status, 403, "viewer cannot propose");
  assert.equal((await call(s, "POST", "actions", AN, { ...body, type: "rm_rf" })).status, 400);
  assert.equal((await call(s, "POST", "actions", AN, { ...body, incidentId: "inc_nope" })).status, 404);
  const ok = await call(s, "POST", "actions", AN, body); assert.equal(ok.status, 201); const act = await ok.json() as SocAction;
  assert.equal(act.status, "proposed"); assert.equal(act.requiresApproval, true); assert.match(act.proposedBy, /^user:/);
  assert.equal((await call(s, "POST", `actions/${act.id}/approve`, AN, {})).status, 403, "analyst cannot approve");
  assert.equal((await call(s, "POST", `actions/${act.id}/approve`, AD, {})).status, 200);
  const aud = await s.select<any>(T.audit); assert.ok(aud.some((a) => a.action === "action.propose") && aud.some((a) => a.action === "action.approved"));
  const det = await (await call(s, "GET", "incidents/" + incId, VI)).json(); assert.ok(det.actions.some((a: any) => a.id === act.id));
});

test("role personas: each agent id is accepted, recorded on the run and the prompt differs", async () => {
  Object.assign(process.env, { SOC_ANALYST_TOKEN: AN }); const s = await seeded(); const o = await overview(s);
  const seen: string[] = [];
  const model = async (system: string) => { seen.push(system); return { text: JSON.stringify({ summary: "ok", analysis: "", findings: [], recommendations: [], limitations: [] }), model: "stub" }; };
  for (const agent of ["vuln_analyst", "threat_hunter", "incident_responder", "security_advisor", "siem_specialist", "soc_analyst"] as const) {
    const run = await runAnalyst(s, { kind: "ask", question: "what is going on with logons" }, actor, model, agent); assert.equal(run.agent, agent);
  }
  assert.equal(new Set(seen).size, 6, "six different system prompts");
  assert.ok(seen.every((x) => x.includes("Never invent events")), "shared safety rules present in every persona");
  assert.match(seen[0], /Security Engineer/); assert.match(seen[3], /CISO/);
  const r = await handleSoc(new Request("http://x/api/soc/agents/run", { method: "POST", headers: { authorization: "Bearer " + AN, "content-type": "application/json" }, body: JSON.stringify({ agent: "threat_hunter", target: "", question: "hunt" }) }), ["agents", "run"], { store: s, model });
  assert.equal((await r.json()).run.agent, "threat_hunter");
  const bogus = await handleSoc(new Request("http://x/api/soc/agents/run", { method: "POST", headers: { authorization: "Bearer " + AN, "content-type": "application/json" }, body: JSON.stringify({ agent: "root", target: "", question: "hi" }) }), ["agents", "run"], { store: s, model });
  assert.equal((await bogus.json()).run.agent, "soc_analyst", "unknown agent ids fall back to the default");
  assert.ok(Object.keys(PERSONA).length === 6 && o);
});
