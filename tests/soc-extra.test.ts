// Synthetic TEST FIXTURES only. Covers UEBA, NDR, MITRE coverage, SOAR plans and Elastic mapping/ingest.
import test from "node:test";
import assert from "node:assert/strict";
import { TestStore } from "./test-store";
import { normalizeWindows } from "../lib/soc/windows";
import { runRules, RULES_META } from "../lib/soc/rules";
import { mitreCoverage } from "../lib/soc/mitre";
import { soarPlan, playbookCatalog } from "../lib/soc/soar";
import { elasticToRaw, elasticQuery, elasticHitsToRaw } from "../lib/soc/elastic";
import { handleSoc } from "../lib/soc/api";
import { T } from "../lib/soc/store";
import type { SocEvent } from "../lib/soc/types";

const base = Date.parse("2026-03-10T00:00:00Z"); let rid = 1;
const win = (id: number, tms: number, data: Record<string, string>, o: Record<string, unknown> = {}) => ({ Id: id, RecordId: rid++, TimeCreated: new Date(tms).toISOString(), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: "WS01", EventData: data, ...o });
const sys3 = (tms: number, ip: string, port: string, img = "C:\\Windows\\System32\\svchost.exe") => win(3, tms, { Image: img, DestinationIp: ip, DestinationPort: port, User: "CORP\\bob" }, { LogName: "Microsoft-Windows-Sysmon/Operational", ProviderName: "Microsoft-Windows-Sysmon" });
const norm = (xs: any[]) => xs.map((r) => { const e = normalizeWindows(r, { source: "live", collector: "t" }); if ("error" in e) throw new Error(e.error); return e as SocEvent; });
const H = 3600_000, D = 24 * H;
const logon = (tms: number, user: string, ip: string, type = "3") => win(4624, tms, { TargetUserName: user, IpAddress: ip, LogonType: type });
// 25 weekday logons by alice at 08:00-10:00 UTC from 10.0.0.5 across 25 days.
const baseline = () => Array.from({ length: 25 }, (_, i) => logon(base + i * D + (8 + (i % 3)) * H, "alice", "10.0.0.5"));

test("UEBA: unusual hour and new public source are flagged; normal behaviour is not", () => {
  const d = 30 * D;
  const normal = runRules(norm([...baseline(), logon(base + d + 9 * H, "alice", "10.0.0.5")]));
  assert.equal(normal.filter((a) => a.ruleId.startsWith("UEBA")).length, 0, "normal recent logon raises nothing");
  const odd = runRules(norm([...baseline(), logon(base + d + 3 * H, "alice", "10.0.0.5")])).filter((a) => a.ruleId === "UEBA-001");
  assert.equal(odd.length, 1); assert.match(odd[0].title, /03:00 UTC/); assert.ok(odd[0].confidence <= 0.5); assert.equal(odd[0].eventIds.length, 1);
  const src = runRules(norm([...baseline(), logon(base + d + 9 * H, "alice", "198.51.100.77", "10")])).filter((a) => a.ruleId === "UEBA-002");
  assert.equal(src.length, 1); assert.equal(src[0].severity, "high"); assert.deepEqual(src[0].entities.ips, ["198.51.100.77"]);
  const internal = runRules(norm([...baseline(), logon(base + d + 9 * H, "alice", "10.0.0.99", "3")])).filter((a) => a.ruleId === "UEBA-002");
  assert.equal(internal[0].severity, "low");
});
test("UEBA: no alerts without enough baseline", () => {
  const few = [logon(base, "bob", "10.0.0.5"), logon(base + 30 * D + 3 * H, "bob", "203.0.113.5", "10")];
  assert.equal(runRules(norm(few)).filter((a) => a.ruleId.startsWith("UEBA")).length, 0);
});
test("NDR: beaconing detected for regular intervals, not for irregular", () => {
  const reg = Array.from({ length: 12 }, (_, i) => sys3(base + i * 60_000, "203.0.113.50", "8443"));
  const a = runRules(norm(reg)).filter((x) => x.ruleId === "NDR-001"); assert.equal(a.length, 1); assert.match(a[0].title, /every ~60 s/); assert.equal(a[0].eventIds.length, 12);
  let t = base; const irr = Array.from({ length: 12 }, (_, i) => sys3((t += [5, 190, 20, 400, 33, 280, 12, 500, 7, 260, 90, 330][i] * 1000), "203.0.113.51", "8443"));
  assert.equal(runRules(norm(irr)).filter((x) => x.ruleId === "NDR-001").length, 0);
});
test("NDR: port scan and host sweep detected; few connections are not", () => {
  const scan = Array.from({ length: 25 }, (_, i) => sys3(base + i * 2000, "10.1.1.10", String(1000 + i)));
  const a = runRules(norm(scan)).filter((x) => x.ruleId === "NDR-002"); assert.equal(a.length, 1); assert.match(a[0].title, /25 ports on 10\.1\.1\.10/);
  const sweep = Array.from({ length: 22 }, (_, i) => sys3(base + i * 2000, `10.2.0.${i + 1}`, "445"));
  assert.ok(runRules(norm(sweep)).some((x) => x.ruleId === "NDR-002" && /addresses on port 445/.test(x.title)));
  assert.equal(runRules(norm(scan.slice(0, 5))).filter((x) => x.ruleId === "NDR-002").length, 0);
});
test("existing rule catalogue includes the new rules (ids unique)", () => {
  const ids = RULES_META.map((r) => r.id); assert.equal(new Set(ids).size, ids.length); for (const id of ["UEBA-001", "UEBA-002", "NDR-001", "NDR-002"]) assert.ok(ids.includes(id));
});
test("MITRE coverage: tactics, techniques and honest gaps", () => {
  const c = mitreCoverage(); assert.equal(c.totalTactics, 14); assert.ok(c.coveredTactics >= 8);
  assert.ok(c.tactics.find((t) => t.tactic === "Discovery")!.techniques.some((t) => t.id === "T1046"));
  assert.ok(c.gaps.includes("Exfiltration") && c.gaps.includes("Reconnaissance")); assert.match(c.note, /not that every technique/);
  assert.ok(!c.tactics.some((t) => t.techniques.some((x) => x.id === "N/A")));
});
test("SOAR: plans are proposals; disruptive steps need approval; nothing auto-executes", () => {
  const p = soarPlan({ id: "alt_1", ruleId: "WIN-AUTH-002", host: "WS01", title: "x", entities: { users: ["administrator"], ips: ["203.0.113.9"] } });
  assert.equal(p.playbook, "credential-attack"); assert.ok(p.proposals.every((x) => x.autoExecute === false));
  assert.ok(p.proposals.find((x) => x.type === "block_ip")!.requiresApproval); assert.ok(p.proposals.find((x) => x.type === "reset_password")!.requiresApproval); assert.equal(p.proposals.find((x) => x.type === "investigate")!.requiresApproval, false);
  const m = soarPlan({ id: "a", ruleId: "WIN-MAL-001", host: "H", title: "t", entities: { users: [], ips: [] } }); assert.ok(m.proposals.some((x) => x.type === "isolate_host" && x.requiresApproval));
  assert.equal(soarPlan({ id: "a", ruleId: "NDR-001", host: "H", title: "t", entities: { users: [], ips: ["1.2.3.4"] } }).playbook, "network-behaviour");
  assert.equal(soarPlan({ id: "a", ruleId: "UNKNOWN", host: "H", title: "t", entities: { users: [], ips: [] } }).playbook, "none"); assert.ok(playbookCatalog().length >= 5);
  assert.match(p.note, /Nothing is executed automatically/);
});
test("Elastic: ECS Winlogbeat documents map into the existing pipeline and trigger existing rules", () => {
  const hit = (i: number) => ({ _source: { "@timestamp": new Date(base + i * 30_000).toISOString(), host: { name: "srv01.corp" }, winlog: { event_id: 4625, channel: "Security", provider_name: "Microsoft-Windows-Security-Auditing", computer_name: "SRV01", record_id: 500 + i, event_data: { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" } } } });
  const { events, skipped } = elasticHitsToRaw([...Array.from({ length: 8 }, (_, i) => hit(i)), { _source: { message: "not windows" } }, null]); assert.equal(events.length, 8); assert.equal(skipped, 2);
  const out = runRules(norm(events)); assert.ok(out.some((a) => a.ruleId === "WIN-AUTH-001"));
  assert.equal(elasticToRaw({ foo: 1 }), null);
  const q = elasticQuery({ sinceIso: "2026-01-01T00:00:00Z", size: 99999 }); assert.equal((q.body as any).size, 1000); assert.equal(q.index, "winlogbeat-*"); assert.ok(!/delete|update|_bulk/i.test(JSON.stringify(q)));
});
test("API: mitre, soar and elastic ingest respect roles", async () => {
  Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890" }); delete process.env.SOC_DEV_AUTH;
  const s = new TestStore(); const call = (m: string, p: string, tok?: string, body?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: m, headers: { ...(tok ? { authorization: "Bearer " + tok } : {}), "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), p.split("?")[0].split("/"), { store: s, model: null });
  assert.equal((await call("GET", "mitre")).status, 401); assert.equal((await call("GET", "mitre", "viewer-token-1234567890")).status, 200);
  assert.equal((await call("GET", "mitre", "ingest-token-1234567890")).status, 403);
  const hits = Array.from({ length: 8 }, (_, i) => ({ _source: { "@timestamp": new Date(Date.now() - 3600_000 + i * 30_000).toISOString(), winlog: { event_id: 4625, channel: "Security", computer_name: "SRV01", record_id: 900 + i, event_data: { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" } } } }));
  assert.equal((await call("POST", "ingest/elastic", "viewer-token-1234567890", { hits })).status, 403);
  { const x = await call("POST", "ingest/elastic", "ingest-token-1234567890", { nothits: 1 }); assert.equal(x.status, 400, await x.clone().text()); }
  const r = await call("POST", "ingest/elastic", "ingest-token-1234567890", { hits }); assert.equal(r.status, 200); const j = await r.json(); assert.equal(j.accepted, 8); assert.ok(j.newAlerts >= 1);
  const alerts = await s.select<any>(T.alerts); const al = alerts.find((a) => a.ruleId === "WIN-AUTH-001")!;
  const plan = await (await call("GET", "soar/plan?alert=" + al.id, "viewer-token-1234567890")).json(); assert.equal(plan.playbook, "credential-attack");
  assert.equal((await call("GET", "soar/plan?alert=nope", "viewer-token-1234567890")).status, 404);
  assert.ok((await (await call("GET", "soar/playbooks", "viewer-token-1234567890")).json()).playbooks.length >= 5);
});
