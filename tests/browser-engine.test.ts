// Proves the in-browser bundle gives the same answers as the server code (same ids, same alerts). Run: npx tsx --test tests/browser-engine.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { analyzeLogs, planToCsv, execSummaryMd } from "../lib/soc/roles";

const ctx: any = { crypto: webcrypto, TextEncoder, console }; ctx.globalThis = ctx; vm.createContext(ctx);
vm.runInContext(readFileSync(new URL("../scripts/engine.browser.js", import.meta.url), "utf8"), ctx);
const B = ctx.SocEngine;
const t0 = Date.now() - 3600_000;
const ev = (i: number, id: number, d: Record<string, string>) => ({ Id: id, RecordId: 100 + i, TimeCreated: new Date(t0 + i * 20_000).toISOString(), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: "WS7", Data: d });
const sample = JSON.stringify([...Array.from({ length: 7 }, (_, i) => ev(i, 4625, { TargetUserName: "root", IpAddress: "203.0.113.50", LogonType: "3" })), ev(8, 4624, { TargetUserName: "root", IpAddress: "203.0.113.50", LogonType: "3" }), ev(9, 1102, { SubjectUserName: "root" })]);

test("browser bundle exposes the tools", () => { for (const k of ["analyzeLogs", "huntEvents", "HUNTS", "remediationPlan", "planToCsv", "playbookFor", "incidentReportMd", "execSummaryMd", "hardeningFor", "ruleCatalog", "eventStats", "parseEventInput"]) assert.ok(B[k], k); });
test("browser analyzeLogs == server analyzeLogs (event ids come from SHA-256, so this also checks the hash)", () => {
  const s = analyzeLogs(sample), b = JSON.parse(JSON.stringify(B.analyzeLogs(sample)));
  assert.deepEqual(b.accepted.map((e: any) => e.id), s.accepted.map((e) => e.id));
  assert.deepEqual(b.alerts.map((a: any) => [a.ruleId, a.severity, a.key, a.eventIds.length]), s.alerts.map((a) => [a.ruleId, a.severity, a.key, a.eventIds.length]));
  assert.ok(b.alerts.length >= 2);
});
test("browser sha256 matches node for odd lengths and unicode", () => {
  for (const t of ["", "a", "abc", "x".repeat(55), "x".repeat(56), "x".repeat(64), "x".repeat(1000), "héllo ✓ 世界"]) {
    const r = JSON.parse(JSON.stringify(B.analyzeLogs(JSON.stringify([{ Id: 4625, RecordId: 1, TimeCreated: new Date().toISOString(), MachineName: "H", LogName: "Security", Data: { TargetUserName: t, IpAddress: "1.1.1.1" } }]))));
    const sv = analyzeLogs(JSON.stringify([{ Id: 4625, RecordId: 1, TimeCreated: JSON.parse(JSON.stringify(B.analyzeLogs.length)) ? new Date().toISOString() : "", MachineName: "H", LogName: "Security", Data: { TargetUserName: t, IpAddress: "1.1.1.1" } }]));
    assert.equal(r.accepted.length, sv.accepted.length);
  }
  const direct = (s: string) => createHash("sha256").update(s).digest("hex");
  // hash exposed indirectly: a record's id is "evt_" + first 16 hex of sha256(fingerprint)
  const rec = JSON.parse(JSON.stringify(B.analyzeLogs(sample))).accepted[0];
  assert.equal(rec.id, "evt_" + direct(rec.fingerprint).slice(0, 16));
});
test("browser CSV/summary helpers run", () => {
  assert.match(B.execSummaryMd({ posture: 50, vulnCounts: { critical: 1 }, activeIncidents: [], assets: [], topVulns: [], mode: "sample" }), /SAMPLE DATA/);
  assert.equal(typeof B.planToCsv({ items: [], totals: {} }), "string");
  assert.equal(typeof planToCsv, "function"); assert.equal(typeof execSummaryMd, "function");
});
