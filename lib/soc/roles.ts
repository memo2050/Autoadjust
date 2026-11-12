// Role tools for the six SOC Team panels. Pure functions (no I/O) so the exact same code runs in tests, on the server and,
// bundled, in the browser. Nothing here executes a response action or contacts a system: it filters, groups, parses and writes text.
import type { Alert, Incident, SocAction, SocEvent, Vuln } from "./types";
import { sevRank } from "./types";
import { normalizeWindows, type RawWinEvent } from "./windows";
import { runRules, RULES_META, type AlertDraft } from "./rules";
import { findAll, kid, kids, parseXml, txt } from "./xml";
import { isPrivateIp, uniq } from "./util";

// ---------------------------------------------------------------- Threat Hunter
export interface HuntQuery { q?: string; eventIds?: number[]; host?: string; user?: string; ip?: string; channel?: string; from?: string; to?: string }
const hay = (e: SocEvent) => `${e.summary} ${e.host} ${e.user ?? ""} ${e.targetUser ?? ""} ${e.srcIp ?? ""} ${e.srcHost ?? ""} ${e.process ?? ""} ${e.parentProcess ?? ""} ${e.commandLine ?? ""} ${Object.values(e.data).join(" ")}`.toLowerCase();

/** Filters events. Every filter that is set must match. Case-insensitive; free text matches any field including raw event data. */
export function huntEvents(events: SocEvent[], q: HuntQuery, limit = 200): { total: number; rows: SocEvent[] } {
  const low = (s?: string) => (s ?? "").trim().toLowerCase();
  const text = low(q.q), host = low(q.host), user = low(q.user), ip = low(q.ip), ch = low(q.channel);
  const from = q.from ? Date.parse(q.from) : NaN, to = q.to ? Date.parse(q.to) : NaN;
  const rows = events.filter((e) => {
    if (q.eventIds && q.eventIds.length && !q.eventIds.includes(e.eventId)) return false;
    if (host && !e.host.toLowerCase().includes(host)) return false;
    if (user && !`${e.user ?? ""} ${e.targetUser ?? ""}`.toLowerCase().includes(user)) return false;
    if (ip && !(e.srcIp ?? "").toLowerCase().includes(ip)) return false;
    if (ch && !e.channel.toLowerCase().includes(ch)) return false;
    const t = Date.parse(e.time);
    if (Number.isFinite(from) && t < from) return false;
    if (Number.isFinite(to) && t > to) return false;
    if (text && !hay(e).includes(text)) return false;
    return true;
  }).sort((a, b) => (a.time < b.time ? 1 : -1));
  return { total: rows.length, rows: rows.slice(0, limit) };
}

export interface HuntPreset { id: string; name: string; hypothesis: string; mitre: string; run: (events: SocEvent[]) => { matches: SocEvent[]; note: string } }
const sec = (e: SocEvent) => e.channel.toLowerCase() === "security";
const CMD_RE = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|downloadstring|net\.webclient|invoke-webrequest|\biex\b|frombase64string|certutil.*-urlcache|bitsadmin.*\/transfer|mshta|rundll32.*javascript|regsvr32.*\/i:http/i;
const byIds = (ids: number[], extra?: (e: SocEvent) => boolean) => (events: SocEvent[]) => events.filter((e) => ids.includes(e.eventId) && (!extra || extra(e)));
export const HUNTS: HuntPreset[] = [
  { id: "failed-sources", name: "Sources with repeated failed logons", hypothesis: "An external or internal address is guessing passwords.", mitre: "T1110",
    run: (ev) => { const f = ev.filter((e) => e.eventId === 4625 && sec(e) && e.srcIp); const by = new Map<string, SocEvent[]>(); f.forEach((e) => by.set(e.srcIp!, [...(by.get(e.srcIp!) ?? []), e]));
      const hit = [...by.entries()].filter(([, v]) => v.length >= 3); return { matches: hit.flatMap(([, v]) => v), note: hit.length ? `${hit.length} source address(es) with 3 or more failed logons: ${hit.map(([ip, v]) => `${ip} (${v.length})`).join(", ")}.` : "No source address has 3 or more failed logons in this data." }; } },
  { id: "encoded-cmd", name: "Encoded or download-style command lines", hypothesis: "A script is hiding its payload or fetching code.", mitre: "T1059.001 / T1105",
    run: (ev) => { const m = ev.filter((e) => e.eventId === 4688 && e.commandLine && CMD_RE.test(e.commandLine)); return { matches: m, note: m.length ? `${m.length} process-creation event(s) with an encoded or download-style command line.` : "No matching command lines. Note: process command-line auditing must be enabled for 4688 events to carry them." }; } },
  { id: "persistence", name: "Persistence: tasks, services, new accounts, group changes", hypothesis: "Someone is making access survive a reboot or password change.", mitre: "T1053 / T1543 / T1136 / T1098",
    run: (ev) => { const m = byIds([4698, 7045, 4697, 4720, 4728, 4732, 4756])(ev); return { matches: m, note: `${m.length} persistence-related event(s).` }; } },
  { id: "log-tamper", name: "Log clearing and audit tampering", hypothesis: "An actor is hiding their tracks.", mitre: "T1070.001 / T1562",
    run: (ev) => { const m = byIds([1102, 104, 4719, 5001])(ev); return { matches: m, note: m.length ? `${m.length} event(s) that clear logs or weaken auditing/protection.` : "No log-clearing or audit-policy events." }; } },
  { id: "public-rdp", name: "Remote Desktop logons from public addresses", hypothesis: "RDP is exposed and being used from the internet.", mitre: "T1021.001 / T1133",
    run: (ev) => { const m = ev.filter((e) => e.eventId === 4624 && e.logonType === 10 && e.srcIp && !isPrivateIp(e.srcIp)); return { matches: m, note: m.length ? `${m.length} RDP logon(s) from non-private addresses.` : "No RDP logons from public addresses." }; } },
  { id: "av-detect", name: "Endpoint protection detections", hypothesis: "Defender already saw something worth correlating.", mitre: "—",
    run: (ev) => { const m = byIds([1116, 1117])(ev); return { matches: m, note: `${m.length} Defender detection/action event(s).` }; } },
  { id: "recovery-inhibit", name: "Shadow copy / backup deletion", hypothesis: "Ransomware preparation.", mitre: "T1490",
    run: (ev) => { const m = ev.filter((e) => e.eventId === 4688 && /vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled|bootstatuspolicy)|wbadmin.*delete/i.test(e.commandLine ?? "")); return { matches: m, note: m.length ? `${m.length} command(s) that delete shadow copies or disable recovery.` : "None found." }; } },
];

export function eventStats(events: SocEvent[]) {
  const top = (f: (e: SocEvent) => string | undefined, n = 6) => { const m = new Map<string, number>(); events.forEach((e) => { const k = f(e); if (k) m.set(k, (m.get(k) ?? 0) + 1); }); return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n); };
  return { total: events.length, byEventId: top((e) => `${e.eventId} ${e.summary}`), byHost: top((e) => e.host), byChannel: top((e) => e.channel), bySource: top((e) => e.srcIp), byUser: top((e) => e.user) };
}

// ---------------------------------------------------------------- SIEM Specialist
export interface ParsedInput { raw: RawWinEvent[]; format: "json" | "ndjson" | "xml" | "none"; error?: string }
const MAX_INPUT = 6_000_000, MAX_EVENTS = 5000;

/** Reads pasted/uploaded log text: a JSON array, {events:[...]}, NDJSON, or wevtutil/Event Viewer XML (<Event> records). */
export function parseEventInput(text: string): ParsedInput {
  const s = (text ?? "").trim();
  if (!s) return { raw: [], format: "none", error: "Nothing to parse. Paste events or choose a file." };
  if (s.length > MAX_INPUT) return { raw: [], format: "none", error: "Input is larger than 6 MB." };
  if (s[0] === "<") {
    try {
      const root = parseXml(s); const evs = findAll(root, "Event");
      if (!evs.length) return { raw: [], format: "xml", error: "No <Event> elements found in the XML." };
      const raw = evs.slice(0, MAX_EVENTS).map((n): RawWinEvent => {
        const sys = kid(n, "System"), data: Record<string, string> = {};
        const ed = kid(n, "EventData") ?? kid(n, "UserData");
        kids(ed, "Data").forEach((d, i) => { data[d.attrs.Name || `Data${i + 1}`] = txt(d); });
        if (ed && !kids(ed, "Data").length) ed.children.forEach((c) => { data[c.name] = txt(c); });
        return { Id: txt(kid(sys, "EventID")), RecordId: txt(kid(sys, "EventRecordID")), TimeCreated: kid(sys, "TimeCreated")?.attrs.SystemTime ?? "", ProviderName: kid(sys, "Provider")?.attrs.Name ?? "", LogName: txt(kid(sys, "Channel")), MachineName: txt(kid(sys, "Computer")), Data: data };
      });
      return { raw, format: "xml" };
    } catch (e) { return { raw: [], format: "xml", error: (e as Error).message }; }
  }
  try { const j = JSON.parse(s); const arr = Array.isArray(j) ? j : Array.isArray(j?.events) ? j.events : j && typeof j === "object" ? [j] : null; if (!arr) return { raw: [], format: "json", error: "JSON must be an array of events or { events: [...] }." }; return { raw: arr.slice(0, MAX_EVENTS), format: "json" }; } catch { /* maybe NDJSON */ }
  const lines = s.split(/\r?\n/).filter((l) => l.trim()); const out: RawWinEvent[] = [];
  for (const l of lines.slice(0, MAX_EVENTS)) { try { out.push(JSON.parse(l)); } catch { return { raw: [], format: "none", error: "Could not read this as JSON, NDJSON or Windows event XML." }; } }
  return { raw: out, format: "ndjson" };
}

export interface LogAnalysis { format: ParsedInput["format"]; received: number; accepted: SocEvent[]; rejected: { index: number; error: string }[]; alerts: (AlertDraft & { preview: true })[]; error?: string }
/** The real normalizer + the real detection rules, applied to text the user supplied. Nothing is stored or sent anywhere. */
export function analyzeLogs(text: string, opts: { host?: string } = {}): LogAnalysis {
  const p = parseEventInput(text);
  if (p.error) return { format: p.format, received: 0, accepted: [], rejected: [], alerts: [], error: p.error };
  const accepted: SocEvent[] = [], rejected: { index: number; error: string }[] = [], seen = new Set<string>();
  p.raw.forEach((r, index) => { if (!r || typeof r !== "object") { rejected.push({ index, error: "not an object" }); return; }
    const e = normalizeWindows(r as RawWinEvent, { host: opts.host, source: "imported", collector: "pasted-input" });
    if ("error" in e) rejected.push({ index, error: e.error }); else if (!seen.has(e.id)) { seen.add(e.id); accepted.push(e); } });
  const alerts = runRules(accepted).map((a) => ({ ...a, preview: true as const })).sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return { format: p.format, received: p.raw.length, accepted, rejected, alerts };
}
export const ruleCatalog = () => RULES_META.map((r) => ({ id: r.id, name: r.name, severity: r.severity, mitre: r.mitre.map((m) => `${m.id} ${m.name}`), tactics: uniq(r.mitre.map((m) => m.tactic)), description: r.description }));

// ---------------------------------------------------------------- Security Engineer
export interface PlanItem { host: string; criticality: number; topPriority: number; vulns: Vuln[]; steps: { solution: string; fixes: string[]; maxPriority: number }[] }
export function remediationPlan(vulns: Vuln[], assets: { id: string; criticality: number }[] = []): { items: PlanItem[]; totals: { findings: number; hosts: number; kev: number; critical: number; high: number } } {
  const open = vulns.filter((v) => v.status !== "fixed_verified" && v.status !== "accepted_risk");
  const by = new Map<string, Vuln[]>(); open.forEach((v) => by.set(v.host, [...(by.get(v.host) ?? []), v]));
  const items = [...by.entries()].map(([host, vs]): PlanItem => {
    vs.sort((a, b) => b.priority - a.priority);
    const sol = new Map<string, { fixes: string[]; maxPriority: number }>();
    vs.forEach((v) => { const k = (v.solution || "No vendor solution given in the scan report.").trim(); const cur = sol.get(k) ?? { fixes: [], maxPriority: 0 }; cur.fixes.push(v.name); cur.maxPriority = Math.max(cur.maxPriority, v.priority); sol.set(k, cur); });
    return { host, criticality: assets.find((a) => a.id === vs[0].assetId)?.criticality ?? 3, topPriority: vs[0].priority, vulns: vs, steps: [...sol.entries()].map(([solution, x]) => ({ solution, ...x })).sort((a, b) => b.maxPriority - a.maxPriority) };
  }).sort((a, b) => b.topPriority - a.topPriority);
  return { items, totals: { findings: open.length, hosts: items.length, kev: open.filter((v) => v.kev).length, critical: open.filter((v) => v.severity === "critical").length, high: open.filter((v) => v.severity === "high").length } };
}
/** CSV-safe: quotes every cell and neutralizes spreadsheet formulas (=, +, -, @). */
export const csvCell = (v: unknown) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
export function planToCsv(plan: ReturnType<typeof remediationPlan>): string {
  const head = ["Order", "Host", "Priority", "Severity", "CVSS", "Finding", "Port", "CVEs", "Known exploited", "Status", "Fix", "Data source"];
  let n = 0; const rows = plan.items.flatMap((i) => i.vulns.map((v) => [++n, v.host, v.priority, v.severity, v.cvss, v.name, v.port, v.cves.join(" "), v.kev ? "yes" : "no", v.status, v.solution, v.source]));
  return [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
}
const HARDEN: Record<string, string[]> = {
  "WIN-AUTH-001": ["Enforce account lockout (for example 10 attempts / 15 min) and 14+ character passwords or passphrases.", "Require MFA on every remote-access path.", "Limit which source addresses may reach logon services."],
  "WIN-AUTH-002": ["Treat the account as possibly compromised: review its activity, then reset its credentials after approval.", "Enable MFA and restrict the account to the hosts it needs."],
  "WIN-AUTH-003": ["Do not expose RDP (3389) to the internet. Put it behind a VPN or RD Gateway with MFA.", "Enable Network Level Authentication."],
  "WIN-AUTH-004": ["Review lockout thresholds and find the process or device repeatedly using an old password."],
  "WIN-PRIV-001": ["Remove standing admin membership; use just-in-time elevation.", "Alert on every change to privileged groups and review who made it."],
  "WIN-ACCT-001": ["Restrict who can create accounts and require a ticket reference for new accounts."],
  "WIN-PERSIST-001": ["Audit scheduled tasks regularly; baseline the legitimate ones and alert on new tasks that launch scripting hosts."],
  "WIN-PERSIST-002": ["Restrict service installation rights; enable application allow-listing (WDAC/AppLocker) so services from user-writable paths cannot start."],
  "WIN-EVASION-001": ["Forward logs to a central store so local clearing cannot erase evidence.", "Limit the right to clear logs and alert on 1102/104."],
  "WIN-EVASION-002": ["Lock audit policy by Group Policy and monitor 4719.", "Enable tamper protection for Defender."],
  "WIN-EXEC-001": ["Enable PowerShell script-block and module logging; consider Constrained Language Mode.", "Enable process command-line auditing (4688) and Sysmon where possible."],
  "WIN-IMPACT-001": ["Keep offline/immutable backups and test restores.", "Restrict who can run vssadmin/wbadmin/bcdedit; alert on shadow-copy deletion."],
  "WIN-MAL-001": ["Make sure the detection was remediated and the host was fully scanned; check how the file arrived.", "Turn on attack-surface-reduction rules."],
  "SYS-NET-001": ["Block outbound internet access for script hosts with an egress firewall / proxy policy.", "Review the process command line and parent for the connection, then the destination reputation."],
  "SYS-CRED-001": ["Enable LSA protection (RunAsPPL) and Credential Guard.", "Treat credentials on that host as exposed until proven otherwise; plan resets after approval."],
  "SYS-RANSOM-001": ["Isolate the host only after human confirmation; preserve memory and logs first.", "Verify offline backups before any restore; check other hosts for the same process."],
  "WIN-BEHAV-001": ["Confirm with the account owner whether the sources are a VPN, jump host or shared use.", "Restrict the account to the hosts it needs and require MFA."],
  "WIN-LATERAL-001": ["Use unique local admin passwords (LAPS), restrict lateral logons with firewall rules, tier administrative accounts."],
};
export function hardeningFor(alerts: Pick<Alert, "ruleId" | "title" | "host">[]): { ruleId: string; title: string; hosts: string[]; advice: string[] }[] {
  const by = new Map<string, { ruleId: string; title: string; hosts: string[]; advice: string[] }>();
  alerts.forEach((a) => { const cur = by.get(a.ruleId) ?? { ruleId: a.ruleId, title: a.title, hosts: [], advice: HARDEN[a.ruleId] ?? ["No hardening guidance is written for this rule yet."] }; if (!cur.hosts.includes(a.host)) cur.hosts.push(a.host); by.set(a.ruleId, cur); });
  return [...by.values()];
}

// ---------------------------------------------------------------- Incident Responder
export interface PlaybookStep { id: string; text: string; needsApproval?: boolean }
export interface PlaybookPhase { phase: string; steps: PlaybookStep[] }
/** A response checklist built from the incident's own alert rules. Steps are suggestions; none is executed by Spark. */
export function playbookFor(inc: Pick<Incident, "id" | "host" | "title">, ruleIds: string[]): PlaybookPhase[] {
  const has = (p: string) => ruleIds.some((r) => r.startsWith(p));
  const identify: PlaybookStep[] = [{ id: "i1", text: `Confirm the evidence on ${inc.host}: open each cited event and check it is real and in scope.` }, { id: "i2", text: "Decide who owns the host and the accounts involved; tell them." }, { id: "i3", text: "Record the time you started and preserve the events (export them) before changing anything." }];
  const contain: PlaybookStep[] = [{ id: "c1", text: `Decide whether to isolate ${inc.host} from the network.`, needsApproval: true }];
  if (has("WIN-AUTH")) contain.push({ id: "c2", text: "Block the offending source address at the firewall.", needsApproval: true }, { id: "c3", text: "Reset the password of any account that logged on successfully from that address.", needsApproval: true });
  if (has("WIN-PRIV") || has("WIN-ACCT")) contain.push({ id: "c4", text: "Disable or remove the newly created account / new group member until verified.", needsApproval: true });
  if (has("WIN-PERSIST")) contain.push({ id: "c5", text: "Disable the suspicious scheduled task or service (do not delete yet: keep it as evidence).", needsApproval: true });
  const eradicate: PlaybookStep[] = [{ id: "e1", text: "Remove the persistence found (tasks, services, accounts, run keys) and any malware file after capturing a copy." }];
  if (has("WIN-MAL")) eradicate.push({ id: "e2", text: "Run a full endpoint-protection scan and confirm the detection was cleaned." });
  if (has("WIN-IMPACT") || has("SYS-RANSOM")) eradicate.push({ id: "e3", text: "Check backups are intact and offline before restoring anything." });
  eradicate.push({ id: "e4", text: "Patch or reconfigure the weakness that allowed access (see the Security Engineer panel)." });
  const recover: PlaybookStep[] = [{ id: "r1", text: "Return the host to service only after the verification check passes." }, { id: "r2", text: "Watch the host and accounts closely for a week for repeat activity." }];
  const lessons: PlaybookStep[] = [{ id: "l1", text: "Write the timeline and what worked / failed." }, { id: "l2", text: "Add a detection or control so this is caught earlier next time." }];
  return [{ phase: "1 · Identify and scope", steps: identify }, { phase: "2 · Contain (approval needed)", steps: contain }, { phase: "3 · Eradicate", steps: eradicate }, { phase: "4 · Recover", steps: recover }, { phase: "5 · Lessons learned", steps: lessons }];
}

export interface IncidentReportInput { incident: Incident; timeline?: { time: string; title: string; detail?: string; source?: string }[]; actions?: Pick<SocAction, "type" | "target" | "description" | "status" | "decidedBy">[]; notes?: string[] }
export function incidentReportMd(x: IncidentReportInput, now = new Date().toISOString()): string {
  const i = x.incident;
  const L = [`# Incident report: ${i.title}`, "", `- **Incident id:** ${i.id}`, `- **Host:** ${i.host}`, `- **Severity:** ${i.severity} · **Confidence (rule-based):** ${Math.round(i.confidence * 100)}%`, `- **Status:** ${i.status}`, `- **First / last seen:** ${i.firstSeen} / ${i.lastSeen}`, `- **ATT&CK tactics:** ${(i.tactics ?? []).join(" → ") || "n/a"}`, `- **Data source:** ${i.source === "demo" ? "SAMPLE (simulated) data, not a real incident" : i.source}`, `- **Report generated:** ${now}`, "", "## Why this was raised", "", i.reasoning || "n/a", ""];
  if (i.verification) L.push("## Remediation verification", "", `Result: **${i.verification.status}**`, ...i.verification.details.map((d) => `- ${d}`), "");
  L.push("## Timeline", "", ...((x.timeline ?? []).length ? x.timeline!.map((t) => `- ${t.time} · ${t.title}${t.detail ? ` (${t.detail.slice(0, 200)})` : ""}`) : ["No timeline entries."]), "");
  L.push("## Response actions", "", ...((x.actions ?? []).length ? x.actions!.map((a) => `- ${a.type} → ${a.target}: ${a.description} [${a.status}${a.decidedBy ? ` by ${a.decidedBy}` : ""}]`) : ["None recorded."]), "");
  if (x.notes && x.notes.length) L.push("## Responder notes", "", ...x.notes.map((n) => `- ${n}`), "");
  L.push("---", "Generated by Spark from stored data. Findings are rule-based hypotheses for a human to verify; this report does not prove compromise.");
  return L.join("\n");
}

// ---------------------------------------------------------------- CISO
export interface ExecInput { posture: number | null; vulnCounts: Record<string, number>; activeIncidents: Pick<Incident, "title" | "severity" | "status" | "host" | "source">[]; kevVulns?: number; assets: { hostname: string; score: number }[]; topVulns: Pick<Vuln, "name" | "host" | "severity" | "kev" | "priority">[]; pendingActions?: number; mode: "sample" | "connected" }
export function topRisks(x: ExecInput, n = 5): { rank: number; risk: string; why: string }[] {
  const r: { w: number; risk: string; why: string }[] = [];
  x.activeIncidents.forEach((i) => r.push({ w: 100 + sevRank(i.severity) * 10 + (i.status === "open" ? 5 : 0), risk: `${i.severity.toUpperCase()} incident on ${i.host}: ${i.title}`, why: `Status "${i.status}". Needs an owner and a containment decision.` }));
  x.topVulns.forEach((v) => r.push({ w: (v.kev ? 90 : 40) + v.priority / 2, risk: `${v.name} on ${v.host}`, why: `${v.severity} severity, priority ${v.priority}/100${v.kev ? ", listed as known-exploited" : ""}.` }));
  return r.sort((a, b) => b.w - a.w).slice(0, n).map((y, i) => ({ rank: i + 1, risk: y.risk, why: y.why }));
}
export function execSummaryMd(x: ExecInput, now = new Date().toISOString()): string {
  const v = x.vulnCounts, act = x.activeIncidents, crit = act.filter((i) => i.severity === "critical").length;
  const L = ["# Security status summary", "", x.mode === "sample" ? "> **SAMPLE DATA.** This summary was produced from simulated data and does not describe a real environment." : "> Built from the data currently stored in your SOC backend.", "", `Generated ${now}`, "", "## Headline numbers", "",
    `- Security posture score: **${x.posture == null ? "not available (no assets yet)" : x.posture + "/100"}** (100 minus the average asset risk; a simple score, not an audit)`, `- Active incidents: **${act.length}** (${crit} critical)`, `- Open vulnerabilities: **${v.critical ?? 0} critical, ${v.high ?? 0} high, ${v.medium ?? 0} medium, ${v.low ?? 0} low**`, `- Known-exploited vulnerabilities open: **${x.kevVulns ?? 0}**`, x.pendingActions != null ? `- Response actions waiting for a human decision: **${x.pendingActions}**` : "", "", "## Top risks", ""].filter((l, i, a) => !(l === "" && a[i - 1] === ""));
  const t = topRisks(x); L.push(...(t.length ? t.map((r) => `${r.rank}. ${r.risk}: ${r.why}`) : ["No open risks in the data."]), "", "## Decisions needed", "");
  const d: string[] = []; if (crit) d.push(`Assign an owner to the ${crit} critical incident(s).`); if (x.kevVulns) d.push(`Approve emergency patching for ${x.kevVulns} known-exploited vulnerability(ies).`); if (x.pendingActions) d.push(`Approve or reject ${x.pendingActions} proposed response action(s).`);
  L.push(...(d.length ? d.map((s) => `- ${s}`) : ["- None right now."]), "", "## Limits of this summary", "", "- Counts come only from systems connected to Spark; unmonitored systems are invisible here.", "- No history is stored yet, so there is no trend line.");
  return L.join("\n");
}

/** Validates a manually proposed response action (analyst role). It is only ever recorded as "proposed"; Spark never executes it. */
export const MANUAL_ACTION_TYPES = ["isolate_host", "disable_account", "block_ip", "request_scan", "reset_password", "patch", "investigate", "other"] as const;
export function validateManualAction(b: any): { ok: true; type: (typeof MANUAL_ACTION_TYPES)[number]; target: string; description: string; rationale: string } | { ok: false; error: string } {
  const type = String(b?.type ?? ""), target = String(b?.target ?? "").trim(), description = String(b?.description ?? "").trim(), rationale = String(b?.rationale ?? "").trim();
  if (!(MANUAL_ACTION_TYPES as readonly string[]).includes(type)) return { ok: false, error: "Unknown action type." };
  if (!target || target.length > 200) return { ok: false, error: "A target (host, account or IP, up to 200 characters) is required." };
  if (!description || description.length > 500) return { ok: false, error: "A description (up to 500 characters) is required." };
  if (rationale.length > 1000) return { ok: false, error: "Rationale is limited to 1000 characters." };
  return { ok: true, type: type as (typeof MANUAL_ACTION_TYPES)[number], target, description, rationale };
}
