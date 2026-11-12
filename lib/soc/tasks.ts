// Server-side agent task runs with MEASURED progress.
// A run is a list of real steps. The client asks the server to execute one step at a time (POST /tasks/:id/next);
// each call really runs that step against the stored data and records its start, end and duration.
// Progress is stepsDone / stepsTotal from those records. Nothing here is timed or animated.
// Agents are READ-ONLY. Their disruptive recommendations become "proposed" actions that a human must approve; no code path executes them.
import { T, type Store } from "./store";
import type { ActionType, Alert, Asset, DataSource, Incident, Severity, SocAction, SocEvent, Vuln } from "./types";
import { sevRank } from "./types";
import { HUNTS, execSummaryMd, hardeningFor, huntEvents, playbookFor, remediationPlan, topRisks, type ExecInput } from "./roles";
import { RULES_META } from "./rules";
import { audit, HttpError, type Actor } from "./pipeline";
import { hid, isPrivateIp, nowIso, rid, uniq } from "./util";

export type RoleKey = "analyst" | "engineer" | "hunter" | "responder" | "siem" | "ciso";
export const ROLE_KEYS: RoleKey[] = ["analyst", "engineer", "hunter", "responder", "siem", "ciso"];
export interface TaskStep { id: string; name: string; status: "waiting" | "running" | "done" | "failed"; startedAt?: string; endedAt?: string; durationMs?: number; detail?: string; error?: string }
export interface TaskRec { p: "P1" | "P2" | "P3"; t: string; type?: ActionType; target?: string; dis: boolean; incidentId?: string }
export interface TaskResult {
  head: string; severity: Severity; findings: { sev: Severity; t: string; ev: string[] }[];
  table?: { title: string; cols: string[]; rows: (string | number)[][] }; extra?: { title: string; code: string }[];
  recs: TaskRec[]; limits: string[]; pivots: { ips: string[]; hosts: string[]; users: string[] }; handoff: string; actionIds: string[]; incidentId?: string;
  stages?: { n: string; s: "done" | "active" | "todo" }[];
}
export interface TaskRun {
  id: string; role: RoleKey; task: string; actor: string; status: "running" | "completed" | "failed" | "cancelled";
  steps: TaskStep[]; stepsDone: number; stepsTotal: number; progress: number; state: Record<string, any>; result: TaskResult | null; error?: string;
  context?: { ips?: string[]; hosts?: string[]; users?: string[]; from?: string; message?: string }; retryOf?: string; investigationId?: string;
  source: DataSource; createdAt: string; startedAt?: string; endedAt?: string;
}

interface Ctx { store: Store; run: TaskRun; st: Record<string, any>; overview?: () => Promise<any>; incident?: (id: string) => Promise<any>; collectors?: () => Promise<any[]> }
type Handler = (c: Ctx) => Promise<string>;
interface StepDef { id: string; name: string; run: Handler }

const sevMax = (xs: { sev: Severity }[]): Severity => xs.reduce<Severity>((m, x) => (sevRank(x.sev) > sevRank(m) ? x.sev : m), "low");
const events = (s: Store, n = 2000) => s.select<SocEvent>(T.events, { order: ["time", "desc"], limit: n });
const secOnly = (e: SocEvent) => e.channel.toLowerCase() === "security";
const srcOf = (xs: { source: DataSource }[]): DataSource => (xs.some((x) => x.source === "live") ? "live" : xs.some((x) => x.source === "imported") ? "imported" : "demo");
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + "…" : s);

// ------------------------------------------------------------------ analyst
const ANALYST: StepDef[] = [
  { id: "load", name: "Load recent events from the database", run: async ({ store, st }) => { const ev = await events(store); st.ev = ev.length; st.secN = ev.filter(secOnly).length; st.src = srcOf(ev); return `${ev.length} events (${st.secN} from the Security log)`; } },
  { id: "group", name: "Group failed logons by source address", run: async ({ store, st, run }) => {
    const ev = (await events(store)).filter((e) => (secOnly(e) && e.eventId === 4625) || e.data.category === "failed_logon"), by = new Map<string, SocEvent[]>();
    ev.forEach((e) => by.set(e.srcIp || "(no address)", [...(by.get(e.srcIp || "(no address)") ?? []), e]));
    const pri = run.context?.ips ?? [];
    st.groups = [...by.entries()].map(([ip, l]) => ({ ip, n: l.length, users: uniq(l.map((e) => e.targetUser || e.user || "?")).slice(0, 8), first: l.reduce((m, e) => (e.time < m ? e.time : m), l[0].time), last: l.reduce((m, e) => (e.time > m ? e.time : m), l[0].time), ids: l.slice(0, 3).map((e) => e.id), host: l[0].host }))
      .sort((a, b) => Number(pri.includes(b.ip)) - Number(pri.includes(a.ip)) || b.n - a.n);
    return `${ev.length} failed logons from ${by.size} source(s)${pri.length ? `; ${pri.join(", ")} checked first (handoff from ${run.context?.from ?? "an earlier agent"})` : ""}`; } },
  { id: "success", name: "Check for a successful logon after the failures", run: async ({ store, st }) => {
    const ok = (await events(store)).filter((e) => secOnly(e) && e.eventId === 4624);
    st.groups.forEach((g: any) => { g.after = ok.filter((o) => o.srcIp === g.ip && o.time >= g.first).length; g.afterUser = ok.find((o) => o.srcIp === g.ip && o.time >= g.first)?.user; });
    const n = st.groups.filter((g: any) => g.after && g.n >= 3).length; return `${n} source(s) were followed by a successful logon`; } },
  { id: "alerts", name: "Correlate with stored detection alerts", run: async ({ store, st }) => {
    const al = (await store.select<Alert>(T.alerts, { order: ["lastSeen", "desc"], limit: 200 })).filter((a) => sevRank(a.severity) >= sevRank("medium"));
    st.alerts = al.slice(0, 8).map((a) => ({ sev: a.severity, t: `Rule ${a.ruleId}: ${a.title} on ${a.host} (${Math.round(a.confidence * 100)}% rule confidence)`, ev: a.eventIds.slice(0, 3), host: a.host, ips: a.entities?.ips ?? [] })); return `${al.length} medium-or-higher alert(s)`; } },
  { id: "write", name: "Rate severity and write findings", run: async ({ st, run }) => {
    const F: TaskResult["findings"] = [], recs: TaskRec[] = [];
    for (const g of st.groups.filter((g: any) => g.n >= 3)) {
      const sv: Severity = g.after ? "critical" : g.n >= 5 ? "high" : "medium";
      F.push({ sev: sv, t: `${g.n} failed logons from ${g.ip} against ${g.users.length} account(s) (${g.users.slice(0, 4).join(", ")})${g.after ? `. A SUCCESSFUL logon (${g.afterUser ?? "?"}) followed from the same address, so that account may be compromised.` : "."}`, ev: g.ids });
      if (sv !== "medium" && g.ip !== "(no address)" && !isPrivateIp(g.ip)) recs.push({ p: "P1", t: `Block ${g.ip} at the firewall after confirming it is not a legitimate source.`, type: "block_ip", target: g.ip, dis: true });
      if (g.after && g.afterUser) recs.push({ p: "P1", t: `Reset the password of ${g.afterUser} and review the logon that followed the failures.`, type: "reset_password", target: g.afterUser, dis: true });
    }
    st.alerts.forEach((a: any) => F.push({ sev: a.sev, t: a.t, ev: a.ev }));
    F.sort((a, b) => sevRank(b.sev) - sevRank(a.sev)); const sv = F.length ? sevMax(F) : "low";
    if (!recs.length) recs.push({ p: "P3", t: F.length ? "Review the cited events and decide whether a response is needed." : "Keep monitoring; add log sources if you expect activity.", dis: false });
    st.out = { head: F.length ? `${F.length} finding(s), overall severity ${sv.toUpperCase()}.` : `No suspicious activity above low severity in ${st.ev} events.`, severity: sv, findings: F.slice(0, 12), recs, table: { title: "Suspicious sources (failed logons)", cols: ["Source IP", "Failed", "Accounts", "First seen", "Last seen", "Logon after failures"], rows: st.groups.slice(0, 12).map((g: any) => [g.ip, g.n, g.users.join(", "), g.first, g.last, g.after ? `YES (${g.after})` : "no"]) },
      limits: [`Evidence is limited to ${st.ev} stored events; absence of findings is not proof of safety.`], pivots: { ips: st.groups.filter((g: any) => g.n >= 3 && g.ip !== "(no address)").map((g: any) => g.ip).slice(0, 6), hosts: uniq(st.groups.filter((g: any) => g.n >= 3).map((g: any) => g.host)), users: uniq(st.groups.flatMap((g: any) => g.users)).slice(0, 10) } };
    return `${F.length} finding(s), severity ${sv}`; } },
];

// ------------------------------------------------------------------ hunter
const HUNT_STEPS: StepDef[] = HUNTS.map((h) => ({ id: "h:" + h.id, name: `Hunt: ${h.name}`, run: async ({ store, st }) => { const r = h.run(await events(store, 3000)); (st.hunts ??= {})[h.id] = { n: r.matches.length, note: r.note, ids: r.matches.slice(0, 3).map((e) => e.id), hosts: uniq(r.matches.map((e) => e.host)) }; return r.note; } }));
const HSEV: Record<string, Severity> = { "failed-sources": "medium", "encoded-cmd": "high", persistence: "medium", "log-tamper": "high", "public-rdp": "high", "av-detect": "medium", "recovery-inhibit": "critical" };
const HUNTER = (pivotIps: string[]): StepDef[] => [
  { id: "load", name: "Load events to search", run: async ({ store, st }) => { const ev = await events(store, 3000); st.ev = ev.length; st.hosts = uniq(ev.map((e) => e.host)).length; return `${ev.length} events on ${st.hosts} host(s)`; } },
  ...HUNT_STEPS,
  ...(pivotIps.length ? [{ id: "pivot", name: "Pivot on addresses from earlier agents", run: async ({ store, st }: Ctx) => { const ev = await events(store, 3000); st.pivot = pivotIps.slice(0, 3).map((ip) => { const r = huntEvents(ev, { ip }, 300); return { ip, n: r.total, hosts: uniq(r.rows.map((e) => e.host)), ids: uniq(r.rows.map((e) => e.eventId)), ev: r.rows.slice(0, 3).map((e) => e.id) }; }); return st.pivot.map((p: any) => `${p.ip}: ${p.n} event(s) on ${p.hosts.length} host(s)`).join("; "); } }] : []),
  { id: "ioc", name: "Extract indicators of compromise", run: async ({ store, st }) => {
    const ev = await events(store, 3000), io = new Map<string, { type: string; v: string; n: number; t: string }>(), add = (type: string, v: string | undefined, t: string) => { if (!v) return; const k = type + "|" + v; const c = io.get(k); if (c) c.n++; else io.set(k, { type, v, n: 1, t }); };
    ev.forEach((e) => { if (e.srcIp && !isPrivateIp(e.srcIp)) add("Public IP", e.srcIp, e.time); add("Malware name", e.data["Threat Name"], e.time); if (e.data.Path && /\.(exe|dll|ps1|bat|vbs|js)$/i.test(e.data.Path)) add("File path", e.data.Path, e.time); (e.commandLine?.match(/https?:\/\/[^\s"']+/g) ?? []).forEach((u) => add("URL", u.slice(0, 100), e.time)); });
    st.iocs = [...io.values()].sort((a, b) => b.n - a.n).slice(0, 20); return `${io.size} indicator(s)`; } },
  { id: "lateral", name: "Check lateral movement and suspicious authentication", run: async ({ store, st }) => {
    const ev = (await events(store, 3000)).filter((e) => (e.eventId === 4624 && (e.logonType === 3 || e.logonType === 10)) || e.eventId === 4648), byU = new Map<string, Set<string>>();
    ev.forEach((e) => { const u = e.targetUser || e.user; if (u) (byU.get(u) ?? byU.set(u, new Set()).get(u)!).add(e.host); });
    st.lateral = [...byU.entries()].filter(([, h]) => h.size >= 2).map(([u, h]) => ({ u, hosts: [...h] })); return `${st.lateral.length} account(s) used on 2 or more hosts`; } },
  { id: "write", name: "Score the intrusion chain and write findings", run: async ({ st }) => {
    const F: TaskResult["findings"] = [], h = st.hunts ?? {}, hit = HUNTS.filter((x) => h[x.id]?.n);
    hit.forEach((x) => F.push({ sev: HSEV[x.id] ?? "medium", t: `${x.name} — ${h[x.id].note} Hypothesis: ${x.hypothesis} (${x.mitre})`, ev: h[x.id].ids }));
    (st.pivot ?? []).forEach((p: any) => { if (p.n) F.unshift({ sev: p.hosts.length > 1 ? "high" : "medium", t: `Related activity for ${p.ip}: ${p.n} event(s) (ids ${p.ids.join(", ")}) across ${p.hosts.join(", ")}.`, ev: p.ev }); });
    (st.lateral ?? []).forEach((l: any) => F.push({ sev: "high", t: `Account ${l.u} logged on over the network to ${l.hosts.length} hosts (${l.hosts.join(", ")}). Verify this is expected administration.`, ev: [] }));
    const stages = { access: !!h["failed-sources"]?.n, exec: !!(h["encoded-cmd"]?.n || h["av-detect"]?.n), persist: !!h.persistence?.n, evade: !!h["log-tamper"]?.n, lateral: (st.lateral ?? []).length > 0, impact: !!h["recovery-inhibit"]?.n }, k = Object.values(stages).filter(Boolean).length;
    if (k >= 3) F.unshift({ sev: "high", t: `${k} of 6 intrusion-chain stages show activity in this data. That is consistent with a multi-step intrusion. It is a hypothesis and is NOT attribution to any named APT group.`, ev: [] });
    F.sort((a, b) => sevRank(b.sev) - sevRank(a.sev)); const sv = F.length ? sevMax(F) : "low", recs: TaskRec[] = [];
    if (hit[0]) recs.push({ p: "P2", t: `Pivot on “${hit[0].name}” in the Threat Hunter tab and read the matching raw events.`, dis: false });
    recs.push({ p: "P3", t: "Enable process command-line auditing (4688) / Sysmon so future hunts see more.", dis: false });
    st.out = { head: F.length ? `${F.length} lead(s); ${k} of 6 chain stages active; top severity ${sv.toUpperCase()}.` : `No hunting leads in ${st.ev} events.`, severity: sv, findings: F.slice(0, 12), recs,
      table: { title: "Indicators of compromise (extracted)", cols: ["Type", "Indicator", "Seen", "First seen"], rows: (st.iocs ?? []).map((i: any) => [i.type, i.v, i.n, i.t]) },
      limits: ["Hunts only see stored events; a hunt is a hypothesis test, not a clearance.", "No threat-intelligence feed is connected, so indicators are not checked for reputation."], pivots: { ips: uniq([...(st.pivot ?? []).map((p: any) => p.ip), ...(st.iocs ?? []).filter((i: any) => i.type === "Public IP").map((i: any) => i.v)]).slice(0, 6), hosts: uniq([...Object.values(h).flatMap((x: any) => x.hosts), ...(st.lateral ?? []).flatMap((l: any) => l.hosts)]).slice(0, 8), users: (st.lateral ?? []).map((l: any) => l.u) } };
    return `${F.length} lead(s), chain ${k}/6`; } },
];

// ------------------------------------------------------------------ engineer
const ENGINEER: StepDef[] = [
  { id: "load", name: "Load scan findings and assets", run: async ({ store, st }) => { const [v, a] = await Promise.all([store.select<Vuln>(T.vulns, { limit: 20000 }), store.select<Asset>(T.assets, { limit: 500 })]); st.vulns = v.filter((x) => x.status !== "fixed_verified" && x.status !== "accepted_risk").sort((x, y) => y.priority - x.priority).slice(0, 200); st.assets = a.map((x) => ({ id: x.id, criticality: x.criticality })); st.src = srcOf(v); return `${v.length} finding(s), ${st.vulns.length} open, on ${a.length} asset(s)`; } },
  { id: "plan", name: "Build the remediation plan", run: async ({ st, run }) => { const hl = (run.context?.hosts ?? []).map((h) => h.toLowerCase()); if (hl.length) st.vulns.sort((a: Vuln, b: Vuln) => Number(hl.includes(b.host.toLowerCase())) - Number(hl.includes(a.host.toLowerCase())) || b.priority - a.priority); st.plan = remediationPlan(st.vulns, st.assets); return `${st.plan.items.length} host group(s), ${st.plan.totals.critical} critical, ${st.plan.totals.kev} known-exploited${hl.length ? `; ${run.context!.hosts!.join(", ")} prioritized (handoff)` : ""}`; } },
  { id: "classify", name: "Classify misconfigurations", run: async ({ st }) => {
    const cat: Record<string, RegExp> = { "Legacy / insecure protocol": /smbv1|telnet|ftp\b|sslv|tls ?1\.0|ntlmv1|rc4|cleartext/i, "Weak or default credentials": /default|weak|password|anonymous|blank/i, "Missing signing / encryption": /signing|unencrypted|cipher|certificate|ssl|tls/i, "Exposed remote access": /rdp|remote desktop|vnc|ssh|winrm/i };
    st.cats = Object.entries(cat).map(([k, re]) => { const m = st.vulns.filter((v: Vuln) => re.test(`${v.name} ${v.summary}`)); return { k, n: m.length, hosts: uniq(m.map((v: Vuln) => v.host)) }; }).filter((c) => c.n); return `${st.cats.length} misconfiguration class(es)`; } },
  { id: "ports", name: "Review exposed high-risk services seen by the scan", run: async ({ st }) => { const risky: Record<number, string> = { 21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 5985: "WinRM" }, seen = new Map<string, any>();
    st.vulns.forEach((v: Vuln) => { const p = parseInt(v.port, 10); if (risky[p]) { const k = v.host + p; (seen.get(k) ?? seen.set(k, { h: v.host, p, n: risky[p], c: 0 }).get(k)).c++; } }); st.exp = [...seen.values()]; return `${st.exp.length} service(s); no firewall configuration was read`; } },
  { id: "harden", name: "Derive hardening steps from detection alerts", run: async ({ store, st }) => { const al = await store.select<Alert>(T.alerts, { order: ["lastSeen", "desc"], limit: 200 }); st.hard = hardeningFor(al); return `${st.hard.length} hardening checklist(s)`; } },
  { id: "write", name: "Write findings and remediation plan", run: async ({ st }) => {
    const F: TaskResult["findings"] = [], recs: TaskRec[] = [];
    st.vulns.slice(0, 6).forEach((v: Vuln) => F.push({ sev: v.severity, t: `${v.name} on ${v.host} (${v.port}), CVSS ${v.cvss}, priority ${v.priority}/100${v.kev ? ", known exploited" : ""}. Fix: ${clip(v.solution || "none given in the scan", 110)}`, ev: [] }));
    st.exp.filter((x: any) => [445, 3389, 23, 21].includes(x.p)).forEach((x: any) => { F.push({ sev: "high", t: `${x.n} (${x.p}/tcp) is reachable on ${x.h} according to the scan. Restrict it by firewall rule or disable it if unused.`, ev: [] }); if (x.p === 445 || x.p === 3389) recs.push({ p: "P2", t: `Change the firewall rule that exposes ${x.n} on ${x.h} (restrict to management addresses).`, type: "other", target: x.h, dis: true }); });
    st.plan.items.slice(0, 3).forEach((i: any) => recs.push({ p: i.topPriority >= 80 ? "P1" : "P2", t: `Patch / fix ${i.host}: ${clip(i.steps[0].solution, 120)}`, type: "patch", target: i.host, dis: true }));
    F.sort((a, b) => sevRank(b.sev) - sevRank(a.sev)); const sv = F.length ? sevMax(F) : "low";
    st.out = { head: `${st.plan.totals.findings} open finding(s) on ${st.plan.totals.hosts} host(s); top severity ${sv.toUpperCase()}.`, severity: sv, findings: F.slice(0, 12), recs, table: { title: "Remediation order", cols: ["#", "Host", "Priority", "Fix (grouped)"], rows: st.plan.items.slice(0, 8).map((i: any, n: number) => [n + 1, i.host, i.topPriority, i.steps.slice(0, 2).map((s: any) => clip(s.solution, 90)).join(" | ")]) },
      extra: st.hard.slice(0, 4).map((h: any) => ({ title: `Hardening for ${h.title}`, code: h.advice.map((a: string) => "- " + a).join("\n") })), limits: ["No firewall or device configuration was read. The service list comes only from scan findings.", "Configuration changes are proposals; Spark does not apply them."], pivots: { ips: [], hosts: st.plan.items.map((i: any) => i.host).slice(0, 6), users: [] } };
    return `${F.length} finding(s)`; } },
];

// ------------------------------------------------------------------ responder
const RESPONDER: StepDef[] = [
  { id: "select", name: "Select the incident to respond to", run: async ({ store, st, run }) => {
    const incs = (await store.select<Incident>(T.incidents, { limit: 500 })).filter((i) => i.status !== "closed").sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (a.lastSeen < b.lastSeen ? 1 : -1));
    const t = run.task.toLowerCase(), hl = (run.context?.hosts ?? []).map((h) => h.toLowerCase());
    const pick = incs.find((i) => t.includes(i.id.toLowerCase()) || t.includes(i.host.toLowerCase())) ?? incs.find((i) => hl.includes(i.host.toLowerCase())) ?? incs[0];
    if (!pick) { st.none = true; return "no active incident"; } st.inc = pick.id; return `${pick.id} (${pick.severity}) on ${pick.host}`; } },
  { id: "detail", name: "Load incident evidence and timeline", run: async ({ st, incident }) => { if (st.none) return "skipped: no incident"; st.d = await incident!(st.inc); return `${st.d.alerts.length} alert(s), ${st.d.timeline.length} timeline entries, ${st.d.events.length} event(s)`; } },
  { id: "playbook", name: "Build the response playbook and stage", run: async ({ st }) => { if (st.none) return "skipped"; const i = st.d.incident; const cur = ({ open: 1, investigating: 1, contained: 3, remediated: 4, closed: 5 } as Record<string, number>)[i.status] ?? 1; st.cur = cur; st.pb = playbookFor(i, st.d.alerts.map((a: Alert) => a.ruleId)); return `${st.pb.reduce((n: number, p: any) => n + p.steps.length, 0)} step(s); stage ${["Detection", "Investigation", "Containment", "Eradication", "Recovery"][Math.min(cur, 4)]}`; } },
  { id: "approvals", name: "Check approvals already requested for this incident", run: async ({ store, st }) => { if (st.none) return "skipped"; st.acts = await store.select<SocAction>(T.actions, { where: { incidentId: st.inc } }); return `${st.acts.length} action(s) on record, ${st.acts.filter((a: SocAction) => a.status === "proposed").length} awaiting approval`; } },
  { id: "write", name: "Write response recommendations", run: async ({ st }) => {
    if (st.none) { st.out = { head: "There are no active incidents to respond to.", severity: "low", findings: [], recs: [], limits: ["Incidents are created when related alerts are correlated."], pivots: { ips: [], hosts: [], users: [] } }; return "no incident"; }
    const i = st.d.incident as Incident, pr = ({ critical: "P1", high: "P2", medium: "P3", low: "P4" } as Record<string, string>)[i.severity] ?? "P3", F: TaskResult["findings"] = [{ sev: i.severity, t: `${i.title} — ${i.reasoning}`, ev: [] }], recs: TaskRec[] = [];
    st.d.alerts.slice(0, 5).forEach((a: Alert) => F.push({ sev: a.severity, t: `${a.title} (${a.ruleId}) on ${a.host}.`, ev: a.eventIds.slice(0, 3) }));
    const ips: string[] = uniq(st.d.alerts.flatMap((a: Alert) => (a.entities?.ips ?? []) as string[])), us: string[] = uniq(st.d.alerts.flatMap((a: Alert) => (a.entities?.users ?? []) as string[]));
    const has = new Set(st.acts.map((a: SocAction) => `${a.type}|${a.target}`));
    const ip0 = String(ips[0] ?? ""), us0 = String(us[0] ?? ""), map: Record<string, { type: ActionType; target: string }> = { c1: { type: "isolate_host", target: i.host }, c2: { type: "block_ip", target: ip0 }, c3: { type: "reset_password", target: us0 }, c4: { type: "disable_account", target: us0 } };
    st.pb.forEach((ph: any) => ph.steps.forEach((s: any) => { const m = s.needsApproval ? map[s.id] : undefined; recs.push({ p: /Contain/.test(ph.phase) ? "P1" : /Eradicate/.test(ph.phase) ? "P2" : "P3", t: `[${ph.phase.replace(/^\d · /, "")}] ${s.text}${m && has.has(`${m.type}|${m.target}`) ? " (request already on record)" : ""}`, type: m && m.target && !has.has(`${m.type}|${m.target}`) ? m.type : undefined, target: m?.target, dis: !!s.needsApproval, incidentId: i.id }); }));
    st.out = { head: `Incident ${i.id.slice(0, 12)}: ${i.severity.toUpperCase()} / ${pr}, stage ${["Detection", "Investigation", "Containment", "Eradication", "Recovery"][Math.min(st.cur, 4)]}.`, severity: i.severity, findings: F, recs, incidentId: i.id,
      stages: ["Detection", "Investigation", "Containment", "Eradication", "Recovery"].map((n, x) => ({ n, s: x < st.cur ? "done" : x === st.cur ? "active" : "todo" })), table: { title: "Response timeline", cols: ["Time", "Event", "Detail"], rows: st.d.timeline.slice(0, 14).map((x: any) => [x.time, x.title, clip(x.detail ?? "", 100)]) },
      limits: ["Containment steps are proposals. Spark does not isolate hosts, block addresses, reset passwords or change firewalls."], pivots: { ips, hosts: [i.host], users: us } };
    return `priority ${pr}, ${recs.length} step(s)`; } },
];

// ------------------------------------------------------------------ siem
const SIEM: StepDef[] = [
  { id: "rules", name: "Read the detection rule catalog", run: async ({ st }) => { st.rules = RULES_META.length; return `${RULES_META.length} built-in rules`; } },
  { id: "classify", name: "Classify stored alerts by rule and severity", run: async ({ store, st }) => { const al = await store.select<Alert>(T.alerts, { order: ["lastSeen", "desc"], limit: 1000 }), by: Record<string, number> = {}, sv: Record<string, number> = {}; al.forEach((a) => { by[a.ruleId] = (by[a.ruleId] ?? 0) + 1; sv[a.severity] = (sv[a.severity] ?? 0) + 1; }); st.byRule = by; st.bySev = sv; st.nAlerts = al.length; return `${al.length} alert(s) across ${Object.keys(by).length} rule(s)`; } },
  { id: "coverage", name: "Check log source coverage", run: async ({ store, st, collectors }) => { st.col = collectors ? await collectors() : []; const ev = await events(store, 2000); st.chan = uniq(ev.map((e) => e.channel)); return `${st.col.length} collector host(s); channels seen: ${st.chan.join(", ") || "none"}`; } },
  { id: "repeat", name: "Search for repeated failed logons", run: async ({ store, st, run }) => { const ip = run.task.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)?.[0], r = huntEvents(await events(store, 3000), { eventIds: [4625], ip }, 1000), by = new Map<string, SocEvent[]>(); r.rows.forEach((e) => { const k = `${e.srcIp ?? "-"}|${e.targetUser || e.user || "-"}`; (by.get(k) ?? by.set(k, []).get(k)!).push(e); }); st.rep = [...by.entries()].filter(([, l]) => l.length >= 3).map(([k, l]) => ({ ip: k.split("|")[0], user: k.split("|")[1], n: l.length, host: l[0].host, ids: l.slice(0, 3).map((e) => e.id) })).sort((a, b) => b.n - a.n); st.rows = r.rows.slice(0, 12); st.total = r.total; return `${r.total} failed logon(s); ${st.rep.length} source/account pair(s) with 3 or more`; } },
  { id: "queries", name: "Generate SIEM queries", run: async ({ st, run }) => { const ip = run.task.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)?.[0], f = ip ? ` (Source_Network_Address="${ip}" OR IpAddress="${ip}")` : "";
    st.q = `# Splunk SPL\nindex=wineventlog source="WinEventLog:Security" EventCode=4625${f} | stats count min(_time) as first max(_time) as last values(Account_Name) as accounts by Source_Network_Address | where count>=3 | sort - count\n\n# Microsoft Sentinel / Log Analytics KQL\nSecurityEvent\n| where EventID == 4625${ip ? `\n| where IpAddress == "${ip}"` : ""}\n| summarize Count=count(), Accounts=make_set(TargetUserName) by IpAddress\n| where Count >= 3\n\n# PowerShell on a Windows host\nGet-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} | Group-Object { $_.Properties[19].Value } | Where-Object Count -ge 3`; return "3 queries generated (text only; Spark did not run them anywhere)"; } },
  { id: "write", name: "Write findings", run: async ({ st }) => {
    const F: TaskResult["findings"] = st.rep.slice(0, 5).map((r: any) => ({ sev: (r.n >= 10 ? "high" : "medium") as Severity, t: `${r.n} failed logons from ${r.ip} against ${r.user}.`, ev: r.ids })); const miss = !st.col.length;
    F.push({ sev: miss ? "medium" : "low", t: miss ? "No collector has reported yet, so Spark has no Windows log source connected." : `Log sources: ${st.col.map((c: any) => `${c.host} (${c.status})`).join(", ")}. Linux, firewall and network logs have no collector.`, ev: [] });
    F.sort((a, b) => sevRank(b.sev) - sevRank(a.sev));
    st.out = { head: `${st.total} failed logon event(s); ${st.rep.length} repeated-failure pair(s); ${st.nAlerts} alert(s) across ${Object.keys(st.byRule).length} rule(s).`, severity: sevMax(F), findings: F, recs: [{ p: "P3", t: "Run the generated query in your SIEM to confirm on the full dataset.", dis: false }, { p: "P3", t: "Add a detection for 5+ failed logons per source in 10 minutes and enable Sysmon / 4688 command-line auditing.", dis: false }],
      table: { title: "Failed logon events (newest first)", cols: ["Time", "Host", "User", "Source IP", "Summary"], rows: st.rows.map((e: SocEvent) => [e.time, e.host, e.targetUser || e.user || "", e.srcIp ?? "", e.summary]) }, extra: [{ title: "Generated queries (NOT executed)", code: st.q }],
      limits: ["Results come from events stored in Spark, not from your SIEM. Queries are text and were not run anywhere."], pivots: { ips: st.rep.map((r: any) => r.ip).slice(0, 6), hosts: uniq(st.rep.map((r: any) => r.host)), users: uniq(st.rep.map((r: any) => r.user)) } };
    return `${F.length} finding(s)`; } },
];

// ------------------------------------------------------------------ ciso
const CISO: StepDef[] = [
  { id: "overview", name: "Read posture, incidents and vulnerabilities", run: async ({ st, overview }) => { st.o = await overview!(); return `posture ${st.o.posture ?? "n/a"}/100, ${st.o.activeIncidents.length} active incident(s)`; } },
  { id: "pending", name: "Count decisions waiting for approval", run: async ({ store, st }) => { st.pend = (await store.select<SocAction>(T.actions, { where: { status: "proposed" } })).length; return `${st.pend} action(s) awaiting approval`; } },
  { id: "risks", name: "Rank top risks", run: async ({ st }) => { st.ei = { posture: st.o.posture, vulnCounts: st.o.vulnCounts, activeIncidents: st.o.activeIncidents, kevVulns: st.o.kevVulns, assets: st.o.assets.map((a: any) => ({ hostname: a.hostname, score: a.score })), topVulns: st.o.topVulns, pendingActions: st.pend, mode: "connected" } as ExecInput; st.risks = topRisks(st.ei, 5); return `${st.risks.length} risk(s)`; } },
  { id: "kpi", name: "Compile KPIs", run: async ({ st }) => { const o = st.o, vc = o.vulnCounts; st.kpi = [["Security posture", o.posture == null ? "n/a" : `${o.posture}/100`, "100 minus average asset risk; not an audit"], ["Active incidents", o.activeIncidents.length, `${o.activeIncidents.filter((i: Incident) => i.severity === "critical").length} critical`], ["Critical + high vulnerabilities", (vc.critical ?? 0) + (vc.high ?? 0), "open findings"], ["Known-exploited vulnerabilities", o.kevVulns ?? 0, "CISA KEV, if imported"], ["Actions awaiting approval", st.pend, "decisions for an approver"], ["Mean time to respond", "not available", "no history is stored yet"]]; return `${st.kpi.length} KPI(s)`; } },
  { id: "write", name: "Write the executive briefing", run: async ({ st, run }) => {
    const F: TaskResult["findings"] = st.risks.map((r: any) => ({ sev: (/CRITICAL/.test(r.risk) ? "critical" : /HIGH|known-exploited/.test(r.risk + r.why) ? "high" : "medium") as Severity, t: `${r.risk}. ${r.why}`, ev: [] }));
    (run.context?.message ? [run.context.message] : []).forEach((m) => F.unshift({ sev: "low", t: `Handoff from ${run.context?.from ?? "an earlier agent"}: ${m}`, ev: [] }));
    const o = st.o, crit = o.activeIncidents.filter((i: Incident) => i.severity === "critical").length, recs: TaskRec[] = [];
    if (crit) recs.push({ p: "P1", t: `Assign an accountable owner and a containment decision for the ${crit} critical incident(s) today.`, dis: false }); if (o.kevVulns) recs.push({ p: "P1", t: `Approve emergency patching for ${o.kevVulns} known-exploited vulnerability(ies).`, dis: false }); if (st.pend) recs.push({ p: "P2", t: `Approve or reject ${st.pend} pending action(s) so containment is not stalled.`, dis: false });
    recs.push({ p: "P3", t: "Strategic: extend log coverage (Sysmon, Linux, firewall, network), baseline MFA on remote access, test restores of offline backups.", dis: false });
    st.out = { head: `Posture ${o.posture == null ? "n/a" : o.posture + "/100"}; ${o.activeIncidents.length} active incident(s); ${st.risks.length} top risk(s).`, severity: F.length ? sevMax(F) : "low", findings: F.slice(0, 10), recs, table: { title: "Security KPIs", cols: ["KPI", "Value", "Note"], rows: st.kpi }, extra: [{ title: "Executive summary (draft)", code: execSummaryMd(st.ei) }],
      limits: ["Counts cover only systems connected to Spark. No trend data, financial impact or compliance mapping is available."], pivots: { ips: [], hosts: [], users: [] } };
    return `${F.length} finding(s)`; } },
];

export function stepDefs(role: RoleKey, ctx?: TaskRun["context"]): StepDef[] {
  switch (role) { case "analyst": return ANALYST; case "engineer": return ENGINEER; case "hunter": return HUNTER(ctx?.ips ?? []); case "responder": return RESPONDER; case "siem": return SIEM; case "ciso": return CISO; }
}
const defsFor = (r: TaskRun) => stepDefs(r.role, r.context);

export async function createTask(store: Store, body: { role?: string; task?: string; context?: TaskRun["context"]; investigationId?: string }, actor: Actor): Promise<TaskRun> {
  if (!ROLE_KEYS.includes(body.role as RoleKey)) throw new HttpError(400, "role must be one of " + ROLE_KEYS.join(", "));
  const role = body.role as RoleKey, ctx = body.context ? { ips: (body.context.ips ?? []).slice(0, 10).map(String), hosts: (body.context.hosts ?? []).slice(0, 10).map(String), users: (body.context.users ?? []).slice(0, 10).map(String), from: body.context.from ? String(body.context.from).slice(0, 40) : undefined, message: body.context.message ? String(body.context.message).slice(0, 400) : undefined } : undefined;
  const run: TaskRun = { id: rid("task"), role, task: String(body.task ?? "").slice(0, 400), actor: actor.name, status: "running", steps: [], stepsDone: 0, stepsTotal: 0, progress: 0, state: {}, result: null, context: ctx, investigationId: body.investigationId ? String(body.investigationId).slice(0, 60) : undefined, source: "live", createdAt: nowIso() };
  run.steps = defsFor(run).map((d) => ({ id: d.id, name: d.name, status: "waiting" })); run.stepsTotal = run.steps.length;
  await store.upsert(T.tasks, [run]); await audit(store, actor, "task.create", run.id, { role, task: run.task, steps: run.stepsTotal, investigationId: run.investigationId });
  return run;
}
export interface TaskDeps { overview: () => Promise<any>; incident: (id: string) => Promise<any>; collectors: () => Promise<any[]> }
/** Executes exactly ONE waiting step, records real timing, and finalizes the run after the last step. */
export async function advanceTask(store: Store, id: string, actor: Actor, deps: TaskDeps): Promise<TaskRun> {
  const run = await store.get<TaskRun>(T.tasks, id); if (!run) throw new HttpError(404, "Task not found");
  if (run.status !== "running") return run;
  const idx = run.steps.findIndex((s) => s.status === "waiting"); if (idx < 0) return finalize(store, run, actor);
  const def = defsFor(run)[idx]; if (!def) throw new HttpError(500, "Step definition missing");
  const step = run.steps[idx], t0 = Date.now(); step.status = "running"; step.startedAt = nowIso(); run.startedAt ??= step.startedAt;
  try { step.detail = await def.run({ store, run, st: run.state, ...deps }); step.status = "done"; }
  catch (e: any) { step.status = "failed"; step.error = String(e?.message ?? e).slice(0, 300); run.status = "failed"; run.error = `Step “${step.name}” failed: ${step.error}`; await audit(store, actor, "task.fail", run.id, { step: step.id, error: step.error }); }
  step.endedAt = nowIso(); step.durationMs = Date.now() - t0; run.stepsDone = run.steps.filter((s) => s.status === "done").length; run.progress = Math.round((run.stepsDone / run.stepsTotal) * 100);
  if (run.status === "running" && run.stepsDone === run.stepsTotal) return finalize(store, run, actor);
  await store.upsert(T.tasks, [run]); return run;
}
const HANDOFF: Record<RoleKey, (o: TaskResult) => string> = {
  siem: (o) => o.pivots.ips[0] ? `Repeated failed logons from ${o.pivots.ips.slice(0, 3).join(", ")}. ${o.head}` : `No repeated failed-logon source found. ${o.head}`,
  analyst: (o) => o.pivots.ips[0] ? `Severity ${o.severity.toUpperCase()}. Investigate whether ${o.pivots.ips[0]} is associated with additional suspicious activity. ${o.head}` : `Severity ${o.severity.toUpperCase()}. ${o.head}`,
  hunter: (o) => `Hunt result: ${o.findings[0]?.t.slice(0, 150) ?? o.head}`, engineer: (o) => `Weaknesses: ${o.head}`, responder: (o) => `${o.head} Containment steps need explicit approval; nothing was executed.`, ciso: (o) => o.head,
};
async function finalize(store: Store, run: TaskRun, actor: Actor): Promise<TaskRun> {
  const out = run.state.out as Omit<TaskResult, "handoff" | "actionIds"> | undefined; if (!out) { run.status = "failed"; run.error = "The run finished without producing a result."; await store.upsert(T.tasks, [run]); return run; }
  // Agents may only PROPOSE disruptive actions. They become "proposed" records that a human must approve; nothing executes them.
  const ids: string[] = [];
  for (const r of out.recs) if (r.dis && r.type && r.target) {
    const act: SocAction = { id: hid("act", `agent:${run.role}|${r.type}|${r.target}|${r.incidentId ?? ""}`), source: "live", incidentId: r.incidentId, type: r.type, target: r.target, description: r.t.slice(0, 300), rationale: `Proposed by the ${run.role} agent (task ${run.id}). Rule-based analysis; a human must verify the evidence and approve.`, proposedBy: `agent:${run.role}`, status: "proposed", requiresApproval: true, createdAt: nowIso() };
    if (!(await store.get<SocAction>(T.actions, act.id))) { await store.upsert(T.actions, [act]); await audit(store, { name: `agent:${run.role}`, role: "agent" }, "action.propose", act.id, { type: act.type, target: act.target, task: run.id }); }
    ids.push(act.id);
  }
  run.result = { ...out, handoff: HANDOFF[run.role]({ ...out, handoff: "", actionIds: [] } as TaskResult), actionIds: ids };
  run.state = {}; run.status = "completed"; run.endedAt = nowIso(); run.stepsDone = run.stepsTotal; run.progress = 100;
  await store.upsert(T.tasks, [run]); await audit(store, actor, "task.complete", run.id, { role: run.role, severity: out.severity, findings: out.findings.length, proposedActions: ids.length });
  return run;
}
export async function cancelTask(store: Store, id: string, actor: Actor): Promise<TaskRun> {
  const run = await store.get<TaskRun>(T.tasks, id); if (!run) throw new HttpError(404, "Task not found");
  if (run.status !== "running") return run; run.status = "cancelled"; run.endedAt = nowIso(); run.error = "Cancelled by " + actor.name;
  await store.upsert(T.tasks, [run]); await audit(store, actor, "task.cancel", run.id, { stepsDone: run.stepsDone }); return run;
}
/** Re-runs from the failed step; completed steps are kept. */
export async function retryTask(store: Store, id: string, actor: Actor): Promise<TaskRun> {
  const run = await store.get<TaskRun>(T.tasks, id); if (!run) throw new HttpError(404, "Task not found");
  if (run.status !== "failed") throw new HttpError(409, "Only a failed task can be retried.");
  run.steps.forEach((s) => { if (s.status === "failed") { s.status = "waiting"; s.error = undefined; } }); run.status = "running"; run.error = undefined;
  await store.upsert(T.tasks, [run]); await audit(store, actor, "task.retry", run.id, {}); return run;
}
export const publicTask = (r: TaskRun) => ({ ...r, state: undefined });
