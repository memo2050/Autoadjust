import type { Alert, MitreRef, Severity, SocEvent } from "./types";
import { sevRank } from "./types";
import { isPrivateIp, ms, uniq } from "./util";

export type AlertDraft = Omit<Alert, "id" | "createdAt" | "source" | "incidentId">;
export interface RuleMeta { id: string; name: string; severity: Severity; mitre: MitreRef[]; description: string }
interface Rule { meta: RuleMeta; run: (events: SocEvent[]) => AlertDraft[] }

const M = {
  brute: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  spray: { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },
  valid: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  rdp: { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  extsvc: { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
  acctman: { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  newacct: { id: "T1136.001", name: "Create Account: Local Account", tactic: "Persistence" },
  schtask: { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
  winsvc: { id: "T1543.003", name: "Windows Service", tactic: "Persistence" },
  clearlog: { id: "T1070.001", name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  audit: { id: "T1562.002", name: "Disable Windows Event Logging", tactic: "Defense Evasion" },
  avoff: { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
  ps: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  xfer: { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  lolbin: { id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion" },
  inhibit: { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
  remote: { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  av: { id: "N/A", name: "Endpoint protection detection", tactic: "Execution" },
  c2: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  lsass: { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
  encrypt: { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
} satisfies Record<string, MitreRef>;

export const CFG = { bruteMin: 5, bruteGapMs: 10 * 60_000, sprayUsers: 5, successWindowMs: 15 * 60_000, fanoutMin: 3, fanoutGapMs: 15 * 60_000, groupGapMs: 30 * 60_000 };

const byTime = (a: SocEvent, b: SocEvent) => ms(a.time) - ms(b.time);
const ids = (e: SocEvent[]) => e.map((x) => x.id);
const first = (e: SocEvent[]) => e.reduce((m, x) => (x.time < m ? x.time : m), e[0].time);
const last = (e: SocEvent[]) => e.reduce((m, x) => (x.time > m ? x.time : m), e[0].time);
const ents = (e: SocEvent[]) => ({ users: uniq(e.map((x) => x.user).filter(Boolean) as string[]).slice(0, 20), ips: uniq(e.map((x) => x.srcIp).filter(Boolean) as string[]).slice(0, 20) });

function draft(rule: RuleMeta, ev: SocEvent[], o: { title: string; severity?: Severity; confidence: number; mitre?: MitreRef[]; reasoning: string; keyPart: string }): AlertDraft {
  return {
    ruleId: rule.id, key: `${rule.id}|${ev[0].assetId}|${o.keyPart}`, title: o.title, severity: o.severity ?? rule.severity, confidence: o.confidence,
    mitre: o.mitre ?? rule.mitre, assetId: ev[0].assetId, host: ev[0].host, eventIds: ids(ev).slice(0, 200), firstSeen: first(ev), lastSeen: last(ev),
    reasoning: o.reasoning, entities: ents(ev),
  };
}
/** Split time-sorted events into clusters where consecutive gap <= gapMs. */
function clusters(ev: SocEvent[], gapMs: number): SocEvent[][] {
  const s = [...ev].sort(byTime), out: SocEvent[][] = [];
  for (const e of s) { const c = out[out.length - 1]; if (c && ms(e.time) - ms(c[c.length - 1].time) <= gapMs) c.push(e); else out.push([e]); }
  return out;
}
const groupBy = <T,>(xs: T[], f: (x: T) => string) => { const m = new Map<string, T[]>(); for (const x of xs) { const k = f(x); (m.get(k) ?? m.set(k, []).get(k)!).push(x); } return m; };
const ok4624 = (e: SocEvent) => e.eventId === 4624 && e.channel.toLowerCase() === "security";
const f4625 = (e: SocEvent) => e.eventId === 4625 && e.channel.toLowerCase() === "security";
const sec = (e: SocEvent, id: number) => e.eventId === id && e.channel.toLowerCase() === "security";
const isSys = (e: SocEvent, id: number) => e.eventId === id && /sysmon/i.test(e.channel);
/** Process creation from either the Security log (4688) or Sysmon (1). */
const isProc = (e: SocEvent) => sec(e, 4688) || isSys(e, 1);

const PRIV_GROUPS = /^(administrators|domain admins|enterprise admins|schema admins|backup operators|account operators|server operators|remote desktop users)$/i;
const CMD: { re: RegExp; label: string; mitre: MitreRef; sev: Severity }[] = [
  { re: /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/i, label: "PowerShell with an encoded command", mitre: M.ps, sev: "high" },
  { re: /(invoke-expression|\biex\b)\s*[\(\s].*(downloadstring|webclient|invoke-webrequest|iwr|http)/i, label: "PowerShell download-and-execute pattern", mitre: M.ps, sev: "high" },
  { re: /downloadstring|net\.webclient|invoke-webrequest.*\|\s*iex/i, label: "PowerShell web download", mitre: M.xfer, sev: "medium" },
  { re: /certutil(\.exe)?.*-(urlcache|verifyctl).*http/i, label: "certutil used to download a file", mitre: M.xfer, sev: "high" },
  { re: /bitsadmin.*\/transfer/i, label: "bitsadmin used to transfer a file", mitre: M.xfer, sev: "medium" },
  { re: /mshta(\.exe)?\s+(https?:|vbscript:|javascript:)/i, label: "mshta running remote or script content", mitre: M.lolbin, sev: "high" },
  { re: /regsvr32.*\/i:https?:/i, label: "regsvr32 loading a remote script", mitre: M.lolbin, sev: "high" },
  { re: /rundll32.*(javascript:|\\\\.*\.dll)/i, label: "rundll32 running script or a network DLL", mitre: M.lolbin, sev: "medium" },
];
const IMPACT = [
  { re: /vssadmin(\.exe)?\s+delete\s+shadows/i, label: "volume shadow copies deleted (vssadmin)" },
  { re: /wmic.*shadowcopy.*delete/i, label: "volume shadow copies deleted (wmic)" },
  { re: /bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i, label: "Windows recovery disabled (bcdedit)" },
  { re: /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)/i, label: "backup catalog deleted (wbadmin)" },
];
const WRITABLE = /(\\users\\[^\\]+\\appdata\\|\\temp\\|\\windows\\temp\\|\\programdata\\|\\users\\public\\|\\downloads\\)/i;
const SHELLY = /(powershell|pwsh|cmd(\.exe)?\s+\/c|wscript|cscript|mshta|rundll32|regsvr32|http:\/\/|https:\/\/|frombase64string)/i;

const mk = (id: string, name: string, severity: Severity, mitre: MitreRef[], description: string): RuleMeta => ({ id, name, severity, mitre, description });
const R_BRUTE = mk("WIN-AUTH-001", "Brute force / password spraying", "medium", [M.brute], `${CFG.bruteMin}+ failed logons (4625) from one source within ${CFG.bruteGapMs / 60000} min gaps; 5+ distinct users from one source is treated as password spraying.`);
const R_SUCC = mk("WIN-AUTH-002", "Successful logon after repeated failures", "critical", [M.brute, M.valid], "A successful logon (4624) for the same user or source within 15 minutes after 5+ failures; privileged logon (4672) right after raises confidence.");
const R_RDP = mk("WIN-AUTH-003", "Remote Desktop logon from a public IP", "high", [M.rdp, M.extsvc], "Logon type 10 (RemoteInteractive) from a non-private source address.");
const R_LOCK = mk("WIN-AUTH-004", "Account lockout", "low", [M.brute], "Account lockout event (4740); often follows password guessing.");
const R_GRP = mk("WIN-PRIV-001", "Member added to a privileged group", "high", [M.acctman], "4728/4732/4756 adding a member to Administrators, Domain Admins and similar groups.");
const R_ACCT = mk("WIN-ACCT-001", "User account created", "medium", [M.newacct], "4720 user account created.");
const R_TASK = mk("WIN-PERSIST-001", "Scheduled task created", "low", [M.schtask], "4698 scheduled task created; severity rises when the task runs a shell, script engine, URL or file from a user-writable folder.");
const R_SVC = mk("WIN-PERSIST-002", "Service installed", "low", [M.winsvc], "System 7045 service installed; severity rises for user-writable paths or shells.");
const R_CLEAR = mk("WIN-EVASION-001", "Event log cleared", "high", [M.clearlog], "Security 1102 or System 104: an event log was cleared.");
const R_AUDIT = mk("WIN-EVASION-002", "Audit policy changed or protection disabled", "medium", [M.audit, M.avoff], "Security 4719 audit policy changed; Defender 5001 real-time protection disabled.");
const R_CMD = mk("WIN-EXEC-001", "Suspicious command line", "high", [M.ps], "4688 process creation whose command line matches known download-cradle, encoded-command or LOLBin patterns. Requires process-creation auditing with command-line logging.");
const R_IMPACT = mk("WIN-IMPACT-001", "Ransomware precursor: recovery inhibited", "critical", [M.inhibit], "Commands that delete shadow copies, backups or disable Windows recovery (4688).");
const R_AV = mk("WIN-MAL-001", "Endpoint protection detected malware", "high", [M.av], "Microsoft Defender events 1116/1117; severity follows Defender's own severity.");
const R_FAN = mk("WIN-LATERAL-001", "Explicit-credential logons to many servers", "medium", [M.remote], "4648 by one account to 3+ distinct target servers within 15 minute gaps.");

const R_NET = mk("SYS-NET-001", "Script engine or LOLBin connected to a public address", "medium", [M.c2, M.xfer], "Sysmon event 3 where a script host or living-off-the-land binary (PowerShell, wscript, mshta, rundll32, regsvr32, certutil, bitsadmin, cmd) connects to a non-private IP; non-web ports raise severity. Requires Sysmon with network logging.");
const R_LSASS = mk("SYS-CRED-001", "Process opened LSASS memory", "critical", [M.lsass], "Sysmon event 10 where a non-system process opens lsass.exe with memory-read access rights (credential dumping pattern). Requires Sysmon process-access logging.");
const R_RANSOM = mk("SYS-RANSOM-001", "Mass file creation consistent with encryption", "critical", [M.encrypt], `Sysmon event 11: one process creates ${100}+ files within 60 seconds and most share one uncommon extension, or many files named like ransom notes. A ransomware indicator, not proof.`);
const R_BEHAV = mk("WIN-BEHAV-001", "Account used from many different source addresses", "medium", [M.valid], "Successful network or remote logons (4624 type 3/10) for one account from 4+ distinct source addresses within 30 minutes. A behavior anomaly that needs a human to judge whether it is a jump host, VPN or misuse.");
const NETPROC = /(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|cmd)\.exe$/i;
const WEBPORTS = new Set(["80", "443", "53", "8080", "8443"]);
const COMMONEXT = new Set(["txt", "log", "tmp", "docx", "xlsx", "pdf", "jpg", "png", "dll", "exe", "json", "xml", "pf", "etl", "dat", "db", "ini"]);
const RANSOMNOTE = /(decrypt|recover|restore|readme|how[_ -]?to).*\.(txt|html|hta)$/i;
const extOf = (f: string) => { const m = /\.([A-Za-z0-9]{1,12})$/.exec(f); return m ? m[1].toLowerCase() : ""; };

const RULES: Rule[] = [
  { meta: R_NET, run(ev) {
    return ev.filter((e) => isSys(e, 3) && e.process && NETPROC.test(e.process) && e.srcIp && !isPrivateIp(e.srcIp)).map((e) => {
      const port = e.data.DestinationPort ?? "?", odd = !WEBPORTS.has(port);
      return draft(R_NET, [e], { title: `${e.process!.split("\\").pop()} connected to ${e.srcIp}:${port}`, severity: odd ? "high" : "medium", confidence: odd ? 0.7 : 0.5, keyPart: `${e.process}|${e.srcIp}|${port}`,
        reasoning: `${e.process} (user ${e.user ?? "?"}) opened an outbound connection to ${e.srcIp}:${port} at ${e.time}. Script hosts and system binaries normally do not talk to the internet; ${odd ? "the port is not a common web port, which raises concern." : "web ports are common, so check the destination and command line."}` });
    });
  } },
  { meta: R_LSASS, run(ev) {
    return ev.filter((e) => isSys(e, 10) && /lsass\.exe$/i.test(e.data.TargetImage ?? "") && /0x(1010|1410|1438|143a|1fffff)/i.test(e.data.GrantedAccess ?? "") && !/\\(windows\\system32\\|program files\\windows defender\\|programdata\\microsoft\\windows defender\\)/i.test(e.data.SourceImage ?? e.process ?? "")).map((e) =>
      draft(R_LSASS, [e], { title: `${(e.data.SourceImage ?? e.process ?? "?").split("\\").pop()} opened lsass.exe memory`, confidence: 0.8, keyPart: `${e.data.SourceImage ?? e.process}`,
        reasoning: `${e.data.SourceImage ?? e.process ?? "A process"} opened lsass.exe with access ${e.data.GrantedAccess} at ${e.time}. That access reads credential memory and is how tools such as Mimikatz dump passwords. Security products also do this, so confirm the source binary.` }));
  } },
  { meta: R_RANSOM, run(ev) {
    const out: AlertDraft[] = [];
    for (const [img, list] of groupBy(ev.filter((e) => isSys(e, 11)), (e) => e.process ?? "?")) {
      const s = [...list].sort(byTime);
      for (let i = 0; i < s.length; i++) {
        let j = i; while (j + 1 < s.length && ms(s[j + 1].time) - ms(s[i].time) <= 60_000) j++;
        const win = s.slice(i, j + 1); if (win.length < 100) continue;
        const files = win.map((e) => e.data.TargetFilename ?? ""), exts = new Map<string, number>(); files.forEach((f) => exts.set(extOf(f), (exts.get(extOf(f)) ?? 0) + 1));
        const [top, n] = [...exts.entries()].sort((a, b) => b[1] - a[1])[0] ?? ["", 0], notes = files.filter((f) => RANSOMNOTE.test(f)).length;
        if ((top && !COMMONEXT.has(top) && n / win.length >= 0.7) || notes >= 10) { out.push(draft(R_RANSOM, win, { title: `Possible ransomware activity: ${img.split("\\").pop()} created ${win.length} files in 60 seconds`, confidence: 0.8, keyPart: img,
          reasoning: `${img} created ${win.length} files within 60 seconds; ${Math.round(n / win.length * 100)}% share the extension ".${top || "(none)"}"${notes >= 10 ? ` and ${notes} look like ransom notes` : ""}. Mass creation of one unusual file type is typical of encryption. Isolate the host only after a human confirms.` })); break; }
      }
    }
    return out;
  } },
  { meta: R_BEHAV, run(ev) {
    const out: AlertDraft[] = [];
    for (const [u, list] of groupBy(ev.filter((e) => ok4624(e) && (e.logonType === 3 || e.logonType === 10) && e.srcIp && e.srcIp !== "-"), (e) => e.user ?? "?"))
      for (const c of clusters(list, 30 * 60_000)) { const ips = uniq(c.map((e) => e.srcIp!)); if (ips.length >= 4) out.push(draft(R_BEHAV, c, { title: `${u} logged on from ${ips.length} different addresses`, confidence: 0.5, keyPart: u, reasoning: `Account ${u} had successful network/remote logons from ${ips.length} distinct addresses (${ips.slice(0, 5).join(", ")}) within 30 minutes. This could be a shared service account, a VPN or credential misuse; verify with the owner.` })); }
    return out;
  } },
  { meta: R_BRUTE, run(ev) {
    const out: AlertDraft[] = [];
    for (const [src, list] of groupBy(ev.filter(f4625), (e) => e.srcIp && e.srcIp !== "-" ? `ip:${e.srcIp}` : `user:${e.user ?? "?"}`)) {
      for (const c of clusters(list, CFG.bruteGapMs)) {
        if (c.length < CFG.bruteMin) continue;
        const users = uniq(c.map((e) => e.user ?? "?"));
        const spray = users.length >= CFG.sprayUsers;
        out.push(draft(R_BRUTE, c, { title: spray ? `Password spraying: ${c.length} failed logons against ${users.length} accounts` : `Brute force: ${c.length} failed logons`, severity: spray || c.length >= 20 ? "high" : "medium", confidence: spray ? 0.85 : c.length >= 20 ? 0.85 : 0.7, mitre: spray ? [M.spray] : [M.brute], keyPart: src,
          reasoning: `${c.length} failed logons (4625) from ${src.replace(/^(ip|user):/, "")} between ${c[0].time} and ${c[c.length - 1].time}, targeting ${users.length} account(s): ${users.slice(0, 5).join(", ")}${users.length > 5 ? "…" : ""}.` }));
      }
    }
    return out;
  } },
  { meta: R_SUCC, run(ev) {
    const out: AlertDraft[] = [], fails = ev.filter(f4625), wins = ev.filter(ok4624), priv = ev.filter((e) => sec(e, 4672));
    for (const [src, list] of groupBy(fails, (e) => e.srcIp && e.srcIp !== "-" ? e.srcIp : "")) {
      if (!src) continue;
      for (const c of clusters(list, CFG.bruteGapMs)) {
        if (c.length < CFG.bruteMin) continue;
        const end = ms(c[c.length - 1].time);
        const hit = wins.filter((w) => w.srcIp === src && ms(w.time) >= ms(c[0].time) && ms(w.time) <= end + CFG.successWindowMs && (w.logonType === 3 || w.logonType === 10 || w.logonType === 2));
        if (!hit.length) continue;
        const w = hit[0], p = priv.filter((e) => e.user === w.user && Math.abs(ms(e.time) - ms(w.time)) <= 120_000);
        const evd = [...c, w, ...p];
        out.push(draft(R_SUCC, evd, { title: `Possible compromised account: ${w.user ?? "unknown"} logged on from ${src} after ${c.length} failures`, confidence: p.length ? 0.9 : 0.8,
          keyPart: `${src}|${w.user ?? "?"}`, reasoning: `${c.length} failed logons from ${src}, then a successful logon (type ${w.logonType}) for "${w.user ?? "?"}" at ${w.time}.${p.length ? " Special privileges (4672) were assigned to the new session, so the account may be privileged." : ""} This is consistent with a successful password guess but could also be a user who mistyped; verify with the account owner.` }));
      }
    }
    return out;
  } },
  { meta: R_RDP, run(ev) {
    return ev.filter((e) => ok4624(e) && e.logonType === 10 && e.srcIp && !isPrivateIp(e.srcIp)).map((e) => draft(R_RDP, [e], { title: `Remote Desktop logon from public IP ${e.srcIp} as ${e.user ?? "?"}`, confidence: 0.6, keyPart: `${e.srcIp}|${e.user ?? "?"}`,
      reasoning: `Logon type 10 for "${e.user ?? "?"}" from ${e.srcIp}, which is not a private address. Confirm the RDP exposure and the source are expected.` }));
  } },
  { meta: R_LOCK, run(ev) { return ev.filter((e) => sec(e, 4740)).map((e) => draft(R_LOCK, [e], { title: `Account locked out: ${e.user ?? "?"}`, confidence: 0.6, keyPart: e.user ?? "?", reasoning: `Account "${e.user ?? "?"}" was locked out at ${e.time}${e.data.TargetDomainName ? ` (caller computer ${e.data.TargetDomainName})` : ""}.` })); } },
  { meta: R_GRP, run(ev) {
    return ev.filter((e) => [4728, 4732, 4756].some((i) => sec(e, i)) && PRIV_GROUPS.test(e.data.TargetUserName ?? "")).map((e) => draft(R_GRP, [e], { title: `Added to privileged group ${e.data.TargetUserName}: ${e.targetUser ?? "?"}`, confidence: 0.75, keyPart: `${e.data.TargetUserName}|${e.targetUser}`,
      reasoning: `Member ${e.targetUser ?? "?"} was added to "${e.data.TargetUserName}" by ${e.user ?? "?"} at ${e.time}. Confirm this was an approved change.` }));
  } },
  { meta: R_ACCT, run(ev) { return ev.filter((e) => sec(e, 4720)).map((e) => draft(R_ACCT, [e], { title: `User account created: ${e.user ?? "?"}`, confidence: 0.6, keyPart: e.user ?? "?", reasoning: `Account "${e.user ?? "?"}" created by ${e.data.SubjectUserName ?? "?"} at ${e.time}. Confirm it matches a ticket or onboarding request.` })); } },
  { meta: R_TASK, run(ev) {
    return ev.filter((e) => sec(e, 4698)).map((e) => {
      const body = `${e.data.TaskContent ?? ""} ${e.data.TaskName ?? ""}`, bad = SHELLY.test(body) || WRITABLE.test(body);
      return draft(R_TASK, [e], { title: `Scheduled task created: ${e.data.TaskName ?? "?"}`, severity: bad ? "high" : "low", confidence: bad ? 0.7 : 0.4, keyPart: e.data.TaskName ?? "?",
        reasoning: `Task "${e.data.TaskName ?? "?"}" created by ${e.user ?? "?"} at ${e.time}.${bad ? " The task definition references a shell/script engine, URL or a user-writable path, which is common for persistence." : " Nothing unusual was found in the task definition."}` });
    });
  } },
  { meta: R_SVC, run(ev) {
    return ev.filter((e) => e.eventId === 7045 && e.channel.toLowerCase() === "system").map((e) => {
      const p = e.data.ImagePath ?? "", bad = SHELLY.test(p) || WRITABLE.test(p);
      return draft(R_SVC, [e], { title: `Service installed: ${e.data.ServiceName ?? "?"}`, severity: bad ? "high" : "low", confidence: bad ? 0.7 : 0.4, keyPart: e.data.ServiceName ?? "?",
        reasoning: `Service "${e.data.ServiceName ?? "?"}" with image path ${p || "(not recorded)"} installed at ${e.time}.${bad ? " The path is user-writable or launches a shell, which is common for malware persistence." : ""}` });
    });
  } },
  { meta: R_CLEAR, run(ev) {
    return ev.filter((e) => sec(e, 1102) || (e.eventId === 104 && e.channel.toLowerCase() === "system")).map((e) => draft(R_CLEAR, [e], { title: `${e.channel} event log cleared by ${e.user ?? "?"}`, confidence: 0.9, keyPart: `${e.channel}|${e.time}`,
      reasoning: `The ${e.channel} log was cleared by ${e.user ?? "?"} at ${e.time}. Attackers clear logs to hide activity; legitimate clears are rare and should be documented.` }));
  } },
  { meta: R_AUDIT, run(ev) {
    return ev.filter((e) => sec(e, 4719) || (e.eventId === 5001 && /defender/i.test(e.channel))).map((e) => draft(R_AUDIT, [e], { title: e.eventId === 5001 ? "Defender real-time protection was disabled" : "Audit policy changed", severity: e.eventId === 5001 ? "high" : "medium", confidence: 0.7, mitre: e.eventId === 5001 ? [M.avoff] : [M.audit], keyPart: String(e.eventId),
      reasoning: e.eventId === 5001 ? `Microsoft Defender reported real-time protection disabled at ${e.time}.` : `Audit policy changed by ${e.user ?? "?"} at ${e.time}.` }));
  } },
  { meta: R_CMD, run(ev) {
    const out: AlertDraft[] = [];
    for (const e of ev.filter((x) => isProc(x) && x.commandLine)) {
      const hits = CMD.filter((c) => c.re.test(e.commandLine!));
      if (!hits.length) continue;
      const top = hits.sort((a, b) => sevRank(b.sev) - sevRank(a.sev))[0];
      out.push(draft(R_CMD, [e], { title: `${top.label} by ${e.user ?? "?"}`, severity: top.sev, mitre: [top.mitre], confidence: 0.7, keyPart: e.id,
        reasoning: `Process ${e.process ?? "?"} (parent ${e.parentProcess ?? "?"}) ran a command line matching: ${hits.map((h) => h.label).join("; ")}. These patterns are used by attackers but also by some admin scripts; review the full command line.` }));
    }
    return out;
  } },
  { meta: R_IMPACT, run(ev) {
    const out: AlertDraft[] = [];
    for (const e of ev.filter((x) => isProc(x) && x.commandLine)) {
      const hits = IMPACT.filter((c) => c.re.test(e.commandLine!));
      if (hits.length) out.push(draft(R_IMPACT, [e], { title: `Recovery inhibited: ${hits[0].label}`, confidence: 0.85, keyPart: e.id, reasoning: `${hits.map((h) => h.label).join("; ")} by ${e.user ?? "?"} at ${e.time}. Ransomware commonly does this immediately before encrypting files; treat as urgent unless it is a documented maintenance action.` }));
    }
    return out;
  } },
  { meta: R_AV, run(ev) {
    return ev.filter((e) => (e.eventId === 1116 || e.eventId === 1117) && /defender/i.test(e.channel)).map((e) => {
      const sv = (e.data["Severity Name"] ?? e.data.SeverityName ?? "").toLowerCase();
      const severity: Severity = sv === "severe" ? "critical" : sv === "high" ? "high" : sv === "low" ? "low" : "medium";
      const name = e.data["Threat Name"] ?? e.data.ThreatName ?? "unknown threat";
      return draft(R_AV, [e], { title: `Defender ${e.eventId === 1117 ? "acted on" : "detected"}: ${name}`, severity, confidence: 0.9, keyPart: `${name}|${e.data.Path ?? e.data["Path"] ?? ""}`,
        reasoning: `Microsoft Defender reported "${name}" (${sv || "severity not given"})${e.data.Path ? ` at ${e.data.Path}` : ""} at ${e.time}. Check whether it was blocked or only detected.` });
    });
  } },
  { meta: R_FAN, run(ev) {
    const out: AlertDraft[] = [];
    for (const [u, list] of groupBy(ev.filter((e) => sec(e, 4648)), (e) => e.user ?? "?"))
      for (const c of clusters(list, CFG.fanoutGapMs)) {
        const targets = uniq(c.map((e) => e.data.TargetServerName ?? "").filter((t) => t && t !== "localhost"));
        if (targets.length >= CFG.fanoutMin) out.push(draft(R_FAN, c, { title: `${u} used explicit credentials on ${targets.length} servers`, confidence: 0.6, keyPart: u, reasoning: `Account ${u} made explicit-credential logons (4648) to ${targets.length} distinct targets (${targets.slice(0, 5).join(", ")}) within a short period. This can indicate lateral movement or an admin tool.` }));
      }
    return out;
  } },
];

export const RULES_META: RuleMeta[] = RULES.map((r) => r.meta);
export function runRules(events: SocEvent[]): AlertDraft[] {
  const out: AlertDraft[] = [];
  for (const r of RULES) out.push(...r.run(events));
  return out;
}
