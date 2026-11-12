// THE command catalog for Auto Adjust diagnostics (v1: tier R0 = read-only). This file is the server's copy; the executor has its own local copy
// (collector/noc-agent/*) and re-validates every job against it. tests/exec-framework.test.ts checks the two stay identical.
// There is no shell: Linux commands are argv arrays, Windows commands are FIXED PowerShell text that reads parameters from environment variables.
export type ParamType = "unit" | "hostname" | "host" | "port" | "int" | "enum";
export interface ParamDef { type: ParamType; min?: number; max?: number; values?: string[]; os?: Array<"linux" | "windows">; required?: boolean; localAllow?: "services" | "logUnits" }
export type Cmd = { argv: string[]; fallback?: { internal: "proc_net_listen"; when: "program_missing" } } | { internal: "tcp_connect" } | { ps: string };
export interface Template { id: string; title: string; tier: "R0" | "R1"; params: Record<string, ParamDef>; linux?: Cmd; windows?: Cmd; timeoutSec: number; maxLines: number; maxBytes: number; targetCheck?: Array<"host" | "name"> }

export const HARD_MAX_TIMEOUT_SEC = 60, HARD_MAX_BYTES = 16384, HARD_MAX_LINES = 400;
const RE = {
  unit: /^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$/,
  hostname: /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/,
  ipv4: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
};
const T = (t: Template): Template => t;
export const CATALOG: Template[] = [
  T({ id: "sys.uptime", title: "System uptime", tier: "R0", params: {}, timeoutSec: 10, maxLines: 20, maxBytes: 4096,
    linux: { argv: ["uptime"] }, windows: { ps: "Get-CimInstance Win32_OperatingSystem | Select-Object @{n='LastBoot';e={$_.LastBootUpTime}},@{n='UptimeHours';e={[math]::Round(((Get-Date)-$_.LastBootUpTime).TotalHours,1)}} | Format-List" } }),
  T({ id: "sys.cpu_top", title: "Top 15 processes by CPU (name only, never command lines)", tier: "R0", params: {}, timeoutSec: 10, maxLines: 16, maxBytes: 4096,
    linux: { argv: ["ps", "-eo", "pid,pcpu,pmem,comm", "--sort=-pcpu"] }, windows: { ps: "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Id,ProcessName,CPU,WorkingSet | Format-Table -AutoSize" } }),
  T({ id: "sys.mem", title: "Memory usage", tier: "R0", params: {}, timeoutSec: 10, maxLines: 20, maxBytes: 4096,
    linux: { argv: ["free", "-m"] }, windows: { ps: "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List" } }),
  T({ id: "sys.disk", title: "Disk space", tier: "R0", params: {}, timeoutSec: 15, maxLines: 40, maxBytes: 8192,
    linux: { argv: ["df", "-hP"] }, windows: { ps: "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | Format-Table -AutoSize" } }),
  T({ id: "sys.load", title: "Load average / processor queue", tier: "R0", params: {}, timeoutSec: 5, maxLines: 5, maxBytes: 1024,
    linux: { argv: ["cat", "/proc/loadavg"] }, windows: { ps: "(Get-Counter '\\System\\Processor Queue Length').CounterSamples | Select-Object Path,CookedValue | Format-List" } }),
  T({ id: "svc.status", title: "Service state (read-only)", tier: "R0", params: { unit: { type: "unit", required: true, localAllow: "services" } }, timeoutSec: 10, maxLines: 20, maxBytes: 4096,
    linux: { argv: ["systemctl", "show", "{unit}", "--no-pager", "-p", "Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus,ActiveEnterTimestamp"] },
    windows: { ps: "Get-Service -Name $env:AA_P_UNIT | Select-Object Name,Status,StartType | Format-List" } }),
  T({ id: "net.listen", title: "Listening TCP/UDP ports (no process details)", tier: "R0", params: {}, timeoutSec: 10, maxLines: 120, maxBytes: 12288,
    linux: { argv: ["ss", "-tuln"], fallback: { internal: "proc_net_listen", when: "program_missing" } }, windows: { ps: "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort | Format-Table -AutoSize" } }),
  T({ id: "net.reach", title: "TCP connect test to one registered device", tier: "R0", params: { host: { type: "host", required: true }, port: { type: "port", required: true } }, targetCheck: ["host"], timeoutSec: 5, maxLines: 5, maxBytes: 1024,
    linux: { internal: "tcp_connect" }, windows: { internal: "tcp_connect" } }),
  T({ id: "net.ping", title: "Ping one registered device (3 packets)", tier: "R0", params: { host: { type: "host", required: true } }, targetCheck: ["host"], timeoutSec: 15, maxLines: 20, maxBytes: 2048,
    linux: { argv: ["ping", "-c", "3", "-W", "2", "{host}"] }, windows: { ps: "Test-Connection -ComputerName $env:AA_P_HOST -Count 3 | Format-Table -AutoSize" } }),
  T({ id: "dns.lookup", title: "Resolve one host name", tier: "R0", params: { name: { type: "hostname", required: true } }, timeoutSec: 10, maxLines: 10, maxBytes: 2048,
    linux: { argv: ["getent", "hosts", "{name}"] }, windows: { ps: "Resolve-DnsName -Name $env:AA_P_NAME -Type A | Format-Table -AutoSize" } }),
  T({ id: "log.tail", title: "Last N log lines of one allow-listed unit / Windows log", tier: "R0",
    params: { unit: { type: "unit", os: ["linux"], required: true, localAllow: "logUnits" }, log: { type: "enum", values: ["Application", "System"], os: ["windows"], required: true }, n: { type: "int", min: 1, max: 200, required: true } },
    timeoutSec: 20, maxLines: 200, maxBytes: 16384,
    linux: { argv: ["journalctl", "-u", "{unit}", "-n", "{n}", "--no-pager", "-o", "short-iso"] },
    windows: { ps: "Get-WinEvent -LogName $env:AA_P_LOG -MaxEvents ([int]$env:AA_P_N) | ForEach-Object { '{0:o} [{1}] {2} {3}' -f $_.TimeCreated,$_.LevelDisplayName,$_.ProviderName,(($_.Message -split \"`n\")[0]) }" } }),
];
/** Program names that may never appear as argv[0] or as a word of fixed PowerShell text, no matter who edits the catalog. */
export const DENY_PROGRAMS = ["sh", "bash", "dash", "zsh", "ksh", "csh", "fish", "cmd", "cmd.exe", "powershell", "pwsh", "python", "python3", "perl", "ruby", "node", "php", "rm", "dd", "mkfs", "shutdown", "reboot", "halt", "poweroff", "init", "kill", "killall", "pkill", "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "netsh", "useradd", "userdel", "usermod", "passwd", "chpasswd", "chmod", "chown", "icacls", "takeown", "apt", "apt-get", "yum", "dnf", "rpm", "dpkg", "pip", "npm", "curl", "wget", "nc", "ncat", "ssh", "scp", "sudo", "su", "mount", "umount", "crontab", "at", "tee", "mv", "cp", "ln", "sed", "awk", "xargs", "env", "eval", "exec"];
export const DENY_PS = /\b(Set|Remove|Stop|Restart|Start|New|Disable|Enable|Clear|Invoke|Add|Move|Copy|Rename|Out|Export|Import|Install|Uninstall|Register|Unregister|Grant|Revoke|Update)-[A-Za-z]+|\biex\b|\bInvokeExpression\b|\bDownloadString\b|\bnet\s+user\b|Start-Process|-EncodedCommand/i;
export const DENY_SYSTEMCTL_VERBS = ["start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "daemon-reload", "reboot", "poweroff", "halt", "edit", "set-property"];

export function auditCatalog(cat: Template[] = CATALOG): string[] {
  const bad: string[] = [], ids = new Set<string>();
  for (const t of cat) {
    if (ids.has(t.id)) bad.push(`${t.id}: duplicate id`); ids.add(t.id);
    if (t.timeoutSec < 1 || t.timeoutSec > HARD_MAX_TIMEOUT_SEC) bad.push(`${t.id}: timeout outside 1..${HARD_MAX_TIMEOUT_SEC}`);
    if (t.maxBytes > HARD_MAX_BYTES || t.maxLines > HARD_MAX_LINES) bad.push(`${t.id}: output limit above hard maximum`);
    for (const os of ["linux", "windows"] as const) {
      const c = t[os]; if (!c) continue;
      if ("argv" in c) {
        const prog = c.argv[0].split("/").pop()!; if (DENY_PROGRAMS.includes(prog)) bad.push(`${t.id}/${os}: program ${prog} is denied`);
        if (c.argv[0].includes("{")) bad.push(`${t.id}/${os}: program name must be fixed`);
        if (prog === "systemctl" && c.argv.some((a) => DENY_SYSTEMCTL_VERBS.includes(a))) bad.push(`${t.id}/${os}: systemctl verb denied`);
        if (c.argv.some((a) => /[;&|`$<>\n\\]/.test(a.replace(/\{[a-z]+\}/g, "")))) bad.push(`${t.id}/${os}: shell metacharacter in argv`);
        for (const a of c.argv) for (const m of a.matchAll(/\{([a-z]+)\}/g)) if (!t.params[m[1]]) bad.push(`${t.id}/${os}: placeholder {${m[1]}} has no parameter`);
      } else if ("ps" in c) { if (DENY_PS.test(c.ps)) bad.push(`${t.id}/${os}: PowerShell text uses a denied verb`); if (/\$\(.*AA_P_/.test(c.ps) || /"[^"]*\$env:AA_P/.test(c.ps)) bad.push(`${t.id}/${os}: parameters must not be interpolated into strings`); }
    }
    if (t.tier !== "R0") bad.push(`${t.id}: tier ${t.tier} is not part of the v1 catalog`);
  }
  return bad;
}

export const byId = (id: string, cat: Template[] = CATALOG) => cat.find((t) => t.id === id);
export class ParamError extends Error {}
const isoct = (a: string) => a.split(".").map(Number);
/** Addresses a diagnostic may never be pointed at, whatever the registered devices say. */
export function forbiddenTarget(h: string): string | null {
  if (RE.ipv4.test(h)) { const [a, b] = isoct(h); if (a === 127) return "loopback"; if (a === 0) return "unspecified"; if (a === 169 && b === 254) return "link-local / cloud metadata"; if (a >= 224) return "multicast / reserved"; return null; }
  const l = h.toLowerCase(); if (l === "localhost" || l.endsWith(".localhost") || l.endsWith(".internal") && l.startsWith("metadata")) return "loopback name"; return null;
}
/** Validates and normalizes parameters for a template + OS. Unknown parameters are errors. Returns strings only. */
export function validateParams(t: Template, os: "linux" | "windows", raw: unknown): Record<string, string> {
  if (raw == null) raw = {}; if (typeof raw !== "object" || Array.isArray(raw)) throw new ParamError("params must be an object");
  const given = raw as Record<string, unknown>, out: Record<string, string> = {};
  for (const k of Object.keys(given)) { const d = t.params[k]; if (!d || (d.os && !d.os.includes(os))) throw new ParamError(`Unknown parameter '${k}' for ${t.id} on ${os}`); }
  for (const [k, d] of Object.entries(t.params)) {
    if (d.os && !d.os.includes(os)) continue;
    const v = given[k]; if (v === undefined || v === null || v === "") { if (d.required) throw new ParamError(`Parameter '${k}' is required`); continue; }
    if (typeof v !== "string" && typeof v !== "number") throw new ParamError(`Parameter '${k}' must be a string or number`);
    const s = String(v); if (s.length > 253) throw new ParamError(`Parameter '${k}' is too long`);
    switch (d.type) {
      case "unit": if (!RE.unit.test(s)) throw new ParamError(`Parameter '${k}' is not a valid unit/service name`); break;
      case "hostname": if (!RE.hostname.test(s)) throw new ParamError(`Parameter '${k}' is not a valid host name`); break;
      case "host": if (!RE.ipv4.test(s) && !RE.hostname.test(s)) throw new ParamError(`Parameter '${k}' must be an IPv4 address or host name`); break;
      case "port": case "int": { if (!/^\d{1,6}$/.test(s)) throw new ParamError(`Parameter '${k}' must be a whole number`); const n = Number(s), lo = d.type === "port" ? 1 : d.min ?? 0, hi = d.type === "port" ? 65535 : d.max ?? 1e6; if (n < lo || n > hi) throw new ParamError(`Parameter '${k}' must be between ${lo} and ${hi}`); out[k] = String(n); continue; }
      case "enum": if (!d.values!.includes(s)) throw new ParamError(`Parameter '${k}' must be one of ${d.values!.join(", ")}`); break;
    }
    out[k] = s;
  }
  return out;
}
export function buildArgv(t: Template, os: "linux" | "windows", p: Record<string, string>): string[] | null {
  const c = t[os]; if (!c || !("argv" in c)) return null; return c.argv.map((a) => a.replace(/\{([a-z]+)\}/g, (_, k) => p[k]));
}
export function preview(t: Template, os: "linux" | "windows", p: Record<string, string>): string {
  const c = t[os]; if (!c) return "(not available on this OS)";
  if ("argv" in c) return buildArgv(t, os, p)!.map((a) => (/^[A-Za-z0-9@%+=:,./_-]+$/.test(a) ? a : JSON.stringify(a))).join(" ") + "   [argv, no shell]" + (c.fallback ? "\n(if the program is not installed: built-in read-only fallback that parses /proc/net/{tcp,udp,tcp6,udp6}; reports UNSUPPORTED unless the result is complete and reliable)" : "");
  if ("internal" in c) return `built-in TCP connect to ${p.host}:${p.port} (no external program)`;
  return `powershell -NoProfile -NonInteractive -Command "<fixed text>"   [parameters via environment AA_P_*: ${Object.keys(p).join(", ") || "none"}]\n${c.ps}`;
}
if (auditCatalog().length) throw new Error("Command catalog failed its own safety audit: " + auditCatalog().join("; "));
