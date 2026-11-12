// Zabbix JSON-RPC client + normalizer. Needs Zabbix 6.4 or newer (Bearer-token auth). The fetcher is injectable so tests can use a fixture server.
// Nothing here invents data: a metric with no matching Zabbix item is reported as "unsupported/not monitored".
import type { NocType } from "../soc/noc";
import type { SourceStatus } from "./types";

export interface ZConf { url: string; token?: string; user?: string; password?: string; verifyTls?: boolean }
export type Fetcher = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<any>; text(): Promise<string> }>;
const defaultFetch: Fetcher = (u, i) => fetch(u, i as RequestInit) as any;

export class ZError extends Error { constructor(public kind: "unreachable" | "auth" | "api" | "http", msg: string, public code?: number) { super(msg); } }
const endpoint = (u: string) => u.replace(/\/+$/, "").replace(/\/api_jsonrpc\.php$/, "") + "/api_jsonrpc.php";

async function rpc(c: ZConf, method: string, params: unknown, f: Fetcher, bearer?: string): Promise<any> {
  const headers: Record<string, string> = { "Content-Type": "application/json-rpc" }; if (bearer) headers.Authorization = "Bearer " + bearer;
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 15000); let res;
  try { res = await f(endpoint(c.url), { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }), signal: ctl.signal }); }
  catch (e: any) { throw new ZError("unreachable", `Cannot reach ${c.url}: ${e?.cause?.code ?? e?.name === "AbortError" ? "timeout" : e?.message ?? "network error"}`); }
  finally { clearTimeout(to); }
  if (res.status === 401 || res.status === 403) throw new ZError("auth", `Zabbix refused the request (HTTP ${res.status}).`);
  if (!res.ok) throw new ZError("http", `Zabbix returned HTTP ${res.status}. Check the URL (it should be the base address of the Zabbix web frontend).`);
  let j: any; try { j = await res.json(); } catch { throw new ZError("http", "The address answered, but not with Zabbix JSON. Check the URL."); }
  if (j.error) { const m = `${j.error.message ?? ""} ${j.error.data ?? ""}`.trim(), auth = /not authori[sz]ed|session terminated|incorrect user name|login name or password|re-login|permission/i.test(m); throw new ZError(auth ? "auth" : "api", `Zabbix API error: ${m}`, j.error.code); }
  return j.result;
}
async function login(c: ZConf, f: Fetcher): Promise<string> {
  if (c.token) return c.token;
  if (!c.user || !c.password) throw new ZError("auth", "No API token or user/password is configured.");
  return String(await rpc(c, "user.login", { username: c.user, password: c.password }, f));
}

export async function testConnection(c: ZConf, f: Fetcher = defaultFetch): Promise<{ status: SourceStatus; version?: string; detail: string }> {
  let version: string; try { version = String(await rpc(c, "apiinfo.version", [], f)); } catch (e) { return fromErr(e); }
  try { const t = await login(c, f); const n = await rpc(c, "host.get", { countOutput: true }, f, t); return { status: "CONNECTED", version, detail: `Zabbix ${version} reachable and authenticated; ${n} host(s) visible to this account.` }; }
  catch (e) { const r = fromErr(e); return { ...r, version }; }
}
export function fromErr(e: unknown): { status: SourceStatus; detail: string } {
  if (e instanceof ZError) return { status: e.kind === "unreachable" ? "DISCONNECTED" : e.kind === "auth" ? "AUTHENTICATION FAILED" : "ERROR", detail: e.message };
  return { status: "ERROR", detail: String((e as Error)?.message ?? e) };
}

export interface ZIface { name: string; description?: string; up?: boolean; inBps?: number; outBps?: number; speedBps?: number; errorsIn?: number; errorsOut?: number; dropsIn?: number; dropsOut?: number }
export interface ZHost { hostid: string; id: string; name: string; hostname: string; ip?: string; type: NocType; groups: string[]; known: boolean; up: boolean; metrics: { latencyMs?: number; lossPct?: number; cpu?: number; mem?: number; disk?: number }; uptimeSec?: number; interfaces: ZIface[]; unsupported: string[]; itemErrors: string[]; lastclock?: number }
export interface ZProblem { eventid: string; name: string; severity: number; clock: number; resolved: boolean; hostid?: string; host?: string; hostName?: string }

const slug = (s: string) => s.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
const num = (v: unknown) => { const n = Number(v); return v === "" || v == null || !Number.isFinite(n) ? undefined : n; };
export function guessType(groups: string[], inv: { type?: string; os?: string } = {}, hasAgent = false, hasSnmp = false): NocType {
  const t = (groups.join(" ") + " " + (inv.type ?? "") + " " + (inv.os ?? "")).toLowerCase();
  if (/firewall|fortigate|pfsense|palo|asa\b/.test(t)) return "firewall"; if (/router|routing/.test(t)) return "router"; if (/switch/.test(t)) return "switch";
  if (/access ?point|wireless|wifi|wlan|\bap\b/.test(t)) return "accesspoint"; if (/printer/.test(t)) return "printer"; if (/hypervisor|esxi|vmware|proxmox/.test(t)) return "hypervisor";
  if (/virtual machine|\bvm\b/.test(t)) return "vm"; if (/windows|linux|server|ubuntu|debian|centos/.test(t) || hasAgent) return "server"; if (hasSnmp) return "switch"; return "endpoint";
}
const IFACE_RE = /^net\.if\.(in|out|status|in\.errors|out\.errors|in\.discards|out\.discards|total|speed)\[(.+)\]$/;
function ifName(key: string, itemName: string): string { const m = itemName.match(/Interface ([^:(]+)(?:\(([^)]*)\))?:/); const p = key.match(/\[(.+)\]/)?.[1]?.split(",")[0] ?? ""; return (m?.[1] ?? p).trim() || p; }

/** Turns raw host/item arrays into normalized hosts. Exported for tests. */
export function normalizeHosts(hosts: any[], items: any[], now = Date.now()): ZHost[] {
  const by = new Map<string, any[]>(); for (const it of items) { const a = by.get(it.hostid) ?? []; a.push(it); by.set(it.hostid, a); }
  return hosts.map((h): ZHost => {
    const its = by.get(h.hostid) ?? [], ifs = h.interfaces ?? [], main = ifs.find((i: any) => i.main === "1") ?? ifs[0], groups = (h.hostgroups ?? h.groups ?? []).map((g: any) => g.name);
    const m: ZHost["metrics"] = {}, un: string[] = [], errs: string[] = [], ports = new Map<string, ZIface>(); let uptime: number | undefined, ping: number | undefined, last = 0, diskMax: number | undefined;
    for (const it of its) {
      const v = it.state === "1" ? undefined : num(it.lastvalue), k: string = it.key_ ?? ""; const lc = num(it.lastclock) ?? 0; if (lc > last) last = lc;
      if (it.state === "1" && it.error) errs.push(`${it.name}: ${String(it.error).slice(0, 120)}`);
      if (v == null) continue;
      if (k === "icmpping") ping = v; else if (k.startsWith("icmppingsec")) m.latencyMs = Math.round(v * 1000 * 100) / 100; else if (k.startsWith("icmppingloss")) m.lossPct = v;
      else if (/^system\.cpu\.util/.test(k) || /cpu utilization/i.test(it.name)) m.cpu = Math.max(m.cpu ?? 0, v);
      else if (/^vm\.memory\.util/.test(k) || /memory utilization/i.test(it.name)) m.mem = v;
      else if (/^vm\.memory\.size\[pavailable\]/.test(k)) m.mem = Math.round((100 - v) * 10) / 10;
      else if (/^vfs\.fs\.(size\[.+,pused\]|pused)/.test(k) || /space utilization/i.test(it.name)) diskMax = Math.max(diskMax ?? 0, v);
      else if (/^system\.uptime/.test(k) || /sysUpTime/i.test(k)) uptime = v > 1e8 ? Math.round(v / 100) : v;
      else { const im = k.match(IFACE_RE); if (im) { const nm = ifName(k, it.name), p = ports.get(nm) ?? { name: nm }; const kind = im[1];
        if (kind === "in") p.inBps = v; else if (kind === "out") p.outBps = v; else if (kind === "status") p.up = v === 1; else if (kind === "speed") p.speedBps = v;
        else if (kind === "in.errors") p.errorsIn = v; else if (kind === "out.errors") p.errorsOut = v; else if (kind === "in.discards") p.dropsIn = v; else if (kind === "out.discards") p.dropsOut = v; ports.set(nm, p); } }
    }
    if (diskMax != null) m.disk = diskMax;
    for (const [metric, label] of [["cpu", "CPU"], ["mem", "memory"], ["disk", "disk"], ["latencyMs", "latency"], ["lossPct", "packet loss"]] as const) if (m[metric] == null) un.push(label);
    const avail = ifs.map((i: any) => String(i.available)), anyUp = avail.includes("1"), allDown = avail.length > 0 && avail.every((a: string) => a === "2");
    const fresh = last > 0 && now / 1000 - last < 900;
    const known = ping != null || anyUp || allDown || fresh;
    const up = ping === 0 ? false : ping === 1 ? true : allDown ? false : anyUp || fresh;
    return { hostid: h.hostid, id: slug(h.name || h.host), name: h.name || h.host, hostname: h.host, ip: main?.ip || undefined, type: guessType(groups, h.inventory ?? {}, ifs.some((i: any) => i.type === "1"), ifs.some((i: any) => i.type === "2")), groups, known, up: known ? up : false, metrics: m, uptimeSec: uptime, interfaces: [...ports.values()].map((p) => ({ ...p, speedBps: p.speedBps })), unsupported: un, itemErrors: errs.slice(0, 10), lastclock: last || undefined };
  });
}

const ITEM_KEYS = ["icmpping", "system.cpu.util", "vm.memory", "vfs.fs", "net.if", "system.uptime", "sysUpTime"];
export async function fetchSnapshot(c: ZConf, f: Fetcher = defaultFetch): Promise<{ hosts: ZHost[]; problems: ZProblem[] }> {
  const t = await login(c, f);
  const hosts = await rpc(c, "host.get", { output: ["hostid", "host", "name", "status"], selectInterfaces: ["interfaceid", "ip", "dns", "type", "main", "available", "port"], selectHostGroups: ["name"], selectInventory: ["os", "type", "model"], filter: { status: 0 }, limit: 1000 }, f, t);
  const hostids = hosts.map((h: any) => h.hostid);
  const items = hostids.length ? await rpc(c, "item.get", { output: ["itemid", "hostid", "name", "key_", "lastvalue", "lastclock", "units", "state", "error"], hostids, monitored: true, search: { key_: ITEM_KEYS }, searchByAny: true, limit: 20000 }, f, t) : [];
  return { hosts: normalizeHosts(hosts, items), problems: await fetchProblems(c, f, t) };
}
export async function fetchProblems(c: ZConf, f: Fetcher = defaultFetch, tok?: string): Promise<ZProblem[]> {
  const t = tok ?? await login(c, f);
  const pr = await rpc(c, "problem.get", { output: ["eventid", "objectid", "name", "severity", "clock", "r_eventid"], recent: true, sortfield: ["eventid"], sortorder: "DESC", limit: 300 }, f, t);
  if (!pr.length) return [];
  const ev = await rpc(c, "event.get", { eventids: pr.map((p: any) => p.eventid), output: ["eventid"], selectHosts: ["hostid", "host", "name"] }, f, t), hm = new Map<string, any>(ev.map((e: any) => [e.eventid, e.hosts?.[0]]));
  return pr.map((p: any): ZProblem => { const h = hm.get(p.eventid); return { eventid: p.eventid, name: p.name, severity: Number(p.severity), clock: Number(p.clock), resolved: !!p.r_eventid && p.r_eventid !== "0", hostid: h?.hostid, host: h?.host, hostName: h?.name }; });
}
export async function executeScript(c: ZConf, scriptId: string, hostId: string, f: Fetcher = defaultFetch): Promise<{ ok: boolean; output: string }> {
  const t = await login(c, f); const r = await rpc(c, "script.execute", { scriptid: scriptId, hostid: hostId }, f, t);
  return { ok: r?.response === "success", output: String(r?.value ?? "").slice(0, 4000) };
}
export const zSeverity = (n: number): "info" | "warning" | "high" | "critical" => (n >= 5 ? "critical" : n >= 4 ? "high" : n >= 2 ? "warning" : "info");
