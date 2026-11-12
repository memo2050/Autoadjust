// Network discovery, topology, manual map editing, and controlled configuration changes.
// Honest limits: this code runs on the backend and cannot scan a private network. A discovery agent INSIDE the network
// polls for approved scan jobs (outbound only), scans, and reports. The backend only accepts hosts inside the approved range.
import { HttpError, audit } from "../soc/pipeline";
import { deviceStatus, NOC_TABLE, NOC_TYPES, type NocDevice, type NocType } from "../soc/noc";
import { T } from "../soc/store";
import type { Alert, Incident } from "../soc/types";
import { hid, ms, rid, sha256, slug } from "../soc/util";
import { cryptoConfigured, decryptJson, encryptJson } from "./crypto";
import { NT, type NocIncident } from "./types";
import { effectiveStatus, type Ctx } from "./ops";
import type { Source } from "./types";

/* ---------- target parsing and scope enforcement ---------- */
const ip2n = (ip: string): number | null => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim()); if (!m) return null; const o = m.slice(1).map(Number); return o.some((x) => x > 255) ? null : ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3]; };
export const n2ip = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
export interface Targets { ranges: [number, number][]; hostnames: string[]; size: number }
const PRIVATE: [number, number][] = [[ip2n("10.0.0.0")!, ip2n("10.255.255.255")!], [ip2n("172.16.0.0")!, ip2n("172.31.255.255")!], [ip2n("192.168.0.0")!, ip2n("192.168.255.255")!], [ip2n("100.64.0.0")!, ip2n("100.127.255.255")!]];
const MAX_SCAN = Number(process.env.NOC_MAX_SCAN_HOSTS) || 65536;
export function parseTargets(list: unknown): Targets {
  if (!Array.isArray(list) || !list.length || list.length > 50) throw new HttpError(400, "targets must be a list of 1 to 50 entries: CIDR (192.168.1.0/24), range (192.168.1.10-192.168.1.50), single IP, or hostname");
  const ranges: [number, number][] = [], hostnames: string[] = [];
  for (const raw of list) {
    const t = String(raw).trim(); let m: RegExpExecArray | null;
    if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(t))) { const b = ip2n(m[1]), bits = Number(m[2]); if (b == null || bits < 8 || bits > 32) throw new HttpError(400, `Invalid CIDR "${t}" (prefix must be /8 to /32)`); const size = 2 ** (32 - bits), start = Math.floor(b / size) * size; ranges.push([start, start + size - 1]); }
    else if ((m = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(t))) { const a = ip2n(m[1]), b = ip2n(m[2]); if (a == null || b == null || b < a) throw new HttpError(400, `Invalid range "${t}"`); ranges.push([a, b]); }
    else if (ip2n(t) != null) { const a = ip2n(t)!; ranges.push([a, a]); }
    else if (/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i.test(t) && !/^[\d.]+$/.test(t)) hostnames.push(t.toLowerCase());
    else throw new HttpError(400, `"${t}" is not a CIDR, IP range, IP address or hostname`);
  }
  const size = ranges.reduce((a, r) => a + (r[1] - r[0] + 1), 0) + hostnames.length;
  if (size > MAX_SCAN) throw new HttpError(400, `Scope covers ${size} addresses; the limit is ${MAX_SCAN} (set NOC_MAX_SCAN_HOSTS to change).`);
  if (process.env.NOC_ALLOW_PUBLIC_SCAN !== "1") for (const r of ranges) if (!PRIVATE.some((p) => r[0] >= p[0] && r[1] <= p[1])) throw new HttpError(400, "Only private address ranges (10/8, 172.16/12, 192.168/16, 100.64/10) can be scanned. Public ranges are blocked unless the operator sets NOC_ALLOW_PUBLIC_SCAN=1.");
  return { ranges, hostnames, size };
}
export const inScope = (t: Targets, ip?: string, host?: string) => { const n = ip ? ip2n(ip) : null; return (n != null && t.ranges.some((r) => n >= r[0] && n <= r[1])) || (!!host && t.hostnames.includes(host.toLowerCase())); };

export interface Scope { id: string; name: string; targets: string[]; size: number; authorized: boolean; authorizedBy: string; authorizedAt: string; note?: string; createdAt: string }
export interface ScanOpts { methods: ("icmp" | "arp" | "tcp" | "snmp")[]; timeoutMs: number; intensity: "low" | "normal" | "high"; tcpPorts: number[]; snmpProfile?: string }
export interface Scan { id: string; scopeId: string; scopeName: string; status: "queued" | "running" | "completed" | "failed" | "cancelled"; options: ScanOpts; total: number; done: number; found: number; rejected: number; message?: string; error?: string; agentId?: string; startedBy: string; createdAt: string; startedAt?: string; lastBeatAt?: string; endedAt?: string }
export const INTENSITY = { low: 10, normal: 50, high: 200 } as const;

export async function createScope(c: Ctx, b: any) {
  const name = String(b?.name ?? "").trim().slice(0, 60); if (!name) throw new HttpError(400, "name is required");
  const t = parseTargets(b?.targets);
  if (b?.authorized !== true) throw new HttpError(400, "You must confirm you are authorized to scan these ranges (authorized: true). Scanning networks you do not own or manage may be illegal.");
  const s: Scope = { id: rid("scp"), name, targets: (b.targets as unknown[]).map((x) => String(x).trim()), size: t.size, authorized: true, authorizedBy: c.actor.name, authorizedAt: new Date().toISOString(), note: b?.note ? String(b.note).slice(0, 300) : undefined, createdAt: new Date().toISOString() };
  await c.store.upsert(NT.scopes, [s]); await audit(c.store, c.actor, "noc.scope.create", s.id, { name, targets: s.targets, size: s.size }); return s;
}
export async function deleteScope(c: Ctx, id: string) { if (!(await c.store.get(NT.scopes, id))) throw new HttpError(404, "Scope not found"); await c.store.remove(NT.scopes, { id }); await audit(c.store, c.actor, "noc.scope.delete", id, {}); return { deleted: id }; }
function cleanOpts(o: any): ScanOpts {
  const all = ["icmp", "arp", "tcp", "snmp"], methods = (Array.isArray(o?.methods) && o.methods.length ? o.methods : ["icmp", "arp"]).map(String).filter((x: string) => all.includes(x)) as ScanOpts["methods"];
  if (!methods.length) throw new HttpError(400, "methods must include icmp, arp, tcp or snmp");
  const timeoutMs = Math.max(200, Math.min(10000, Number(o?.timeoutMs) || 1500)), intensity = (["low", "normal", "high"].includes(o?.intensity) ? o.intensity : "low") as ScanOpts["intensity"];
  const tcpPorts = (Array.isArray(o?.tcpPorts) ? o.tcpPorts : [22, 80, 443, 3389]).map(Number).filter((p: number) => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 20);
  return { methods, timeoutMs, intensity, tcpPorts, snmpProfile: o?.snmpProfile ? String(o.snmpProfile).slice(0, 40) : undefined };
}
export async function startScan(c: Ctx, b: any) {
  const sc = await c.store.get<Scope>(NT.scopes, String(b?.scopeId ?? "")); if (!sc) throw new HttpError(404, "Scan scope not found. Create an approved scope first.");
  if (!sc.authorized) throw new HttpError(403, "This scope is not authorized.");
  const active = (await c.store.select<Scan>(NT.scans, { where: { scopeId: sc.id }, limit: 50 })).find((x) => x.status === "queued" || x.status === "running"); if (active) throw new HttpError(409, `A scan of this scope is already ${active.status} (${active.id}).`);
  const t = new Date().toISOString(), s: Scan = { id: rid("scn"), scopeId: sc.id, scopeName: sc.name, status: "queued", options: cleanOpts(b?.options), total: sc.size, done: 0, found: 0, rejected: 0, message: "Waiting for a discovery agent to pick this job up.", startedBy: c.actor.name, createdAt: t };
  await c.store.upsert(NT.scans, [s]); await audit(c.store, c.actor, "noc.scan.start", s.id, { scope: sc.name, options: s.options }); return s;
}
export async function cancelScan(c: Ctx, id: string) { const s = await c.store.get<Scan>(NT.scans, id); if (!s) throw new HttpError(404, "Scan not found"); if (s.status === "completed" || s.status === "failed" || s.status === "cancelled") throw new HttpError(409, `Scan already ${s.status}`); s.status = "cancelled"; s.endedAt = new Date().toISOString(); s.message = "Cancelled by " + c.actor.name; await c.store.upsert(NT.scans, [s]); await audit(c.store, c.actor, "noc.scan.cancel", id, {}); return s; }
/** Agent claims the oldest queued scan. */
export async function claimScan(c: Ctx, agentName: string) {
  const t = new Date().toISOString(); await c.store.upsert(NT.agents, [{ id: slug(agentName), name: agentName, lastSeenAt: t, role: "discovery" }]);
  const q = (await c.store.select<Scan>(NT.scans, { where: { status: "queued" }, limit: 20 })).sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))[0]; if (!q) return { scan: null };
  const sc = await c.store.get<Scope>(NT.scopes, q.scopeId); if (!sc) { q.status = "failed"; q.error = "Scope was deleted"; await c.store.upsert(NT.scans, [q]); return { scan: null }; }
  q.status = "running"; q.startedAt = t; q.lastBeatAt = t; q.agentId = slug(agentName); q.message = "Scan running on agent " + agentName; await c.store.upsert(NT.scans, [q]);
  return { scan: { id: q.id, targets: sc.targets, options: q.options, maxPerSecond: INTENSITY[q.options.intensity] } };
}
const num = (v: unknown) => (Number.isFinite(Number(v)) && v !== "" && v != null ? Number(v) : undefined);
const MACRE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
const OUI: Record<string, string> = { "00:50:56": "VMware", "00:0c:29": "VMware", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "00:1b:21": "Intel", "f0:9f:c2": "Ubiquiti", "24:a4:3c": "Ubiquiti", "00:0b:86": "Aruba", "00:1e:bd": "Cisco", "00:17:5a": "Cisco", "00:1a:a1": "Cisco" };
export function guessType(h: any): NocType {
  if ((NOC_TYPES as readonly string[]).includes(h.type)) return h.type;
  const d = `${h.sysDescr ?? ""} ${h.vendor ?? ""} ${h.hostname ?? ""}`.toLowerCase(), p: number[] = h.ports ?? [];
  if (/firewall|fortigate|palo alto|pfsense|asa\b|sophos/.test(d)) return "firewall"; if (/router|routeros|ios xr|edge/.test(d)) return "router"; if (/switch|catalyst|procurve|aruba.*switch|powerconnect/.test(d)) return "switch";
  if (/access point|\bap\b|unifi|wireless|wlan/.test(d)) return "accesspoint"; if (/printer|laserjet|jetdirect|brother|epson/.test(d) || p.includes(9100) || p.includes(631)) return "printer";
  if (/esxi|vmware esx|hyper-v|proxmox/.test(d)) return "hypervisor"; if (p.includes(1883) || p.includes(8883) || /raspberry|esp32|camera|sensor|thermostat/.test(d)) return "iot";
  if (/windows server|linux|ubuntu|debian|centos|red hat/.test(d) && (p.includes(22) || p.includes(443) || p.includes(80))) return "server";
  const hn = String(h.hostname ?? h.sysName ?? "").toLowerCase(); if (/^(rtr|router|gw)[-_\d]/.test(hn)) return "router"; if (/^(sw|switch)[-_\d]/.test(hn)) return "switch"; if (/^(fw|firewall)[-_\d]/.test(hn)) return "firewall"; if (/^ap[-_\d]/.test(hn)) return "accesspoint"; if (/^(prn|printer)[-_\d]/.test(hn)) return "printer";
  if (p.includes(3389) || p.includes(5985)) return "endpoint"; if (/^(srv|server|db|sql|web|app|dc|mail)[-_\d]/.test(hn) || p.filter((x) => [22, 80, 443, 1433, 3306, 5432, 8080].includes(x)).length >= 2) return "server"; return "endpoint";
}
/** Agent reports a batch of discovered hosts. Hosts outside the approved scope are rejected and counted. */
export async function reportScan(c: Ctx, id: string, b: any) {
  const s = await c.store.get<Scan>(NT.scans, id); if (!s) throw new HttpError(404, "Scan not found"); if (s.status !== "running") throw new HttpError(409, `Scan is ${s.status}; results are not accepted.`);
  const sc = await c.store.get<Scope>(NT.scopes, s.scopeId); if (!sc) throw new HttpError(409, "Scope no longer exists"); const targets = parseTargets(sc.targets), hosts: any[] = Array.isArray(b?.hosts) ? b.hosts.slice(0, 500) : [];
  const t = new Date().toISOString(); let accepted = 0, rejected = 0, links = 0; const unresolved: string[] = [], nbQ: [NocDevice, any[]][] = [];
  const all = await c.store.select<NocDevice>(NOC_TABLE, { limit: 5000 });
  for (const h of hosts) {
    const ip = h?.ip ? String(h.ip) : undefined, host = h?.hostname ? String(h.hostname).slice(0, 100) : undefined;
    if (!inScope(targets, ip, host)) { rejected++; continue; }
    const mac = h?.mac && MACRE.test(String(h.mac)) ? String(h.mac).toLowerCase().replace(/-/g, ":") : undefined, ports = (Array.isArray(h?.ports) ? h.ports : []).map(Number).filter((p: number) => p > 0 && p < 65536).slice(0, 50);
    const ex = all.find((d) => (mac && d.mac === mac) || (ip && d.ip === ip)), type = guessType({ ...h, ports }), vendor = h?.vendor ? String(h.vendor).slice(0, 60) : mac ? OUI[mac.slice(0, 8)] : undefined;
    const id2 = ex?.id ?? (mac ? "dev-" + mac.replace(/:/g, "") : "dev-" + String(ip ?? host).replace(/\./g, "-")), rtt = num(h?.rttMs);
    const d: NocDevice = { ...(ex ?? { id: id2, name: host || h?.sysName || ip || id2, type, ip, source: "live" as const, up: true, metrics: {}, links: [], history: [], receivedAt: t, collector: "discovery" }),
      ip: ip ?? ex?.ip, name: ex?.name ?? (h?.sysName ? String(h.sysName).slice(0, 100) : host || ip || id2), type: ex ? (ex.discovered && !ex.sourceId ? type : ex.type) : type, up: h?.up !== false, mac: mac ?? ex?.mac, vendor: vendor ?? ex?.vendor, sysDescr: h?.sysDescr ? String(h.sysDescr).slice(0, 300) : ex?.sysDescr,
      metrics: { ...(ex?.metrics ?? {}), ...(rtt != null ? { latencyMs: rtt } : {}) }, receivedAt: t, known: true,
      discovered: { firstAt: ex?.discovered?.firstAt ?? t, lastAt: t, scanId: s.id, methods: Array.isArray(h?.methods) ? h.methods.map(String).slice(0, 4) : [], ports }, approved: ex?.approved ?? (ex?.sourceId ? true : false), approvedBy: ex?.approvedBy };
    if (rtt != null) d.history = [...(ex?.history ?? []), { t, latencyMs: rtt }].slice(-120);
    await c.store.upsert(NOC_TABLE, [d]); if (!ex) all.push(d); else Object.assign(ex, d); accepted++;
    nbQ.push([d, Array.isArray(h?.neighbors) ? h.neighbors.slice(0, 200) : []]);
  }
  for (const [d, nbs] of nbQ) {
    for (const nb of nbs) {
      const rn = nb?.remoteMac && MACRE.test(String(nb.remoteMac)) ? String(nb.remoteMac).toLowerCase().replace(/-/g, ":") : undefined, rd = all.find((x) => x.id !== d.id && ((nb?.remoteIp && x.ip === String(nb.remoteIp)) || (rn && x.mac === rn) || (nb?.remoteName && (x.name.toLowerCase() === String(nb.remoteName).toLowerCase() || (x.hostname ?? "").toLowerCase() === String(nb.remoteName).toLowerCase()))));
      if (!rd) { unresolved.push(String(nb?.remoteName ?? nb?.remoteIp ?? rn ?? "?")); continue; }
      const proto = ["lldp", "cdp", "arp", "fdb", "snmp"].includes(nb?.proto) ? nb.proto : "lldp", [a, bb] = [d.id, rd.id].sort(), lid = hid("lnk", a + "|" + bb);
      const prev = await c.store.get<any>(NT.links, lid);
      await c.store.upsert(NT.links, [{ id: lid, a, b: bb, aPort: a === d.id ? nb?.localPort : nb?.remotePort, bPort: a === d.id ? nb?.remotePort : nb?.localPort, proto, source: "discovered", firstSeen: prev?.firstSeen ?? t, lastSeen: t, speedMbps: num(nb?.speedMbps) ?? prev?.speedMbps }]); links++;
    }
  }
  s.done = Math.min(s.total, Math.max(s.done, Number(b?.done) || s.done)); s.found += accepted; s.rejected += rejected; s.lastBeatAt = t; s.message = String(b?.message ?? `Scanned ${s.done} of ${s.total} addresses`).slice(0, 200); await c.store.upsert(NT.scans, [s]);
  if (rejected) await audit(c.store, { name: "system", role: "system" }, "noc.scan.out_of_scope", s.id, { rejected });
  return { accepted, rejected, links, unresolved: unresolved.slice(0, 20) };
}
export async function finishScan(c: Ctx, id: string, b: any) {
  const s = await c.store.get<Scan>(NT.scans, id); if (!s) throw new HttpError(404, "Scan not found"); if (s.status !== "running") throw new HttpError(409, `Scan is ${s.status}`);
  s.status = b?.ok === false ? "failed" : "completed"; s.endedAt = new Date().toISOString(); if (b?.ok === false) s.error = String(b?.error ?? "Agent reported failure").slice(0, 300); else s.done = s.total; s.message = b?.ok === false ? s.error : `Completed: ${s.found} device(s) found`;
  await c.store.upsert(NT.scans, [s]); await audit(c.store, { name: "system", role: "system" }, "noc.scan." + s.status, id, { found: s.found, rejected: s.rejected }); return s;
}
export async function discoveryView(c: Ctx) {
  const now = Date.now(), scans = await c.store.select<Scan>(NT.scans, { order: ["createdAt", "desc"], limit: 20 });
  for (const s of scans) if (s.status === "running" && s.lastBeatAt && now - ms(s.lastBeatAt) > 5 * 60_000) { s.status = "failed"; s.error = "Agent stopped reporting for 5 minutes"; s.endedAt = new Date().toISOString(); await c.store.upsert(NT.scans, [s]); }
  const agents = await c.store.select<any>(NT.agents, { limit: 20 }), scopes = await c.store.select<Scope>(NT.scopes, { limit: 100 });
  return { scopes, scans, agents: agents.map((a) => ({ ...a, online: now - ms(a.lastSeenAt) < 120_000 })), note: "Scans run on a discovery agent inside your network. With no agent online, jobs stay queued." };
}
export async function adopt(c: Ctx, id: string) { const d = await c.store.get<NocDevice>(NOC_TABLE, id); if (!d) throw new HttpError(404, "Device not found"); d.approved = true; d.approvedBy = c.actor.name; await c.store.upsert(NOC_TABLE, [d]); await audit(c.store, c.actor, "noc.device.adopt", id, {}); return { id, approved: true }; }

/* ---------- topology ---------- */
export interface MapDoc { nodes: Record<string, { x?: number; y?: number; label?: string; desc?: string; zone?: string; vlan?: string; subnet?: string; hidden?: boolean }>; manualNodes: { id: string; name: string; type: string; ip?: string; x?: number; y?: number; zone?: string; vlan?: string; subnet?: string; desc?: string }[]; manualLinks: { id: string; a: string; b: string; label?: string; aPort?: string; bPort?: string }[]; hiddenLinks: string[]; groups: { id: string; kind: "vlan" | "subnet" | "zone" | "segment"; name: string; color?: string }[] }
export interface MapRow { id: string; name: string; env: string; description?: string; version: number; doc: MapDoc; updatedBy: string; updatedAt: string; createdAt: string }
const EMPTY: MapDoc = { nodes: {}, manualNodes: [], manualLinks: [], hiddenLinks: [], groups: [] };
const str = (v: unknown, n: number) => (v == null ? undefined : String(v).slice(0, n));
export function cleanDoc(d: any): MapDoc {
  if (!d || typeof d !== "object") throw new HttpError(400, "doc is required");
  const nodes: MapDoc["nodes"] = {}; const nn = d.nodes && typeof d.nodes === "object" ? Object.entries(d.nodes).slice(0, 3000) : [];
  for (const [k, v] of nn as [string, any][]) nodes[String(k).slice(0, 80)] = { x: num(v?.x), y: num(v?.y), label: str(v?.label, 80), desc: str(v?.desc, 300), zone: str(v?.zone, 60), vlan: str(v?.vlan, 20), subnet: str(v?.subnet, 40), hidden: v?.hidden === true ? true : undefined };
  const mn = (Array.isArray(d.manualNodes) ? d.manualNodes : []).slice(0, 500).map((x: any) => { if (!x?.id || !x?.name) throw new HttpError(400, "manualNodes need id and name"); return { id: String(x.id).slice(0, 60), name: String(x.name).slice(0, 80), type: (NOC_TYPES as readonly string[]).includes(x.type) ? x.type : "endpoint", ip: str(x.ip, 45), x: num(x.x), y: num(x.y), zone: str(x.zone, 60), vlan: str(x.vlan, 20), subnet: str(x.subnet, 40), desc: str(x.desc, 300) }; });
  const ml = (Array.isArray(d.manualLinks) ? d.manualLinks : []).slice(0, 2000).map((x: any) => { if (!x?.id || !x?.a || !x?.b) throw new HttpError(400, "manualLinks need id, a and b"); return { id: String(x.id).slice(0, 60), a: String(x.a).slice(0, 80), b: String(x.b).slice(0, 80), label: str(x.label, 60), aPort: str(x.aPort, 40), bPort: str(x.bPort, 40) }; });
  const gr = (Array.isArray(d.groups) ? d.groups : []).slice(0, 200).map((x: any) => ({ id: String(x?.id ?? rid("grp")).slice(0, 60), kind: (["vlan", "subnet", "zone", "segment"].includes(x?.kind) ? x.kind : "zone") as MapDoc["groups"][number]["kind"], name: String(x?.name ?? "").slice(0, 60), color: /^#[0-9a-f]{6}$/i.test(x?.color ?? "") ? x.color : undefined })).filter((x: any) => x.name);
  return { nodes, manualNodes: mn, manualLinks: ml, hiddenLinks: (Array.isArray(d.hiddenLinks) ? d.hiddenLinks : []).slice(0, 3000).map((x: any) => String(x).slice(0, 80)), groups: gr };
}
export async function listMaps(c: Ctx) { let m = await c.store.select<MapRow>(NT.maps, { limit: 100 }); if (!m.length) { const t = new Date().toISOString(); const r: MapRow = { id: "map_default", name: "Main network", env: "production", version: 0, doc: EMPTY, updatedBy: "system", updatedAt: t, createdAt: t }; await c.store.upsert(NT.maps, [r]); m = [r]; } return m.map(({ doc: _d, ...x }) => x); }
export async function createMap(c: Ctx, b: any) { const name = String(b?.name ?? "").trim().slice(0, 60); if (!name) throw new HttpError(400, "name is required"); const t = new Date().toISOString(); const r: MapRow = { id: rid("map"), name, env: String(b?.env ?? "production").slice(0, 30), description: str(b?.description, 300), version: 0, doc: EMPTY, updatedBy: c.actor.name, updatedAt: t, createdAt: t }; await c.store.upsert(NT.maps, [r]); await audit(c.store, c.actor, "noc.map.create", r.id, { name }); return r; }
export async function saveMap(c: Ctx, id: string, b: any) {
  const m = await c.store.get<MapRow>(NT.maps, id); if (!m) throw new HttpError(404, "Map not found"); if (b?.baseVersion != null && Number(b.baseVersion) !== m.version) throw new HttpError(409, `Someone saved version ${m.version} since you loaded ${b.baseVersion}. Reload to merge.`);
  const doc = cleanDoc(b?.doc), t = new Date().toISOString(); m.version += 1; m.doc = doc; m.updatedBy = c.actor.name; m.updatedAt = t; if (b?.name) m.name = String(b.name).slice(0, 60);
  await c.store.upsert(NT.maps, [m]); await c.store.upsert(NT.mapVersions, [{ id: `${m.id}:${m.version}`, mapId: m.id, version: m.version, doc, by: c.actor.name, at: t, note: str(b?.note, 200) }]);
  await audit(c.store, c.actor, "noc.map.save", id, { version: m.version, note: "Visual change only. No device configuration was changed." }); return { id, version: m.version, note: "Saved. This changed only the map; no network device was touched." };
}
export async function mapVersions(c: Ctx, id: string) { return (await c.store.select<any>(NT.mapVersions, { where: { mapId: id }, order: ["version", "desc"], limit: 30 })).map(({ doc: _d, ...x }) => x); }
export async function restoreVersion(c: Ctx, id: string, version: number) { const v = await c.store.get<any>(NT.mapVersions, `${id}:${version}`); if (!v) throw new HttpError(404, "Version not found"); return saveMap(c, id, { doc: v.doc, note: `Restored version ${version}` }); }

type TNode = { id: string; name: string; type: string; ip?: string; mac?: string; vendor?: string; manual: boolean; status: string; reasons: string[]; stale?: boolean; managed: boolean; unmanaged: boolean; tier: string; x?: number; y?: number; zone?: string; vlan?: string; subnet?: string; desc?: string; hidden?: boolean; metrics?: any; lastSeen?: string; incidents: { id: string; title: string; severity: string; status: string }[]; soc: { id: string; kind: string; title: string; severity: string }[]; affected?: boolean; rootCause?: boolean; compromised?: boolean };
export async function topology(c: Ctx, mapId?: string) {
  const maps = await listMaps(c), mid = mapId && maps.some((m) => m.id === mapId) ? mapId : maps[0].id, map = (await c.store.get<MapRow>(NT.maps, mid))!, doc = map.doc ?? EMPTY, now = c.now ? c.now() : Date.now();
  const [devs, lks, sources, incs, socA, socI] = await Promise.all([c.store.select<NocDevice>(NOC_TABLE, { limit: 3000 }), c.store.select<any>(NT.links, { limit: 6000 }), c.store.select<Source>(NT.sources, { limit: 100 }), c.store.select<NocIncident>(NT.incidents, { limit: 500 }), c.store.select<Alert>(T.alerts, { limit: 1000 }), c.store.select<Incident>(T.incidents, { limit: 500 })]);
  const live = devs.filter((d) => d.source === "live"), srcOk = (d: NocDevice) => { const s = sources.find((x) => x.id === d.sourceId); return !d.sourceId || (!!s && effectiveStatus(s, now).status === "CONNECTED"); };
  const nodes: TNode[] = live.map((d) => { const stale = !srcOk(d), st = d.known === false ? { status: "unknown", reasons: ["No availability data"] } : stale ? { status: "unknown", reasons: ["Monitoring source is not delivering data"] } : !d.sourceId && d.approved !== true && d.discovered ? { status: "discovered", reasons: [`Found by a discovery scan at ${d.discovered.lastAt}. It answered then, but it is not monitored, so its health is unknown.`] } : deviceStatus(d), ov = doc.nodes[d.id] ?? {};
    return { id: d.id, name: ov.label || d.name, type: d.type, ip: d.ip, mac: d.mac, vendor: d.vendor, manual: false, status: st.status, reasons: st.reasons, stale, managed: !!d.sourceId || d.approved === true, unmanaged: !d.sourceId && d.approved !== true, tier: "", x: ov.x, y: ov.y, zone: ov.zone, vlan: ov.vlan, subnet: ov.subnet, desc: ov.desc, hidden: ov.hidden, metrics: d.metrics, lastSeen: d.receivedAt, incidents: [], soc: [] }; });
  for (const m of doc.manualNodes) nodes.push({ id: m.id, name: m.name, type: m.type, ip: m.ip, manual: true, status: "unknown", reasons: ["Manually added. Not monitored."], managed: true, unmanaged: false, tier: "", x: m.x, y: m.y, zone: m.zone, vlan: m.vlan, subnet: m.subnet, desc: m.desc, incidents: [], soc: [] });
  const byId = new Map(nodes.map((n) => [n.id, n])); const hidden = new Set(doc.hiddenLinks);
  const links = [...lks.filter((l) => byId.has(l.a) && byId.has(l.b) && !hidden.has(l.id)).map((l) => ({ id: l.id, a: l.a, b: l.b, aPort: l.aPort, bPort: l.bPort, proto: l.proto, source: "discovered", lastSeen: l.lastSeen, speedMbps: l.speedMbps })), ...doc.manualLinks.filter((l) => byId.has(l.a) && byId.has(l.b)).map((l) => ({ id: l.id, a: l.a, b: l.b, aPort: l.aPort, bPort: l.bPort, label: l.label, proto: "manual", source: "manual" }))];
  // links reported by monitoring telemetry (device.links) are also drawn
  for (const d of live) for (const l of d.links ?? []) if (byId.has(l.to) && !links.some((x) => (x.a === d.id && x.b === l.to) || (x.a === l.to && x.b === d.id))) { const [a, b] = [d.id, l.to].sort(); links.push({ id: hid("lnk", a + "|" + b), a, b, proto: "telemetry", source: "telemetry" } as any); }
  const adj = new Map<string, string[]>(); for (const l of links) { (adj.get(l.a) ?? adj.set(l.a, []).get(l.a)!).push(l.b); (adj.get(l.b) ?? adj.set(l.b, []).get(l.b)!).push(l.a); }
  const deg = (id: string) => (adj.get(id) ?? []).length, infra = nodes.filter((n) => ["internet", "router", "firewall"].includes(n.type)), root = nodes.find((n) => n.type === "internet") ?? infra.sort((a, b) => deg(b.id) - deg(a.id))[0] ?? nodes.sort((a, b) => deg(b.id) - deg(a.id))[0];
  const depth = new Map<string, number>(); if (root) { depth.set(root.id, 0); const q = [root.id]; while (q.length) { const x = q.shift()!; for (const y of adj.get(x) ?? []) if (!depth.has(y)) { depth.set(y, depth.get(x)! + 1); q.push(y); } } }
  const childSw = (id: string) => (adj.get(id) ?? []).some((y) => byId.get(y)!.type === "switch" && (depth.get(y) ?? 0) > (depth.get(id) ?? 0)), swDepths = nodes.filter((n) => n.type === "switch" && depth.has(n.id)).map((n) => depth.get(n.id)!), minSw = swDepths.length ? Math.min(...swDepths) : 0;
  for (const n of nodes) n.tier = n.type === "internet" || n.type === "cloud" ? "edge" : n.type === "router" || n.type === "firewall" ? "gateway" : n.type === "switch" ? (depth.get(n.id) === minSw && childSw(n.id) ? "core" : childSw(n.id) ? "distribution" : "access") : n.type === "accesspoint" ? "access" : n.type === "server" || n.type === "hypervisor" || n.type === "storage" ? "server" : "endpoint";
  // NOC overlay: open incidents, impact
  for (const i of incs) if (i.status !== "Resolved" && i.status !== "Closed") { const n = (i.deviceId && byId.get(i.deviceId)) || nodes.find((x) => x.name.toLowerCase() === i.host.toLowerCase()); n?.incidents.push({ id: i.id, title: i.title, severity: i.severity, status: i.status }); }
  const down = new Set(nodes.filter((n) => n.status === "offline").map((n) => n.id)), reach = new Set<string>(); if (root && !down.has(root.id)) { reach.add(root.id); const q = [root.id]; while (q.length) { const x = q.shift()!; for (const y of adj.get(x) ?? []) if (!reach.has(y) && !down.has(y)) { reach.add(y); q.push(y); } } }
  if (root && down.size) { for (const n of nodes) if (n.id !== root.id && !n.manual && !down.has(n.id) && !reach.has(n.id) && depth.has(n.id)) n.affected = true; for (const id of down) { const n = byId.get(id)!; if ((adj.get(id) ?? []).some((y) => reach.has(y))) n.rootCause = true; } }
  // SOC overlay
  const openSocI = socI.filter((i) => i.status !== "closed"), match = (host: string, n: TNode) => host.toLowerCase() === n.name.toLowerCase() || host.toLowerCase() === (n.ip ?? "").toLowerCase() || host.toLowerCase() === n.id;
  for (const n of nodes) for (const i of openSocI) if (match(i.host, n)) n.soc.push({ id: i.id, kind: "incident", title: i.title, severity: i.severity });
  for (const a of socA) { const n = nodes.find((x) => match(a.host, x) || (a.entities?.ips ?? []).includes(x.ip ?? "~")); if (n && !n.soc.some((s) => s.id === a.id)) n.soc.push({ id: a.id, kind: "alert", title: a.title, severity: a.severity }); }
  for (const n of nodes) n.compromised = n.soc.some((s) => s.kind === "incident" && (s.severity === "critical" || s.severity === "high"));
  const unauthorized = nodes.filter((n) => n.unmanaged).map((n) => n.id);
  const stats = { nodes: nodes.length, links: links.length, discovered: nodes.filter((n) => n.status === "discovered").length, online: nodes.filter((n) => n.status === "healthy" || n.status === "warning" || n.status === "degraded").length, offline: down.size, unknown: nodes.filter((n) => n.status === "unknown").length, unmanaged: unauthorized.length, affected: nodes.filter((n) => n.affected).length, rootCauses: nodes.filter((n) => n.rootCause).map((n) => n.name), withSocAlerts: nodes.filter((n) => n.soc.length).length, compromised: nodes.filter((n) => n.compromised).length };
  return { map: { id: map.id, name: map.name, env: map.env, version: map.version, updatedBy: map.updatedBy, updatedAt: map.updatedAt, doc }, maps, nodes, links, root: root?.id ?? null, stats, time: new Date(now).toISOString(), integrations: { firewallEvents: false, note: "Firewall and security events appear on devices only after a SOC log source for that firewall is connected. None is built in." }, note: "Positions, labels and manual links are visual only. Saving a map never changes a network device." };
}
