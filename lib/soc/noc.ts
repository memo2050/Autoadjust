// NOC telemetry (Phase 4). The platform stores whatever telemetry a monitoring source POSTs; it never polls devices itself.
// Status is DERIVED from the numbers with the thresholds below, so every colour on the topology can be explained.
import type { Store } from "./store";
import { HttpError } from "./pipeline";
import { nowIso } from "./util";

export const NOC_TABLE = "noc_devices";
export const NOC_TYPES = ["internet", "router", "switch", "firewall", "server", "hypervisor", "vm", "cloud", "endpoint", "accesspoint", "printer", "storage", "iot"] as const;
export type NocType = (typeof NOC_TYPES)[number];
export type NocStatus = "healthy" | "warning" | "degraded" | "critical" | "offline";
export interface NocMetrics { latencyMs?: number; lossPct?: number; cpu?: number; mem?: number; disk?: number; bwInMbps?: number; bwOutMbps?: number; bwCapMbps?: number }
export interface NocLink { to: string; utilPct?: number; capMbps?: number }
export interface NocSample { t: string; latencyMs?: number; lossPct?: number; cpu?: number; mem?: number; disk?: number; bwMbps?: number }
export interface NocDevice { id: string; name: string; type: NocType; ip?: string; source: "live"; up: boolean; metrics: NocMetrics; links: NocLink[]; config?: Record<string, string | number | boolean>; history: NocSample[]; receivedAt: string; collector: string; sourceId?: string; hostId?: string; hostname?: string; uptimeSec?: number; known?: boolean; unsupported?: string[]; itemErrors?: string[]; groups?: string[]; mac?: string; vendor?: string; sysDescr?: string; discovered?: { firstAt: string; lastAt: string; scanId: string; methods: string[]; ports?: number[] }; approved?: boolean; approvedBy?: string }

/** Thresholds. Mirrored in the browser (noc.js) so sample and live data are judged identically. */
export const NOC_THRESHOLDS = {
  latencyMs: [50, 100, 250], lossPct: [1, 3, 10], cpu: [70, 85, 95], mem: [80, 90, 97], disk: [80, 90, 95], util: [80, 90, 97],
} as const;
const RANK: NocStatus[] = ["healthy", "warning", "degraded", "critical"];
export function bwUtil(m: NocMetrics): number | undefined { return m.bwCapMbps && m.bwCapMbps > 0 && (m.bwInMbps != null || m.bwOutMbps != null) ? (Math.max(m.bwInMbps ?? 0, m.bwOutMbps ?? 0) / m.bwCapMbps) * 100 : undefined; }
export function deviceStatus(d: { up: boolean; metrics: NocMetrics }): { status: NocStatus; reasons: string[] } {
  if (!d.up) return { status: "offline", reasons: ["Device is reported down (no response from the monitoring source)."] };
  const m = d.metrics, reasons: string[] = []; let lvl = 0;
  const chk = (v: number | undefined, th: readonly number[], label: string, unit: string) => {
    if (v == null) return; const k = v >= th[2] ? 3 : v >= th[1] ? 2 : v >= th[0] ? 1 : 0;
    if (k) { reasons.push(`${label} ${Math.round(v * 10) / 10}${unit} (${RANK[k]} at ${th[k - 1]}${unit}+)`); lvl = Math.max(lvl, k); }
  };
  chk(m.latencyMs, NOC_THRESHOLDS.latencyMs, "latency", " ms"); chk(m.lossPct, NOC_THRESHOLDS.lossPct, "packet loss", "%"); chk(m.cpu, NOC_THRESHOLDS.cpu, "CPU", "%");
  chk(m.mem, NOC_THRESHOLDS.mem, "memory", "%"); chk(m.disk, NOC_THRESHOLDS.disk, "disk", "%"); chk(bwUtil(m), NOC_THRESHOLDS.util, "bandwidth utilization", "%");
  return { status: RANK[lvl], reasons };
}

const num = (v: unknown, lo: number, hi: number, f: string): number | undefined => {
  if (v === undefined || v === null || v === "") return undefined; const n = Number(v);
  if (!Number.isFinite(n) || n < lo || n > hi) throw new HttpError(400, `${f} must be a number between ${lo} and ${hi}`); return n;
};
const slug = (s: unknown) => String(s ?? "").trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);

export async function ingestTelemetry(store: Store, body: any, actorName: string) {
  const list = Array.isArray(body) ? body : body?.devices;
  if (!Array.isArray(list) || !list.length) throw new HttpError(400, "Body must be { source, devices: [...] } with at least one device");
  if (list.length > 500) throw new HttpError(413, "Send at most 500 devices per request");
  const collector = String(body?.source ?? body?.collector ?? actorName).slice(0, 60), now = nowIso(), out: NocDevice[] = [];
  for (const [i, x] of list.entries()) {
    const id = slug(x?.id ?? x?.name); if (!id) throw new HttpError(400, `devices[${i}] needs an id or name`);
    const type = String(x?.type ?? "").toLowerCase() as NocType; if (!NOC_TYPES.includes(type)) throw new HttpError(400, `devices[${i}].type must be one of ${NOC_TYPES.join(", ")}`);
    const mm = x?.metrics ?? {}, metrics: NocMetrics = {
      latencyMs: num(mm.latencyMs, 0, 60000, "latencyMs"), lossPct: num(mm.lossPct, 0, 100, "lossPct"), cpu: num(mm.cpu, 0, 100, "cpu"), mem: num(mm.mem, 0, 100, "mem"), disk: num(mm.disk, 0, 100, "disk"),
      bwInMbps: num(mm.bwInMbps, 0, 1e7, "bwInMbps"), bwOutMbps: num(mm.bwOutMbps, 0, 1e7, "bwOutMbps"), bwCapMbps: num(mm.bwCapMbps, 0, 1e7, "bwCapMbps"),
    };
    Object.keys(metrics).forEach((k) => (metrics as any)[k] === undefined && delete (metrics as any)[k]);
    const links: NocLink[] = (Array.isArray(x?.links) ? x.links : []).slice(0, 64).map((l: any) => ({ to: slug(l?.to), utilPct: num(l?.utilPct, 0, 100, "links.utilPct"), capMbps: num(l?.capMbps, 0, 1e7, "links.capMbps") })).filter((l: NocLink) => l.to);
    let config: NocDevice["config"];
    if (x?.config && typeof x.config === "object" && !Array.isArray(x.config)) {
      const es = Object.entries(x.config as Record<string, unknown>); if (es.length > 40) throw new HttpError(400, `devices[${i}].config has more than 40 keys`);
      config = {}; for (const [ck, cv] of es) { if (typeof cv === "string" || typeof cv === "number" || typeof cv === "boolean") config[String(ck).slice(0, 40)] = typeof cv === "string" ? cv.slice(0, 200) : cv; }
    }
    const prev = await store.get<NocDevice>(NOC_TABLE, id), bw = metrics.bwInMbps != null || metrics.bwOutMbps != null ? Math.max(metrics.bwInMbps ?? 0, metrics.bwOutMbps ?? 0) : undefined;
    const sample: NocSample = { t: now, latencyMs: metrics.latencyMs, lossPct: metrics.lossPct, cpu: metrics.cpu, mem: metrics.mem, disk: metrics.disk, bwMbps: bw };
    out.push({ id, name: String(x?.name ?? id).slice(0, 80), type, ip: x?.ip ? String(x.ip).slice(0, 64) : undefined, source: "live", up: x?.up !== false, metrics, links, config, history: [...(prev?.history ?? []), sample].slice(-60), receivedAt: now, collector });
  }
  await store.upsert(NOC_TABLE, out);
  return { received: out.length, devices: out.map((d) => ({ id: d.id, status: deviceStatus(d).status })) };
}

export async function listDevices(store: Store) {
  const rows = await store.select<NocDevice>(NOC_TABLE, { limit: 1000 });
  return rows.map((d) => ({ ...d, ...deviceStatus(d), ageSec: Math.max(0, Math.round((Date.now() - Date.parse(d.receivedAt)) / 1000)) }));
}
