// Real-time NOC evaluation for telemetry sent by native agents / collectors (POST /noc/telemetry).
// Before this module telemetry only updated the device table: nothing opened an alert or incident, nothing noticed a silent device, and no history was kept.
//  * Threshold breach (degraded/critical) or "down"  -> NocEvent + incident through the existing 14-step workflow (processAlert), deduplicated per device+condition.
//  * Metric back below the warning threshold         -> event resolved, incident resolved by FRESH DATA (onResolved).
//  * A device that stops reporting                   -> "No data from X" event + incident, resolved when data returns.
//  * Every sample is stored (noc_metrics) so history, charts and availability % are computed from stored data only.
import { admitDevices } from "./limits";
import type { Store } from "../soc/store";
import { bwUtil, deviceStatus, ingestTelemetry, NOC_TABLE, NOC_THRESHOLDS, type NocDevice } from "../soc/noc";
import { hid, rid } from "../soc/util";
import { NT, type NocEvent } from "./types";
import { onResolved, processAlert, type Ctx } from "./ops";

const T = (c: Ctx) => (c.now ? c.now() : Date.now());
const lvl = (v: number | undefined, th: readonly number[]) => (v == null ? 0 : v >= th[2] ? 3 : v >= th[1] ? 2 : v >= th[0] ? 1 : 0);
type Cond = { key: string; level: number; title: string; detail: string };

/** Every condition this device is in right now, by metric. Level 0 = fine, 1 = warning (shown, no incident), 2 = degraded, 3 = critical. */
export function conditions(d: Pick<NocDevice, "name" | "up" | "metrics">): Cond[] {
  const m = d.metrics, n = d.name, r1 = (x: number) => Math.round(x * 10) / 10;
  if (!d.up) return [{ key: "down", level: 3, title: `${n} is down`, detail: "The agent reports the device unreachable (failed availability check)." }];
  const out: Cond[] = [
    { key: "cpu", level: lvl(m.cpu, NOC_THRESHOLDS.cpu), title: `High CPU usage on ${n}`, detail: `CPU ${m.cpu != null ? r1(m.cpu) : "?"}% (warning ${NOC_THRESHOLDS.cpu[0]}, degraded ${NOC_THRESHOLDS.cpu[1]}, critical ${NOC_THRESHOLDS.cpu[2]})` },
    { key: "mem", level: lvl(m.mem, NOC_THRESHOLDS.mem), title: `High memory usage on ${n}`, detail: `Memory ${m.mem != null ? r1(m.mem) : "?"}% used` },
    { key: "disk", level: lvl(m.disk, NOC_THRESHOLDS.disk), title: `Disk almost full on ${n}`, detail: `Disk ${m.disk != null ? r1(m.disk) : "?"}% used` },
    { key: "latency", level: lvl(m.latencyMs, NOC_THRESHOLDS.latencyMs), title: `High latency to ${n}`, detail: `Latency ${m.latencyMs != null ? r1(m.latencyMs) : "?"} ms` },
    { key: "loss", level: lvl(m.lossPct, NOC_THRESHOLDS.lossPct), title: `Packet loss to ${n}`, detail: `Packet loss ${m.lossPct != null ? r1(m.lossPct) : "?"}%` },
    { key: "bw", level: lvl(bwUtil(m), NOC_THRESHOLDS.util), title: `High bandwidth utilization on ${n}`, detail: `Link utilization ${bwUtil(m) != null ? r1(bwUtil(m)!) : "?"}%` },
  ];
  return out;
}
const sev = (l: number): NocEvent["severity"] => (l >= 3 ? "critical" : "high");

async function openOrUpdate(c: Ctx, dev: NocDevice, cd: Cond, stamp: string) {
  const id = hid("nev", `tel|${dev.id}|${cd.key}`), prev = await c.store.get<NocEvent>(NT.events, id);
  if (cd.level >= 2) {
    if (prev && prev.status === "problem") { const s = sev(cd.level); if (prev.severity !== s || prev.detail !== cd.detail) { prev.severity = s; prev.detail = cd.detail; await c.store.upsert(NT.events, [prev]); } return prev.incidentId ? { opened: false } : { opened: false }; }
    const ev: NocEvent = { id, sourceId: "native", deviceId: dev.id, host: dev.name, severity: sev(cd.level), title: cd.title, detail: cd.detail, status: "problem", time: stamp, receivedAt: stamp, origin: "system" };
    await c.store.upsert(NT.events, [ev]); await processAlert(c, ev, { category: cd.key === "down" ? "availability" : cd.key === "bw" || cd.key === "latency" || cd.key === "loss" ? "network" : "server" }); return { opened: true };
  }
  if (cd.level === 0 && prev && prev.status === "problem") { prev.status = "resolved"; prev.resolvedAt = stamp; await c.store.upsert(NT.events, [prev]); await onResolved(c, prev, "Fresh telemetry shows the metric is back to normal."); return { resolved: true }; }
  return {};
}

/** Stores the telemetry, keeps history, and opens/resolves events + incidents from what the data says. */
export async function ingestAndEvaluate(c: Ctx, body: any) {
  let skipped: string[] = [], lim: number | null = null;
  if (c.deviceMax != null) {                                    // plan device limit (only when billing is enforced): refuse NEW devices beyond it, never block existing ones
    const list = Array.isArray(body) ? body : body?.devices;
    if (Array.isArray(list) && list.length && list.length <= 500) {
      const idOf = (x: any) => String(x?.id ?? x?.name ?? "").trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
      const adm = await admitDevices(c.store, list.map(idOf).filter(Boolean), c.deviceMax); skipped = adm.skipped; lim = adm.limit;
      if (skipped.length) { const kept = list.filter((x: any) => !idOf(x) || adm.allowed.has(idOf(x))); body = Array.isArray(body) ? kept : { ...body, devices: kept };
        if (!kept.length) return { received: 0, devices: [], eventsOpened: 0, eventsResolved: 0, stored: 0, deviceLimit: lim, deviceLimitSkipped: skipped.length, skippedDevices: skipped.slice(0, 50) }; }
    }
  }
  const res = await ingestTelemetry(c.store, body, c.actor.name), stamp = new Date(T(c)).toISOString();
  let opened = 0, resolved = 0; const rows: any[] = [];
  for (const o of res.devices) {
    const dev = await c.store.get<NocDevice>(NOC_TABLE, o.id); if (!dev) continue;
    const m = dev.metrics, kv: Record<string, number | undefined> = { up: dev.up ? 1 : 0, cpu: m.cpu, mem: m.mem, disk: m.disk, latencyMs: m.latencyMs, lossPct: m.lossPct, bwInMbps: m.bwInMbps, bwOutMbps: m.bwOutMbps };
    for (const [key, value] of Object.entries(kv)) if (value != null) rows.push({ id: rid("nmt"), deviceId: dev.id, sourceId: "native", key, value, t: stamp });
    const stale = hid("nev", `tel|${dev.id}|stale`), se = await c.store.get<NocEvent>(NT.events, stale);
    if (se && se.status === "problem") { se.status = "resolved"; se.resolvedAt = stamp; await c.store.upsert(NT.events, [se]); await onResolved(c, se, "The device is sending data again."); resolved++; }
    for (const cd of conditions(dev)) { const r: any = await openOrUpdate(c, dev, cd, stamp); if (r.opened) opened++; if (r.resolved) resolved++; }
    if (!dev.up) for (const cd of conditions({ ...dev, up: true })) { /* while down, metric events stay as they are */ void cd; }
    if (dev.up) { const down = await c.store.get<NocEvent>(NT.events, hid("nev", `tel|${dev.id}|down`)); if (down && down.status === "problem") { down.status = "resolved"; down.resolvedAt = stamp; await c.store.upsert(NT.events, [down]); await onResolved(c, down, "Fresh telemetry shows the device is up again."); resolved++; } }
  }
  if (rows.length) await c.store.upsert(NT.metrics, rows);
  return { ...res, eventsOpened: opened, eventsResolved: resolved, stored: rows.length, ...(skipped.length ? { deviceLimit: lim, deviceLimitSkipped: skipped.length, skippedDevices: skipped.slice(0, 50) } : {}) };
}

/** Devices fed by native agents/collectors (not by a monitoring source) that stopped reporting. Run on every overview request and by a scheduler. */
export async function sweepDevices(c: Ctx) {
  const now = T(c), stamp = new Date(now).toISOString(), out: string[] = [];
  for (const d of await c.store.select<NocDevice>(NOC_TABLE, { limit: 1000 })) {
    if (d.sourceId) continue;                                   // source-backed devices are covered by the source sweep
    const after = Number(d.config?.staleAfterSec) || 300, age = now - Date.parse(d.receivedAt);
    if (!(age > after * 1000)) continue;
    const id = hid("nev", `tel|${d.id}|stale`), prev = await c.store.get<NocEvent>(NT.events, id); if (prev && prev.status === "problem") continue;
    const ev: NocEvent = { id, sourceId: "native", deviceId: d.id, host: d.name, severity: "high", title: `No data from ${d.name}`, detail: `Last sample ${d.receivedAt} (${Math.round(age / 1000)} s ago, limit ${after} s). The device or its agent has stopped reporting.`, status: "problem", time: stamp, receivedAt: stamp, origin: "system" };
    await c.store.upsert(NT.events, [ev]); await processAlert(c, ev, { category: "availability" }); out.push(d.id);
  }
  return out;
}


/** PostgREST/Supabase cap one response (default 1000 rows), so long windows are read in pages keyed on the time column. Never silently truncates: stops only when a page is short or `max` rows are collected. */
async function pagedByTime<R extends { id?: string; t: string }>(c: Ctx, where: Record<string, string>, since: string, max: number, page = 1000): Promise<R[]> {
  const out: R[] = [], seen = new Set<string>(); let from = since;
  for (let i = 0; i < 500 && out.length < max; i++) {
    const rows = await c.store.select<R>(NT.metrics, { where, gte: ["t", from], order: ["t", "asc"], limit: page });
    let added = 0; for (const r of rows) { const k = r.id ?? `${r.t}|${out.length}`; if (!seen.has(k)) { seen.add(k); out.push(r); added++; } }
    if (rows.length < page || added === 0) break; from = rows[rows.length - 1].t;
  }
  return out.slice(0, max);
}

/** Availability from STORED samples only. Percentage = up samples / all samples in the window; coverage tells how trustworthy that is. */
export async function availability(c: Ctx, hours = 24, deviceId?: string) {
  const since = new Date(T(c) - hours * 3600_000).toISOString();
  const rows = await pagedByTime<{ id?: string; deviceId: string; key: string; value: number; t: string }>(c, { key: "up", ...(deviceId ? { deviceId } : {}) }, since, 200000);
  const by = new Map<string, typeof rows>(); for (const r of rows) (by.get(r.deviceId) ?? by.set(r.deviceId, []).get(r.deviceId)!).push(r);
  const devs = new Map((await c.store.select<NocDevice>(NOC_TABLE, { limit: 1000 })).map((d) => [d.id, d]));
  return { windowHours: hours, since, basis: "stored 'up' samples; each sample is one agent report", devices: [...by.entries()].map(([id, l]) => {
    const up = l.filter((x) => x.value === 1).length, first = l[0].t, last = l[l.length - 1].t; let longestGapSec = 0; for (let i = 1; i < l.length; i++) longestGapSec = Math.max(longestGapSec, Math.round((Date.parse(l[i].t) - Date.parse(l[i - 1].t)) / 1000));
    return { deviceId: id, name: devs.get(id)?.name ?? id, samples: l.length, upSamples: up, downSamples: l.length - up, availabilityPct: Math.round((up / l.length) * 10000) / 100, firstSample: first, lastSample: last, longestGapSec };
  }) };
}
export async function history(c: Ctx, deviceId: string, key: string, hours = 24, limit = 1000) {
  if (!/^[a-zA-Z]+$/.test(key)) return { deviceId, key, points: [] };
  const since = new Date(T(c) - hours * 3600_000).toISOString();
  const rows = await pagedByTime<{ id?: string; value: number; t: string }>(c, { deviceId, key }, since, limit);
  return { deviceId, key, hours, points: rows.map((r) => ({ t: r.t, v: r.value })) };
}

/** Raw stored samples (with their row ids, so analysis can cite real evidence) for one device + metric. */
export async function seriesRows(c: Ctx, deviceId: string, key: string, hours = 24, max = 5000) {
  if (!/^[a-zA-Z]+$/.test(key)) return [];
  return pagedByTime<{ id: string; value: number; t: string }>(c, { deviceId, key }, new Date(T(c) - hours * 3600_000).toISOString(), max);
}
