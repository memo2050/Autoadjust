// NOC operations core: monitoring sources, snapshots, alerts -> incidents -> 14-step workflow, approvals, execution, verification.
// Everything here is stored in the database. Nothing is simulated; absent data is reported as "no data".
import type { Store } from "../soc/store";
import { HttpError, audit, type Actor } from "../soc/pipeline";
import { deviceStatus, NOC_TABLE, NOC_TYPES, type NocDevice, type NocType } from "../soc/noc";
import { hid, nowIso, rid, ms } from "../soc/util";
import type { ModelFn } from "../soc/agents";
import { cryptoConfigured, decryptJson, encryptJson } from "./crypto";
import { assertSafeTarget, type Resolver } from "../tenant/ssrf";
import { executeScript, fetchSnapshot, fromErr, testConnection, zSeverity, type Fetcher, type ZConf, type ZHost, type ZProblem } from "./zabbix";
import { admitDevices } from "./limits";
import { NT, type Activity, type AgentKey, type AutoAction, type Approval, type Execution, type Iface, type NocEvent, type NocIncident, type Recommendation, type Source, type SourceStatus, type SourceType, type WfStep, type Workflow } from "./types";

export interface Ctx { store: Store; actor: Actor; fetcher?: Fetcher; model?: ModelFn | null; now?: () => number; resolver?: Resolver; /** monitored-device limit for this organization (null/undefined = unlimited) */ deviceMax?: number | null }
const T = (c: Ctx) => (c.now ? c.now() : Date.now());
const iso = (c: Ctx) => new Date(T(c)).toISOString();
const SOURCE_TYPES: SourceType[] = ["zabbix", "prometheus", "grafana", "snmp", "syslog", "http", "icmp", "generic"];

/* ---------------- sources ---------------- */
export function validateUrl(u: string): string {
  let url: URL; try { url = new URL(u); } catch { throw new HttpError(400, "URL is not valid (example: https://zabbix.example.lan)"); }
  if (!/^https?:$/.test(url.protocol)) throw new HttpError(400, "URL must start with http:// or https://");
  if (url.username || url.password) throw new HttpError(400, "Do not put credentials in the URL; use the credential fields.");
  const h = url.hostname.toLowerCase();
  if (/^169\.254\./.test(h) || h === "metadata.google.internal" || h === "0.0.0.0") throw new HttpError(400, "That address is blocked (link-local / metadata).");
  const allow = (process.env.NOC_ALLOWED_HOSTS ?? "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  if (allow.length && !allow.includes(h)) throw new HttpError(400, `Host ${h} is not in NOC_ALLOWED_HOSTS.`);
  return url.toString().replace(/\/+$/, "");
}
export function publicSource(s: Source, now = Date.now()) {
  const { secret: _s, ...rest } = s; const st = effectiveStatus(s, now);
  return { ...rest, status: st.status, detail: st.detail, ageSec: s.lastSyncAt ? Math.round((now - ms(s.lastSyncAt)) / 1000) : null };
}
export function effectiveStatus(s: Source, now: number): { status: SourceStatus; detail: string } {
  if (s.status === "CONNECTED" && s.lastSyncAt && now - ms(s.lastSyncAt) > s.staleAfterSec * 1000) return { status: "DISCONNECTED", detail: `No data received since ${s.lastSyncAt} (more than ${s.staleAfterSec} s). Last known state was CONNECTED.` };
  if (s.status === "CONNECTED" && !s.lastSyncAt) return { status: "NO DATA", detail: "Connected, but no data has been received yet." };
  return { status: s.status, detail: s.detail };
}
export async function createSource(c: Ctx, b: any) {
  const name = String(b?.name ?? "").trim().slice(0, 60), type = String(b?.type ?? "zabbix") as SourceType, mode = b?.mode === "push" ? "push" : "pull";
  if (!name) throw new HttpError(400, "name is required"); if (!SOURCE_TYPES.includes(type)) throw new HttpError(400, `type must be one of ${SOURCE_TYPES.join(", ")}`);
  const url = mode === "push" && !b?.url ? "(bridge: outbound push)" : validateUrl(String(b?.url ?? ""));
  if (mode === "pull") await safeUrl(c, url, "Monitoring source URL");
  const creds = { token: b?.token ? String(b.token) : undefined, user: b?.user ? String(b.user) : undefined, password: b?.password ? String(b.password) : undefined };
  const has = !!(creds.token || creds.user || creds.password);
  if (has && !cryptoConfigured()) throw new HttpError(400, "The server has no NOC_SECRET_KEY, so it refuses to store credentials. Set NOC_SECRET_KEY (32+ random characters) on the backend first.");
  const stale = Math.max(60, Math.min(86400, Number(b?.staleAfterSec) || 300)), t = iso(c);
  const s: Source = { id: rid("src"), name, type, url, mode, enabled: true, status: "NO DATA", detail: "Created. Not tested or synchronized yet.", secret: has ? encryptJson(creds) : undefined, hasSecret: has, verifyTls: b?.verifyTls !== false, staleAfterSec: stale, deviceCount: 0, interfaceCount: 0, createdBy: c.actor.name, createdAt: t, updatedAt: t };
  await c.store.upsert(NT.sources, [s]); await audit(c.store, c.actor, "noc.source.create", s.id, { name, type, mode, url, credentials: has ? "stored encrypted" : "none" });
  return publicSource(s, T(c));
}
async function getSource(c: Ctx, id: string): Promise<Source> { const s = await c.store.get<Source>(NT.sources, id); if (!s) throw new HttpError(404, "Monitoring source not found"); return s; }
/** Customer-typed addresses are fetched by OUR server, so they are re-checked (DNS rebinding) every time they are used. Push-mode sources are never contacted. */
const safeUrl = (c: Ctx, u: string, what: string) => assertSafeTarget(u, what, process.env, c.resolver, { allowPath: true, httpEnv: "NOC_ALLOW_HTTP" });
async function zconfSafe(c: Ctx, s: Source): Promise<ZConf> { if (s.mode === "pull") await safeUrl(c, s.url, "Monitoring source URL"); return zconf(s); }
function zconf(s: Source): ZConf { const cr = s.secret ? decryptJson(s.secret) : {}; return { url: s.url, token: cr.token, user: cr.user, password: cr.password, verifyTls: s.verifyTls }; }
export async function testSource(c: Ctx, id: string) {
  const s = await getSource(c, id); let r: { status: SourceStatus; detail: string; version?: string };
  if (s.type !== "zabbix") r = { status: "NO DATA", detail: `${s.type} connections are not built yet. Send ${s.type} data through Zabbix, or post alerts to /api/soc/noc/alerts.` };
  else if (s.mode === "push") r = { status: s.lastSyncAt ? "CONNECTED" : "NO DATA", detail: s.lastSyncAt ? "Bridge is pushing data." : "Waiting for the bridge to push its first batch. A push source cannot be tested from the backend." };
  else { try { r = await testConnection(await zconfSafe(c, s), c.fetcher); } catch (e) { r = fromErr(e); } }
  s.status = r.status === "CONNECTED" && !s.lastSyncAt ? "CONNECTED" : r.status; s.detail = r.detail; s.version = r.version ?? s.version; s.lastTestAt = iso(c); s.updatedAt = s.lastTestAt; if (r.status !== "CONNECTED") s.lastErrorAt = s.lastTestAt;
  await c.store.upsert(NT.sources, [s]); await audit(c.store, c.actor, "noc.source.test", id, { status: r.status });
  return { ...publicSource(s, T(c)), testStatus: r.status, status: r.status };
}
export async function deleteSource(c: Ctx, id: string) { await getSource(c, id); await c.store.remove(NT.sources, { id }); await audit(c.store, c.actor, "noc.source.delete", id, {}); return { deleted: id }; }
export async function syncSource(c: Ctx, id: string) {
  const s = await getSource(c, id); if (s.type !== "zabbix" || s.mode !== "pull") throw new HttpError(400, "Only pull-mode Zabbix sources can be synchronized from the backend. Push sources are updated by their bridge.");
  try { const snap = await fetchSnapshot(await zconfSafe(c, s), c.fetcher); const r = await applySnapshot(c, s, snap.hosts, snap.problems); await audit(c.store, c.actor, "noc.source.sync", id, r); return { source: publicSource((await getSource(c, id)), T(c)), ...r }; }
  catch (e) { const r = fromErr(e); s.status = r.status; s.detail = r.detail; s.lastErrorAt = iso(c); s.updatedAt = s.lastErrorAt; await c.store.upsert(NT.sources, [s]); await audit(c.store, c.actor, "noc.source.sync_failed", id, { status: r.status }); throw new HttpError(502, r.detail, { status: r.status }); }
}

/* ---------------- snapshots ---------------- */
const n1 = (v: number | undefined) => (v == null ? undefined : Math.round(v * 10) / 10);
export async function applySnapshot(c: Ctx, s: Source, hosts: ZHost[], problems: ZProblem[]) {
  const t = iso(c), stamp = T(c); let ifaces = 0, newEvents = 0, incidents = 0;
  const adm = await admitDevices(c.store, hosts.map((h) => h.id), c.deviceMax); let deviceLimitSkipped = adm.skipped.length;
  for (const h of hosts) {
    if (!adm.allowed.has(h.id)) continue;                      // new device beyond the plan's device limit: not added (existing devices are never blocked)
    const prev = await c.store.get<NocDevice>(NOC_TABLE, h.id);
    const bwIn = h.interfaces.reduce((a, i) => a + (i.inBps ?? 0), 0) / 1e6, bwOut = h.interfaces.reduce((a, i) => a + (i.outBps ?? 0), 0) / 1e6, haveBw = h.interfaces.some((i) => i.inBps != null || i.outBps != null);
    const cap = h.interfaces.reduce((a, i) => a + (i.speedBps ?? 0), 0) / 1e6;
    const metrics: NocDevice["metrics"] = { ...h.metrics }; if (haveBw) { metrics.bwInMbps = n1(bwIn); metrics.bwOutMbps = n1(bwOut); if (cap > 0) metrics.bwCapMbps = n1(cap); }
    (Object.keys(metrics) as (keyof typeof metrics)[]).forEach((k) => metrics[k] === undefined && delete metrics[k]);
    const sample = { t, latencyMs: metrics.latencyMs, lossPct: metrics.lossPct, cpu: metrics.cpu, mem: metrics.mem, disk: metrics.disk, bwMbps: haveBw ? Math.max(bwIn, bwOut) : undefined };
    const dev: NocDevice = { id: h.id, name: h.name, type: (NOC_TYPES as readonly string[]).includes(h.type) ? h.type : "endpoint", ip: h.ip, source: "live", up: h.up, metrics, links: prev?.links ?? [], history: [...(prev?.history ?? []), sample].slice(-120), receivedAt: t, collector: s.name, sourceId: s.id, hostId: h.hostid, hostname: h.hostname, uptimeSec: h.uptimeSec, known: h.known, unsupported: h.unsupported, itemErrors: h.itemErrors, groups: h.groups, config: prev?.config };
    await c.store.upsert(NOC_TABLE, [dev]);
    const rows = h.interfaces.map((i): Iface => ({ id: hid("nif", h.id + "|" + i.name), deviceId: h.id, sourceId: s.id, name: i.name, description: i.description, up: i.up, inBps: i.inBps, outBps: i.outBps, speedBps: i.speedBps, utilPct: i.speedBps && (i.inBps != null || i.outBps != null) ? n1(Math.max(i.inBps ?? 0, i.outBps ?? 0) / i.speedBps * 100) : undefined, errorsIn: i.errorsIn, errorsOut: i.errorsOut, dropsIn: i.dropsIn, dropsOut: i.dropsOut, updatedAt: t }));
    if (rows.length) await c.store.upsert(NT.interfaces, rows); ifaces += rows.length;
    const mrows = Object.entries({ latencyMs: metrics.latencyMs, lossPct: metrics.lossPct, cpu: metrics.cpu, mem: metrics.mem, disk: metrics.disk, uptimeSec: h.uptimeSec, bwInMbps: metrics.bwInMbps, bwOutMbps: metrics.bwOutMbps, up: h.known ? (h.up ? 1 : 0) : undefined }).filter(([, v]) => v != null).map(([k, v]) => ({ id: rid("nmt"), deviceId: h.id, sourceId: s.id, key: k, value: Number(v), t }));
    if (mrows.length) await c.store.upsert(NT.metrics, mrows);
  }
  const byHostId = new Map(hosts.map((h) => [h.hostid, h]));
  for (const p of problems) {
    const id = hid("nev", s.id + "|" + p.eventid), prev = await c.store.get<NocEvent>(NT.events, id), host = p.host ?? p.hostName ?? "unknown", dev = byHostId.get(p.hostid ?? "")?.id;
    if (prev) { if (!prev.resolvedAt && p.resolved) { prev.status = "resolved"; prev.resolvedAt = t; await c.store.upsert(NT.events, [prev]); await onResolved(c, prev); } continue; }
    const ev: NocEvent = { id, sourceId: s.id, externalId: p.eventid, deviceId: dev, host, severity: zSeverity(p.severity), title: p.name, status: p.resolved ? "resolved" : "problem", time: new Date(p.clock * 1000).toISOString(), receivedAt: t, resolvedAt: p.resolved ? t : undefined, origin: "zabbix" };
    await c.store.upsert(NT.events, [ev]); newEvents++;
    if (!p.resolved && incidents < 50 && (ev.severity === "warning" || ev.severity === "high" || ev.severity === "critical")) { await processAlert(c, ev); incidents++; }
  }
  // A problem this source reported earlier but no longer lists (not even as resolved) is cleared in Zabbix.
  const seen = new Set(problems.map((p) => String(p.eventid)));
  for (const ev of await c.store.select<NocEvent>(NT.events, { where: { sourceId: s.id, status: "problem" }, limit: 500 })) if (ev.origin === "zabbix" && ev.externalId && !seen.has(ev.externalId)) { ev.status = "resolved"; ev.resolvedAt = t; await c.store.upsert(NT.events, [ev]); await onResolved(c, ev, "Zabbix no longer lists this problem."); }
  s.status = "CONNECTED"; s.detail = `Synchronized ${hosts.length} host(s), ${ifaces} interface(s), ${problems.length} problem record(s).`; s.lastSyncAt = t; s.deviceCount = hosts.length; s.interfaceCount = ifaces; if (newEvents) s.lastEventAt = t; s.updatedAt = t;
  const wasDown = s.disconnectedAt; s.disconnectedAt = undefined; await c.store.upsert(NT.sources, [s]);
  if (wasDown) await recoverSource(c, s);
  await checkVerifying(c, stamp);
  return { hosts: hosts.length - deviceLimitSkipped, interfaces: ifaces, newEvents, incidentsOpened: incidents, at: t, ...(deviceLimitSkipped ? { deviceLimit: adm.limit, deviceLimitSkipped, skippedDevices: adm.skipped.slice(0, 50) } : {}) };
}
/** Marks sources that stopped delivering data as DISCONNECTED and records it once as an event and an incident. */
export async function sweepSources(c: Ctx) {
  const now = T(c), list = await c.store.select<Source>(NT.sources, { limit: 200 }); const out: string[] = [];
  for (const s of list) {
    if (!s.enabled || s.disconnectedAt) continue; const e = effectiveStatus(s, now);
    if (e.status === "DISCONNECTED" && s.status === "CONNECTED") {
      s.status = "DISCONNECTED"; s.detail = e.detail; s.disconnectedAt = iso(c); s.lastErrorAt = s.disconnectedAt; await c.store.upsert(NT.sources, [s]);
      const ev: NocEvent = { id: hid("nev", s.id + "|disconnect|" + s.disconnectedAt), sourceId: s.id, host: s.name, severity: "critical", title: `Monitoring source "${s.name}" stopped sending data`, detail: e.detail, status: "problem", time: s.disconnectedAt, receivedAt: s.disconnectedAt, origin: "system" };
      await c.store.upsert(NT.events, [ev]); await processAlert(c, ev, { category: "monitoring" }); await audit(c.store, { name: "system", role: "system" }, "noc.source.disconnected", s.id, { detail: e.detail }); out.push(s.id);
    }
  }
  return out;
}
async function recoverSource(c: Ctx, s: Source) {
  const evs = (await c.store.select<NocEvent>(NT.events, { where: { sourceId: s.id, origin: "system", status: "problem" }, limit: 50 }));
  for (const ev of evs) { ev.status = "resolved"; ev.resolvedAt = iso(c); await c.store.upsert(NT.events, [ev]); await onResolved(c, ev, "Monitoring data is flowing again."); }
}

/* ---------------- alerts ---------------- */
export interface Alert { sourceId?: string; origin: NocEvent["origin"]; externalId?: string; host: string; ip?: string; severity: NocEvent["severity"]; title: string; detail?: string; status: "problem" | "resolved"; time: string }
export function normalizeAlerts(body: any): Alert[] {
  const out: Alert[] = []; const sev = (x: string): Alert["severity"] => (/disaster|critical|page/i.test(x) ? "critical" : /high|error/i.test(x) ? "high" : /average|warn/i.test(x) ? "warning" : "info");
  if (body?.source === "zabbix" || body?.eventid) out.push({ origin: "zabbix", externalId: String(body.eventid ?? ""), host: String(body.host ?? body.hostname ?? "unknown"), ip: body.ip, severity: sev(String(body.severity ?? "")), title: String(body.name ?? body.subject ?? "Zabbix problem").slice(0, 300), detail: body.message ? String(body.message).slice(0, 1000) : undefined, status: /^(ok|resolved)$/i.test(String(body.status ?? "")) ? "resolved" : "problem", time: body.time ? new Date(body.time).toISOString() : new Date().toISOString() });
  else if (Array.isArray(body?.alerts)) for (const a of body.alerts) out.push({ origin: String(body.receiver ?? "").length || a.generatorURL ? "alertmanager" : "grafana", externalId: String(a.fingerprint ?? ""), host: String(a.labels?.instance ?? a.labels?.host ?? a.labels?.hostname ?? "unknown"), severity: sev(String(a.labels?.severity ?? "warning")), title: String(a.annotations?.summary ?? a.labels?.alertname ?? "Alert").slice(0, 300), detail: a.annotations?.description ? String(a.annotations.description).slice(0, 1000) : undefined, status: a.status === "resolved" ? "resolved" : "problem", time: a.startsAt ? new Date(a.startsAt).toISOString() : new Date().toISOString() });
  else if (body?.host && body?.title) out.push({ origin: "generic", externalId: body.id ? String(body.id) : undefined, host: String(body.host), ip: body.ip, severity: sev(String(body.severity ?? "warning")), title: String(body.title).slice(0, 300), detail: body.detail ? String(body.detail).slice(0, 1000) : undefined, status: body.status === "resolved" ? "resolved" : "problem", time: body.time ? new Date(body.time).toISOString() : new Date().toISOString() });
  else throw new HttpError(400, "Unrecognized alert payload. Send a Zabbix webhook object, a Grafana/Alertmanager {alerts:[...]} body, or {host, title, severity}.");
  return out.slice(0, 100);
}
export async function receiveAlerts(c: Ctx, alerts: Alert[], sourceId?: string) {
  const out: { eventId: string; incidentId?: string; status: string }[] = [];
  for (const a of alerts) {
    const devs = await c.store.select<NocDevice>(NOC_TABLE, { limit: 1000 }), key = a.host.toLowerCase();
    const dev = devs.find((d) => d.id === key || d.name.toLowerCase() === key || (d.hostname ?? "").toLowerCase() === key || (a.ip && d.ip === a.ip));
    const id = hid("nev", (sourceId ?? a.origin) + "|" + (a.externalId || a.host + "|" + a.title + "|" + a.time)), prev = await c.store.get<NocEvent>(NT.events, id);
    if (prev) { if (a.status === "resolved" && prev.status !== "resolved") { prev.status = "resolved"; prev.resolvedAt = iso(c); await c.store.upsert(NT.events, [prev]); await onResolved(c, prev); } out.push({ eventId: id, incidentId: prev.incidentId, status: "duplicate" }); continue; }
    const ev: NocEvent = { id, sourceId: sourceId ?? "(webhook)", externalId: a.externalId, deviceId: dev?.id, host: a.host, severity: a.severity, title: a.title, detail: a.detail, status: a.status, time: a.time, receivedAt: iso(c), resolvedAt: a.status === "resolved" ? iso(c) : undefined, origin: a.origin };
    await c.store.upsert(NT.events, [ev]);
    if (sourceId) { const s = await c.store.get<Source>(NT.sources, sourceId); if (s) { s.lastEventAt = ev.receivedAt; await c.store.upsert(NT.sources, [s]); } }
    const inc = a.status === "problem" && a.severity !== "info" ? await processAlert(c, ev) : undefined; out.push({ eventId: id, incidentId: inc?.id, status: a.status });
  }
  return out;
}

/* ---------------- incident workflow (the 14 steps) ---------------- */
export const WF_NAMES = ["Receive the alert from the monitoring source", "Create the incident record", "Identify the affected device", "Assign the incident to an AI agent", "Retrieve metrics and history", "Analyze the incident", "Identify the probable root cause", "Generate recommended corrective actions", "Request administrator approval when required", "Execute the authorized action through the backend", "Retrieve fresh monitoring information", "Verify whether the problem is resolved", "Update the incident status", "Record the process in execution history"];
export function categorize(title: string): { category: string; agent: AgentKey } {
  const t = title.toLowerCase();
  if (/monitoring source|stopped sending/.test(t)) return { category: "monitoring", agent: "supervisor" };
  if (/bandwidth|traffic|throughput|utili[sz]ation.*(link|interface)|saturat/.test(t)) return { category: "bandwidth", agent: "performance" };
  if (/cpu|memory|ram|swap|disk|filesystem|file system|space|service|process|uptime|restart|reboot|load/.test(t)) return { category: "server", agent: "server" };
  if (/unreachable|down|ping|icmp|latency|packet|loss|interface|link|port|bgp|ospf|snmp|dns|timeout/.test(t)) return { category: "network", agent: "engineer" };
  return { category: "general", agent: "responder" };
}
const sevInc = (s: NocEvent["severity"]): NocIncident["severity"] => (s === "critical" ? "critical" : s === "high" ? "high" : s === "warning" ? "medium" : "low");
function stepRunner(wf: Workflow, c: Ctx) {
  return async (n: number, fn: () => Promise<string | void>, optional = false) => {
    const st = wf.steps[n - 1]; st.status = "running"; st.startedAt = iso(c); const t0 = Date.now();
    try { const d = await fn(); st.status = "done"; st.detail = d ? String(d).slice(0, 400) : undefined; } catch (e: any) { st.status = optional ? "skipped" : "failed"; st.error = String(e?.message ?? e).slice(0, 300); if (!optional) throw e; }
    finally { st.endedAt = iso(c); st.ms = Date.now() - t0; wf.updatedAt = st.endedAt; await c.store.upsert(NT.workflows, [wf]); }
  };
}
export async function processAlert(c: Ctx, ev: NocEvent, force?: { category?: string }): Promise<NocIncident> {
  const t = iso(c), wf: Workflow = { id: rid("nwf"), incidentId: "", status: "running", steps: WF_NAMES.map((name, i) => ({ n: i + 1, name, status: "waiting" as const })), createdAt: t, updatedAt: t }, run = stepRunner(wf, c);
  let inc!: NocIncident; let dev: NocDevice | null = null; const cat = categorize(ev.title); if (force?.category) cat.category = force.category;
  await run(1, async () => `${ev.origin} alert "${ev.title}" on ${ev.host} (${ev.severity}) received ${ev.receivedAt}`);
  await run(2, async () => {
    const open = (await c.store.select<NocIncident>(NT.incidents, { limit: 500 })).filter((i) => i.status !== "Resolved" && i.status !== "Closed").find((i) => i.host === ev.host && i.title === ev.title);
    if (open) { inc = open; if (!inc.eventIds.includes(ev.id)) inc.eventIds.push(ev.id); inc.updatedAt = t; wf.incidentId = inc.id; return `Alert matches open incident ${inc.id}; attached (no duplicate created).`; }
    inc = { id: "NOC-" + (1000 + (await c.store.select<NocIncident>(NT.incidents, { limit: 5000 })).length + 1), title: ev.title, severity: sevInc(ev.severity), status: "New", deviceId: ev.deviceId, host: ev.host, sourceId: ev.sourceId, eventIds: [ev.id], externalId: ev.externalId, assignedAgent: cat.agent, category: cat.category, recommendations: [], approvalIds: [], executionIds: [], createdAt: t, updatedAt: t, source: "live" };
    wf.incidentId = inc.id; await c.store.upsert(NT.incidents, [inc]); ev.incidentId = inc.id; await c.store.upsert(NT.events, [ev]); return `Created ${inc.id} (${inc.severity}).`;
  });
  inc.workflowId = wf.id; await c.store.upsert(NT.incidents, [inc]);
  await run(3, async () => { dev = ev.deviceId ? await c.store.get<NocDevice>(NOC_TABLE, ev.deviceId) : null; if (!dev) { return `Host "${ev.host}" is not in the monitored device inventory; analysis will use the alert text only.`; } inc.deviceId = dev.id; return `${dev.name} (${dev.type}${dev.ip ? ", " + dev.ip : ""}), status ${deviceStatus(dev).status}.`; });
  await run(4, async () => { inc.assignedAgent = cat.agent; inc.status = "Investigating"; return `Assigned to the ${AGENT_NAMES[cat.agent]} (category: ${cat.category}).`; });
  let facts: string[] = []; let related: NocEvent[] = [];
  await run(5, async () => {
    facts = []; if (dev) { const d = dev as NocDevice, s = deviceStatus(d); facts.push(`status ${s.status}${s.reasons.length ? ": " + s.reasons.join("; ") : ""}`); if (d.uptimeSec != null) facts.push(`uptime ${Math.round(d.uptimeSec / 3600)} h`); const h = (d.history ?? []).slice(-12); if (h.length > 1) facts.push(`${h.length} recent samples; cpu ${h.map((x) => x.cpu ?? "-").join(",")}; latency ${h.map((x) => x.latencyMs ?? "-").join(",")}`); const ifs = await c.store.select<Iface>(NT.interfaces, { where: { deviceId: d.id }, limit: 100 }); const bad = ifs.filter((i) => i.up === false || (i.errorsIn ?? 0) + (i.errorsOut ?? 0) > 0 || (i.dropsIn ?? 0) + (i.dropsOut ?? 0) > 0); facts.push(`${ifs.length} interface(s) known, ${bad.length} with a problem${bad.length ? " (" + bad.slice(0, 4).map((i) => i.name + (i.up === false ? " down" : " errors/drops")).join(", ") + ")" : ""}`); }
    related = (await c.store.select<NocEvent>(NT.events, { limit: 300 })).filter((e) => e.id !== ev.id && Math.abs(ms(e.time) - ms(ev.time)) < 30 * 60_000 && (e.deviceId === ev.deviceId || e.host === ev.host || (e.status === "problem" && (e.severity === "critical" || e.severity === "high"))));
    facts.push(`${related.length} related event(s) within 30 minutes`); return facts.join(" | ");
  });
  await run(6, async () => {
    const evidence = [`alert: ${ev.title}`, ...facts]; let aiText: string | undefined, aiError: string | undefined;
    if (c.model) { try { const r = await c.model("You are a NOC incident analyst. Use ONLY the evidence given. Say what is known, what is not, and label every cause as a hypothesis. Max 120 words.", `<evidence>\n${evidence.join("\n")}\n${related.slice(0, 8).map((e) => `related: ${e.host} ${e.title} (${e.severity})`).join("\n")}\n</evidence>`); aiText = r.text.slice(0, 1500); } catch (e: any) { aiError = String(e?.message ?? e).slice(0, 200); } }
    inc.analysis = { method: aiText ? "ai+rules" : "rules", summary: `${ev.title} on ${ev.host}. ${dev ? "Device is " + deviceStatus(dev).status + "." : "Device not in inventory."}`, evidence, aiText, aiError };
    return aiText ? "Rule-based analysis plus AI analysis (hypotheses)." : `Rule-based analysis only${aiError ? "; AI call failed: " + aiError : c.model === null || c.model === undefined ? "; AI is not configured on the server" : ""}.`;
  });
  await run(7, async () => { const rc = rootCause(inc, dev, related); inc.rootCause = rc; return `${rc.text} (${rc.confidence} confidence, hypothesis)`; });
  await run(8, async () => { inc.recommendations = recommend(inc, dev, related); const acts = await matchActions(c, inc, dev); for (const a of acts) inc.recommendations.push({ p: "P1", text: `Automation available: "${a.name}" (needs administrator approval before it can run).`, disruptive: true, actionId: a.id }); await c.store.upsert(NT.incidents, [inc]); return `${inc.recommendations.length} recommendation(s), ${acts.length} registered automation(s) matched.`; });
  await run(9, async () => {
    const acts = inc.recommendations.filter((r) => r.actionId); if (!acts.length) { wf.steps[8].status = "skipped"; return "No registered automation applies; no approval needed. Recommendations are for a person to carry out."; }
    let n = 0; for (const r of acts) { const ap = await ensureApproval(c, inc, dev, r.actionId!); if (ap) n++; } inc.status = "Pending Approval"; return `${n} approval request(s) created. Nothing runs until an administrator approves.`;
  });
  for (const k of [10, 11, 12]) wf.steps[k - 1].status = "waiting";
  await run(13, async () => { await c.store.upsert(NT.incidents, [inc]); return `Incident status: ${inc.status}. Steps 10-12 run only after an approval is executed and fresh data arrives.`; });
  await run(14, async () => { await audit(c.store, { name: "system", role: "system" }, "noc.incident.workflow", inc.id, { workflow: wf.id, source: ev.origin }); inc.updatedAt = iso(c); await c.store.upsert(NT.incidents, [inc]); return `Workflow ${wf.id} recorded.`; });
  wf.status = inc.status === "Pending Approval" ? "waiting" : "completed"; await c.store.upsert(NT.workflows, [wf]); return inc;
}
export const AGENT_NAMES: Record<AgentKey, string> = { supervisor: "NOC Supervisor", engineer: "Network Engineer", server: "Server Administrator", performance: "Performance Analyst", responder: "Incident Responder", automation: "Automation Engineer" };
function rootCause(inc: NocIncident, dev: NocDevice | null, related: NocEvent[]): NonNullable<NocIncident["rootCause"]> {
  const down = related.filter((e) => e.status === "problem" && /unreachable|down|ping|icmp/i.test(e.title)), ev: string[] = [];
  if (inc.category === "monitoring") return { text: "The monitoring source or the path to it is failing, not (necessarily) the monitored devices. Check the Zabbix server VM, its network, and the bridge.", confidence: "medium", hypothesis: true, evidence: ["no data received within the stale window"] };
  if (inc.category === "network" && /unreachable|down|ping|icmp/i.test(inc.title) && down.length >= 2) { const prefix = (dev?.ip ?? "").split(".").slice(0, 3).join("."); const sub = down.filter((e) => prefix && (e.host.startsWith(prefix) || true)); ev.push(`${down.length} other reachability problems within 30 minutes`, ...down.slice(0, 4).map((e) => `${e.host}: ${e.title}`)); return { text: `Several devices lost reachability at about the same time (${down.length + 1}). A shared upstream device, link or the monitoring path is more likely than ${down.length + 1} independent failures.`, confidence: "medium", hypothesis: true, evidence: ev }; }
  if (inc.category === "network" && /unreachable|down|ping|icmp/i.test(inc.title)) return { text: "The device stopped answering. Likely causes: power or hardware failure, its uplink or switch port down, a network change, or the monitoring path failing. Not enough evidence to tell which.", confidence: "low", hypothesis: true, evidence: dev ? [`status ${deviceStatus(dev).status}`] : [] };
  if (dev) { const s = deviceStatus(dev); if (s.reasons.length) return { text: `The measured values explain the alert: ${s.reasons.join("; ")}.`, confidence: "medium", hypothesis: true, evidence: s.reasons }; }
  return { text: "The alert text is the only evidence; the cause cannot be determined from the data available.", confidence: "low", hypothesis: true, evidence: [] };
}
function recommend(inc: NocIncident, dev: NocDevice | null, related: NocEvent[]): Recommendation[] {
  const r: Recommendation[] = [], ip = dev?.ip ?? inc.host;
  switch (inc.category) {
    case "monitoring": r.push({ p: "P1", text: "Check that the Zabbix server VM is running and that its web/API port is reachable from the backend (or that the bridge service is running)." }, { p: "P2", text: "Check the bridge or API token: an expired token shows as AUTHENTICATION FAILED." }); break;
    case "network": r.push({ p: "P1", text: `From a management host: ping ${ip} (50 packets) and traceroute to ${ip}; compare with the monitoring data.` }, { p: "P2", text: "Check the uplink switch port status, error counters and recent configuration changes." }, { p: "P3", text: "If many devices are affected, check the shared upstream switch/router first." }); break;
    case "server": r.push({ p: "P1", text: `Log in to ${inc.host} and check the top processes, free memory and disk usage; look for runaway jobs or a full log directory.` }, { p: "P2", text: "Check the service's own logs for errors that started around the alert time." }); break;
    case "bandwidth": r.push({ p: "P1", text: "Identify the top talkers on the link (flow data or switch counters)." }, { p: "P2", text: "Apply QoS or move heavy hosts to another uplink; consider more capacity if this repeats." }); break;
    default: r.push({ p: "P2", text: "Review the trigger definition and the last values in Zabbix for this host." });
  }
  if (related.length > 3) r.push({ p: "P2", text: `${related.length} related events occurred nearby; review them together (see the incident timeline).` });
  return r;
}
async function matchActions(c: Ctx, inc: NocIncident, dev: NocDevice | null): Promise<AutoAction[]> {
  const all = await c.store.select<AutoAction>(NT.actions, { limit: 200 });
  return all.filter((a) => a.enabled && (!dev || a.appliesToTypes.length === 0 || a.appliesToTypes.includes(dev.type)) && (!a.match || new RegExp(a.match, "i").test(inc.title + " " + inc.host))).slice(0, 3);
}
async function ensureApproval(c: Ctx, inc: NocIncident, dev: NocDevice | null, actionId: string): Promise<Approval | null> {
  const act = await c.store.get<AutoAction>(NT.actions, actionId); if (!act) return null;
  const ex = (await c.store.select<Approval>(NT.approvals, { where: { incidentId: inc.id, actionId }, limit: 5 }))[0]; if (ex) return null;
  const ap: Approval = { id: rid("nap"), incidentId: inc.id, actionId, type: act.kind, target: dev?.name ?? inc.host, hostId: dev?.hostId, description: `${act.name}: ${act.description}`, risk: { level: act.risk, why: act.kind === "zabbix_script" ? "Runs an administrator-registered Zabbix script on the monitored host. It may restart a service or change state." : "Calls an administrator-registered automation endpoint.", ifApproved: "The backend runs the registered action once, then re-reads fresh monitoring data to check whether the problem is gone.", ifIgnored: "The incident stays open; nothing is changed." }, evidence: [inc.title, ...(inc.analysis?.evidence ?? []).slice(0, 3)], status: "proposed", proposedBy: "agent:" + inc.assignedAgent, createdAt: iso(c) };
  await c.store.upsert(NT.approvals, [ap]); inc.approvalIds.push(ap.id); await audit(c.store, { name: "agent:" + inc.assignedAgent, role: "agent" }, "noc.approval.request", ap.id, { incident: inc.id, action: act.name }); return ap;
}
export async function onResolved(c: Ctx, ev: NocEvent, why = "The monitoring source reports the problem resolved.") {
  const inc = ev.incidentId ? await c.store.get<NocIncident>(NT.incidents, ev.incidentId) : (await c.store.select<NocIncident>(NT.incidents, { limit: 500 })).find((i) => i.eventIds.includes(ev.id));
  if (!inc || inc.status === "Resolved" || inc.status === "Closed") return;
  const open = (await Promise.all(inc.eventIds.map((x) => c.store.get<NocEvent>(NT.events, x)))).filter((e) => e && e.status === "problem");
  if (open.length) return;
  inc.status = "Resolved"; inc.resolvedAt = iso(c); inc.updatedAt = inc.resolvedAt; inc.verification = { status: "resolved", checkedAt: inc.resolvedAt, detail: why + " (confirmed by data collected from the monitoring source)" };
  await c.store.upsert(NT.incidents, [inc]); await audit(c.store, { name: "system", role: "system" }, "noc.incident.resolved", inc.id, { why });
  if (inc.workflowId) { const wf = await c.store.get<Workflow>(NT.workflows, inc.workflowId); if (wf) { const t = inc.resolvedAt!, ran = inc.executionIds.length > 0; for (const n of [10, 11, 12]) { const st = wf.steps[n - 1]; if (st.status === "waiting") { st.status = ran && n > 10 ? "done" : "skipped"; st.endedAt = t; st.detail = ran ? (n === 10 ? "Executed earlier." : n === 11 ? "Fresh monitoring data collected." : inc.verification!.detail) : "No action was executed; the monitoring source reported the problem cleared on its own."; } } wf.steps[12] = { ...wf.steps[12], status: "done", endedAt: t, detail: "Incident Resolved" }; wf.status = "completed"; wf.updatedAt = t; await c.store.upsert(NT.workflows, [wf]); } }
}

/* ---------------- approvals, execution, verification ---------------- */
export async function decideApproval(c: Ctx, id: string, what: "approve" | "reject", note?: string) {
  const ap = await c.store.get<Approval>(NT.approvals, id); if (!ap) throw new HttpError(404, "Approval not found"); if (ap.status !== "proposed") throw new HttpError(409, `Already ${ap.status}.`);
  if (c.actor.name.startsWith("agent:")) throw new HttpError(403, "An AI agent cannot decide an approval.");
  ap.status = what === "approve" ? "approved" : "rejected"; ap.decidedBy = c.actor.name; ap.decidedAt = iso(c); ap.note = note ? String(note).slice(0, 500) : undefined;
  const inc = await c.store.get<NocIncident>(NT.incidents, ap.incidentId);
  if (what === "reject") { if (inc) { inc.updatedAt = ap.decidedAt; if (inc.status === "Pending Approval" && !(await hasProposed(c, inc.id, id))) inc.status = "Investigating"; await c.store.upsert(NT.incidents, [inc]); } await c.store.upsert(NT.approvals, [ap]); await audit(c.store, c.actor, "noc.approval.reject", id, { incident: ap.incidentId, note: ap.note }); return { approval: ap }; }
  const act = await c.store.get<AutoAction>(NT.actions, ap.actionId); if (!act || !act.enabled) { ap.status = "rejected"; ap.note = "The registered action no longer exists or was disabled."; await c.store.upsert(NT.approvals, [ap]); throw new HttpError(409, ap.note); }
  const src = act.sourceId ? await c.store.get<Source>(NT.sources, act.sourceId) : null, direct = act.kind === "webhook" || (src?.mode === "pull" && src.type === "zabbix");
  const ex: Execution = { id: rid("nex"), approvalId: id, incidentId: ap.incidentId, actionId: act.id, kind: act.kind, sourceId: act.sourceId, scriptId: act.scriptId, hostId: ap.hostId, target: ap.target, mode: direct ? "direct" : "bridge", status: "queued", requestedBy: c.actor.name, createdAt: iso(c) };
  ap.executionId = ex.id; await c.store.upsert(NT.approvals, [ap]); await c.store.upsert(NT.executions, [ex]);
  if (inc) { inc.status = "Executing"; inc.executionIds.push(ex.id); inc.updatedAt = iso(c); await c.store.upsert(NT.incidents, [inc]); }
  await audit(c.store, c.actor, "noc.approval.approve", id, { incident: ap.incidentId, action: act.name, execution: ex.id, mode: ex.mode });
  if (direct) await runExecution(c, ex, act, src); return { approval: ap, execution: await c.store.get<Execution>(NT.executions, ex.id) };
}
async function hasProposed(c: Ctx, incId: string, except: string) { return (await c.store.select<Approval>(NT.approvals, { where: { incidentId: incId, status: "proposed" }, limit: 10 })).some((a) => a.id !== except); }
async function runExecution(c: Ctx, ex: Execution, act: AutoAction, src: Source | null) {
  ex.status = "running"; ex.startedAt = iso(c); await c.store.upsert(NT.executions, [ex]);
  try {
    if (act.kind === "zabbix_script") { if (!src || !act.scriptId || !ex.hostId) throw new Error("Missing Zabbix source, script id, or host id for this device."); const r = await executeScript(await zconfSafe(c, src), act.scriptId, ex.hostId, c.fetcher); ex.status = r.ok ? "succeeded" : "failed"; ex.response = r.output; if (!r.ok) ex.error = "Zabbix reported the script as failed."; }
    else { if (!act.webhookUrl) throw new Error("No webhook URL."); const body = JSON.stringify({ executionId: ex.id, action: act.name, target: ex.target, incident: ex.incidentId }); const f = c.fetcher ?? ((u: string, i: any) => fetch(u, i) as any); const res = await f(await safeUrl(c, validateUrl(act.webhookUrl), "Webhook URL"), { method: "POST", headers: { "Content-Type": "application/json" }, body }); ex.status = res.ok ? "succeeded" : "failed"; ex.response = (await res.text()).slice(0, 2000); if (!res.ok) ex.error = `Webhook returned HTTP ${res.status}.`; }
  } catch (e: any) { ex.status = "failed"; ex.error = String(e?.message ?? e).slice(0, 400); }
  ex.endedAt = iso(c); await c.store.upsert(NT.executions, [ex]); await audit(c.store, { name: "system", role: "system" }, "noc.execution." + ex.status, ex.id, { incident: ex.incidentId, error: ex.error });
  await afterExecution(c, ex);
}
async function afterExecution(c: Ctx, ex: Execution) {
  const inc = await c.store.get<NocIncident>(NT.incidents, ex.incidentId); if (!inc) return;
  inc.status = ex.status === "succeeded" ? "Verifying" : "Investigating"; inc.updatedAt = iso(c);
  if (ex.status === "succeeded") inc.verification = { status: "awaiting_data", checkedAt: iso(c), detail: "Action ran. Waiting for fresh monitoring data collected after it finished." };
  else inc.verification = { status: "not_resolved", checkedAt: iso(c), detail: "The action did NOT run successfully (" + (ex.error ?? "failed") + "). Nothing was changed by it." };
  await c.store.upsert(NT.incidents, [inc]);
  if (inc.workflowId) { const wf = await c.store.get<Workflow>(NT.workflows, inc.workflowId); if (wf) { const t = iso(c); wf.steps[9] = { ...wf.steps[9], status: ex.status === "succeeded" ? "done" : "failed", startedAt: ex.startedAt, endedAt: ex.endedAt, detail: ex.status === "succeeded" ? `Executed through the backend (${ex.mode}); response: ${(ex.response ?? "").slice(0, 120)}` : undefined, error: ex.error }; wf.status = "waiting"; wf.updatedAt = t; await c.store.upsert(NT.workflows, [wf]); } }
}
/** Bridge reports the result of an execution it carried out. */
export async function reportExecution(c: Ctx, id: string, b: any) {
  const ex = await c.store.get<Execution>(NT.executions, id); if (!ex) throw new HttpError(404, "Execution not found"); if (ex.status === "succeeded" || ex.status === "failed") throw new HttpError(409, "Result already recorded.");
  ex.startedAt = ex.startedAt ?? iso(c); ex.endedAt = iso(c); ex.status = b?.ok === true ? "succeeded" : "failed"; ex.response = String(b?.output ?? "").slice(0, 4000); if (!b?.ok) ex.error = String(b?.error ?? "The bridge reported failure.").slice(0, 400);
  await c.store.upsert(NT.executions, [ex]); await audit(c.store, c.actor, "noc.execution." + ex.status, id, { via: "bridge" }); await afterExecution(c, ex); return ex;
}
export async function pendingExecutions(c: Ctx) { const q = await c.store.select<Execution>(NT.executions, { where: { status: "queued", mode: "bridge" }, limit: 20 }); const out = []; for (const e of q) { e.status = "running"; e.startedAt = iso(c); await c.store.upsert(NT.executions, [e]); out.push({ id: e.id, kind: e.kind, scriptId: e.scriptId, hostId: e.hostId, target: e.target }); } return out; }
/** Evaluate "Verifying" incidents against data collected after the execution finished. */
export async function checkVerifying(c: Ctx, now = T(c)) {
  const list = (await c.store.select<NocIncident>(NT.incidents, { where: { status: "Verifying" }, limit: 100 }));
  for (const inc of list) await verifyOne(c, inc, now);
}
async function verifyOne(c: Ctx, inc: NocIncident, now: number) {
  const exs = (await Promise.all(inc.executionIds.map((x) => c.store.get<Execution>(NT.executions, x)))).filter(Boolean) as Execution[], last = exs.filter((e) => e.endedAt).sort((a, b) => (a.endedAt! < b.endedAt! ? 1 : -1))[0]; if (!last) return;
  const src = last.sourceId ? await c.store.get<Source>(NT.sources, last.sourceId) : (await c.store.select<Source>(NT.sources, { limit: 50 }))[0] ?? null;
  const fresh = src?.lastSyncAt && ms(src.lastSyncAt) > ms(last.endedAt!);
  const evs = (await Promise.all(inc.eventIds.map((x) => c.store.get<NocEvent>(NT.events, x)))).filter(Boolean) as NocEvent[], open = evs.filter((e) => e.status === "problem"), t = new Date(now).toISOString();
  if (!fresh) { inc.verification = { status: "awaiting_data", checkedAt: t, detail: "No monitoring data newer than the action has arrived yet." }; await c.store.upsert(NT.incidents, [inc]); return; }
  const ok = open.length === 0; inc.verification = { status: ok ? "resolved" : "not_resolved", checkedAt: t, detail: ok ? `Fresh data from ${src!.name} (${src!.lastSyncAt}) shows the problem cleared.` : `Fresh data from ${src!.name} (${src!.lastSyncAt}) still reports ${open.length} active problem(s): ${open.map((e) => e.title).join("; ").slice(0, 200)}.` };
  inc.status = ok ? "Resolved" : "Investigating"; if (ok) inc.resolvedAt = t; inc.updatedAt = t; last.verification = inc.verification; await c.store.upsert(NT.executions, [last]); await c.store.upsert(NT.incidents, [inc]);
  if (inc.workflowId) { const wf = await c.store.get<Workflow>(NT.workflows, inc.workflowId); if (wf) { wf.steps[10] = { ...wf.steps[10], status: "done", endedAt: t, detail: `Fresh data from ${src!.name} at ${src!.lastSyncAt}` }; wf.steps[11] = { ...wf.steps[11], status: "done", endedAt: t, detail: inc.verification.detail }; wf.steps[12] = { ...wf.steps[12], status: "done", endedAt: t, detail: `Incident ${inc.status}` }; wf.status = "completed"; wf.updatedAt = t; await c.store.upsert(NT.workflows, [wf]); } }
  await audit(c.store, { name: "system", role: "system" }, "noc.incident.verified", inc.id, { result: inc.verification.status });
}
export async function verifyIncident(c: Ctx, id: string) {
  const inc = await c.store.get<NocIncident>(NT.incidents, id); if (!inc) throw new HttpError(404, "Incident not found");
  const last = (await Promise.all(inc.executionIds.map((x) => c.store.get<Execution>(NT.executions, x)))).filter(Boolean)[0] as Execution | undefined; const src = last?.sourceId ? await c.store.get<Source>(NT.sources, last.sourceId) : null;
  if (src && src.mode === "pull" && src.type === "zabbix") { try { const snap = await fetchSnapshot(await zconfSafe(c, src), c.fetcher); await applySnapshot(c, src, snap.hosts, snap.problems); } catch (e) { const r = fromErr(e); throw new HttpError(502, "Could not retrieve fresh monitoring data: " + r.detail); } }
  const cur = (await c.store.get<NocIncident>(NT.incidents, id))!; if (cur.status === "Verifying") await verifyOne(c, cur, T(c)); return c.store.get<NocIncident>(NT.incidents, id);
}

/* ---------------- automation registry ---------------- */
export async function createAction(c: Ctx, b: any) {
  const name = String(b?.name ?? "").trim().slice(0, 80), kind = b?.kind as AutoAction["kind"]; if (!name) throw new HttpError(400, "name is required"); if (kind !== "zabbix_script" && kind !== "webhook") throw new HttpError(400, "kind must be zabbix_script or webhook");
  if (kind === "zabbix_script" && (!b?.sourceId || !b?.scriptId)) throw new HttpError(400, "zabbix_script needs sourceId and scriptId (the id of a script you created in Zabbix: Alerts > Scripts)."); if (kind === "webhook") await safeUrl(c, validateUrl(String(b?.webhookUrl ?? "")), "Webhook URL");
  if (b?.match) { try { new RegExp(String(b.match)); } catch { throw new HttpError(400, "match is not a valid regular expression"); } }
  const types = (Array.isArray(b?.appliesToTypes) ? b.appliesToTypes : []).filter((x: string) => (NOC_TYPES as readonly string[]).includes(x)) as NocType[];
  const a: AutoAction = { id: rid("nac"), name, description: String(b?.description ?? "").slice(0, 300), kind, sourceId: b?.sourceId ? String(b.sourceId) : undefined, scriptId: b?.scriptId ? String(b.scriptId) : undefined, webhookUrl: b?.webhookUrl ? String(b.webhookUrl) : undefined, appliesToTypes: types, match: b?.match ? String(b.match).slice(0, 200) : undefined, risk: b?.risk === "medium" ? "medium" : "high", enabled: true, createdBy: c.actor.name, createdAt: iso(c) };
  await c.store.upsert(NT.actions, [a]); await audit(c.store, c.actor, "noc.action.register", a.id, { name, kind }); return a;
}
