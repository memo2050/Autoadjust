// Six NOC agents. Each run is executed server-side against stored data, timed per step, and saved as an activity.
// An agent is only reported as having done work when a run finished and was stored. No data -> noData result.
import { deviceStatus, NOC_TABLE, type NocDevice } from "../soc/noc";
import { HttpError, audit } from "../soc/pipeline";
import { rid } from "../soc/util";
import { ms } from "../soc/util";
import { AGENTS, NT, type Activity, type AgentKey, type AgentResult, type Approval, type Execution, type Iface, type NocEvent, type NocIncident, type Source, type WfStep, type Workflow, type AutoAction } from "./types";
import { AGENT_NAMES, effectiveStatus, publicSource, applySnapshot, type Ctx } from "./ops";
import type { ZHost, ZProblem } from "./zabbix";

const ds = (d: NocDevice): { status: string; reasons: string[] } => (d.known === false ? { status: "unknown", reasons: ["No availability item (ping/agent/SNMP) exists for this host, so up/down is not known."] } : deviceStatus(d));
const sevRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
type SeV = keyof typeof sevRank;
export async function runAgent(c: Ctx, role: string, b: any = {}) {
  if (!AGENTS.includes(role as AgentKey)) throw new HttpError(404, "Unknown agent");
  const agent = role as AgentKey, t0 = new Date().toISOString(), act: Activity = { id: rid("nact"), agent, task: String(b?.task ?? "routine").slice(0, 80), incidentId: b?.incidentId ? String(b.incidentId) : undefined, status: "running", steps: [], actor: c.actor.name, startedAt: t0, createdAt: t0 };
  const step = async <T>(name: string, fn: () => Promise<T>, detail?: (r: T) => string): Promise<T> => {
    const s: WfStep = { n: act.steps.length + 1, name, status: "running", startedAt: new Date().toISOString() }; act.steps.push(s); const t = Date.now();
    try { const r = await fn(); s.status = "done"; s.detail = detail ? detail(r) : undefined; return r; } catch (e: any) { s.status = "failed"; s.error = String(e?.message ?? e).slice(0, 300); throw e; } finally { s.ms = Date.now() - t; s.endedAt = new Date().toISOString(); }
  };
  try {
    const data = await step("Read stored monitoring data", async () => ({
      devs: await c.store.select<NocDevice>(NOC_TABLE, { limit: 2000 }), sources: await c.store.select<Source>(NT.sources, { limit: 100 }), evs: await c.store.select<NocEvent>(NT.events, { order: ["receivedAt", "desc"], limit: 300 }),
      incs: await c.store.select<NocIncident>(NT.incidents, { order: ["createdAt", "desc"], limit: 300 }), ifs: await c.store.select<Iface>(NT.interfaces, { limit: 3000 }),
      aps: await c.store.select<Approval>(NT.approvals, { limit: 300 }), exs: await c.store.select<Execution>(NT.executions, { limit: 300 }), acts: await c.store.select<AutoAction>(NT.actions, { limit: 100 }) }),
      (d) => `${d.devs.length} device(s), ${d.sources.length} source(s), ${d.incs.length} incident(s)`);
    const live = data.devs.filter((d) => d.source === "live");
    const res = await step("Apply " + AGENT_NAMES[agent] + " logic", async () => build[agent](c, data, live, act.incidentId));
    await step("Store result", async () => { act.result = res; act.status = "completed"; act.endedAt = new Date().toISOString(); await c.store.upsert(NT.activities, [act]); }, () => `Activity ${act.id}`);
  } catch (e: any) { act.status = "failed"; act.error = String(e?.message ?? e).slice(0, 300); act.endedAt = new Date().toISOString(); await c.store.upsert(NT.activities, [act]); }
  await audit(c.store, c.actor, "noc.agent.run", agent, { activity: act.id, status: act.status });
  return act;
}
type D = { devs: NocDevice[]; sources: Source[]; evs: NocEvent[]; incs: NocIncident[]; ifs: Iface[]; aps: Approval[]; exs: Execution[]; acts: AutoAction[] };
const noData = (head: string, why: string): AgentResult => ({ head, sev: "low", findings: [], recs: [{ p: "P2", t: why }], limits: [why], noData: true });
const open = (d: D) => d.incs.filter((i) => i.status !== "Resolved" && i.status !== "Closed");
const build: Record<AgentKey, (c: Ctx, d: D, live: NocDevice[], incId?: string) => AgentResult> = {
  supervisor(c, d, live) {
    if (!d.sources.length) return noData("No monitoring source is configured.", "Add a monitoring source in the Monitoring Connectivity Center.");
    const now = Date.now(), bad = d.sources.filter((s) => effectiveStatus(s, now).status !== "CONNECTED"), o = open(d), crit = o.filter((i) => i.severity === "critical" || i.severity === "high");
    const findings: AgentResult["findings"] = [...bad.map((s) => ({ sev: "high", t: `Source "${s.name}" is ${effectiveStatus(s, now).status}`, ev: [effectiveStatus(s, now).detail] })), ...crit.slice(0, 6).map((i) => ({ sev: i.severity, t: `${i.id}: ${i.title}`, ev: [`status ${i.status}`, `agent ${AGENT_NAMES[i.assignedAgent]}`] }))];
    const pend = d.aps.filter((a) => a.status === "proposed");
    return { head: `${d.sources.length - bad.length}/${d.sources.length} source(s) healthy, ${o.length} open incident(s), ${pend.length} approval(s) waiting.`, sev: crit.length || bad.length ? "high" : o.length ? "medium" : "low", findings, recs: [...(pend.length ? [{ p: "P1", t: `${pend.length} approval request(s) are waiting for an administrator.` }] : []), ...(bad.length ? [{ p: "P1", t: "Restore the disconnected monitoring source(s) first; other results are stale until then." }] : [])], limits: ["Coordination view only; it does not change anything."] };
  },
  engineer(c, d, live) {
    const net = live.filter((x) => ["router", "switch", "firewall", "accesspoint", "loadbalancer"].includes(x.type)); if (!net.length) return noData("No live network devices (router/switch/firewall/AP) are in the inventory.", "Add network devices to Zabbix (SNMP) and synchronize the source.");
    const f: AgentResult["findings"] = []; const rows: (string | number)[][] = [];
    for (const dv of net) { const st = ds(dv), ifs = d.ifs.filter((i) => i.deviceId === dv.id); const down = ifs.filter((i) => i.up === false), err = ifs.filter((i) => (i.errorsIn ?? 0) + (i.errorsOut ?? 0) + (i.dropsIn ?? 0) + (i.dropsOut ?? 0) > 0);
      rows.push([dv.name, dv.type, st.status, ifs.length, down.length, err.length, dv.metrics.latencyMs ?? "no data", dv.metrics.lossPct ?? "no data"]);
      if (st.status !== "healthy" && st.status !== "unknown") f.push({ sev: st.status === "critical" || st.status === "offline" ? "high" : "medium", t: `${dv.name} is ${st.status}`, ev: st.reasons });
      if (down.length) f.push({ sev: "medium", t: `${dv.name}: ${down.length} interface(s) down`, ev: down.slice(0, 5).map((i) => i.name) });
      if (err.length) f.push({ sev: "low", t: `${dv.name}: errors/drops on ${err.length} interface(s)`, ev: err.slice(0, 5).map((i) => `${i.name} err ${(i.errorsIn ?? 0) + (i.errorsOut ?? 0)} drop ${(i.dropsIn ?? 0) + (i.dropsOut ?? 0)}`) }); }
    return { head: `${net.length} network device(s) reviewed, ${f.length} finding(s).`, sev: f.some((x) => x.sev === "high") ? "high" : f.length ? "medium" : "low", findings: f, table: { title: "Network devices", cols: ["Device", "Type", "State", "Ifaces", "Down", "Err/drop", "Latency ms", "Loss %"], rows }, recs: f.length ? [{ p: "P1", t: "Check the listed devices and interfaces first (cabling, port state, uplink)." }] : [], limits: ["Interface data exists only for items Zabbix collects (SNMP net.if.*)."] };
  },
  server(c, d, live) {
    const sv = live.filter((x) => ["server", "hypervisor", "vm"].includes(x.type)); if (!sv.length) return noData("No live servers or VMs are in the inventory.", "Install Zabbix Agent 2 on servers (or SNMP) and synchronize the source.");
    const f: AgentResult["findings"] = [], rows: (string | number)[][] = [];
    for (const dv of sv) { const st = ds(dv); rows.push([dv.name, dv.type, st.status, dv.metrics.cpu ?? "no data", dv.metrics.mem ?? "no data", dv.metrics.disk ?? "no data", dv.uptimeSec != null ? Math.round(dv.uptimeSec / 3600) : "no data"]); if (st.status !== "healthy" && st.status !== "unknown") f.push({ sev: st.status === "critical" || st.status === "offline" ? "high" : "medium", t: `${dv.name}: ${st.reasons.join("; ") || st.status}`, ev: st.reasons }); if (dv.uptimeSec != null && dv.uptimeSec < 900) f.push({ sev: "medium", t: `${dv.name} restarted recently (uptime ${Math.round(dv.uptimeSec / 60)} min)`, ev: [`uptime ${dv.uptimeSec}s`] }); }
    return { head: `${sv.length} server/VM(s) reviewed, ${f.length} finding(s).`, sev: f.some((x) => x.sev === "high") ? "high" : f.length ? "medium" : "low", findings: f, table: { title: "Servers", cols: ["Server", "Type", "State", "CPU %", "Mem %", "Disk %", "Uptime h"], rows }, recs: f.length ? [{ p: "P2", t: "Investigate the listed servers; restarts require an approved, registered action." }] : [], limits: ["Values come only from Zabbix items present on each host; missing ones show as no data."] };
  },
  performance(c, d, live) {
    if (!live.length) return noData("No live devices to analyze.", "Synchronize a monitoring source first.");
    const f: AgentResult["findings"] = [], rows: (string | number)[][] = [];
    for (const dv of live) { const h = (dv.history ?? []).filter((x) => x.latencyMs != null || x.cpu != null); if (h.length < 3) continue; const trend = (k: "cpu" | "latencyMs") => { const v = h.map((x) => x[k]).filter((x): x is number => x != null); return v.length >= 3 ? Math.round((v[v.length - 1] - v[0]) * 10) / 10 : null; }; const dc = trend("cpu"), dl = trend("latencyMs"); rows.push([dv.name, h.length, dc ?? "n/a", dl ?? "n/a"]); if (dc != null && dc > 20) f.push({ sev: "medium", t: `${dv.name}: CPU rose ${dc} points over ${h.length} samples`, ev: [`first ${h[0].cpu}, last ${h[h.length - 1].cpu}`] }); if (dl != null && dl > 20) f.push({ sev: "medium", t: `${dv.name}: latency rose ${dl} ms over ${h.length} samples`, ev: [] }); }
    const hot = d.ifs.filter((i) => (i.utilPct ?? 0) >= 70); for (const i of hot.slice(0, 6)) f.push({ sev: (i.utilPct ?? 0) >= 90 ? "high" : "medium", t: `${d.devs.find((x) => x.id === i.deviceId)?.name ?? i.deviceId} ${i.name} at ${i.utilPct}% utilization`, ev: [`in ${i.inBps ?? "n/a"} bps, out ${i.outBps ?? "n/a"} bps, speed ${i.speedBps ?? "n/a"} bps`] });
    if (!rows.length && !hot.length) return noData("Not enough history yet (needs at least 3 samples per device).", "Let the source synchronize a few more times, then run this agent again.");
    return { head: `${rows.length} device trend(s) and ${hot.length} busy link(s) analyzed.`, sev: f.some((x) => x.sev === "high") ? "high" : f.length ? "medium" : "low", findings: f, table: { title: "Trends (change over stored samples)", cols: ["Device", "Samples", "CPU change", "Latency change"], rows }, recs: f.length ? [{ p: "P2", t: "Review the listed trends; sustained growth usually needs capacity or tuning." }] : [], limits: ["Trends use only samples stored since the source was added; no forecasting is made."] };
  },
  responder(c, d, live, incId) {
    const o = open(d).sort((a, b) => sevRank[b.severity as SeV] - sevRank[a.severity as SeV]); if (!o.length) return { head: "No open incidents.", sev: "low", findings: [], recs: [], limits: [] };
    const sel = incId ? o.filter((i) => i.id === incId) : o.slice(0, 8);
    return { head: `${o.length} open incident(s); showing ${sel.length}.`, sev: (sel[0]?.severity as SeV) ?? "low", findings: sel.map((i) => ({ sev: i.severity, t: `${i.id}: ${i.title}`, ev: [`status ${i.status}`, i.rootCause ? "probable cause (hypothesis): " + i.rootCause.text : "no root-cause analysis yet", `${i.approvalIds.length} approval(s), ${i.executionIds.length} execution(s)`] })), recs: sel.flatMap((i) => i.recommendations.slice(0, 2).map((r) => ({ p: r.p, t: r.text, actionId: r.actionId, incidentId: i.id }))), limits: ["Incidents are created from real alerts only."] };
  },
  automation(c, d) {
    const act = d.acts, ap = d.aps.filter((a) => a.status === "proposed"), ex = d.exs;
    const rows = ex.slice(0, 20).map((e) => [e.id, e.target, e.mode, e.status, e.verification?.status ?? "-"]);
    return { head: `${act.length} registered action(s), ${ap.length} waiting approval, ${ex.length} execution(s) (${ex.filter((e) => e.status === "succeeded").length} succeeded, ${ex.filter((e) => e.status === "failed").length} failed).`, sev: ex.some((e) => e.status === "failed") ? "medium" : "low", findings: ex.filter((e) => e.status === "failed").slice(0, 5).map((e) => ({ sev: "medium", t: `Execution ${e.id} on ${e.target} failed`, ev: [e.error ?? ""] })), table: rows.length ? { title: "Executions", cols: ["Execution", "Target", "Mode", "Status", "Verified"], rows } : undefined, recs: act.length ? [] : [{ p: "P2", t: "No automation is registered. An administrator can register Zabbix scripts or webhooks; agents can only propose those." }], limits: ["Agents propose only registered actions; every one needs administrator approval."] };
  },
};

export async function overview(c: Ctx) {
  const now = c.now ? c.now() : Date.now(), s = c.store;
  const [sources, devs, ifs, evs, incs, acts, aps, exs, actions, wfs] = await Promise.all([s.select<Source>(NT.sources, { limit: 100 }), s.select<NocDevice>(NOC_TABLE, { limit: 2000 }), s.select<Iface>(NT.interfaces, { limit: 5000 }), s.select<NocEvent>(NT.events, { order: ["receivedAt", "desc"], limit: 100 }), s.select<NocIncident>(NT.incidents, { order: ["createdAt", "desc"], limit: 200 }), s.select<Activity>(NT.activities, { order: ["createdAt", "desc"], limit: 100 }), s.select<Approval>(NT.approvals, { order: ["createdAt", "desc"], limit: 100 }), s.select<Execution>(NT.executions, { order: ["createdAt", "desc"], limit: 100 }), s.select<AutoAction>(NT.actions, { limit: 100 }), s.select<Workflow>(NT.workflows, { order: ["createdAt", "desc"], limit: 100 })]);
  const live = devs.filter((d) => d.source === "live"), stale = (d: NocDevice) => { const src = sources.find((x) => x.id === d.sourceId); return !src || effectiveStatus(src, now).status !== "CONNECTED"; };
  const st = live.map((d) => ({ d, s: stale(d) ? { status: "unknown" as string, reasons: ["monitoring source is not delivering data"] } : ds(d) }));
  const avg = (k: "cpu" | "mem") => { const v = live.filter((d) => !stale(d)).map((d) => d.metrics[k]).filter((x): x is number => x != null); return v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length * 10) / 10 : null; };
  const bw = live.filter((d) => !stale(d) && d.metrics.bwInMbps != null); const ob = (e: NocEvent) => e.status === "problem";
  const known = live.filter((d) => d.known !== false && !stale(d));
  return {
    time: new Date(now).toISOString(), dataLabel: live.length ? "LIVE" : "NO DATA", demo: false,
    sources: sources.map((x) => publicSource(x, now)), devices: live.map((d) => ({ ...d, stale: stale(d), health: st.find((x) => x.d.id === d.id)!.s })), interfaces: ifs,
    events: evs, incidents: incs, activities: acts, approvals: aps, executions: exs, actions: actions.map((a) => ({ ...a })), workflows: wfs,
    counts: { devices: live.length, connected: known.filter((d) => d.up).length, disconnected: live.filter((d) => stale(d) || (d.known !== false && !d.up)).length, critical: evs.filter((e) => ob(e) && (e.severity === "critical" || e.severity === "high")).length, warning: evs.filter((e) => ob(e) && e.severity === "warning").length, activeIncidents: incs.filter((i) => i.status !== "Resolved" && i.status !== "Closed").length, pendingApprovals: aps.filter((a) => a.status === "proposed").length, availabilityPct: known.length ? Math.round(known.filter((d) => d.up).length / known.length * 1000) / 10 : null, avgCpu: avg("cpu"), avgMem: avg("mem"), bwInMbps: bw.length ? Math.round(bw.reduce((a, d) => a + (d.metrics.bwInMbps ?? 0), 0) * 10) / 10 : null, bwOutMbps: bw.length ? Math.round(bw.reduce((a, d) => a + (d.metrics.bwOutMbps ?? 0), 0) * 10) / 10 : null, healthy: st.filter((x) => x.s.status === "healthy").length, warn: st.filter((x) => x.s.status === "warning").length, crit: st.filter((x) => x.s.status === "critical").length, interfaces: ifs.length },
    agents: Object.fromEntries(AGENTS.map((a) => { const last = acts.find((x) => x.agent === a && x.status === "completed"); return [a, { name: AGENT_NAMES[a], lastRun: last?.endedAt ?? null, operational: !!last, lastActivity: last?.id ?? null, runs: acts.filter((x) => x.agent === a).length }]; })),
  };
}
/** Push-mode ingest: a bridge inside the network posts a normalized snapshot outbound-only. */
export async function pushSnapshot(c: Ctx, body: any) {
  const id = String(body?.sourceId ?? ""); const src = await c.store.get<Source>(NT.sources, id); if (!src || src.mode !== "push") throw new HttpError(404, "Push source not found. Create a source with mode \"push\" first and use its id.");
  if (!Array.isArray(body?.hosts) || body.hosts.length > 2000) throw new HttpError(400, "hosts must be an array (max 2000)");
  const hosts: ZHost[] = body.hosts.map((h: any) => { if (!h?.hostid || !h?.name) throw new HttpError(400, "Each host needs hostid and name"); return { hostid: String(h.hostid).slice(0, 40), id: String(h.id ?? h.name).toLowerCase().replace(/[^a-z0-9._-]+/g, "-").slice(0, 64), name: String(h.name).slice(0, 100), hostname: String(h.hostname ?? h.name).slice(0, 100), ip: h.ip ? String(h.ip).slice(0, 45) : undefined, type: h.type ?? "endpoint", groups: (h.groups ?? []).map(String).slice(0, 10), known: h.known === true, up: h.up === true, metrics: h.metrics ?? {}, uptimeSec: Number.isFinite(h.uptimeSec) ? h.uptimeSec : undefined, interfaces: (h.interfaces ?? []).slice(0, 200), unsupported: (h.unsupported ?? []).map(String), itemErrors: (h.itemErrors ?? []).map(String).slice(0, 10) }; });
  const problems: ZProblem[] = (body.problems ?? []).slice(0, 500).map((p: any) => ({ eventid: String(p.eventid), name: String(p.name ?? "").slice(0, 300), severity: Number(p.severity) || 0, clock: Number(p.clock) || Math.floor(Date.now() / 1000), resolved: p.resolved === true, hostid: p.hostid ? String(p.hostid) : undefined, host: p.host ? String(p.host) : undefined }));
  return applySnapshot(c, src, hosts, problems);
}
