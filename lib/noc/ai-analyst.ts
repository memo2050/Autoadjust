// AI NOC analyst (analysis and recommendation ONLY). Computes health, anomalies, trends, correlations and ranked root-cause hypotheses from THIS organization's
// stored telemetry, events, incidents and read-only diagnostic results. An optional language model only writes a narrative, discarded if it cites unknown evidence.
// It executes nothing; any diagnostic it suggests is a read-only catalog template that a human must request or confirm.
import { deviceStatus, NOC_TABLE, NOC_THRESHOLDS, bwUtil, type NocDevice } from "../soc/noc";
import { HttpError, audit } from "../soc/pipeline";
import { ms } from "../soc/util";
import type { ModelFn } from "../soc/agents";
import { NT, type NocEvent, type NocIncident } from "./types";
import { seriesRows } from "./realtime";
import type { Ctx } from "./ops";
import { XT, type Job } from "./exec/jobs";
import { conf, narrate, type Confidence, type Recommendation, type SuggestedDiagnostic } from "./exec/ai-common";

const KEYS = ["cpu", "mem", "disk", "latencyMs", "lossPct", "bwInMbps", "bwOutMbps"] as const;
const MIN_DELTA: Record<string, number> = { cpu: 15, mem: 10, disk: 5, latencyMs: 50, lossPct: 2, bwInMbps: 10, bwOutMbps: 10 };
const LABEL: Record<string, string> = { cpu: "CPU %", mem: "memory %", disk: "disk %", latencyMs: "latency ms", lossPct: "packet loss %", bwInMbps: "inbound Mbps", bwOutMbps: "outbound Mbps" };
const median = (a: number[]) => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const r1 = (x: number) => Math.round(x * 10) / 10;
export interface Anomaly { deviceId: string; metric: string; direction: "up" | "down"; baseline: number; current: number; zScore: number; since: string; confidence: Confidence; evidence: string[]; why: string }
export interface Trend { deviceId: string; metric: string; slopePerHour: number; r2: number; etaHoursTo100?: number; evidence: string[]; why: string }
export interface Cause { cause: string; confidence: Confidence; score: number; supports: string[]; contradicts: string[]; evidence: string[]; nextChecks: string[] }

/** Robust level-shift detector: compares the latest samples with the median of an earlier baseline using median absolute deviation. Needs enough data or says so. */
export function detect(rows: { id: string; value: number; t: string }[], metric: string, deviceId: string): { anomaly?: Anomaly; trend?: Trend; insufficient?: boolean } {
  if (rows.length < 12) return { insufficient: true };
  const nRecent = Math.max(3, Math.floor(rows.length * 0.1)), base = rows.slice(0, rows.length - nRecent).map((r) => r.value), recent = rows.slice(-nRecent), med = median(base), mad = median(base.map((v) => Math.abs(v - med)));
  const cur = median(recent.map((r) => r.value)), scale = Math.max(1.4826 * mad, MIN_DELTA[metric] / 10), z = (cur - med) / scale, out: { anomaly?: Anomaly; trend?: Trend } = {};
  if (Math.abs(z) >= 3.5 && Math.abs(cur - med) >= MIN_DELTA[metric]) {
    const ev = recent.map((r) => r.id); let since = recent[0].t; for (let i = rows.length - nRecent - 1; i >= 0; i--) { if (Math.abs(rows[i].value - med) / scale >= 3.5) { since = rows[i].t; } else break; }
    out.anomaly = { deviceId, metric, direction: cur > med ? "up" : "down", baseline: r1(med), current: r1(cur), zScore: r1(z), since, confidence: conf((Math.abs(z) >= 6 ? 1 : 0) + (rows.length >= 30 ? 1 : 0) + (recent.length >= 5 ? 1 : 0)), evidence: ev,
      why: `${LABEL[metric]} is ${r1(cur)} now versus a typical ${r1(med)} (robust deviation ${r1(z)}, from ${base.length} earlier samples, last ${recent.length} samples used for "now").` };
  }
  const tail = rows.slice(-Math.min(rows.length, 48)), t0 = ms(tail[0].t), xs = tail.map((r) => (ms(r.t) - t0) / 3600_000), ys = tail.map((r) => r.value), n = xs.length, mx = xs.reduce((a, b) => a + b, 0) / n, my = ys.reduce((a, b) => a + b, 0) / n;
  const sxx = xs.reduce((a, x) => a + (x - mx) ** 2, 0), sxy = xs.reduce((a, x, i) => a + (x - mx) * (ys[i] - my), 0), syy = ys.reduce((a, y) => a + (y - my) ** 2, 0);
  if (sxx > 0 && syy > 0 && xs[n - 1] >= 1) { const slope = sxy / sxx, r2 = (sxy * sxy) / (sxx * syy);
    if (r2 >= 0.6 && Math.abs(slope) * xs[n - 1] >= MIN_DELTA[metric] / 2) out.trend = { deviceId, metric, slopePerHour: r1(slope * 100) / 100, r2: Math.round(r2 * 100) / 100, etaHoursTo100: slope > 0 && ys[n - 1] < 100 && ["disk", "mem"].includes(metric) ? Math.round(((100 - ys[n - 1]) / slope) * 10) / 10 : undefined, evidence: tail.slice(-3).map((r) => r.id),
      why: `${LABEL[metric]} moved ${r1(slope * 100) / 100} per hour over the last ${r1(xs[n - 1])} h (fit quality R² ${Math.round(r2 * 100) / 100}).` }; }
  return out;
}

export async function analyzeNoc(c: Ctx, opts: { deviceId?: string; incidentId?: string; hours?: number; proposeDiagnostics?: (s: SuggestedDiagnostic[]) => Promise<SuggestedDiagnostic[]> } = {}, model: ModelFn | null = null) {
  const hours = Math.max(1, Math.min(168, opts.hours ?? 24)), now = c.now ? c.now() : Date.now(), limits: string[] = [];
  const devs = await c.store.select<NocDevice>(NOC_TABLE, { limit: 1000 }), evs = await c.store.select<NocEvent>(NT.events, { limit: 2000 }), incs = await c.store.select<NocIncident>(NT.incidents, { limit: 1000 });
  const jobs = (await c.store.select<Job>(XT.jobs, { order: ["requestedAt", "desc"], limit: 300 }).catch(() => [] as Job[])).filter((j) => j.status === "succeeded" && !j.dryRun);
  let focusId = opts.deviceId?.toLowerCase();
  if (opts.incidentId) { const inc = incs.find((i) => i.id === opts.incidentId); if (!inc) throw new HttpError(404, "Incident not found in this organization."); focusId = (inc.deviceId ?? inc.host).toLowerCase(); }
  if (focusId && !devs.some((d) => d.id === focusId)) throw new HttpError(404, "Device not found in this organization.");
  if (!devs.length) limits.push("No devices have reported to this organization yet, so there is nothing to analyze. Install an agent or connect a monitoring source.");
  const byId = new Map(devs.map((d) => [d.id, d])), neighbors = (id: string) => { const d = byId.get(id), s = new Set<string>(); for (const l of d?.links ?? []) s.add(l.to); for (const o of devs) if (o.links.some((l) => l.to === id)) s.add(o.id); return [...s].filter((x) => byId.has(x)); };
  const scope = focusId ? [...new Set([focusId, ...neighbors(focusId)])] : devs.map((d) => d.id);

  const health = devs.map((d) => { const st = deviceStatus(d), age = now - ms(d.receivedAt), silent = age > 600_000; return { deviceId: d.id, name: d.name, status: silent && st.status !== "offline" ? "no_recent_data" : st.status, reasons: silent ? [...st.reasons, `Last report ${Math.round(age / 60000)} min ago.`] : st.reasons, lastReport: d.receivedAt }; });
  const anomalies: Anomaly[] = [], trends: Trend[] = [], noHistory: string[] = [], flapping: { deviceId: string; transitions: number; evidence: string[] }[] = [];
  for (const id of scope) {
    let any = false;
    for (const k of KEYS) { const rows = await seriesRows(c, id, k, hours); if (rows.length) any = true; const r = detect(rows, k, id); if (r.anomaly) anomalies.push(r.anomaly); if (r.trend) trends.push(r.trend); }
    const up = await seriesRows(c, id, "up", hours); let tr = 0; for (let i = 1; i < up.length; i++) if (up[i].value !== up[i - 1].value) tr++; if (tr >= 4) flapping.push({ deviceId: id, transitions: tr, evidence: up.slice(-4).map((r) => r.id) });
    if (!any) noHistory.push(id);
  }
  if (noHistory.length) limits.push(`No stored history for: ${noHistory.slice(0, 8).join(", ")}. Anomaly and trend detection need at least 12 samples per metric; until then only current values are judged.`);
  // ---------- correlation across linked devices ----------
  const correlations: { kind: string; summary: string; deviceIds: string[]; evidence: string[]; confidence: Confidence }[] = [];
  const by = new Map<string, Anomaly[]>(); for (const a of anomalies) (by.get(a.deviceId) ?? by.set(a.deviceId, []).get(a.deviceId)!).push(a);
  for (const [id, list] of by) for (const n of neighbors(id)) if (n > id && by.has(n) && Math.abs(ms(by.get(n)![0].since) - ms(list[0].since)) < 900_000) correlations.push({ kind: "linked_devices_changed_together", summary: `${id} and ${n} are linked and both changed within 15 minutes of each other (${list[0].metric} / ${by.get(n)![0].metric}).`, deviceIds: [id, n], evidence: [...list[0].evidence, ...by.get(n)![0].evidence], confidence: "medium" });
  // ---------- root-cause hypotheses ----------
  const focusDevices = focusId ? [focusId] : health.filter((h) => !["healthy", "unknown"].includes(h.status)).map((h) => h.deviceId).slice(0, 10);
  const analyses = focusDevices.map((id) => {
    const d = byId.get(id)!, st = deviceStatus(d), m = d.metrics, an = anomalies.filter((a) => a.deviceId === id), tr = trends.filter((t) => t.deviceId === id), nb = neighbors(id).map((x) => byId.get(x)!), causes: Cause[] = [], devEv = evs.filter((e) => e.deviceId === id && e.status === "problem").map((e) => e.id);
    const cpuJob = jobs.find((j) => j.hostId === id && j.template === "sys.cpu_top" && now - ms(j.endedAt ?? j.requestedAt) < 6 * 3600_000), topLine = cpuJob?.output?.split("\n").find((l, i) => i > 0 && l.trim());
    const add = (cause: string, points: number, supports: string[], contradicts: string[], evidence: string[], nextChecks: string[]) => causes.push({ cause, confidence: conf(Math.min(3, points)), score: points, supports, contradicts, evidence, nextChecks });
    if (!d.up) {
      const downN = nb.filter((n) => !n.up || deviceStatus(n).status === "offline");
      if (downN.length) add(`Upstream or shared-dependency failure involving ${downN.map((n) => n.name).join(", ")}`, 2 + (downN.length > 1 ? 1 : 0), [`${downN.length} linked device(s) are also down`], [], [id, ...downN.map((n) => n.id)], [`Check ${downN[0].name} first; ${d.name} may recover when it does.`]);
      else if (nb.length) add(`${d.name} itself is down (power, OS, agent or local network), neighbours are up`, 2, [`${nb.length} linked neighbour(s) are healthy`], ["A silent agent can look like a down host if only the agent reported availability"], [id, ...nb.map((n) => n.id)], ["Confirm with a probe from another host (net.reach)", "Check console/power"]);
      else add(`${d.name} is reported down; no topology is known to say whether the cause is local or upstream`, 1, ["Device reported unreachable"], ["No link data to rule out an upstream cause"], [id], ["Add link information or probe it from a second host"]);
    }
    const cpuHigh = (m.cpu ?? 0) >= NOC_THRESHOLDS.cpu[0], memHigh = (m.mem ?? 0) >= NOC_THRESHOLDS.mem[0], diskHigh = (m.disk ?? 0) >= NOC_THRESHOLDS.disk[0];
    if (cpuHigh || an.some((a) => a.metric === "cpu" && a.direction === "up")) {
      const sup = [`CPU ${m.cpu ?? "?"}%`]; let pts = 1; const ev = [id, ...an.filter((a) => a.metric === "cpu").flatMap((a) => a.evidence)];
      if (an.some((a) => a.metric === "cpu")) { pts++; sup.push("CPU is a statistical outlier versus its own baseline"); }
      if (cpuJob && topLine) { pts++; sup.push(`diagnostic ${cpuJob.id} (read-only, ${cpuJob.endedAt}) lists top process: ${topLine.trim().slice(0, 80)}`); ev.push(cpuJob.id); }
      add(`CPU-bound workload on ${d.name}`, pts, sup, memHigh ? [] : ["Memory is normal, so this is not obviously memory pressure"], ev, cpuJob ? ["Decide whether the listed process is expected"] : ["Request diagnostic sys.cpu_top to see which process is responsible"]);
    }
    if (memHigh) add(`Memory pressure on ${d.name}`, 1 + (an.some((a) => a.metric === "mem") ? 1 : 0), [`memory ${m.mem}%`], cpuHigh ? [] : ["CPU is not elevated"], [id, ...an.filter((a) => a.metric === "mem").flatMap((a) => a.evidence)], ["Request diagnostic sys.mem and sys.cpu_top"]);
    const dTr = tr.find((t) => t.metric === "disk");
    if (diskHigh || dTr) add(`Disk space exhaustion risk on ${d.name}`, (diskHigh ? 1 : 0) + (dTr ? 1 : 0) + (dTr?.etaHoursTo100 != null && dTr.etaHoursTo100 < 72 ? 1 : 0), [diskHigh ? `disk ${m.disk}%` : "", dTr ? `${dTr.why}${dTr.etaHoursTo100 != null ? ` At this rate it reaches 100% in about ${dTr.etaHoursTo100} h.` : ""}` : ""].filter(Boolean), [], [id, ...(dTr?.evidence ?? [])], ["Request diagnostic sys.disk to see which filesystem"]);
    const net = (m.latencyMs ?? 0) >= NOC_THRESHOLDS.latencyMs[0] || (m.lossPct ?? 0) >= NOC_THRESHOLDS.lossPct[0];
    if (net) { const bwBusy = [d, ...nb].filter((x) => (bwUtil(x.metrics) ?? 0) >= NOC_THRESHOLDS.util[0]); bwBusy.length ? add(`Link saturation near ${bwBusy.map((x) => x.name).join(", ")}`, 2 + (an.some((a) => a.metric === "latencyMs") ? 1 : 0), [`latency ${m.latencyMs ?? "?"} ms / loss ${m.lossPct ?? "?"}%`, `utilization high on ${bwBusy.map((x) => x.name).join(", ")}`], [], [id, ...bwBusy.map((x) => x.id)], ["Identify the top talker on the busy link"])
      : add(`Network path problem to ${d.name} (not explained by bandwidth)`, 1 + (an.some((a) => a.metric === "latencyMs" || a.metric === "lossPct") ? 1 : 0), [`latency ${m.latencyMs ?? "?"} ms / loss ${m.lossPct ?? "?"}%`], ["No link is saturated according to stored data"], [id], ["Run net.reach / net.ping from a neighbouring host to separate host from path"]); }
    const fl = flapping.find((f) => f.deviceId === id); if (fl) add(`${d.name} is flapping (${fl.transitions} up/down changes in ${hours} h)`, 2, [`${fl.transitions} state changes in stored availability samples`], [], [id, ...fl.evidence], ["Check cabling, power, or an agent restarting"]);
    if (!causes.length) limits.push(`${d.name}: no hypothesis could be formed from the available data (status ${st.status}).`);
    causes.sort((a, b) => b.score - a.score);
    return { deviceId: id, name: d.name, status: st.status, reasons: st.reasons, activeEvents: devEv, anomalies: an, trends: tr, rootCauses: causes, neighbours: nb.map((n) => n.id) };
  });
  // ---------- recommendations + suggested read-only diagnostics ----------
  const recs: Recommendation[] = [], diag: SuggestedDiagnostic[] = [];
  for (const a of analyses) { const top = a.rootCauses[0]; if (!top) continue; const sev = a.status === "offline" || a.status === "critical" ? "urgent" : "high";
    recs.push({ id: `rec:${a.deviceId}:0`, kind: "recommendation", priority: sev, action: `Investigate: ${top.cause}. ${top.nextChecks[0] ?? ""}`.trim(), rationale: `Most likely cause (${top.confidence} confidence): ${top.supports.join("; ")}.`, evidenceIds: top.evidence, confidence: top.confidence, requiresHuman: true, status: "not_executed", changesSystem: false });
    if (/CPU-bound/.test(top.cause)) { recs.push({ id: `rec:${a.deviceId}:1`, kind: "recommendation", priority: "medium", action: "If the busy process is not expected, a person may stop or restart it or scale the workload. Auto Adjust does not and cannot do this.", rationale: "Corrective action is outside the read-only scope of this platform.", evidenceIds: top.evidence, confidence: "low", requiresHuman: true, status: "not_executed", changesSystem: true }); diag.push({ template: "sys.cpu_top", hostId: a.deviceId, why: "See which process uses the CPU." , status: "suggested_not_requested" }); }
    if (/Memory pressure/.test(top.cause)) diag.push({ template: "sys.mem", hostId: a.deviceId, why: "Confirm memory and swap use.", status: "suggested_not_requested" }), diag.push({ template: "sys.cpu_top", hostId: a.deviceId, why: "See the top consumers.", status: "suggested_not_requested" });
    if (/Disk space/.test(top.cause)) { diag.push({ template: "sys.disk", hostId: a.deviceId, why: "See which filesystem is filling.", status: "suggested_not_requested" }); recs.push({ id: `rec:${a.deviceId}:2`, kind: "recommendation", priority: "high", action: "Plan cleanup or expansion before the projected full time. A person must perform it.", rationale: top.supports.join("; "), evidenceIds: top.evidence, confidence: top.confidence, requiresHuman: true, status: "not_executed", changesSystem: true }); }
    if (/Network path|Link saturation|down/.test(top.cause) && a.neighbours[0]) { const nIp = byId.get(a.neighbours[0])?.ip; if (nIp) diag.push({ template: "net.reach", hostId: a.neighbours[0], params: { host: byId.get(a.deviceId)?.ip ?? a.deviceId, port: 22 }, why: "Probe from a neighbouring host to tell a host fault from a path fault.", status: "suggested_not_requested" }); }
  }
  const suggested = opts.proposeDiagnostics ? await opts.proposeDiagnostics(diag) : diag;
  const allowed = new Set<string>([...devs.map((d) => d.id), ...evs.map((e) => e.id), ...incs.map((i) => i.id), ...jobs.map((j) => j.id), ...analyses.flatMap((a) => [...a.anomalies.flatMap((x) => x.evidence), ...a.trends.flatMap((x) => x.evidence), ...a.rootCauses.flatMap((x) => x.evidence)]), ...recs.map((r) => r.id), ...flapping.flatMap((f) => f.evidence)]);
  const nar = await narrate(model, "You are a NOC analyst assistant. Explain the most likely root cause and the evidence for a network operations manager.", { health: health.filter((h) => h.status !== "healthy").slice(0, 10), analyses: analyses.map((a) => ({ device: a.deviceId, status: a.status, causes: a.rootCauses.slice(0, 2).map((x) => ({ cause: x.cause, confidence: x.confidence, evidence: x.evidence.slice(0, 5) })) })) }, allowed);
  if (nar.discarded) limits.push(nar.discarded);
  await audit(c.store, c.actor, "noc.ai.analyze", opts.incidentId ?? focusId ?? "all", { devices: devs.length, anomalies: anomalies.length, method: nar.text ? "rules+ai" : "rules" });
  return { generatedAt: new Date(now).toISOString(), windowHours: hours, method: nar.text ? "rules+ai" : "rules", aiModel: nar.model ?? null, narrative: nar.text ?? null, narrativeNote: nar.text ? "Written by an AI model from the computed findings; the numbers and evidence ids are computed from your data." : null,
    health, anomalies, trends, correlations, analyses, recommendations: recs, suggestedDiagnostics: suggested, limitations: [...new Set(limits)], dataUsed: { devices: devs.length, events: evs.length, incidents: incs.length, diagnosticResults: jobs.length },
    contract: "Analysis only. Nothing in this result was executed on any system. Recommendations are for a human; suggested diagnostics are read-only checks that a human must request or confirm." };
}
