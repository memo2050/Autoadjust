// AI SOC analyst (analysis and recommendation ONLY). Deterministic, explainable core computed from THIS organization's stored alerts, incidents, events,
// assets and vulnerabilities; an optional language model may add a narrative, which is discarded if it cites evidence that does not exist.
// It performs no action on any host and cannot approve anything.
import type { Store } from "./store";
import { T } from "./store";
import { HttpError, audit, type Actor } from "./pipeline";
import { sevRank, type Alert, type Asset, type Incident, type SocEvent, type Vuln } from "./types";
import { ms } from "./util";
import type { ModelFn } from "./agents";
import { conf, narrate, type Recommendation, type SuggestedDiagnostic } from "../noc/exec/ai-common";

const SEV_POINTS: Record<string, number> = { critical: 40, high: 30, medium: 18, low: 8, info: 2 };
const KILL_CHAIN = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const OPEN = new Set(["open", "investigating", "contained"]);
export interface Factor { name: string; points: number; why: string; evidence: string[] }
export interface Priority { incidentId: string; title: string; host: string; severity: string; status: string; score: number; level: "critical" | "high" | "medium" | "low"; factors: Factor[]; confidence: "low" | "medium" | "high"; explanation: string }
export interface Correlation { id: string; kind: "shared_ip" | "shared_user" | "same_technique_multi_host" | "kill_chain_progression"; summary: string; incidentIds: string[]; alertIds: string[]; entity?: string; confidence: "low" | "medium" | "high"; why: string }

export async function analyzeSoc(store: Store, opts: { incidentId?: string; now?: number; proposeDiagnostics?: (s: SuggestedDiagnostic[]) => Promise<SuggestedDiagnostic[]> } = {}, actor: Actor, model: ModelFn | null = null) {
  const now = opts.now ?? Date.now();
  const [incs, alerts, events, assets, vulns] = await Promise.all([store.select<Incident>(T.incidents, { limit: 2000 }), store.select<Alert>(T.alerts, { limit: 5000 }), store.select<SocEvent>(T.events, { order: ["time", "desc"], limit: 5000 }), store.select<Asset>(T.assets, { limit: 1000 }), store.select<Vuln>(T.vulns, { limit: 5000 })]);
  if (opts.incidentId && !incs.some((i) => i.id === opts.incidentId)) throw new HttpError(404, "Incident not found in this organization.");
  const open = incs.filter((i) => OPEN.has(i.status)), alertById = new Map(alerts.map((a) => [a.id, a])), assetBy = new Map(assets.map((a) => [a.id, a])), limits: string[] = [];
  if (!incs.length) limits.push("This organization has no incidents stored, so there is nothing to prioritize. No data is not the same as no threats: check that collectors are sending data.");
  if (incs.length && !events.length) limits.push("No raw events are stored; conclusions rest on alerts only.");
  const vulnBy = new Map<string, Vuln[]>(); for (const v of vulns) (vulnBy.get(v.assetId) ?? vulnBy.set(v.assetId, []).get(v.assetId)!).push(v);

  // ---------- correlation (entities shared between open incidents) ----------
  const ents = new Map<string, { kind: "shared_ip" | "shared_user"; incidents: Set<string>; alerts: Set<string> }>();
  const addEnt = (key: string, kind: "shared_ip" | "shared_user", inc: string, al: string) => { const e = ents.get(key) ?? ents.set(key, { kind, incidents: new Set(), alerts: new Set() }).get(key)!; e.incidents.add(inc); e.alerts.add(al); };
  for (const i of open) for (const aid of i.alertIds) { const a = alertById.get(aid); if (!a) continue; for (const ip of a.entities.ips) addEnt("ip:" + ip, "shared_ip", i.id, a.id); for (const u of a.entities.users) addEnt("user:" + u.toLowerCase(), "shared_user", i.id, a.id); }
  const correlations: Correlation[] = [];
  for (const [k, e] of ents) if (e.incidents.size >= 2) correlations.push({ id: "corr:" + k, kind: e.kind, summary: `${e.kind === "shared_ip" ? "Address" : "Account"} ${k.slice(k.indexOf(":") + 1)} appears in ${e.incidents.size} open incidents`, incidentIds: [...e.incidents], alertIds: [...e.alerts].slice(0, 20), entity: k, confidence: e.incidents.size >= 3 ? "high" : "medium",
    why: "The same entity was recorded in alerts that belong to different incidents. This is a lead, not proof: shared NAT addresses and service accounts cause coincidental matches." });
  const tech = new Map<string, { hosts: Set<string>; incidents: Set<string>; alerts: Set<string>; name: string }>();
  for (const a of alerts) { if (ms(a.lastSeen) < now - 24 * 3600_000) continue; for (const m of a.mitre) { const t = tech.get(m.id) ?? tech.set(m.id, { hosts: new Set(), incidents: new Set(), alerts: new Set(), name: m.name }).get(m.id)!; t.hosts.add(a.host); t.alerts.add(a.id); if (a.incidentId) t.incidents.add(a.incidentId); } }
  for (const [id, t] of tech) if (t.hosts.size >= 2) correlations.push({ id: "corr:tech:" + id, kind: "same_technique_multi_host", summary: `${id} ${t.name} seen on ${t.hosts.size} hosts in the last 24 h (${[...t.hosts].slice(0, 5).join(", ")})`, incidentIds: [...t.incidents], alertIds: [...t.alerts].slice(0, 20), confidence: t.hosts.size >= 3 ? "high" : "medium", why: "The same technique on several hosts in one day can indicate one campaign, or one noisy detection rule applied everywhere." });
  for (const i of open) { const stages = [...new Set(i.tactics)].filter((x) => KILL_CHAIN.includes(x)).sort((a, b) => KILL_CHAIN.indexOf(a) - KILL_CHAIN.indexOf(b)); if (stages.length >= 3) correlations.push({ id: "corr:chain:" + i.id, kind: "kill_chain_progression", summary: `Incident ${i.id} spans ${stages.length} attack stages: ${stages.join(" → ")}`, incidentIds: [i.id], alertIds: i.alertIds.slice(0, 20), confidence: stages.length >= 4 ? "high" : "medium", why: "Several different tactics on one incident suggest progression rather than an isolated event." }); }

  // ---------- prioritization (every point is explained and traceable) ----------
  const corrCount = (id: string) => correlations.filter((c) => c.incidentIds.includes(id)).length;
  const priorities: Priority[] = open.map((i) => {
    const f: Factor[] = [], al = i.alertIds.map((x) => alertById.get(x)).filter(Boolean) as Alert[], asset = assetBy.get(i.assetId);
    f.push({ name: "severity", points: SEV_POINTS[i.severity] ?? 0, why: `Incident severity is ${i.severity}.`, evidence: [i.id] });
    if (asset) f.push({ name: "asset criticality", points: asset.criticality * 4, why: `${asset.hostname} is rated ${asset.criticality}/5 by a human.`, evidence: [asset.id] }); else limits.push(`No asset record for ${i.host}; criticality not considered for ${i.id}.`);
    const rules = new Set(al.map((a) => a.ruleId)).size, evN = al.reduce((n, a) => n + a.eventIds.length, 0), ev = Math.min(15, rules * 3 + Math.min(6, Math.floor(evN / 5)) + Math.round(i.confidence * 3));
    f.push({ name: "evidence strength", points: ev, why: `${al.length} alert(s) from ${rules} distinct rule(s), ${evN} supporting event(s), detection confidence ${Math.round(i.confidence * 100)}%.`, evidence: al.map((a) => a.id).slice(0, 10) });
    const age = now - ms(i.lastSeen), rec = age < 3600_000 ? 10 : age < 86400_000 ? 6 : age < 7 * 86400_000 ? 2 : 0; f.push({ name: "recency", points: rec, why: age < 0 ? "Activity just recorded." : `Last activity ${Math.round(age / 60000)} min ago.`, evidence: [i.id] });
    const cc = corrCount(i.id); if (cc) f.push({ name: "correlation", points: Math.min(10, cc * 4), why: `Linked to ${cc} correlation lead(s) with other activity.`, evidence: correlations.filter((c) => c.incidentIds.includes(i.id)).map((c) => c.id) });
    const stages = new Set(i.tactics).size; if (stages >= 3) f.push({ name: "attack progression", points: 5, why: `${stages} different tactics recorded.`, evidence: [i.id] });
    const kev = (vulnBy.get(i.assetId) ?? []).filter((v) => v.kev && v.status !== "fixed_verified" && v.status !== "accepted_risk"); if (kev.length) f.push({ name: "known exploited vulnerability", points: 8, why: `${kev.length} open vulnerability on this asset is in the CISA KEV catalog.`, evidence: kev.slice(0, 5).map((v) => v.id) });
    const score = Math.min(100, f.reduce((s, x) => s + x.points, 0)), level: Priority["level"] = score >= 75 ? "critical" : score >= 55 ? "high" : score >= 35 ? "medium" : "low";
    const confidence = conf((al.length ? 1 : 0) + (rules >= 2 ? 1 : 0) + (evN >= 5 ? 1 : 0) + (i.confidence >= 0.7 ? 0 : 0));
    return { incidentId: i.id, title: i.title, host: i.host, severity: i.severity, status: i.status, score, level, factors: f, confidence, explanation: `Score ${score}/100 = ${f.map((x) => `${x.name} ${x.points}`).join(" + ")}. Highest contributors: ${[...f].sort((a, b) => b.points - a.points).slice(0, 2).map((x) => x.name).join(", ")}.` };
  }).sort((a, b) => b.score - a.score || sevRank(b.severity as any) - sevRank(a.severity as any));

  // ---------- focused investigation ----------
  let investigation: any;
  if (opts.incidentId) {
    const i = incs.find((x) => x.id === opts.incidentId)!, al = i.alertIds.map((x) => alertById.get(x)).filter(Boolean) as Alert[], evIds = new Set(al.flatMap((a) => a.eventIds)), evs = events.filter((e) => evIds.has(e.id)).sort((a, b) => (a.time < b.time ? -1 : 1));
    const missing = i.alertIds.filter((x) => !alertById.has(x)); if (missing.length) limits.push(`${missing.length} alert(s) referenced by the incident are no longer stored.`);
    investigation = { incidentId: i.id, status: i.status, host: i.host, window: { first: i.firstSeen, last: i.lastSeen },
      timeline: [...al.map((a) => ({ time: a.firstSeen, kind: "alert", id: a.id, text: `${a.title} [${a.severity}] ${a.mitre.map((m) => m.id).join(",")}` })), ...evs.slice(0, 40).map((e) => ({ time: e.time, kind: "event", id: e.id, text: e.summary }))].sort((a, b) => (a.time < b.time ? -1 : 1)).slice(0, 80),
      entities: { users: [...new Set(al.flatMap((a) => a.entities.users))].slice(0, 20), ips: [...new Set(al.flatMap((a) => a.entities.ips))].slice(0, 20) },
      tactics: [...new Set(i.tactics)].sort((a, b) => KILL_CHAIN.indexOf(a) - KILL_CHAIN.indexOf(b)), reasoningFromDetection: i.reasoning, relatedIncidents: [...new Set(correlations.filter((c) => c.incidentIds.includes(i.id)).flatMap((c) => c.incidentIds))].filter((x) => x !== i.id),
      evidenceCount: { alerts: al.length, events: evs.length } };
    if (!evs.length) limits.push("No raw events are stored for this incident; the timeline contains alerts only.");
  }

  // ---------- recommendations (human steps; nothing is executed) ----------
  const recs: Recommendation[] = [], diag: SuggestedDiagnostic[] = [], focus = opts.incidentId ? priorities.filter((p) => p.incidentId === opts.incidentId) : priorities.slice(0, 5);
  for (const p of focus) {
    const i = incs.find((x) => x.id === p.incidentId)!, ids = [i.id, ...i.alertIds.slice(0, 8)];
    const push = (priority: Recommendation["priority"], action: string, rationale: string, changes: boolean, c: "low" | "medium" | "high" = p.confidence) => recs.push({ id: `rec:${i.id}:${recs.length}`, kind: "recommendation", priority, action, rationale, evidenceIds: ids, confidence: c, requiresHuman: true, status: "not_executed", changesSystem: changes });
    const tact = new Set(i.tactics);
    if (p.level === "critical" || p.level === "high") push("urgent", `Assign an owner and start triage of ${i.id} now (${p.level}, score ${p.score}).`, p.explanation, false);
    if (tact.has("Credential Access")) push("high", `Review sign-in activity for the accounts involved and consider a password reset for any account with a successful logon after failures. (A person must do this; Auto Adjust cannot change accounts.)`, "Credential Access tactic recorded on this incident.", true);
    if (tact.has("Lateral Movement") || corrCount(i.id)) push("high", "Check the correlated hosts/accounts for the same indicators before closing this incident.", `Correlation leads: ${correlations.filter((c) => c.incidentIds.includes(i.id)).map((c) => c.summary).slice(0, 2).join("; ")}`, false, "medium");
    if (tact.has("Command and Control") || tact.has("Exfiltration")) push("urgent", "Consider network containment of the host after confirming with its owner (firewall/isolation is a manual step).", "Command-and-control or exfiltration tactic recorded.", true);
    if (!asset(i)) push("low", `Register ${i.host} as an asset and set its criticality so future prioritization is accurate.`, "No asset record exists.", false);
    function asset(x: Incident) { return assetBy.get(x.assetId); }
    diag.push({ template: "sys.cpu_top", hostId: i.host.toLowerCase(), why: "Read-only: list the top processes by CPU (names only) on the host to compare with the alert timeline.", status: "suggested_not_requested" });
  }
  if (!recs.length && incs.length) recs.push({ id: "rec:none", kind: "recommendation", priority: "low", action: "No open incident needs action from this analysis.", rationale: "Every open incident scored low or there are no open incidents.", evidenceIds: [], confidence: "low", requiresHuman: true, status: "not_executed", changesSystem: false });
  const suggested = opts.proposeDiagnostics ? await opts.proposeDiagnostics(diag) : diag;

  const allowed = new Set<string>([...incs.map((i) => i.id), ...alerts.map((a) => a.id), ...events.map((e) => e.id), ...assets.map((a) => a.id), ...vulns.map((v) => v.id), ...correlations.map((c) => c.id), ...recs.map((r) => r.id)]);
  const nar = await narrate(model, "You are a SOC analyst assistant. Summarize the prioritized incidents and the most important correlation for a security manager.", { priorities: priorities.slice(0, 5).map((p) => ({ id: p.incidentId, title: p.title, score: p.score, explanation: p.explanation })), correlations: correlations.slice(0, 5).map((c) => ({ id: c.id, summary: c.summary })), investigation }, allowed);
  if (nar.discarded) limits.push(nar.discarded);
  await audit(store, actor, "soc.ai.analyze", opts.incidentId ?? "all", { incidents: priorities.length, correlations: correlations.length, method: nar.text ? "rules+ai" : "rules" });
  return { generatedAt: new Date(now).toISOString(), method: nar.text ? "rules+ai" : "rules", aiModel: nar.model ?? null, narrative: nar.text ?? null, narrativeNote: nar.text ? "Written by an AI model from the computed findings below; the findings, scores and evidence ids are computed from your data, not by the model." : null,
    priorities, correlations, investigation: investigation ?? null, recommendations: recs, suggestedDiagnostics: suggested, limitations: [...new Set(limits)], dataUsed: { incidents: incs.length, openIncidents: open.length, alerts: alerts.length, events: events.length, assets: assets.length, vulnerabilities: vulns.length },
    contract: "Analysis only. Nothing in this result was executed on any system. 'recommendation' entries are suggestions for a human; 'suggestedDiagnostics' are read-only checks a human may request." };
}
