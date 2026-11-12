import { redactDeep } from "../noc/exec/redact";
import { T, type Store } from "./store";
import type { Alert, Asset, AuditEntry, DataSource, Incident, IncidentStatus, ScanImport, Severity, SocEvent, Verification, Vuln } from "./types";
import { INCIDENT_STATUSES, sevRank } from "./types";
import { CFG, runRules, type AlertDraft } from "./rules";
import { normalizeWindows, type RawWinEvent } from "./windows";
import { parseReport, sevFromCvss } from "./greenbone";
import { vulnPriority } from "./risk";
import { hid, ms, nowIso, rid, sha256, slug, uniq } from "./util";

export interface Actor { name: string; role: string }
const LOOKBACK_MS = 24 * 3600_000, INCIDENT_GAP_MS = 2 * 3600_000;

/** JSON with object keys sorted at every level. Postgres jsonb does not keep key order (it sorts by length, then bytes), so the hash must not depend on it. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v as object).sort().filter((k) => (v as any)[k] !== undefined).map((k) => JSON.stringify(k) + ":" + canonicalJson((v as any)[k])).join(",") + "}";
  return JSON.stringify(v) ?? "null";
}
type HashIn = Pick<AuditEntry, "id" | "time" | "actor" | "role" | "action" | "target" | "detail">;
const hashWith = (e: HashIn, prev: string, seq: number, detail: string) => sha256([prev, seq, e.id, e.time, e.actor, e.role, e.action, e.target, detail].join("|"));
/** Hash of an audit record: commits to its content and to the previous record, so editing or deleting history is detectable. */
export const auditHash = (e: HashIn, prev: string, seq: number) => hashWith(e, prev, seq, canonicalJson(e.detail ?? {}));
/** Records written before canonical hashing used JSON.stringify of the detail in insertion order; they still verify when the stored order happens to match. */
const legacyAuditHash = (e: HashIn, prev: string, seq: number) => hashWith(e, prev, seq, JSON.stringify(e.detail ?? {}));
let auditLock: Promise<unknown> = Promise.resolve();
/** Appends an audit record. Writes are serialized inside one server instance; the SQL migration adds a unique index on seq and
 *  blocks UPDATE/DELETE, so a second instance racing for the same position fails and retries instead of forking the chain. */
export function audit(store: Store, actor: Actor, action: string, target: string, rawDetail: Record<string, unknown> = {}): Promise<void> {
  const detail = redactDeep(rawDetail);   // secrets never reach the audit log
  const run = auditLock.then(async () => {
    for (let attempt = 0; attempt < 4; attempt++) {
      const [last] = await store.select<AuditEntry>(T.audit, { gte: ["seq", "1"], order: ["seq", "desc"], limit: 1 });
      const seq = (last?.seq ?? 0) + 1, prevHash = last?.hash ?? "genesis";
      const e: AuditEntry = { id: rid("aud"), time: nowIso(), actor: actor.name, role: actor.role, action, target, detail, seq, prevHash, hash: "" };
      e.hash = auditHash(e, prevHash, seq);
      try { await store.upsert(T.audit, [e]); return; } catch (err) { if (attempt === 3) throw err; }
    }
  });
  auditLock = run.catch(() => undefined);
  return run;
}
/** Re-computes the whole chain. Records written before the chain existed have no seq and are reported, not verified. */
export async function verifyAuditChain(store: Store): Promise<{ ok: boolean; checked: number; brokenAt?: { seq: number; id: string; reason: string }; unchainedBefore: number }> {
  const rows = await store.select<AuditEntry>(T.audit, { gte: ["seq", "1"], order: ["seq", "asc"], limit: 100000 });
  const all = await store.select<AuditEntry>(T.audit, { limit: 100000 }); let prev = "genesis", n = 0;
  for (const r of rows) {
    n++;
    if (r.seq !== n) return { ok: false, checked: n - 1, brokenAt: { seq: r.seq!, id: r.id, reason: `expected position ${n}; a record is missing or duplicated` }, unchainedBefore: all.length - rows.length };
    if (r.prevHash !== prev) return { ok: false, checked: n - 1, brokenAt: { seq: r.seq!, id: r.id, reason: "previous-hash link does not match" }, unchainedBefore: all.length - rows.length };
    if (r.hash !== auditHash(r, prev, r.seq!) && r.hash !== legacyAuditHash(r, prev, r.seq!)) return { ok: false, checked: n - 1, brokenAt: { seq: r.seq!, id: r.id, reason: "record content was changed after it was written" }, unchainedBefore: all.length - rows.length };
    prev = r.hash!;
  }
  return { ok: true, checked: n, unchainedBefore: all.length - rows.length };
}

// ---------- Windows ingestion ----------
export interface IngestResult { received: number; accepted: number; rejected: { index: number; error: string }[]; assets: string[]; newAlerts: number; updatedAlerts: number; incidentsTouched: number }

export async function ingestWindows(store: Store, payload: { host?: string; ips?: string[]; os?: string; collector?: string; version?: string; events: RawWinEvent[] }, source: DataSource, actor: Actor): Promise<IngestResult> {
  const events: SocEvent[] = [], rejected: IngestResult["rejected"] = [];
  const collector = payload.collector ?? "windows-collector";
  payload.events.forEach((raw, index) => {
    const n = normalizeWindows(raw, { host: payload.host, source, collector });
    if ("error" in n) rejected.push({ index, error: n.error }); else events.push(n);
  });
  const now = nowIso();
  const byAsset = new Map<string, SocEvent[]>();
  for (const e of events) (byAsset.get(e.assetId) ?? byAsset.set(e.assetId, []).get(e.assetId)!).push(e);
  if (events.length) await store.upsert(T.events, events);

  let newAlerts = 0, updatedAlerts = 0, touched = new Set<string>();
  for (const [assetId, evs] of byAsset) {
    const old = await store.get<Asset>(T.assets, assetId);
    const latest = evs.reduce((m, e) => (e.time > m ? e.time : m), evs[0].time);
    const asset: Asset = old ?? { id: assetId, hostname: evs[0].host, ips: [], criticality: 3, authorized: false, source, firstSeen: now, lastSeen: now };
    asset.ips = uniq([...asset.ips, ...(payload.ips ?? [])]).slice(0, 20);
    if (payload.os) asset.os = payload.os;
    asset.lastContactAt = now; asset.collector = collector; asset.collectorVersion = payload.version ?? asset.collectorVersion; asset.lastBatch = evs.length;
    asset.lastSeen = now; asset.lastEventAt = !asset.lastEventAt || latest > asset.lastEventAt ? latest : asset.lastEventAt;
    await store.upsert(T.assets, [asset]);

    const since = new Date(Math.max(0, ms(latest) - LOOKBACK_MS)).toISOString();
    const window = await store.select<SocEvent>(T.events, { where: { assetId }, gte: ["time", since], order: ["time", "asc"], limit: 20000 });
    const r = await applyDrafts(store, runRules(window), source, assetId);
    newAlerts += r.created; updatedAlerts += r.updated; r.incidents.forEach((i) => touched.add(i));
  }
  // A collector that has nothing new still reports in: record the contact so the console can show it is alive.
  if (payload.host) {
    const short = payload.host.split(".")[0], hid0 = slug(short);
    if (!byAsset.has(hid0)) {
      const old = await store.get<Asset>(T.assets, hid0);
      const asset: Asset = old ?? { id: hid0, hostname: short, ips: [], criticality: 3, authorized: false, source, firstSeen: now, lastSeen: now };
      asset.ips = uniq([...asset.ips, ...(payload.ips ?? [])]).slice(0, 20); if (payload.os) asset.os = payload.os;
      asset.lastContactAt = now; asset.lastSeen = now; asset.collector = collector; asset.collectorVersion = payload.version ?? asset.collectorVersion; asset.lastBatch = 0;
      await store.upsert(T.assets, [asset]);
    }
  }
  if (events.length || !payload.host) await audit(store, actor, "ingest.windows", payload.host ?? [...byAsset.keys()].join(","), { received: payload.events.length, accepted: events.length, rejected: rejected.length, source });
  return { received: payload.events.length, accepted: events.length, rejected: rejected.slice(0, 50), assets: [...byAsset.keys()], newAlerts, updatedAlerts, incidentsTouched: touched.size };
}

export async function applyDrafts(store: Store, drafts: AlertDraft[], source: DataSource, assetId: string) {
  const existing = await store.select<Alert>(T.alerts, { where: { assetId }, order: ["lastSeen", "desc"], limit: 5000 });
  const byKey = new Map<string, Alert[]>();
  for (const a of existing) (byKey.get(a.key) ?? byKey.set(a.key, []).get(a.key)!).push(a);
  let created = 0, updated = 0; const changed: Alert[] = [];
  for (const d of drafts) {
    const cand = (byKey.get(d.key) ?? []).find((a) => ms(d.firstSeen) <= ms(a.lastSeen) + CFG.groupGapMs && ms(d.lastSeen) >= ms(a.firstSeen) - CFG.groupGapMs);
    if (cand) {
      const merged: Alert = { ...cand, eventIds: uniq([...cand.eventIds, ...d.eventIds]).slice(0, 200), firstSeen: d.firstSeen < cand.firstSeen ? d.firstSeen : cand.firstSeen, lastSeen: d.lastSeen > cand.lastSeen ? d.lastSeen : cand.lastSeen,
        severity: sevRank(d.severity) > sevRank(cand.severity) ? d.severity : cand.severity, confidence: Math.max(cand.confidence, d.confidence), title: d.title, reasoning: d.reasoning, entities: d.entities };
      const same = JSON.stringify([merged.eventIds, merged.lastSeen, merged.severity, merged.title]) === JSON.stringify([cand.eventIds, cand.lastSeen, cand.severity, cand.title]);
      if (!same) { changed.push(merged); updated++; }
    } else {
      const a: Alert = { ...d, id: hid("alt", `${d.key}|${d.firstSeen}`), source, createdAt: nowIso() };
      changed.push(a); created++; (byKey.get(a.key) ?? byKey.set(a.key, []).get(a.key)!).unshift(a);
    }
  }
  const incidents = changed.length ? await correlate(store, changed, assetId, source) : new Set<string>();
  return { created, updated, incidents };
}

// ---------- Correlation into incidents ----------
async function correlate(store: Store, alerts: Alert[], assetId: string, source: DataSource): Promise<Set<string>> {
  const incs = await store.select<Incident>(T.incidents, { where: { assetId }, order: ["lastSeen", "desc"], limit: 500 });
  const touched = new Set<string>();
  for (const a of alerts.sort((x, y) => ms(x.firstSeen) - ms(y.firstSeen))) {
    let inc = a.incidentId ? incs.find((i) => i.id === a.incidentId) : undefined;
    if (!inc) inc = incs.find((i) => ms(a.firstSeen) <= ms(i.lastSeen) + INCIDENT_GAP_MS && ms(a.lastSeen) >= ms(i.firstSeen) - INCIDENT_GAP_MS && (i.status !== "closed" && i.status !== "remediated" || ms(a.firstSeen) <= ms(i.statusChangedAt)));
    if (!inc) {
      const prev = incs.find((i) => (i.status === "closed" || i.status === "remediated") && ms(a.firstSeen) > ms(i.statusChangedAt) && ms(a.firstSeen) - ms(i.lastSeen) <= 7 * 24 * 3600_000);
      const now = nowIso();
      inc = { id: hid("inc", `${assetId}|${a.id}`), source, title: a.title, severity: a.severity, confidence: a.confidence, status: "open", assetId, host: a.host, alertIds: [], tactics: [], firstSeen: a.firstSeen, lastSeen: a.lastSeen, reasoning: "", statusChangedAt: now, recurrenceOf: prev?.id, createdAt: now, updatedAt: now };
      incs.unshift(inc);
    }
    a.incidentId = inc.id;
    if (!inc.alertIds.includes(a.id)) inc.alertIds.push(a.id);
    touched.add(inc.id);
  }
  await store.upsert(T.alerts, alerts);
  for (const inc of incs.filter((i) => touched.has(i.id))) {
    const all = (await Promise.all(inc.alertIds.map((id) => (alerts.find((a) => a.id === id) ? Promise.resolve(alerts.find((a) => a.id === id)!) : store.get<Alert>(T.alerts, id))))).filter(Boolean) as Alert[];
    recompute(inc, all);
  }
  await store.upsert(T.incidents, incs.filter((i) => touched.has(i.id)));
  return touched;
}

export function recompute(inc: Incident, alerts: Alert[]) {
  const top = [...alerts].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.confidence - a.confidence)[0];
  const tactics = uniq(alerts.flatMap((a) => a.mitre.map((m) => m.tactic)));
  let sev: Severity = top.severity;
  const escalated = tactics.length >= 3 && sev !== "critical";
  if (escalated) sev = (["info", "low", "medium", "high", "critical"] as Severity[])[Math.min(4, sevRank(sev) + 1)];
  inc.title = alerts.length > 1 ? `${top.title} (+${alerts.length - 1} related)` : top.title;
  inc.severity = sev; inc.confidence = Math.max(...alerts.map((a) => a.confidence)); inc.tactics = tactics;
  inc.firstSeen = alerts.reduce((m, a) => (a.firstSeen < m ? a.firstSeen : m), alerts[0].firstSeen);
  inc.lastSeen = alerts.reduce((m, a) => (a.lastSeen > m ? a.lastSeen : m), alerts[0].lastSeen);
  inc.reasoning = `${alerts.length} alert(s) on ${inc.host} grouped because they occurred within ${INCIDENT_GAP_MS / 3600_000} hours of each other. Rules fired: ${uniq(alerts.map((a) => a.ruleId)).join(", ")}. ` +
    `Tactics seen: ${tactics.join(", ") || "none"}.${escalated ? " Severity was raised one level because three or more attack tactics appear together, which suggests a progressing attack rather than an isolated event." : ""}` +
    `${inc.recurrenceOf ? ` This follows earlier incident ${inc.recurrenceOf} that was already marked remediated/closed.` : ""}`;
  inc.updatedAt = nowIso();
}

// ---------- Incident status and verification ----------
const NEXT: Record<IncidentStatus, IncidentStatus[]> = { open: ["investigating", "contained"], investigating: ["open", "contained", "remediated"], contained: ["investigating", "remediated"], remediated: ["investigating", "closed"], closed: ["open"] };

export async function setIncidentStatus(store: Store, id: string, to: IncidentStatus, actor: Actor, note?: string, force = false): Promise<Incident> {
  const inc = await store.get<Incident>(T.incidents, id);
  if (!inc) throw new HttpError(404, "Incident not found");
  if (!INCIDENT_STATUSES.includes(to)) throw new HttpError(400, "Unknown status");
  if (!NEXT[inc.status].includes(to)) throw new HttpError(409, `Cannot move from ${inc.status} to ${to}. Allowed: ${NEXT[inc.status].join(", ")}.`);
  if (to === "closed" && inc.verification?.status !== "passed") {
    if (!force) throw new HttpError(409, "Run the remediation check first, or close it with force=true and a note to record that it was closed without a passing verification.");
    if (!note) throw new HttpError(400, "A note is required when closing without a passing verification.");
    inc.closedWithoutVerification = true;
  }
  const now = nowIso();
  inc.status = to; inc.statusChangedAt = now; inc.updatedAt = now;
  if (to === "remediated") { inc.remediatedAt = now; inc.verification = undefined; }
  await store.upsert(T.incidents, [inc]);
  await audit(store, actor, "incident.status", id, { to, note, force });
  return inc;
}

/** Checks whether the problem is gone using NEW telemetry from the asset after remediation. */
export async function verifyIncident(store: Store, id: string, actor: Actor): Promise<Incident> {
  const inc = await store.get<Incident>(T.incidents, id);
  if (!inc) throw new HttpError(404, "Incident not found");
  if (inc.status !== "remediated" || !inc.remediatedAt) throw new HttpError(409, "Verification runs on incidents marked Remediated.");
  const asset = await store.get<Asset>(T.assets, inc.assetId);
  const alerts = (await Promise.all(inc.alertIds.map((a) => store.get<Alert>(T.alerts, a)))).filter(Boolean) as Alert[];
  const rules = new Set(alerts.map((a) => a.ruleId));
  const after = await store.select<Alert>(T.alerts, { where: { assetId: inc.assetId }, gte: ["lastSeen", inc.remediatedAt] });
  const recur = after.filter((a) => rules.has(a.ruleId) && ms(a.lastSeen) > ms(inc.remediatedAt!));
  const details: string[] = []; let status: Verification["status"];
  const MIN_OBS = 15 * 60_000;
  const lastEvt = asset?.lastEventAt ? ms(asset.lastEventAt) : 0;
  if (recur.length) { status = "failed"; details.push(`${recur.length} new alert(s) from the same rule(s) after remediation: ${recur.map((a) => a.title).slice(0, 3).join("; ")}.`); }
  else if (lastEvt < ms(inc.remediatedAt) + MIN_OBS) { status = "inconclusive"; details.push(`No telemetry from ${inc.host} at least 15 minutes after remediation was recorded (last event ${asset?.lastEventAt ?? "never"}). Keep the collector running and check again later.`); }
  else { status = "passed"; details.push(`Telemetry from ${inc.host} continued until ${asset!.lastEventAt} with no new alerts from ${[...rules].join(", ")} after remediation.`); }
  const vulns = (await store.select<Vuln>(T.vulns, { where: { assetId: inc.assetId } })).filter((v) => v.status === "open" || v.status === "reappeared");
  if (vulns.length) details.push(`Note: ${vulns.length} open vulnerability finding(s) remain on this asset; a new authorized scan is needed to confirm those are fixed.`);
  inc.verification = { status, checkedAt: nowIso(), details };
  inc.updatedAt = nowIso();
  await store.upsert(T.incidents, [inc]);
  await audit(store, actor, "incident.verify", id, { status });
  return inc;
}

// ---------- Vulnerability import ----------
export class HttpError extends Error { constructor(public status: number, message: string, public extra?: Record<string, unknown>) { super(message); } }

export async function importScan(store: Store, content: string, o: { format?: "xml" | "csv"; filename?: string; attest: boolean; attestNote?: string; source: DataSource }, actor: Actor): Promise<ScanImport> {
  let rep; try { rep = parseReport(content, o.format); } catch (e) { throw new HttpError(400, (e as Error).message); }
  const now = nowIso(), scanTime = rep.scanTime ?? now;
  const assets = await store.select<Asset>(T.assets, { limit: 5000 });
  const resolve = (f: { host: string; ip: string }) => assets.find((a) => a.ips.includes(f.ip) || a.id === slug(f.host.split(".")[0]) || a.id === slug(f.ip));
  const hosts = new Map<string, { host: string; ip: string; asset?: Asset }>();
  for (const f of rep.findings) hosts.set(f.ip || f.host, { host: f.host, ip: f.ip, asset: resolve(f) });
  const unauthorized = [...hosts.values()].filter((h) => !h.asset?.authorized);
  if (unauthorized.length && !o.attest) throw new HttpError(409, "Some hosts in this report are not marked as authorized. Confirm you own or are authorized to test them, then retry with attest=true.", { unauthorizedHosts: unauthorized.map((h) => h.host || h.ip) });
  for (const h of unauthorized) {
    const nm = h.host && !/^\d+\.\d+\.\d+\.\d+$/.test(h.host) ? h.host.split(".")[0] : h.ip || h.host;
    const a: Asset = h.asset ?? { id: slug(nm), hostname: h.host || h.ip, ips: h.ip ? [h.ip] : [], criticality: 3, authorized: false, source: o.source, firstSeen: now, lastSeen: now };
    if (h.ip && !a.ips.includes(h.ip)) a.ips.push(h.ip);
    a.authorized = true; a.authorizedBy = actor.name; a.authorizedAt = now; a.authorizationNote = o.attestNote ?? "Attested at report import";
    await store.upsert(T.assets, [a]); h.asset = a;
    await audit(store, actor, "asset.authorize", a.id, { via: "scan import", note: a.authorizationNote });
  }
  const kev = new Set((await store.select<{ id: string }>(T.kev, { limit: 5000 })).map((k) => k.id.toUpperCase()));
  const scanId = hid("scn", `${scanTime}|${[...hosts.keys()].sort().join(",")}|${rep.findings.length}`);
  const prev = await store.select<Vuln>(T.vulns, { limit: 20000 });
  const prevById = new Map(prev.map((v) => [v.id, v]));
  const seen = new Set<string>(); let created = 0, reappeared = 0, fixed = 0; const rows: Vuln[] = [];
  for (const f of rep.findings) {
    const asset = hosts.get(f.ip || f.host)!.asset!;
    const id = hid("vul", `${asset.id}|${f.oid || f.name}|${f.port}`);
    if (seen.has(id)) continue; seen.add(id);
    const isKev = f.cves.some((c) => kev.has(c));
    const p = vulnPriority({ cvss: f.cvss, qod: f.qod, kev: isKev }, asset);
    const old = prevById.get(id);
    if (old && ms(scanTime) < ms(old.lastSeen)) continue; // older report than what we already know: never overwrite newer state
    let status = old?.status ?? "open";
    if (!old) created++; else if (old.status === "fixed_verified") { status = "reappeared"; reappeared++; }
    rows.push({ id, source: o.source, assetId: asset.id, host: asset.hostname, port: f.port, oid: f.oid, name: f.name, cvss: f.cvss, severity: sevFromCvss(f.cvss), cves: f.cves, qod: f.qod, summary: f.summary, solution: f.solution, solutionType: f.solutionType,
      status, firstSeen: old?.firstSeen ?? scanTime, lastSeen: scanTime, scanId, priority: p.score, priorityReasons: p.reasons, kev: isKev, note: old?.note, fixedAt: undefined, updatedAt: now });
  }
  // Findings absent from a LATER scan of the same host are recorded as fixed_verified (not observed by the scanner).
  const scopeAssets = new Set([...hosts.values()].map((h) => h.asset!.id));
  for (const v of prev) {
    if (seen.has(v.id) || !scopeAssets.has(v.assetId) || ms(scanTime) <= ms(v.lastSeen)) continue;
    if (v.status === "fixed_verified" || v.status === "accepted_risk") continue;
    rows.push({ ...v, status: "fixed_verified", fixedAt: scanTime, updatedAt: now }); fixed++;
  }
  if (rows.length) await store.upsert(T.vulns, rows);
  const imp: ScanImport = { id: scanId, source: o.source, format: rep.format, filename: o.filename, scanTime, importedAt: now, importedBy: actor.name, hosts: [...hosts.values()].map((h) => h.host || h.ip), findings: rep.findings.length, logResultsSkipped: rep.logResultsSkipped, newFindings: created, fixedVerified: fixed, reappeared };
  await store.upsert(T.scans, [imp]);
  await audit(store, actor, "import.scan", scanId, { hosts: imp.hosts.length, findings: imp.findings, created, fixed, reappeared });
  return imp;
}

export async function importKev(store: Store, json: unknown, actor: Actor): Promise<{ count: number; catalogVersion?: string }> {
  const o = json as { vulnerabilities?: { cveID?: string }[]; catalogVersion?: string };
  if (!o || !Array.isArray(o.vulnerabilities)) throw new HttpError(400, "Expected the CISA KEV JSON file (known_exploited_vulnerabilities.json).");
  const rows = o.vulnerabilities.filter((v) => v.cveID && /^CVE-\d{4}-\d+$/i.test(v.cveID)).map((v) => ({ id: v.cveID!.toUpperCase() }));
  await store.upsert(T.kev, rows);
  await store.upsert(T.meta, [{ id: "kev", importedAt: nowIso(), count: rows.length, catalogVersion: o.catalogVersion ?? "" }]);
  await audit(store, actor, "import.kev", "kev", { count: rows.length });
  return { count: rows.length, catalogVersion: o.catalogVersion };
}
