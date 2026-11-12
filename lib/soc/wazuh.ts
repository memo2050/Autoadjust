// Wazuh integration. READ-ONLY by design: the only requests made to Wazuh are
//   POST /security/user/authenticate (Manager API login), GET /agents, GET /manager/info, GET /security/users/me   (Manager API, port 55000)
//   GET /_cluster/health, POST /wazuh-alerts-*/_search (a search, not a write)                                         (Wazuh Indexer, port 9200)
// No active-response, restart, delete or configuration call exists in this file. Credentials come from server environment variables or stay on the bridge machine.
import type { Alert, Asset, DataSource, MitreRef, Severity, SocEvent } from "./types";
import { sevRank } from "./types";
import { T, type Store } from "./store";
import { normalizeWindows } from "./windows";
import { applyDrafts, audit, HttpError, type Actor } from "./pipeline";
import type { AlertDraft } from "./rules";
import { clip, hid, nowIso, slug } from "./util";

export interface WazuhCfg { apiUrl: string; apiUser: string; apiPassword: string; indexerUrl: string; indexerUser: string; indexerPassword: string; index: string; minLevel: number }
type Fetcher = typeof fetch;
const uniq = <X,>(a: X[]) => [...new Set(a)];

export function wazuhEnv(env: Record<string, string | undefined> = process.env): WazuhCfg | null {
  const g = (k: string) => (env[k] ?? "").trim();
  if (!g("WAZUH_API_URL") || !g("WAZUH_API_USER") || !g("WAZUH_API_PASSWORD") || !g("WAZUH_INDEXER_URL") || !g("WAZUH_INDEXER_USER") || !g("WAZUH_INDEXER_PASSWORD")) return null;
  const min = Number(g("WAZUH_MIN_LEVEL") || 7);
  return { apiUrl: checkUrl(g("WAZUH_API_URL"), env), apiUser: g("WAZUH_API_USER"), apiPassword: g("WAZUH_API_PASSWORD"), indexerUrl: checkUrl(g("WAZUH_INDEXER_URL"), env), indexerUser: g("WAZUH_INDEXER_USER"), indexerPassword: g("WAZUH_INDEXER_PASSWORD"), index: g("WAZUH_INDEX") || "wazuh-alerts-*", minLevel: Number.isFinite(min) ? Math.min(15, Math.max(1, min)) : 7 };
}
function checkUrl(u: string, env: Record<string, string | undefined>) {
  let x: URL; try { x = new URL(u); } catch { throw new HttpError(500, "A Wazuh URL in the server settings is not a valid URL."); }
  if (x.username || x.password) throw new HttpError(500, "Wazuh URLs must not contain credentials. Put them in the *_USER and *_PASSWORD settings.");
  if (x.protocol !== "https:" && !(x.protocol === "http:" && (env.WAZUH_ALLOW_HTTP === "1" || /^(localhost|127\.0\.0\.1)$/.test(x.hostname)))) throw new HttpError(500, "Wazuh URLs must use https (set WAZUH_ALLOW_HTTP=1 only on a trusted lab network).");
  return x.origin;
}

// ---------------------------------------------------------------- client (GET / search only)
export class WazuhClient {
  private jwt = ""; public requests: string[] = [];
  constructor(private c: WazuhCfg, private f: Fetcher = fetch) {}
  private basic(u: string, p: string) { return "Basic " + Buffer.from(`${u}:${p}`).toString("base64"); }
  private async call(url: string, init: RequestInit, what: string) {
    this.requests.push(`${init.method ?? "GET"} ${url.replace(/^https?:\/\/[^/]+/, "")}`);
    let r: Response; try { r = await this.f(url, { ...init, signal: AbortSignal.timeout(20_000) }); } catch (e: any) { throw new Error(`${what}: cannot reach Wazuh (${String(e?.cause?.code ?? e?.message ?? e).slice(0, 120)}). Check the address, firewall and TLS certificate.`); }
    if (r.status === 401 || r.status === 403) throw Object.assign(new Error(`${what}: rejected the credentials or the account lacks permission (HTTP ${r.status}).`), { auth: true });
    if (!r.ok) throw new Error(`${what}: Wazuh answered HTTP ${r.status}.`);
    return r;
  }
  async login() { const r = await this.call(`${this.c.apiUrl}/security/user/authenticate?raw=true`, { method: "POST", headers: { Authorization: this.basic(this.c.apiUser, this.c.apiPassword) } }, "Manager API login"); this.jwt = (await r.text()).trim(); if (!this.jwt) throw new Error("Manager API login returned no token."); }
  private async api(path: string, what: string): Promise<any> {
    if (!this.jwt) await this.login();
    try { return await (await this.call(this.c.apiUrl + path, { headers: { Authorization: "Bearer " + this.jwt } }, what)).json(); }
    catch (e: any) { if (e.auth && this.jwt) { this.jwt = ""; await this.login(); return (await this.call(this.c.apiUrl + path, { headers: { Authorization: "Bearer " + this.jwt } }, what)).json(); } throw e; }
  }
  async managerInfo() { const j = await this.api("/manager/info", "Manager info"); const i = j?.data?.affected_items?.[0] ?? {}; return { version: i.version as string | undefined, name: i.name as string | undefined }; }
  async me() { const j = await this.api("/security/users/me", "Account check"); const i = j?.data?.affected_items?.[0] ?? {}; return { user: i.username as string | undefined, roles: (i.roles ?? []).map((r: any) => (typeof r === "string" ? r : r?.name)).filter(Boolean) as string[] }; }
  async agents(): Promise<WazuhAgent[]> { const out: WazuhAgent[] = []; for (let off = 0; off < 5000; off += 500) { const j = await this.api(`/agents?limit=500&offset=${off}&select=id,name,ip,status,os.name,os.version,version,lastKeepAlive,group,node_name`, "Agent list"); const items = j?.data?.affected_items ?? []; out.push(...items); if (items.length < 500) break; } return out; }
  private idx(path: string, init: RequestInit = {}) { return this.call(this.c.indexerUrl + path, { ...init, headers: { Authorization: this.basic(this.c.indexerUser, this.c.indexerPassword), "Content-Type": "application/json" } }, "Wazuh Indexer"); }
  async indexerHealth() { const j: any = await (await this.idx("/_cluster/health")).json(); return { status: j.status as string, nodes: j.number_of_nodes as number }; }
  async alerts(since: string | null, size = 500): Promise<WazuhAlert[]> {
    const body = { size, sort: [{ "@timestamp": "asc" }], query: since ? { range: { "@timestamp": { gte: since } } } : { range: { "@timestamp": { gte: "now-1h" } } } };
    const j: any = await (await this.idx(`/${encodeURIComponent(this.c.index).replace("%2A", "*")}/_search`, { method: "POST", body: JSON.stringify(body) })).json();
    return (j?.hits?.hits ?? []).map((h: any) => ({ ...h._source, _id: h._id }));
  }
  async latestAlertTime(): Promise<string | null> { const j: any = await (await this.idx(`/${this.c.index}/_search`, { method: "POST", body: JSON.stringify({ size: 1, sort: [{ "@timestamp": "desc" }], _source: ["@timestamp"] }) })).json(); return j?.hits?.hits?.[0]?._source?.["@timestamp"] ?? null; }
}
export interface WazuhAgent { id: string; name: string; ip?: string; status?: string; os?: { name?: string; version?: string }; version?: string; lastKeepAlive?: string; group?: string[]; node_name?: string }
export interface WazuhAlert { _id?: string; id?: string; timestamp?: string; "@timestamp"?: string; agent?: { id?: string; name?: string; ip?: string }; manager?: { name?: string }; rule?: { id?: string; level?: number; description?: string; groups?: string[]; firedtimes?: number; mitre?: { id?: string[]; technique?: string[]; tactic?: string[] } };
  data?: Record<string, any>; syscheck?: Record<string, any>; full_log?: string; location?: string; decoder?: { name?: string } }

// ---------------------------------------------------------------- classification (Phase 2 workflows)
export type Category = "brute_force" | "failed_logon" | "suspicious_login" | "priv_esc" | "powershell" | "malware" | "fim" | "network" | "other";
export const CATEGORY_LABEL: Record<Category, string> = { brute_force: "Brute force", failed_logon: "Failed logon", suspicious_login: "Suspicious login", priv_esc: "Privilege escalation", powershell: "Suspicious PowerShell", malware: "Malware indicator", fim: "File integrity change", network: "Suspicious network activity", other: "Wazuh detection" };
export function categorize(a: WazuhAlert): Category {
  const g = (a.rule?.groups ?? []).join(",").toLowerCase(), d = `${a.rule?.description ?? ""}`.toLowerCase(), lv = a.rule?.level ?? 0;
  if (a.syscheck || /(^|,)syscheck/.test(g)) return "fim";
  if (/powershell|encoded command|invoke-expression|downloadstring|-enc\b/.test(d + " " + String(a.data?.win?.eventdata?.commandLine ?? a.data?.win?.eventdata?.scriptBlockText ?? "").toLowerCase())) return "powershell";
  if (/malware|virus|trojan|ransom|webshell|rootkit|virustotal|yara|defender.*(detect|threat)|antivirus/.test(g + " " + d)) return "malware";
  if (/brute|multiple.*(fail|attempt)|authentication_failures|maximum authentication attempts|password spray/.test(d) || (/authentication_failures/.test(g) && lv >= 10)) return "brute_force";
  if (/authentication_fail|win_authentication_failed|invalid_login/.test(g) || /(logon|login|authentication).*(fail|invalid)/.test(d)) return "failed_logon";
  if (/privilege|escalat|sudo|\bsu:|added to .*(admin|group)|group.*(changed|member)/.test(g + " " + d)) return "priv_esc";
  if (/authentication_success/.test(g) && lv >= 7) return "suspicious_login";
  if (/(^|,)(ids|suricata|firewall|web_scan|portscan|attack)(,|$)/.test(g) || /port scan|network scan|firewall|dropped|intrusion|c2|command and control|dns tunnel/.test(d)) return "network";
  return "other";
}
const sevFromLevel = (l: number): Severity => (l >= 15 ? "critical" : l >= 12 ? "high" : l >= 7 ? "medium" : l >= 4 ? "low" : "info");
const SENSITIVE = /(\\windows\\system32|\\windows\\syswow64|\\startup\\|\\drivers\\etc|\/etc\/(passwd|shadow|sudoers|ssh|cron)|authorized_keys|\/\.ssh\/|\/bin\/|\/sbin\/|\/usr\/(s)?bin\/|crontab|\/boot\/|hklm\\software\\microsoft\\windows\\currentversion\\run)/i;
const FALLBACK_MITRE: Partial<Record<Category, MitreRef>> = { brute_force: { id: "T1110", name: "Brute Force", tactic: "Credential Access" }, powershell: { id: "T1059.001", name: "PowerShell", tactic: "Execution" } };
export function mitreOf(a: WazuhAlert, cat: Category): { refs: MitreRef[]; inferred: boolean } {
  const m = a.rule?.mitre, ids = m?.id ?? [];
  if (ids.length) return { refs: ids.map((id, i) => ({ id, name: m?.technique?.[i] ?? id, tactic: (m?.tactic?.[i] ?? m?.tactic?.[0] ?? "Unknown") })), inferred: false };
  const f = FALLBACK_MITRE[cat]; return f ? { refs: [f], inferred: true } : { refs: [], inferred: false };
}
const when = (a: WazuhAlert) => { const t = Date.parse(String(a["@timestamp"] ?? a.timestamp ?? "")); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const flat = (o: any, p = "", out: Record<string, string> = {}, d = 0): Record<string, string> => { if (d > 3 || o == null) return out; for (const [k, v] of Object.entries(o)) { if (Object.keys(out).length >= 40) break; if (v && typeof v === "object" && !Array.isArray(v)) flat(v, p + k + ".", out, d + 1); else if (v != null && v !== "") out[p + k] = clip(Array.isArray(v) ? v.join(",") : String(v), 600); } return out; };

/** Wazuh alert -> Spark event. Windows event-channel alerts become real Windows events so all existing Windows detections also run on them. */
export function alertToEvent(a: WazuhAlert, source: DataSource, collector = "wazuh"): SocEvent | { error: string } {
  const at = when(a); if (!at) return { error: "missing or invalid timestamp" };
  const host = String(a.agent?.name ?? a.manager?.name ?? "").trim(); if (!host) return { error: "missing agent name" };
  const cat = categorize(a), lvl = a.rule?.level ?? 0, rid = String(a.rule?.id ?? "0"), win = a.data?.win;
  let ev: SocEvent;
  if (win?.system?.eventID) {
    const n = normalizeWindows({ EventID: win.system.eventID, LogName: win.system.channel, ProviderName: win.system.providerName, TimeCreated: win.system.systemTime ?? at, MachineName: win.system.computer ?? host, RecordId: win.system.eventRecordID, Level: win.system.severityValue ?? win.system.level, Data: win.eventdata ?? {} }, { host, source, collector });
    if ("error" in n) return n; ev = n;
    ev.host = host.split(".")[0]; ev.assetId = slug(ev.host);
  } else {
    const d = a.data ?? {}, sc = a.syscheck, user = d.dstuser ?? d.srcuser ?? d.user ?? sc?.uname_after;
    ev = { id: "", source, collector, assetId: slug(host.split(".")[0]), host: host.split(".")[0], time: at, channel: "wazuh", provider: `wazuh:${a.decoder?.name ?? a.location ?? "rule"}`, eventId: Number(rid) || 0, level: String(lvl), user: user ? String(user) : undefined,
      srcIp: d.srcip ? String(d.srcip) : undefined, process: d.process ? String(d.process) : undefined, commandLine: d.command ? clip(String(d.command), 1500) : undefined, severity: sevFromLevel(lvl), summary: clip(String(a.rule?.description ?? `Wazuh rule ${rid}`), 300), data: {}, fingerprint: "", ingestedAt: nowIso() };
    ev.data = sc ? { path: String(sc.path ?? ""), event: String(sc.event ?? ""), sha256_after: String(sc.sha256_after ?? ""), md5_after: String(sc.md5_after ?? ""), mode: String(sc.mode ?? ""), changed_attributes: (sc.changed_attributes ?? []).join(","), uname_after: String(sc.uname_after ?? "") } : flat(d);
    ev.fingerprint = ["wazuh", a.id ?? a._id ?? "", host, at, rid].join("|"); ev.id = hid("evt", ev.fingerprint);
  }
  Object.assign(ev.data, { wazuhRuleId: rid, wazuhLevel: String(lvl), wazuhCategory: cat, wazuhGroups: (a.rule?.groups ?? []).join(","), wazuhDescription: clip(String(a.rule?.description ?? ""), 200), wazuhAlertId: String(a.id ?? a._id ?? "") });
  if (cat === "failed_logon" || cat === "brute_force") ev.data.category = "failed_logon";
  return ev;
}

/** Wazuh rule hits at or above the minimum level become Spark alerts, grouped per rule, host and source. Nothing is invented: every draft cites the stored events. */
export function alertsToDrafts(items: { a: WazuhAlert; ev: SocEvent }[], minLevel: number): AlertDraft[] {
  const groups = new Map<string, { a: WazuhAlert; ev: SocEvent[]; cat: Category; sens: boolean }>();
  for (const { a, ev } of items) {
    const cat = categorize(a), lv = a.rule?.level ?? 0, path = String(a.syscheck?.path ?? ""), sens = cat === "fim" && SENSITIVE.test(path);
    if (lv < minLevel && !sens) continue;
    const part = a.syscheck ? path.replace(/[^\\/]*$/, "") : ev.srcIp ?? ev.user ?? "", key = `WZH-${a.rule?.id ?? "0"}|${ev.assetId}|${part}`;
    const g = groups.get(key) ?? groups.set(key, { a, ev: [], cat, sens: false }).get(key)!; g.ev.push(ev); g.sens = g.sens || sens;
  }
  return [...groups.entries()].map(([key, g]) => {
    const lv = g.a.rule?.level ?? 0, first = g.ev.reduce((m, e) => (e.time < m ? e.time : m), g.ev[0].time), last = g.ev.reduce((m, e) => (e.time > m ? e.time : m), g.ev[0].time), { refs, inferred } = mitreOf(g.a, g.cat);
    let sev = sevFromLevel(lv); if (g.sens && sevRank(sev) < sevRank("high")) sev = "high";
    const e0 = g.ev[0], ips = uniq(g.ev.map((e) => e.srcIp).filter(Boolean) as string[]), users = uniq(g.ev.map((e) => e.user).filter(Boolean) as string[]);
    const why: string[] = [`Wazuh rule ${g.a.rule?.id} (level ${lv}) "${g.a.rule?.description ?? ""}" matched ${g.ev.length} time(s) on ${e0.host} between ${first} and ${last}.`, `Category: ${CATEGORY_LABEL[g.cat]}.`];
    if (g.cat === "fim") why.push(`File ${g.a.syscheck?.path} was ${g.a.syscheck?.event ?? "changed"}${g.sens ? "; the path is a sensitive system location, so severity was raised to high" : ""}. Hash after change: ${g.a.syscheck?.sha256_after ?? "not reported"}.`);
    if (ips.length) why.push(`Source address(es): ${ips.slice(0, 5).join(", ")}.`); if (users.length) why.push(`Account(s): ${users.slice(0, 5).join(", ")}.`);
    why.push(refs.length ? (inferred ? `MITRE mapping (${refs[0].id}) is inferred from the detection category because Wazuh did not supply one.` : `MITRE ATT&CK mapping comes from the Wazuh rule.`) : "Wazuh supplied no MITRE mapping for this rule.");
    why.push("This is a Wazuh rule detection that Spark has stored and correlated; Spark did not independently verify it.");
    return { ruleId: `WZH-${g.a.rule?.id ?? "0"}`, key, title: `${CATEGORY_LABEL[g.cat]}: ${clip(g.a.rule?.description ?? "Wazuh alert", 120)}${g.ev.length > 1 ? ` (×${g.ev.length})` : ""}`, severity: sev, confidence: lv >= 12 ? 0.85 : lv >= 10 ? 0.75 : 0.6, mitre: refs,
      assetId: e0.assetId, host: e0.host, eventIds: g.ev.map((e) => e.id).slice(0, 200), firstSeen: first, lastSeen: last, reasoning: why.join(" "), entities: { users, ips } } as AlertDraft;
  });
}

// ---------------------------------------------------------------- ingest
export interface WazuhPush { agents?: WazuhAgent[]; alerts?: WazuhAlert[]; manager?: { version?: string; name?: string }; bridge?: { name?: string; version?: string }; test?: WazuhTest; cursor?: string }
export interface WazuhTest { at: string; by: string; mode: "direct" | "bridge"; ok: boolean; steps: { name: string; ok: boolean; detail: string }[] }
export interface WazuhState { id: "wazuh"; data: { mode?: "direct" | "bridge"; lastSyncAt?: string; lastSuccessAt?: string; lastError?: string; lastErrorAt?: string; cursor?: string; agents?: { total: number; active: number; disconnected: number; pending: number; never: number }; managerVersion?: string; alertsReceived: number; lastAlertAt?: string; bridge?: { name?: string; version?: string }; lastTest?: WazuhTest } }
const getState = async (s: Store): Promise<WazuhState> => (await s.get<WazuhState>(T.meta, "wazuh")) ?? { id: "wazuh", data: { alertsReceived: 0 } };
const putState = (s: Store, st: WazuhState) => s.upsert(T.meta, [st as any]);

export async function ingestWazuh(store: Store, p: WazuhPush, o: { source: DataSource; mode: "direct" | "bridge"; actor: Actor; selfTest?: boolean; minLevel?: number }) {
  const now = nowIso(), agents = (p.agents ?? []).slice(0, 5000), alerts = (p.alerts ?? []).slice(0, 2000), source = o.source;
  // 1. endpoints
  for (const g of agents) {
    if (!g?.name) continue; const id = slug(String(g.name).split(".")[0]), old = await store.get<Asset>(T.assets, id), kp = g.lastKeepAlive && Number.isFinite(Date.parse(g.lastKeepAlive)) ? new Date(g.lastKeepAlive).toISOString() : undefined;
    const a: Asset = { ...(old ?? { id, hostname: String(g.name).split(".")[0], ips: [], criticality: 3, authorized: false, source, firstSeen: now, lastSeen: now }), ips: uniq([...(old?.ips ?? []), ...(g.ip && g.ip !== "any" ? [g.ip] : [])]).slice(0, 20), os: [g.os?.name, g.os?.version].filter(Boolean).join(" ") || old?.os,
      agentId: g.id, agentStatus: (["active", "disconnected", "pending", "never_connected"].includes(String(g.status)) ? g.status : "disconnected") as Asset["agentStatus"], agentVersion: g.version, agentSyncedAt: now, wazuhGroups: g.group, collector: old?.collector ?? "wazuh", lastSeen: now };
    if (kp) a.lastContactAt = kp; await store.upsert(T.assets, [a]);
  }
  // 2. events
  const evs: { a: WazuhAlert; ev: SocEvent }[] = [], rejected: { index: number; error: string }[] = [];
  alerts.forEach((a, index) => { const e = alertToEvent(a, source, o.selfTest ? "spark-selftest" : "wazuh"); if ("error" in e) rejected.push({ index, error: e.error }); else evs.push({ a, ev: e }); });
  if (evs.length) await store.upsert(T.events, evs.map((x) => x.ev));
  // 3. assets for hosts that only appear through alerts
  const byAsset = new Map<string, typeof evs>(); for (const x of evs) (byAsset.get(x.ev.assetId) ?? byAsset.set(x.ev.assetId, []).get(x.ev.assetId)!).push(x);
  let created = 0, updated = 0; const incidents = new Set<string>();
  const cfgMin = o.minLevel ?? (Number(process.env.WAZUH_MIN_LEVEL ?? 7) || 7);
  for (const [assetId, list] of byAsset) {
    const old = await store.get<Asset>(T.assets, assetId), latest = list.reduce((m, x) => (x.ev.time > m ? x.ev.time : m), list[0].ev.time);
    await store.upsert(T.assets, [{ ...(old ?? { id: assetId, hostname: list[0].ev.host, ips: [], criticality: 3, authorized: false, source, firstSeen: now, lastSeen: now }), lastSeen: now, lastEventAt: !old?.lastEventAt || latest > old.lastEventAt ? latest : old.lastEventAt, collector: old?.collector ?? (o.selfTest ? "spark-selftest" : "wazuh"), lastBatch: list.length } as Asset]);
    // 4. detections: Wazuh rule hits + the existing Windows rules on Wazuh-delivered Windows events
    const drafts = alertsToDrafts(list, cfgMin), win = list.filter((x) => x.ev.channel !== "wazuh").map((x) => x.ev);
    let all = drafts;
    if (win.length) { const { runRules } = await import("./rules"); const lookback = new Date(Date.parse(latest) - 3 * 3600_000).toISOString(), hist = await store.select<SocEvent>(T.events, { where: { assetId }, gte: ["time", lookback], order: ["time", "asc"], limit: 20000 }); all = [...drafts, ...runRules(hist.filter((e) => e.channel !== "wazuh"))]; }
    const r = await applyDrafts(store, all, source, assetId); created += r.created; updated += r.updated; r.incidents.forEach((i) => incidents.add(i));
  }
  // 5. state (real syncs only; a self-test never changes the live connection state)
  if (!o.selfTest) {
    const st = await getState(store), d = st.data, sum = agents.length ? { total: agents.length, active: agents.filter((g) => g.status === "active").length, disconnected: agents.filter((g) => g.status === "disconnected").length, pending: agents.filter((g) => g.status === "pending").length, never: agents.filter((g) => g.status === "never_connected").length } : d.agents;
    const newest = alerts.map((a) => when(a)).filter(Boolean).sort().pop() as string | undefined;
    st.data = { ...d, mode: o.mode, lastSyncAt: now, lastSuccessAt: now, lastError: undefined, lastErrorAt: undefined, agents: sum, managerVersion: p.manager?.version ?? d.managerVersion, alertsReceived: d.alertsReceived + evs.length, lastAlertAt: newest && (!d.lastAlertAt || newest > d.lastAlertAt) ? newest : d.lastAlertAt, cursor: p.cursor ?? newest ?? d.cursor, bridge: p.bridge ?? d.bridge, lastTest: p.test ?? d.lastTest };
    await putState(store, st);
  }
  await audit(store, o.actor, o.selfTest ? "wazuh.selftest" : "ingest.wazuh", "wazuh", { mode: o.mode, agents: agents.length, alerts: alerts.length, accepted: evs.length, rejected: rejected.length, newAlerts: created, source });
  return { agents: agents.length, received: alerts.length, accepted: evs.length, rejected: rejected.slice(0, 20), newAlerts: created, updatedAlerts: updated, incidentsTouched: incidents.size };
}
export async function recordWazuhError(store: Store, message: string, mode: "direct" | "bridge", actor: Actor) {
  const st = await getState(store); st.data = { ...st.data, mode, lastSyncAt: nowIso(), lastError: clip(message, 400), lastErrorAt: nowIso() }; await putState(store, st); await audit(store, actor, "wazuh.sync.error", "wazuh", { mode, error: clip(message, 200) });
}

/** Direct mode: the server pulls from Wazuh using credentials from its own environment. */
export async function syncWazuh(store: Store, actor: Actor, fetcher: Fetcher = fetch, cfg: WazuhCfg | null) {
  if (!cfg) throw new HttpError(409, "Wazuh is not configured on the server (WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD, WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD). If you run the bridge next to Wazuh, it pushes data by itself.");
  const c = new WazuhClient(cfg, fetcher), st = await getState(store);
  try {
    const [mi, agents] = await Promise.all([c.managerInfo(), c.agents()]);
    let cursor = st.data.cursor ?? null, all: WazuhAlert[] = [];
    for (let page = 0; page < 5; page++) { const got = await c.alerts(cursor, 500); all.push(...got); if (got.length < 500) break; const last = when(got[got.length - 1]); if (!last) break; cursor = last === cursor ? new Date(Date.parse(last) + 1).toISOString() : last; }
    const seen = new Set<string>(); all = all.filter((a) => { const k = String(a.id ?? a._id ?? ""); if (!k) return true; if (seen.has(k)) return false; seen.add(k); return true; });
    return { ...(await ingestWazuh(store, { agents, alerts: all, manager: mi, cursor: cursor ?? undefined }, { source: "live", mode: "direct", actor, minLevel: cfg.minLevel })), requests: c.requests.length, readOnly: c.requests.every((r) => /^(GET|POST \/security\/user\/authenticate|POST \/[^ ]*_search)/.test(r)) };
  } catch (e: any) { await recordWazuhError(store, e.message, "direct", actor); throw new HttpError(502, e.message); }
}

// ---------------------------------------------------------------- health check, self-test, status
export async function testWazuhConnection(store: Store, actor: Actor, fetcher: Fetcher = fetch, cfg: WazuhCfg | null): Promise<WazuhTest> {
  const steps: WazuhTest["steps"] = [], ok = (name: string, detail: string) => steps.push({ name, ok: true, detail }), bad = (name: string, detail: string) => steps.push({ name, ok: false, detail });
  if (!cfg) { bad("Server settings", "This organization has no Wazuh connection saved yet. Nothing was contacted."); } else {
    ok("Server settings", `Manager API ${cfg.apiUrl}, Indexer ${cfg.indexerUrl}, index ${cfg.index}. Credentials are held on the server and never sent to the browser.`);
    const c = new WazuhClient(cfg, fetcher);
    const run = async (name: string, f: () => Promise<string>) => { try { ok(name, await f()); return true; } catch (e: any) { bad(name, e.message); return false; } };
    if (await run("Manager API login", async () => { await c.login(); return "Authenticated and received a token."; })) {
      await run("Manager version", async () => { const m = await c.managerInfo(); return `Wazuh ${m.version ?? "(version not reported)"}${m.name ? ", node " + m.name : ""}.`; });
      await run("Account is read-only", async () => { const m = await c.me(); const w = m.roles.filter((r) => !/readonly|read_only/i.test(r)); if (!m.roles.length) return "The API did not report roles; confirm the account is read-only in Wazuh."; if (w.length) throw new Error(`Account "${m.user}" has roles that may allow changes (${w.join(", ")}). Use a read-only role.`); return `Account "${m.user}" has only read-only roles (${m.roles.join(", ")}).`; });
      await run("Endpoint agents", async () => { const g = await c.agents(); const n = (s: string) => g.filter((x) => x.status === s).length; return `${g.length} agent(s): ${n("active")} active, ${n("disconnected")} disconnected, ${n("pending")} pending, ${n("never_connected")} never connected.`; });
    }
    if (await run("Indexer reachable", async () => { const h = await c.indexerHealth(); return `Cluster status ${h.status}, ${h.nodes} node(s).`; })) await run("Alerts index", async () => { const t = await c.latestAlertTime(); if (!t) throw new Error("No alerts found in the index. The connection works but there is nothing to import yet."); return `Newest alert in the index: ${t}.`; });
  }
  const t: WazuhTest = { at: nowIso(), by: actor.name, mode: "direct", ok: steps.every((s) => s.ok), steps };
  const st = await getState(store); st.data.lastTest = t; await putState(store, st); await audit(store, actor, "wazuh.test.connection", "wazuh", { ok: t.ok, failed: steps.filter((s) => !s.ok).map((s) => s.name) }); return t;
}
/** Security event test: pushes ONE clearly marked fake alert through the real pipeline, labelled demo, so you can see ingestion, detection and correlation work. It is never mixed with live data. */
export async function wazuhSelfTest(store: Store, actor: Actor) {
  const t = new Date().toISOString(), a: WazuhAlert = { id: "selftest-" + Date.now(), "@timestamp": t, agent: { id: "999", name: "SPARK-SELFTEST", ip: "10.255.255.1" }, rule: { id: "100999", level: 10, description: "SPARK SELF-TEST: simulated SSH brute force (NOT a real security event)", groups: ["spark_selftest", "authentication_failures"], mitre: { id: ["T1110"], technique: ["Brute Force"], tactic: ["Credential Access"] } }, data: { srcip: "203.0.113.50", dstuser: "selftest" }, location: "spark-selftest" };
  const r = await ingestWazuh(store, { agents: [], alerts: [a] }, { source: "demo", mode: "direct", actor, selfTest: true });
  const ev = await store.select<SocEvent>(T.events, { where: { assetId: "spark-selftest" }, limit: 5 }), al = await store.select<Alert>(T.alerts, { where: { assetId: "spark-selftest" }, limit: 5 });
  const steps = [{ name: "Event stored", ok: ev.length > 0, detail: ev.length ? `Event ${ev[0].id} stored, labelled ${ev[0].source}.` : "No event was stored." }, { name: "Detection created", ok: al.length > 0, detail: al.length ? `Alert "${al[0].title}", severity ${al[0].severity}, MITRE ${al[0].mitre.map((m) => m.id).join(", ") || "none"}.` : "No alert was created." }, { name: "Correlated into an incident", ok: r.incidentsTouched > 0, detail: r.incidentsTouched ? `${r.incidentsTouched} incident(s) opened or updated.` : "No incident was created." }];
  return { ok: steps.every((s) => s.ok), label: "TEST DATA (demo). Remove it with the cleanup button.", steps };
}
export async function wazuhSelfTestCleanup(store: Store, actor: Actor) {
  for (const t of [T.events, T.alerts, T.incidents]) await store.remove(t, { assetId: "spark-selftest" }); await store.remove(T.assets, { id: "spark-selftest" }); await audit(store, actor, "wazuh.selftest.cleanup", "wazuh", {}); return { removed: true };
}
export async function wazuhStatus(store: Store, now = Date.now(), isConfigured?: boolean) {
  const st = (await getState(store)).data; let configured = false; try { configured = isConfigured ?? !!wazuhEnv(); } catch { configured = true; }
  const ms = (s?: string) => (s ? Date.parse(s) : 0), ev = (await store.select<SocEvent>(T.events, { limit: 5000 })).filter((e) => e.collector === "wazuh" || e.collector === "spark-selftest"), live = ev.filter((e) => e.source === "live").length, test = ev.filter((e) => e.source === "demo").length;
  const every = Number(process.env.WAZUH_SYNC_MINUTES ?? 5) || 5; let status: string, detail: string;
  if (!st.lastSyncAt && !configured) { status = "not_connected"; detail = "No Wazuh data has ever been received. Configure direct access on the server or run the bridge next to Wazuh."; }
  else if (!st.lastSyncAt) { status = "configured"; detail = "Server settings are present but no sync has run yet. Run the connection test, then Sync now."; }
  else if (st.lastError && ms(st.lastErrorAt) >= ms(st.lastSuccessAt)) { status = "error"; detail = `Last sync failed: ${st.lastError}`; }
  else if (now - ms(st.lastSuccessAt) <= 3 * every * 60_000) { status = "healthy"; detail = `Last successful sync ${st.lastSuccessAt} (${st.mode} mode).${st.alertsReceived ? "" : " Connected, but Wazuh has sent no alerts yet."}`; }
  else { status = "stale"; detail = `No successful sync since ${st.lastSuccessAt}.`; }
  return { status, detail, mode: st.mode ?? null, lastSyncAt: st.lastSyncAt ?? null, lastSuccessAt: st.lastSuccessAt ?? null, lastError: st.lastError ?? null, manager: st.managerVersion ?? null, agents: st.agents ?? null, alertsReceived: st.alertsReceived, lastAlertAt: st.lastAlertAt ?? null, bridge: st.bridge ?? null, lastTest: st.lastTest ?? null, eventsLive: live, eventsTest: test, readOnly: true, cursor: st.cursor ?? null };
}
