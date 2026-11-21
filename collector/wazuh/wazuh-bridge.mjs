#!/usr/bin/env node
// Spark <- Wazuh bridge. Run it on a machine that can reach your Wazuh Manager API (55000) and Wazuh Indexer (9200).
// OUTBOUND HTTPS to Spark only. Wazuh credentials stay in THIS machine's environment and are never sent to Spark.
// READ-ONLY: it logs in, lists agents, and searches alerts. It never calls active-response, restart, delete or any write endpoint.
// Env: SPARK_URL, SPARK_INGEST_TOKEN, WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD, WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD
//      tenant filter (use when several organizations share this Wazuh server; one bridge instance per organization): WAZUH_TENANT_GROUP (agent group), WAZUH_TENANT_LABEL (+ WAZUH_TENANT_LABEL_KEY, default "tenant"), REQUIRE_TENANT_FILTER=1 (refuse to start without a group)
//      optional: BRIDGE_ONCE=1 (one health check + one sync, then exit), WAZUH_INDEX (wazuh-alerts-*), POLL_SEC (30), BRIDGE_NAME, NODE_EXTRA_CA_CERTS=/path/to/wazuh-root-ca.pem (for a private CA; TLS verification stays ON)
import os from "node:os";
import { tenantFilterFromEnv, agentInTenant, alertInTenant, alertQuery } from "./tenant-filter.mjs";
const E = process.env, need = (k) => { if (!E[k]) { console.error("Missing env " + k); process.exit(2); } return E[k]; };
const SPARK = need("SPARK_URL").replace(/\/+$/, ""), TOK = need("SPARK_INGEST_TOKEN"), API = need("WAZUH_API_URL").replace(/\/+$/, ""), IDX = need("WAZUH_INDEXER_URL").replace(/\/+$/, "");
const AU = need("WAZUH_API_USER"), AP = need("WAZUH_API_PASSWORD"), IU = need("WAZUH_INDEXER_USER"), IP = need("WAZUH_INDEXER_PASSWORD");
const INDEX = E.WAZUH_INDEX || "wazuh-alerts-*", POLL = Math.max(10, Number(E.POLL_SEC) || 30) * 1000, NAME = E.BRIDGE_NAME || os.hostname(), VER = "1.0";
const TF = tenantFilterFromEnv(E); if (TF.problem) { console.error(TF.problem); process.exit(2); }
const log = (...a) => console.log(new Date().toISOString(), ...a), b64 = (u, p) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");
const spark = async (path, method = "GET", body) => { const r = await fetch(`${SPARK}/api/soc/${path}`, { method, headers: { Authorization: "Bearer " + TOK, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000) }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(`Spark ${r.status}: ${j.error ?? ""}`); return j; };
const hit = async (url, init, what) => { let r; try { r = await fetch(url, { ...init, signal: AbortSignal.timeout(20000) }); } catch (e) { throw new Error(`${what}: cannot reach Wazuh (${e?.cause?.code ?? e.message})`); } if (r.status === 401 || r.status === 403) throw new Error(`${what}: credentials rejected (HTTP ${r.status})`); if (!r.ok) throw new Error(`${what}: HTTP ${r.status}`); return r; };
let jwt = ""; const login = async () => { jwt = (await (await hit(`${API}/security/user/authenticate?raw=true`, { method: "POST", headers: { Authorization: b64(AU, AP) } }, "Manager login")).text()).trim(); };
const api = async (path, what) => { if (!jwt) await login(); try { return await (await hit(API + path, { headers: { Authorization: "Bearer " + jwt } }, what)).json(); } catch (e) { if (/rejected/.test(e.message)) { await login(); return (await hit(API + path, { headers: { Authorization: "Bearer " + jwt } }, what)).json(); } throw e; } };
const idx = (path, init = {}) => hit(IDX + path, { ...init, headers: { Authorization: b64(IU, IP), "content-type": "application/json" } }, "Indexer");
const search = async (body) => (await (await idx(`/${INDEX}/_search`, { method: "POST", body: JSON.stringify(body) })).json())?.hits?.hits ?? [];
const when = (a) => { const t = Date.parse(a["@timestamp"] ?? a.timestamp ?? ""); return Number.isFinite(t) ? new Date(t).toISOString() : null; };

async function health() {
  const steps = [], step = async (name, f) => { try { steps.push({ name, ok: true, detail: await f() }); return true; } catch (e) { steps.push({ name, ok: false, detail: e.message }); return false; } };
  if (await step("Manager API login", async () => { await login(); return "Authenticated."; })) {
    await step("Manager version", async () => { const i = (await api("/manager/info", "Manager info"))?.data?.affected_items?.[0] ?? {}; return `Wazuh ${i.version ?? "?"}`; });
    await step("Account is read-only", async () => { const i = (await api("/security/users/me", "Account"))?.data?.affected_items?.[0] ?? {}, roles = (i.roles ?? []).map((r) => r.name ?? r), w = roles.filter((r) => !/readonly|read_only/i.test(r)); if (w.length) throw new Error(`Roles that may allow changes: ${w.join(", ")}. Use a read-only role.`); return `Roles: ${roles.join(", ") || "none reported"}`; });
    if (TF.active) await step("Account is limited to this tenant", async () => { const inG = (await api(`/agents?limit=1&group=${encodeURIComponent(TF.group)}`, "Agents"))?.data?.total_affected_items, all = (await api("/agents?limit=1", "Agents"))?.data?.total_affected_items; if (inG == null || all == null) throw new Error("Wazuh did not report agent totals."); if (all !== inG) throw new Error(`this account can list ${all} agent(s) but only ${inG} are in group ${TF.group}; limit its Wazuh role to that group.`); return `group ${TF.group}: ${inG} agent(s), nothing else visible`; });
    await step("Endpoint agents", async () => `${((await api("/agents?limit=1", "Agents"))?.data?.total_affected_items ?? "?")} agent(s) registered`);
  }
  if (await step("Indexer reachable", async () => { const h = await (await idx("/_cluster/health")).json(); return `Cluster ${h.status}`; })) await step("Alerts index", async () => { const h = await search({ size: 1, sort: [{ "@timestamp": "desc" }], _source: ["@timestamp"] }); if (!h.length) throw new Error("No alerts in the index yet."); return `Newest alert ${h[0]._source["@timestamp"]}`; });
  await spark("wazuh/bridge-test", "POST", { ok: steps.every((s) => s.ok), steps }).catch((e) => log("could not report health to Spark:", e.message)); log("health check:", steps.map((s) => `${s.ok ? "OK" : "FAIL"} ${s.name}`).join("; ")); return steps.every((s) => s.ok);
}
const listAgents = async () => { const out = [], g = TF.active ? `&group=${encodeURIComponent(TF.group)}` : ""; for (let off = 0; off < 5000; off += 500) { const j = await api(`/agents?limit=500&offset=${off}${g}&select=id,name,ip,status,os.name,os.version,version,lastKeepAlive,group,node_name`, "Agents"); const it = j?.data?.affected_items ?? []; out.push(...it); if (it.length < 500) break; } return out; };
async function cycle() {
  const { cursor } = await spark("wazuh/cursor"); let since = cursor ?? null, alerts = [], droppedAgents = 0, droppedAlerts = 0;
  const all = await listAgents(), agents = all.filter((x) => agentInTenant(x, TF)); droppedAgents = all.length - agents.length; const ids = new Set(agents.map((x) => String(x.id)));
  if (!TF.active || ids.size) for (let p = 0; p < 10; p++) { const hits = await search({ size: 500, sort: [{ "@timestamp": "asc" }], query: alertQuery(TF, ids, since ? { "@timestamp": { gte: since } } : { "@timestamp": { gte: "now-1h" } }) }); const got = hits.map((h) => ({ ...h._source, _id: h._id })); const keep = got.filter((x) => alertInTenant(x, TF, ids)); droppedAlerts += got.length - keep.length; alerts.push(...keep); if (got.length < 500) break; const last = when(got[got.length - 1]); if (!last) break; since = last === since ? new Date(Date.parse(last) + 1).toISOString() : last; }
  const info = (await api("/manager/info", "Manager info"))?.data?.affected_items?.[0] ?? {};
  for (let i = 0; i < Math.max(1, Math.ceil(alerts.length / 1000)); i++) { const r = await spark("ingest/wazuh", "POST", { agents: i === 0 ? agents : [], alerts: alerts.slice(i * 1000, (i + 1) * 1000), manager: { version: info.version, name: info.name }, bridge: { name: NAME, version: VER } }); log(`sent ${alerts.slice(i * 1000, (i + 1) * 1000).length} alert(s): accepted ${r.accepted}, new detections ${r.newAlerts}, rejected ${r.rejected?.length ?? 0}`); }
  if (droppedAgents || droppedAlerts) { const m = `tenant filter "${TF.group}": discarded ${droppedAgents} agent(s) and ${droppedAlerts} alert(s) outside the tenant before sending. Check the bridge's Wazuh roles.`; log(m); await spark("wazuh/bridge-error", "POST", { error: m }).catch(() => {}); }
}
log(`Spark-Wazuh bridge ${NAME} (read-only) -> ${SPARK}, every ${POLL / 1000}s`); let n = 0, busy = false;
const tick = async () => { if (busy) return false; busy = true; let ok = true; try { if (n++ % 120 === 0) await health(); await cycle(); } catch (e) { ok = false; log("sync failed:", e.message); await spark("wazuh/bridge-error", "POST", { error: e.message }).catch(() => {}); } busy = false; return ok; };
process.on("SIGTERM", () => { log("stopping"); process.exit(0); }); process.on("SIGINT", () => process.exit(0));
if (E.BRIDGE_ONCE === "1") tick().then((ok) => process.exit(ok ? 0 : 1)); else { tick(); setInterval(tick, POLL); }
