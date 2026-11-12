#!/usr/bin/env node
// Spark NOC <-> Zabbix bridge. Run it INSIDE your network (for example on the Ubuntu VM that hosts Zabbix).
// It makes OUTBOUND HTTPS calls only: no inbound port to your network is needed.
//   1. reads hosts / items / problems from the local Zabbix API and pushes them to the Spark backend
//   2. asks the backend for approved executions, runs the registered Zabbix script, and reports the real result
// Env: ZABBIX_URL (http://localhost), ZABBIX_TOKEN (API token), SPARK_URL (https://your-site), SPARK_INGEST_TOKEN, SPARK_SOURCE_ID (id of a "push" source), INTERVAL_SEC (60)
// Needs Node 18+. No dependencies.
import { fetchSnapshotForBridge } from "./snapshot.mjs";
const E = process.env, need = (k) => { if (!E[k]) { console.error(`Missing env ${k}`); process.exit(2); } return E[k]; };
const Z = need("ZABBIX_URL").replace(/\/+$/, ""), ZT = need("ZABBIX_TOKEN"), S = need("SPARK_URL").replace(/\/+$/, ""), ST = need("SPARK_INGEST_TOKEN"), SID = need("SPARK_SOURCE_ID"), EVERY = Math.max(15, Number(E.INTERVAL_SEC) || 60) * 1000;
const rpc = async (method, params) => { const r = await fetch(Z + "/api_jsonrpc.php", { method: "POST", headers: { "Content-Type": "application/json-rpc", Authorization: "Bearer " + ZT }, body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }) }); const j = await r.json(); if (j.error) throw new Error(`${method}: ${j.error.message} ${j.error.data ?? ""}`); return j.result; };
const spark = async (path, method, body) => { const r = await fetch(S + "/api/soc/" + path, { method, headers: { "Content-Type": "application/json", Authorization: "Bearer " + ST }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); if (!r.ok) throw new Error(`${path} -> HTTP ${r.status} ${t.slice(0, 200)}`); return JSON.parse(t); };
const log = (...a) => console.log(new Date().toISOString(), ...a);
async function push() { const snap = await fetchSnapshotForBridge(rpc); const r = await spark("noc/push", "POST", { sourceId: SID, hosts: snap.hosts, problems: snap.problems }); log("pushed", snap.hosts.length, "hosts", snap.problems.length, "problems ->", JSON.stringify(r)); }
async function executions() {
  const { executions: list } = await spark("noc/executions/pending", "GET");
  for (const ex of list) {
    log("execution", ex.id, ex.kind, "script", ex.scriptId, "host", ex.hostId);
    try { if (ex.kind !== "zabbix_script" || !ex.scriptId || !ex.hostId) throw new Error("unsupported execution"); const r = await rpc("script.execute", { scriptid: ex.scriptId, hostid: ex.hostId }); await spark(`noc/executions/${ex.id}/result`, "POST", { ok: r?.response === "success", output: String(r?.value ?? ""), error: r?.response === "success" ? undefined : "Zabbix reported the script as failed" }); }
    catch (e) { await spark(`noc/executions/${ex.id}/result`, "POST", { ok: false, error: String(e.message).slice(0, 300) }).catch(() => {}); }
  }
}
async function tick() { try { await push(); } catch (e) { log("push failed:", e.message); } try { await executions(); } catch (e) { log("executions failed:", e.message); } }
log("Spark bridge started; interval", EVERY / 1000, "s"); tick(); setInterval(tick, EVERY);
