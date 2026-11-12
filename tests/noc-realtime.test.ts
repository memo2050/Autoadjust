import { TestStore } from "./test-store";
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore } from "../lib/soc/store";
import { handleSoc } from "../lib/soc/api";
import { NT } from "../lib/noc/types";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890", NOC_SECRET_KEY: "k".repeat(40) });
const AD = "admin-token-1234567890";
// A fake Zabbix. It only verifies the code paths; it is NOT evidence that a real Zabbix works.
function fakeZabbix(state: { problem: boolean; reachable: boolean; scriptOk: boolean; badToken?: boolean; calls: string[] }) {
  return async (_u: string, init: any) => {
    if (!state.reachable) throw Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    const b = JSON.parse(init.body); state.calls.push(b.method); const ok = (r: any) => ({ ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result: r }), text: async () => "" });
    if (b.method === "apiinfo.version") return ok("6.4.8");
    if (state.badToken || init.headers.Authorization !== "Bearer ztoken") return { ok: true, status: 200, json: async () => ({ error: { code: -32602, message: "Not authorized.", data: "Session terminated" } }), text: async () => "" };
    const now = Math.floor(Date.now() / 1000);
    if (b.method === "host.get") return b.params.countOutput ? ok("2") : ok([
      { hostid: "10", host: "web01", name: "web01", hostgroups: [{ name: "Linux servers" }], interfaces: [{ ip: "10.0.0.10", main: "1", type: "1", available: "1" }], inventory: {} },
      { hostid: "11", host: "sw01", name: "sw01", hostgroups: [{ name: "Switches" }], interfaces: [{ ip: "10.0.0.2", main: "1", type: "2", available: "1" }], inventory: {} }]);
    if (b.method === "item.get") return ok([
      { itemid: "1", hostid: "10", name: "ICMP ping", key_: "icmpping", lastvalue: "1", lastclock: String(now), state: "0" },
      { itemid: "2", hostid: "10", name: "CPU utilization", key_: "system.cpu.util", lastvalue: state.problem ? "97" : "20", lastclock: String(now), state: "0" },
      { itemid: "3", hostid: "11", name: "ICMP ping", key_: "icmpping", lastvalue: "1", lastclock: String(now), state: "0" },
      { itemid: "4", hostid: "11", name: "Interface Gi0/1: Bits received", key_: "net.if.in[ifHCInOctets.1]", lastvalue: "5000000", lastclock: String(now), state: "0" },
      { itemid: "5", hostid: "11", name: "Interface Gi0/1: Speed", key_: "net.if.speed[ifHighSpeed.1]", lastvalue: "1000000000", lastclock: String(now), state: "0" }]);
    if (b.method === "problem.get") return ok(state.problem ? [{ eventid: "900", objectid: "5", name: "High CPU utilization on web01", severity: "4", clock: String(now), r_eventid: "0" }] : []);
    if (b.method === "event.get") return ok([{ eventid: "900", hosts: [{ hostid: "10", host: "web01", name: "web01" }] }]);
    if (b.method === "script.execute") return ok(state.scriptOk ? { response: "success", value: "restarted" } : { response: "failed", value: "" });
    return { ok: false, status: 500, json: async () => ({}), text: async () => "" };
  };
}
const mk = (store: TestStore, st: any) => (method: string, path: string, tok: string, body?: unknown) => handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store, model: null, fetcher: fakeZabbix(st) } as any);

test("source: secret encrypted, never returned; roles; test statuses", async () => {
  const s = new TestStore(), st: any = { problem: false, reachable: true, scriptOk: true, calls: [] as string[] }, call = mk(s, st);
  assert.equal((await call("POST", "noc/sources", "analyst-token-1234567890", { name: "Z", url: "http://zbx.lan" })).status, 403);
  assert.equal((await call("POST", "noc/sources", AD, { name: "Z", url: "ftp://x" })).status, 400);
  assert.equal((await call("POST", "noc/sources", AD, { name: "Z", url: "http://169.254.169.254" })).status, 400);
  const r = await call("POST", "noc/sources", AD, { name: "Zabbix", type: "zabbix", url: "http://zbx.lan", token: "ztoken" }); const src: any = await r.json(); assert.equal(r.status, 201);
  assert.equal(JSON.stringify(src).includes("ztoken"), false); assert.equal(src.secret, undefined);
  const raw: any = await s.get(NT.sources, src.id); assert.equal(raw.secret.includes("ztoken"), false); assert.match(raw.secret, /^v1\./);
  assert.equal(((await (await call("POST", `noc/sources/${src.id}/test`, AD)).json()) as any).status, "CONNECTED");
  st.badToken = true; assert.equal(((await (await call("POST", `noc/sources/${src.id}/test`, AD)).json()) as any).status, "AUTHENTICATION FAILED");
  st.badToken = false; st.reachable = false; assert.equal(((await (await call("POST", `noc/sources/${src.id}/test`, AD)).json()) as any).status, "DISCONNECTED");
  delete process.env.NOC_SECRET_KEY; assert.equal((await call("POST", "noc/sources", AD, { name: "N", url: "http://a.lan", token: "x" })).status, 400); process.env.NOC_SECRET_KEY = "k".repeat(40);
});

test("sync -> alert -> incident with 14 steps -> approval -> execution -> verification from fresh data", async () => {
  const s = new TestStore(), st = { problem: true, reachable: true, scriptOk: true, calls: [] as string[] }, call = mk(s, st);
  const src: any = await (await call("POST", "noc/sources", AD, { name: "Zabbix", url: "http://zbx.lan", token: "ztoken" })).json();
  const act: any = await (await call("POST", "noc/actions", AD, { name: "Restart app", description: "Restart the web app", kind: "zabbix_script", sourceId: src.id, scriptId: "7", match: "cpu" })).json();
  const sync: any = await (await call("POST", `noc/sources/${src.id}/sync`, AD)).json(); assert.equal(sync.hosts, 2); assert.equal(sync.incidentsOpened, 1);
  let ov: any = await (await call("GET", "noc/overview", "viewer-token-1234567890")).json();
  assert.equal(ov.counts.devices, 2); assert.equal(ov.dataLabel, "LIVE"); assert.equal(ov.counts.activeIncidents, 1);
  const sw = ov.devices.find((d: any) => d.id === "sw01"); assert.ok(sw.unsupported.includes("CPU"), "device without CPU item says so"); assert.equal(sw.metrics.cpu, undefined);
  assert.equal(ov.interfaces.length, 1);
  const inc = ov.incidents[0]; assert.equal(inc.assignedAgent, "server"); assert.equal(inc.rootCause.hypothesis, true);
  const wf = ov.workflows[0]; assert.equal(wf.steps.length, 14); assert.equal(wf.steps[8].status, "done"); assert.equal(wf.steps[9].status, "waiting");
  const ap = ov.approvals[0]; assert.equal(ap.status, "proposed"); assert.equal(ov.executions.length, 0, "nothing runs before approval");
  assert.equal((await call("POST", `noc/approvals/${ap.id}/approve`, "analyst-token-1234567890", {})).status, 403);
  const dec: any = await (await call("POST", `noc/approvals/${ap.id}/approve`, AD, {})).json(); assert.equal(dec.execution.status, "succeeded"); assert.ok(st.calls.includes("script.execute"));
  let i: any = await s.get(NT.incidents, inc.id); assert.equal(i.status, "Verifying"); assert.equal(i.verification.status, "awaiting_data");
  // problem still present on fresh data -> not resolved
  await new Promise((r) => setTimeout(r, 15)); await call("POST", `noc/sources/${src.id}/sync`, AD); i = await s.get(NT.incidents, inc.id); assert.equal(i.verification.status, "not_resolved"); assert.notEqual(i.status, "Resolved");
});

test("failed execution is never reported as success; resolved only when fresh data clears it", async () => {
  const s = new TestStore(), st = { problem: true, reachable: true, scriptOk: false, calls: [] as string[] }, call = mk(s, st);
  const src: any = await (await call("POST", "noc/sources", AD, { name: "Zabbix", url: "http://zbx.lan", token: "ztoken" })).json();
  await call("POST", "noc/actions", AD, { name: "Restart", kind: "zabbix_script", sourceId: src.id, scriptId: "7" });
  await call("POST", `noc/sources/${src.id}/sync`, AD); const ov: any = await (await call("GET", "noc/overview", AD)).json();
  const dec: any = await (await call("POST", `noc/approvals/${ov.approvals[0].id}/approve`, AD, {})).json(); assert.equal(dec.execution.status, "failed");
  let i: any = await s.get(NT.incidents, ov.incidents[0].id); assert.equal(i.verification.status, "not_resolved");
  // now the operator fixes it by hand, Zabbix reports resolved
  st.problem = false; await new Promise((r) => setTimeout(r, 5)); await call("POST", `noc/sources/${src.id}/sync`, AD);
  i = await s.get(NT.incidents, ov.incidents[0].id); assert.equal(i.status, "Resolved", "problem vanished from fresh Zabbix data"); assert.equal(i.verification.status, "resolved");
  const r: any = await (await call("POST", "noc/alerts?source=" + src.id, "ingest-token-1234567890", { source: "zabbix", eventid: "900", host: "web01", name: "High CPU utilization on web01", severity: "High", status: "OK" })).json();
  assert.equal(r.results[0].status, "duplicate"); i = await s.get(NT.incidents, ov.incidents[0].id);
  // different source key (webhook w/o source id) is a separate event, so resolve via same key
  assert.ok(["Investigating", "Resolved"].includes(i.status));
});

test("webhook alerts create incidents, dedupe, and unknown payloads are rejected", async () => {
  const s = new TestStore(), call = mk(s, { problem: false, reachable: true, scriptOk: true, calls: [] });
  const p = { source: "zabbix", eventid: "55", host: "core-rtr", name: "core-rtr is unreachable (ICMP ping)", severity: "Disaster", status: "PROBLEM" };
  assert.equal((await call("POST", "noc/alerts", "viewer-token-1234567890", p)).status, 403);
  let r: any = await (await call("POST", "noc/alerts", "ingest-token-1234567890", p)).json(); assert.ok(r.results[0].incidentId);
  r = await (await call("POST", "noc/alerts", "ingest-token-1234567890", p)).json(); assert.equal(r.results[0].status, "duplicate");
  const inc: any = await s.get(NT.incidents, (await s.select<any>(NT.incidents, {}))[0].id); assert.equal(inc.assignedAgent, "engineer"); assert.equal(inc.severity, "critical");
  const graf = { receiver: "x", alerts: [{ status: "firing", labels: { alertname: "DiskFull", instance: "db01", severity: "critical" }, annotations: { summary: "Disk almost full on db01" }, fingerprint: "ab12" }] };
  r = await (await call("POST", "noc/alerts", "ingest-token-1234567890", graf)).json(); assert.equal((await s.select<any>(NT.incidents, {})).length, 2);
  assert.equal((await call("POST", "noc/alerts", "ingest-token-1234567890", { hello: 1 })).status, 400);
});

test("source that stops sending data is flagged DISCONNECTED once, with an incident", async () => {
  const s = new TestStore(), st = { problem: false, reachable: true, scriptOk: true, calls: [] as string[] }, call = mk(s, st);
  const src: any = await (await call("POST", "noc/sources", AD, { name: "Zabbix", url: "http://zbx.lan", token: "ztoken", staleAfterSec: 60 })).json();
  await call("POST", `noc/sources/${src.id}/sync`, AD);
  const raw: any = await s.get(NT.sources, src.id); raw.lastSyncAt = new Date(Date.now() - 10 * 60_000).toISOString(); await s.upsert(NT.sources, [raw]);
  let ov: any = await (await call("GET", "noc/overview", AD)).json(); assert.equal(ov.sources[0].status, "DISCONNECTED"); assert.equal(ov.devices.every((d: any) => d.stale), true); assert.equal(ov.counts.connected, 0);
  assert.equal(ov.incidents.length, 1); ov = await (await call("GET", "noc/overview", AD)).json(); assert.equal(ov.incidents.length, 1, "only once");
  await call("POST", `noc/sources/${src.id}/sync`, AD); ov = await (await call("GET", "noc/overview", AD)).json(); assert.equal(ov.sources[0].status, "CONNECTED"); assert.equal(ov.incidents[0].status, "Resolved");
});

test("six agents run on stored data, are recorded, and say so when there is no data", async () => {
  const s = new TestStore(), st = { problem: true, reachable: true, scriptOk: true, calls: [] as string[] }, call = mk(s, st);
  let ov: any = await (await call("GET", "noc/overview", AD)).json(); assert.equal(ov.dataLabel, "NO DATA"); assert.equal(ov.agents.supervisor.operational, false);
  const e: any = await (await call("POST", "noc/agents/engineer/run", AD, {})).json(); assert.equal(e.activity.status, "completed"); assert.equal(e.activity.result.noData, true);
  const src: any = await (await call("POST", "noc/sources", AD, { name: "Zabbix", url: "http://zbx.lan", token: "ztoken" })).json(); await call("POST", `noc/sources/${src.id}/sync`, AD);
  for (const a of ["supervisor", "engineer", "server", "performance", "responder", "automation"]) { const r: any = await (await call("POST", `noc/agents/${a}/run`, AD, {})).json(); assert.equal(r.activity.status, "completed", a); assert.ok(r.activity.steps.length >= 3 && r.activity.steps.every((x: any) => typeof x.ms === "number")); }
  ov = await (await call("GET", "noc/overview", AD)).json(); assert.ok(Object.values(ov.agents).every((a: any) => a.operational));
  assert.equal((await call("POST", "noc/agents/bogus/run", AD, {})).status, 404);
});
