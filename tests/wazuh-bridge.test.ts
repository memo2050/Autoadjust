// The Wazuh bridge itself (collector/wazuh/wazuh-bridge.mjs) run as a real process against a MOCK Wazuh and a fake AutoAdjust endpoint.
// Focus: several organizations sharing ONE Wazuh server. Each bridge instance may see only its own tenant's agents and alerts, even if Wazuh ignores the filters.
import test from "node:test"; import assert from "node:assert/strict"; import http from "node:http"; import { spawn } from "node:child_process"; import type { AddressInfo } from "node:net";
import { startMockWazuh } from "./mock-wazuh";
// @ts-ignore plain ESM helpers
import { tenantFilterFromEnv, alertInTenant, agentInTenant, alertQuery } from "../collector/wazuh/tenant-filter.mjs";

const now = Date.now(), ts = (m: number) => new Date(now - m * 60_000).toISOString();
const agent = (id: string, name: string, groups: string[]) => ({ id, name, ip: `10.0.0.${Number(id) + 10}`, status: "active", version: "Wazuh v4.9.2", lastKeepAlive: ts(1), group: groups, os: { name: "Microsoft Windows 11", version: "10" }, node_name: "node01" });
const alert = (id: string, aid: string, name: string, tenant: string | null, desc: string) => ({ id, "@timestamp": ts(5), agent: { id: aid, name, ip: "10.0.0.1", ...(tenant ? { labels: { tenant } } : {}) }, rule: { id: "60122", level: 10, description: desc, groups: ["authentication_failed"] }, manager: { name: "wazuh-mock" } });
const AGENTS = [agent("001", "A-PC-1", ["default", "t-a"]), agent("002", "A-PC-2", ["t-a"]), agent("003", "B-PC-1", ["t-b"])];
const ALERTS = [alert("a1", "001", "A-PC-1", "org-a", "A brute force"), alert("a2", "002", "A-PC-2", "org-a", "A second"), alert("b1", "003", "B-PC-1", "org-b", "B only secret"), alert("m0", "000", "wazuh-mock", null, "manager level")];

async function fakeSpark() {
  const rec: { path: string; body: any }[] = [];
  const srv = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { const path = req.url!.replace("/api/soc/", ""); rec.push({ path, body: b ? JSON.parse(b) : null }); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(path === "wazuh/cursor" ? { cursor: null } : path === "ingest/wazuh" ? { accepted: (JSON.parse(b).alerts?.length ?? 0) + (JSON.parse(b).agents?.length ?? 0), newAlerts: 0, rejected: [] } : { ok: true })); }); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r)); return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, rec, close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); }) };
}
const runBridge = (env: Record<string, string>) => new Promise<{ code: number | null; out: string }>((res) => { const c = spawn("node", ["collector/wazuh/wazuh-bridge.mjs"], { env: { PATH: process.env.PATH!, SPARK_INGEST_TOKEN: "aa_live_test", WAZUH_API_USER: "wazuh-ro", WAZUH_API_PASSWORD: "mock-pass-123", WAZUH_INDEXER_USER: "wazuh-ro", WAZUH_INDEXER_PASSWORD: "mock-pass-123", BRIDGE_ONCE: "1", ...env } }); let out = ""; c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (out += d)); c.on("close", (code) => res({ code, out })); });
async function scenario(tenantEnv: Record<string, string>, mockOpts: Parameters<typeof startMockWazuh>[0] = {}) {
  const w = await startMockWazuh({ agents: AGENTS, alerts: ALERTS, ...mockOpts }), s = await fakeSpark();
  const r = await runBridge({ SPARK_URL: s.url, WAZUH_API_URL: `http://127.0.0.1:${w.port}`, WAZUH_INDEXER_URL: `http://127.0.0.1:${w.port}`, ...tenantEnv });
  const ingest = s.rec.filter((x) => x.path === "ingest/wazuh").map((x) => x.body), res = { r, w, spark: s.rec, agents: ingest.flatMap((b) => b.agents ?? []).map((a: any) => a.name).sort(), alerts: ingest.flatMap((b) => b.alerts ?? []).map((a: any) => a.id).sort() };
  await w.close(); await s.close(); return res;
}

test("two organizations on ONE Wazuh server: each bridge sees only its own agents and alerts", async () => {
  const a = await scenario({ WAZUH_TENANT_GROUP: "t-a", REQUIRE_TENANT_FILTER: "1" }), b = await scenario({ WAZUH_TENANT_GROUP: "t-b", REQUIRE_TENANT_FILTER: "1" });
  assert.equal(a.r.code, 0, a.r.out); assert.deepEqual(a.agents, ["A-PC-1", "A-PC-2"]); assert.deepEqual(a.alerts, ["a1", "a2"]);
  assert.equal(b.r.code, 0, b.r.out); assert.deepEqual(b.agents, ["B-PC-1"]); assert.deepEqual(b.alerts, ["b1"]);
  assert.ok(!JSON.stringify(a.spark).includes("B only secret") && !JSON.stringify(a.spark).includes("B-PC-1") && !JSON.stringify(a.spark).includes("manager level"), "organization A never receives B's or manager-level data");
  assert.ok(a.w.requests.some((x) => x.startsWith("GET /agents")), "agent list requested");
  assert.deepEqual(a.w.requests.filter((x) => !(x.startsWith("GET ") || x === "POST /security/user/authenticate" || x === "POST /wazuh-alerts-*/_search")), [], "read-only");
});
test("filters are sent to Wazuh: agents by group, alerts by the tenant's agent ids and label", async () => {
  const w = await startMockWazuh({ agents: AGENTS, alerts: ALERTS }), s = await fakeSpark();
  const r = await runBridge({ SPARK_URL: s.url, WAZUH_API_URL: `http://127.0.0.1:${w.port}`, WAZUH_INDEXER_URL: `http://127.0.0.1:${w.port}`, WAZUH_TENANT_GROUP: "t-a", WAZUH_TENANT_LABEL: "org-a" });
  assert.equal(r.code, 0, r.out); const ing = s.rec.filter((x) => x.path === "ingest/wazuh").flatMap((x) => x.body.alerts.map((a: any) => a.id)).sort(); assert.deepEqual(ing, ["a1", "a2"]); await w.close(); await s.close();
  // a label that does not match removes the alert even though the agent is in the group
  const wrong = await scenario({ WAZUH_TENANT_GROUP: "t-a", WAZUH_TENANT_LABEL: "org-zzz" }); assert.deepEqual(wrong.alerts, []);
});
test("defence in depth: a Wazuh that ignores every filter still cannot leak another tenant, and the bridge reports it", async () => {
  const a = await scenario({ WAZUH_TENANT_GROUP: "t-a", WAZUH_TENANT_LABEL: "org-a" }, { ignoreFilters: true });
  assert.equal(a.r.code, 0, a.r.out); assert.deepEqual(a.agents, ["A-PC-1", "A-PC-2"]); assert.deepEqual(a.alerts, ["a1", "a2"]);
  assert.ok(!JSON.stringify(a.spark.filter((x) => x.path === "ingest/wazuh")).includes("B only secret"));
  const err = a.spark.find((x) => x.path === "wazuh/bridge-error"); assert.ok(err && /discarded 1 agent\(s\) and \d+ alert\(s\)/.test(err.body.error), JSON.stringify(err));
});
test("health check: reports whether the bridge's Wazuh account can see agents outside the tenant", async () => {
  const shared = await scenario({ WAZUH_TENANT_GROUP: "t-a" }), step = shared.spark.find((x) => x.path === "wazuh/bridge-test")!.body.steps.find((x: any) => x.name === "Account is limited to this tenant");
  assert.equal(step.ok, false); assert.match(step.detail, /can list 3 agent\(s\) but only 2 are in group t-a/);
  const scoped = await scenario({ WAZUH_TENANT_GROUP: "t-a" }, { agents: AGENTS.slice(0, 2) }), ok = scoped.spark.find((x) => x.path === "wazuh/bridge-test")!.body.steps.find((x: any) => x.name === "Account is limited to this tenant");
  assert.equal(ok.ok, true, JSON.stringify(ok));
});
test("fail closed on bad tenant configuration", async () => {
  for (const env of [{ REQUIRE_TENANT_FILTER: "1" }, { WAZUH_TENANT_LABEL: "org-a" }, { WAZUH_TENANT_GROUP: "t-a; drop" }, { WAZUH_TENANT_GROUP: "t-a", WAZUH_TENANT_LABEL_KEY: "a b" }]) {
    const r = await runBridge({ SPARK_URL: "http://127.0.0.1:1", WAZUH_API_URL: "http://127.0.0.1:1", WAZUH_INDEXER_URL: "http://127.0.0.1:1", ...env }); assert.equal(r.code, 2, JSON.stringify(env) + r.out);
  }
});
test("without a tenant filter the bridge behaves as before (single-tenant Wazuh)", async () => { const r = await scenario({}); assert.equal(r.r.code, 0, r.r.out); assert.equal(r.agents.length, 3); assert.equal(r.alerts.length, 4); });
test("filter helpers", () => {
  const f = tenantFilterFromEnv({ WAZUH_TENANT_GROUP: "t-a", WAZUH_TENANT_LABEL: "org-a" }); assert.equal(f.problem, null); const ids = new Set(["001"]);
  assert.equal(alertInTenant({ agent: { id: "001", labels: { tenant: "org-a" } } }, f, ids), true); assert.equal(alertInTenant({ agent: { id: "000" } }, f, new Set(["000"])), false); assert.equal(alertInTenant({ agent: { id: "002", labels: { tenant: "org-a" } } }, f, ids), false);
  assert.equal(agentInTenant({ group: ["x", "t-a"] }, f), true); assert.equal(agentInTenant({ group: ["t-b"] }, f), false); assert.equal(agentInTenant({}, f), false);
  const q = alertQuery(f, ids, { "@timestamp": { gte: "now-1h" } }); assert.deepEqual(q.bool.filter[1], { terms: { "agent.id": ["001"] } }); assert.deepEqual(q.bool.filter[2], { term: { "agent.labels.tenant": "org-a" } });
  assert.deepEqual(alertQuery(tenantFilterFromEnv({}), ids, { r: 1 }), { range: { r: 1 } });
});
