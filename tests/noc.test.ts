import { TestStore } from "./test-store";
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore } from "../lib/soc/store";
import { handleSoc } from "../lib/soc/api";
import { deviceStatus } from "../lib/soc/noc";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890" });
const call = (store: TestStore, method: string, path: string, tok: string, body?: unknown) => handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store, model: null } as any);

test("status is derived from the numbers, with reasons", () => {
  assert.equal(deviceStatus({ up: true, metrics: { latencyMs: 12, lossPct: 0, cpu: 20 } }).status, "healthy");
  assert.equal(deviceStatus({ up: true, metrics: { lossPct: 2.4 } }).status, "warning");
  assert.equal(deviceStatus({ up: true, metrics: { cpu: 88 } }).status, "degraded");
  const c = deviceStatus({ up: true, metrics: { disk: 96, cpu: 10 } }); assert.equal(c.status, "critical"); assert.match(c.reasons[0], /disk 96%/);
  assert.equal(deviceStatus({ up: false, metrics: {} }).status, "offline");
  assert.equal(deviceStatus({ up: true, metrics: { bwInMbps: 950, bwCapMbps: 1000 } }).status, "degraded");
});

test("telemetry ingest: stores, keeps history, validates, and enforces roles", async () => {
  const s = new TestStore();
  let r = await call(s, "POST", "noc/telemetry", "ingest-token-1234567890", { source: "test-poller", devices: [{ name: "Core SW 1", type: "switch", ip: "10.0.0.2", config: { ntp: "time.example.net", telnet: false }, metrics: { latencyMs: 3, lossPct: 0, cpu: 20 }, links: [{ to: "FW 1", utilPct: 40 }] }] });
  const j: any = await r.json(); assert.equal(r.status, 200, JSON.stringify(j)); assert.equal(j.received, 1); assert.equal(j.devices[0].id, "core-sw-1");
  await call(s, "POST", "noc/telemetry", "ingest-token-1234567890", { devices: [{ name: "Core SW 1", type: "switch", metrics: { cpu: 91 } }] });
  r = await call(s, "GET", "noc/devices", "viewer-token-1234567890"); assert.equal(r.status, 200);
  const d: any[] = await r.json(); assert.equal(d.length, 1); assert.equal(d[0].history.length, 2); assert.equal(d[0].status, "degraded"); assert.equal(d[0].source, "live"); assert.equal(d[0].config === undefined || typeof d[0].config === "object", true);
  assert.equal((await call(s, "POST", "noc/telemetry", "viewer-token-1234567890", { devices: [{ name: "x", type: "switch" }] })).status, 403);
  assert.equal((await call(s, "GET", "noc/devices", "ingest-token-1234567890")).status, 403, "collector token cannot read");
  assert.equal((await call(s, "POST", "noc/telemetry", "ingest-token-1234567890", { devices: [{ name: "x", type: "toaster" }] })).status, 400);
  assert.equal((await call(s, "POST", "noc/telemetry", "ingest-token-1234567890", { devices: [{ name: "x", type: "server", metrics: { cpu: 400 } }] })).status, 400);
  const integ: any = await (await call(s, "GET", "integrations", "admin-token-1234567890")).json();
  assert.equal(integ.integrations.find((x: any) => x.id === "noc_telemetry").status, "healthy");
});
