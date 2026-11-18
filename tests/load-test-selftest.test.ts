import test from "node:test"; import assert from "node:assert/strict"; import { spawnSync } from "node:child_process"; import { createServer } from "node:http";
const run = (env: Record<string, string>) => new Promise<{ code: number | null; out: string }>((res) => { const { spawn } = require("node:child_process"); const c = spawn("node", ["scripts/load-test.mjs"], { env: { PATH: process.env.PATH, ...env } }); let out = ""; c.stdout.on("data", (d: Buffer) => (out += d)); c.stderr.on("data", (d: Buffer) => (out += d)); c.on("close", (code: number) => res({ code, out })); });
test("load test refuses non-staging addresses", async () => { for (const u of ["https://autoadjust.net", "https://www.autoadjust.net", "https://prod-staging.example.com", ""]) assert.equal((await run({ STAGING_URL: u })).code, 2, u); });
test("load test runs against a local server, reports percentiles, enforces thresholds", async () => {
  const srv = createServer((q, r) => { r.writeHead(q.url === "/" ? 200 : 401); r.end("x"); }); await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok)); const url = `http://127.0.0.1:${(srv.address() as any).port}`;
  const good = await run({ STAGING_URL: url, LOAD_SECONDS: "2", LOAD_CONCURRENCY: "5" }); assert.equal(good.code, 0, good.out); assert.match(good.out, /LOAD TEST PASS/); assert.match(good.out, /"p95"/);
  const bad = await run({ STAGING_URL: url, LOAD_SECONDS: "2", LOAD_P95_MS: "0.0001" }); assert.equal(bad.code, 1, bad.out); srv.close();
});
