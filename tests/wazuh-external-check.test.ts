import test from "node:test"; import assert from "node:assert/strict"; import net from "node:net";

import { judge, probe } from "../deploy/wazuh/external-check.mjs";
test("exposure verdicts", () => {
  assert.equal(judge(55000, true), "FAIL"); assert.equal(judge(9200, false), "OK");
  assert.equal(judge(1514, true), "OK"); assert.equal(judge(1514, false), "FAIL"); assert.equal(judge(1515, false), "OK");
});
test("probe sees open and closed ports", async () => {
  const s = net.createServer().listen(0, "127.0.0.1"); await new Promise(r => s.once("listening", r));
  const port = (s.address() as any).port;
  assert.equal(await probe("127.0.0.1", port, 1000), true); s.close(); await new Promise(r => s.once("close", r));
  assert.equal(await probe("127.0.0.1", port, 1000), false);
});
