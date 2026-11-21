#!/usr/bin/env node
// Run from OUTSIDE the server (your laptop or any other machine): proves the Wazuh API and Indexer are NOT reachable and only the agent port is.
// Usage: node external-check.mjs <server-host-or-ip>      Exit 0 = exposure is as intended. Sends nothing but TCP connects.
import net from "node:net";
export const EXPECT = { 1514: true, 1515: "either", 55000: false, 9200: false, 9300: false, 443: false, 5601: false, 22: false };
export function probe(host, port, ms = 4000) {
  return new Promise((res) => { const s = net.connect({ host, port }); const done = (v) => { s.destroy(); res(v); };
    s.setTimeout(ms); s.on("connect", () => done(true)); s.on("timeout", () => done(false)); s.on("error", () => done(false)); });
}
export function judge(port, open) { const w = EXPECT[port]; return w === "either" ? "OK" : w === open ? "OK" : "FAIL"; }
async function main() {
  const host = process.argv[2]; if (!host || !/^[A-Za-z0-9.-]+$/.test(host)) { console.error("Usage: node external-check.mjs <host>"); process.exit(2); }
  let bad = 0;
  for (const p of Object.keys(EXPECT).map(Number)) { const o = await probe(host, p); const v = judge(p, o); if (v === "FAIL") bad = 1;
    console.log(`${v.padEnd(4)} port ${String(p).padEnd(6)} ${o ? "open" : "closed/filtered"}${p === 22 ? " (from this machine; must be closed unless this is an admin address)" : ""}`); }
  process.exit(bad);
}
if (process.argv[1] && process.argv[1].endsWith("external-check.mjs")) main();
