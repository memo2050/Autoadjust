// Generates collector/zabbix/snapshot.mjs from lib/noc/zabbix.ts so the bridge uses the exact same normalizer as the backend.
import { createRequire } from "node:module"; import fs from "node:fs";
const require = createRequire("/home/claude/.npm-global/lib/node_modules/ts-node/"); const ts = require("typescript");
let src = fs.readFileSync("lib/noc/zabbix.ts", "utf8").replace(/^import type .*$/gm, "");
const js = ts.transpileModule(src, { compilerOptions: { target: "ES2022", module: "ES2022" } }).outputText;
const tail = `
export async function fetchSnapshotForBridge(rpc) {
  const hosts = await rpc("host.get", { output: ["hostid","host","name","status"], selectInterfaces: ["interfaceid","ip","dns","type","main","available","port"], selectHostGroups: ["name"], selectInventory: ["os","type","model"], filter: { status: 0 }, limit: 1000 });
  const hostids = hosts.map((h) => h.hostid);
  const items = hostids.length ? await rpc("item.get", { output: ["itemid","hostid","name","key_","lastvalue","lastclock","units","state","error"], hostids, monitored: true, search: { key_: ITEM_KEYS }, searchByAny: true, limit: 20000 }) : [];
  const pr = await rpc("problem.get", { output: ["eventid","objectid","name","severity","clock","r_eventid"], recent: true, sortfield: ["eventid"], sortorder: "DESC", limit: 300 });
  let problems = [];
  if (pr.length) { const ev = await rpc("event.get", { eventids: pr.map((p) => p.eventid), output: ["eventid"], selectHosts: ["hostid","host","name"] }); const hm = new Map(ev.map((e) => [e.eventid, e.hosts?.[0]]));
    problems = pr.map((p) => { const h = hm.get(p.eventid); return { eventid: p.eventid, name: p.name, severity: Number(p.severity), clock: Number(p.clock), resolved: !!p.r_eventid && p.r_eventid !== "0", hostid: h?.hostid, host: h?.host, hostName: h?.name }; }); }
  return { hosts: normalizeHosts(hosts, items), problems };
}
`;
fs.writeFileSync("collector/zabbix/snapshot.mjs", "// GENERATED from lib/noc/zabbix.ts by scripts/gen-bridge-snapshot.mjs. Do not edit.\n" + js.replace(/^export \{\};?$/m, "") + tail);
