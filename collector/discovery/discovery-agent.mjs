#!/usr/bin/env node
// Spark discovery agent. Run it INSIDE the network you are authorized to scan (a Linux VM or Raspberry Pi on that LAN).
// OUTBOUND HTTPS only: it polls Spark for scan jobs an admin approved, scans only the approved targets, and reports results.
// SNMP community strings / SSH passwords live ONLY in this machine's environment or files. They are never sent to Spark.
// Env: SPARK_URL, SPARK_INGEST_TOKEN, AGENT_NAME (default hostname), POLL_SEC (10)
//      SNMP_COMMUNITY or SNMP_V3_ARGS (extra args for snmpget/snmpwalk, e.g. "-v3 -l authPriv -u user -a SHA -A pass -x AES -X pass")
//      CONFIG_EXECUTOR = path to an executable that applies config changes (see docs/NOC-TOPOLOGY.md). If unset, approved changes are NOT applied and are reported failed.
// Needs Node 18+, `ping`, and (optional) net-snmp tools `snmpget`/`snmpwalk` and `ip` or `arp`. A method whose tool is missing is skipped and reported.
import os from "node:os"; import net from "node:net"; import { execFile, spawn } from "node:child_process"; import { promisify } from "node:util";
const run = promisify(execFile), E = process.env, need = (k) => { if (!E[k]) { console.error("Missing env " + k); process.exit(2); } return E[k]; };
const S = need("SPARK_URL").replace(/\/+$/, ""), TOK = need("SPARK_INGEST_TOKEN"), NAME = E.AGENT_NAME || os.hostname(), POLL = Math.max(3, Number(E.POLL_SEC) || 10) * 1000;
const log = (...a) => console.log(new Date().toISOString(), ...a);
const spark = async (path, method = "GET", body) => { const r = await fetch(S + "/api/soc/" + path, { method, headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOK }, body: body ? JSON.stringify(body) : undefined }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(`${r.status} ${j.error || ""}`); return j; };
const ip2n = (s) => { const p = s.split(".").map(Number); return p.length === 4 && p.every((x) => x >= 0 && x < 256) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; };
const n2ip = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
function expand(targets) { const ips = new Set(), hosts = []; for (const t of targets) { let m;
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(t))) { const sz = 2 ** (32 - +m[2]), st = Math.floor(ip2n(m[1]) / sz) * sz; for (let i = (sz > 2 ? 1 : 0); i < (sz > 2 ? sz - 1 : sz); i++) ips.add(n2ip(st + i)); }
  else if ((m = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(t))) { for (let i = ip2n(m[1]); i <= ip2n(m[2]); i++) ips.add(n2ip(i)); }
  else if (ip2n(t) != null) ips.add(t); else hosts.push(t); } return { ips: [...ips], hosts }; }
const have = {}; async function tool(cmd) { if (cmd in have) return have[cmd]; try { await run("which", [cmd]); return (have[cmd] = true); } catch { return (have[cmd] = false); } }
async function ping(ip, ms) { try { const t0 = Date.now(); await run("ping", ["-c", "1", "-W", String(Math.max(1, Math.ceil(ms / 1000))), ip], { timeout: ms + 1500 }); return Date.now() - t0; } catch { return null; } }
const tcp = (ip, port, ms) => new Promise((res) => { const s = net.connect({ host: ip, port, timeout: ms }); s.once("connect", () => { s.destroy(); res(true); }); s.once("timeout", () => { s.destroy(); res(false); }); s.once("error", () => res(false)); });
async function arpTable() { const m = new Map(); try { if (await tool("ip")) { const { stdout } = await run("ip", ["neigh"]); for (const l of stdout.split("\n")) { const x = /^(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-f:]{17})/i.exec(l); if (x) m.set(x[1], x[2].toLowerCase()); } } else if (await tool("arp")) { const { stdout } = await run("arp", ["-an"]); for (const l of stdout.split("\n")) { const x = /\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})/i.exec(l); if (x) m.set(x[1], x[2].toLowerCase()); } } } catch {} return m; }
const snmpBase = () => (E.SNMP_V3_ARGS ? E.SNMP_V3_ARGS.split(/\s+/) : ["-v2c", "-c", E.SNMP_COMMUNITY || ""]);
async function snmp(ip, ms) { if (!(E.SNMP_COMMUNITY || E.SNMP_V3_ARGS)) return null; if (!(await tool("snmpget"))) return { missing: true };
  try { const { stdout } = await run("snmpget", [...snmpBase(), "-t", String(Math.ceil(ms / 1000)), "-r", "0", "-Oqv", ip, "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"], { timeout: ms + 2000 }); const [descr, name] = stdout.trim().split("\n"); const nb = await lldp(ip, ms);
    return { sysDescr: descr?.replace(/^"|"$/g, ""), sysName: name?.replace(/^"|"$/g, ""), neighbors: nb }; } catch { return null; } }
async function lldp(ip, ms) { if (!(await tool("snmpwalk"))) return []; try { const { stdout } = await run("snmpwalk", [...snmpBase(), "-t", String(Math.ceil(ms / 1000)), "-r", "0", "-On", ip, "1.0.8802.1.1.2.1.4.1.1.9"], { timeout: ms + 4000 }); return stdout.split("\n").map((l) => /\.9\.\d+\.(\d+)\.\d+ = STRING: "?([^"]+)"?/.exec(l)).filter(Boolean).slice(0, 64).map((x) => ({ localPort: x[1], remoteName: x[2], proto: "lldp" })); } catch { return []; } }
async function pool(items, limit, fn) { let i = 0; await Promise.all(Array.from({ length: limit }, async () => { while (i < items.length) { const x = items[i++]; await fn(x); } })); }
let cancelled = false;
async function scan(job) {
  const { ips, hosts } = expand(job.targets), o = job.options, rate = Math.max(1, job.maxPerSecond), conc = Math.min(64, Math.max(1, Math.round(rate / 4))), gap = 1000 / rate;
  const notes = []; for (const m of o.methods) if (m === "snmp" && !(E.SNMP_COMMUNITY || E.SNMP_V3_ARGS)) notes.push("SNMP skipped: no credentials configured on the agent"); else if (m === "snmp" && !(await tool("snmpget"))) notes.push("SNMP skipped: net-snmp tools not installed");
  log("scan", job.id, ips.length, "addresses; rate", rate, "/s; methods", o.methods.join(",")); let done = 0, batch = [], last = Date.now(); const total = ips.length + hosts.length;
  const flush = async (force) => { if (batch.length && (force || batch.length >= 25 || Date.now() - last > 3000)) { if (o.methods.includes("arp")) { const arp = await arpTable(); for (const h of batch) if (h.ip && arp.has(h.ip)) { h.mac = arp.get(h.ip); h.methods.push("arp"); } } const r = await spark(`noc/scans/${job.id}/progress`, "POST", { done, hosts: batch, message: notes[0] }); batch = []; last = Date.now(); if (r.rejected) log("backend rejected", r.rejected, "out-of-scope host(s)"); } };
  await pool([...ips, ...hosts], conc, async (t) => { if (cancelled) return; await new Promise((r) => setTimeout(r, gap * conc * Math.random() * 2)); const isIp = ip2n(t) != null, h = { methods: [] };
    if (isIp) h.ip = t; else h.hostname = t; let up = false; const addr = t;
    if (o.methods.includes("icmp")) { const rtt = await ping(addr, o.timeoutMs); if (rtt != null) { up = true; h.rttMs = rtt; h.methods.push("icmp"); } }
    if (o.methods.includes("tcp")) { const open = []; for (const p of o.tcpPorts) if (await tcp(addr, p, o.timeoutMs)) open.push(p); if (open.length) { up = true; h.ports = open; h.methods.push("tcp"); } }
    if (up && o.methods.includes("snmp")) { const r = await snmp(addr, o.timeoutMs); if (r && !r.missing) { h.sysDescr = r.sysDescr; h.sysName = r.sysName; h.neighbors = r.neighbors; h.methods.push("snmp"); } }
    done++; if (up) { h.up = true; batch.push(h); } await flush(false).catch((e) => log("report failed", e.message)); });
  await flush(true); return notes;
}
async function scans() { const { scan: job } = await spark("noc/scans/pending?agent=" + encodeURIComponent(NAME)); if (!job) return; cancelled = false;
  try { const notes = await scan(job); await spark(`noc/scans/${job.id}/complete`, "POST", { ok: true, notes }); log("scan complete", job.id); } catch (e) { log("scan failed", e.message); await spark(`noc/scans/${job.id}/complete`, "POST", { ok: false, error: e.message }).catch(() => {}); } }
function exec(cmd, input) { return new Promise((res, rej) => { const p = spawn(cmd, [], { stdio: ["pipe", "pipe", "pipe"] }); let out = "", err = ""; p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (err += d)); p.on("error", rej); p.on("close", (c) => (c === 0 ? res(out) : rej(new Error(err.slice(0, 300) || "executor exit " + c)))); p.stdin.end(JSON.stringify(input)); }); }
// Config executor contract: reads {action:"backup"|"apply"|"readback", device:{id,name,ip,type}, proposed?} as JSON on stdin; prints the device's configuration text (backup/readback) or nothing (apply). Non-zero exit = failure.
async function changes() { const { changes: list } = await spark("noc/changes/pending"); for (const ch of list) { log("change", ch.id, "on", ch.device.name);
  try { if (!E.CONFIG_EXECUTOR) throw new Error("No CONFIG_EXECUTOR is configured on this agent, so nothing was changed on the device."); const b = await exec(E.CONFIG_EXECUTOR, { action: "backup", device: ch.device });
    await spark(`noc/changes/${ch.id}/backup`, "POST", { config: b }); await exec(E.CONFIG_EXECUTOR, { action: "apply", device: ch.device, proposed: ch.proposed }); const run2 = await exec(E.CONFIG_EXECUTOR, { action: "readback", device: ch.device });
    await spark(`noc/changes/${ch.id}/result`, "POST", { ok: true, runningConfig: run2 }); } catch (e) { await spark(`noc/changes/${ch.id}/result`, "POST", { ok: false, error: String(e.message).slice(0, 300) }).catch(() => {}); } } }
log("Spark discovery agent", NAME, "polling", S, "every", POLL / 1000, "s"); let busy = false;
setInterval(async () => { if (busy) return; busy = true; try { await scans(); } catch (e) { log("poll failed:", e.message); } try { await changes(); } catch (e) { log("changes poll failed:", e.message); } busy = false; }, POLL);
