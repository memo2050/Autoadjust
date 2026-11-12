"use strict";
(function () {
/* ===== helpers ===== */
var $ = function (i) { return document.getElementById(i); };
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
function pad(n) { return n < 10 ? "0" + n : "" + n; }
function hms(t) { var d = new Date(t); return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()); }
function dt(t) { var d = new Date(t); return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
function r1(n) { return Math.round(n * 10) / 10; }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
function ago(t) { var s = Math.max(0, (Date.now() - t) / 1000); return s < 60 ? Math.round(s) + " s ago" : s < 3600 ? Math.round(s / 60) + " min ago" : Math.round(s / 3600) + " h ago"; }
var LSK = "nocLocal";
function lsGet() { try { return JSON.parse(localStorage.getItem(LSK) || "{}"); } catch (e) { return {}; } }
function lsPut(o) { try { localStorage.setItem(LSK, JSON.stringify(o)); } catch (e) {} }

/* ===== status model (mirrors lib/soc/noc.ts so sample and live data are judged by the same thresholds) ===== */
var TH = { latencyMs: [50, 100, 250], lossPct: [1, 3, 10], cpu: [70, 85, 95], mem: [80, 90, 97], disk: [80, 90, 95], util: [80, 90, 97] };
var RANK = ["healthy", "warning", "degraded", "critical"];
var COL = { healthy: "#3ddc84", warning: "#ffd43b", degraded: "#ff9f43", critical: "#ff4d5e", offline: "#7b8394" };
var STL = { healthy: "Healthy", warning: "Warning", degraded: "Degraded", critical: "Critical", offline: "Offline" };
function bwUtil(m) { return m.bwCapMbps > 0 && (m.bwInMbps != null || m.bwOutMbps != null) ? Math.max(m.bwInMbps || 0, m.bwOutMbps || 0) / m.bwCapMbps * 100 : undefined; }
function statusOf(d) {
  if (!d.up) return { status: "offline", reasons: ["Device is reported down (no response from the monitoring source)."], items: [{ m: "up", v: 0, t: 1, k: 3, label: "availability" }] };
  var m = d.metrics, reasons = [], items = [], lvl = 0;
  function chk(v, th, label, unit, key) { if (v == null) return; var k = v >= th[2] ? 3 : v >= th[1] ? 2 : v >= th[0] ? 1 : 0; if (k) { reasons.push(label + " " + r1(v) + unit + " (" + RANK[k] + " at " + th[k - 1] + unit + "+)"); items.push({ m: key, v: r1(v), t: th[k - 1], k: k, label: label, unit: unit }); lvl = Math.max(lvl, k); } }
  chk(m.latencyMs, TH.latencyMs, "latency", " ms", "latencyMs"); chk(m.lossPct, TH.lossPct, "packet loss", "%", "lossPct"); chk(m.cpu, TH.cpu, "CPU", "%", "cpu");
  chk(m.mem, TH.mem, "memory", "%", "mem"); chk(m.disk, TH.disk, "disk", "%", "disk"); chk(bwUtil(m), TH.util, "bandwidth utilization", "%", "util");
  return { status: RANK[lvl], reasons: reasons, items: items };
}
function worst(a, b) { var o = ["healthy", "warning", "degraded", "critical", "offline"]; return o.indexOf(a) >= o.indexOf(b) ? a : b; }

/* ===== state ===== */
var N = { real: null, rsel: null, mode: "sample", probe: "none", devices: [], hist: {}, sel: null, agent: null, view: "dash", live: null, polled: 0, incidents: [], approvals: [], audit: [], esc: [], seq: 0, runs: {}, wf: null, tick: 0, feed: [], socInc: [], socMode: "sample", err: "" };
function key() { return N.mode === "live" ? "live" : "sample"; }
function load() { var o = lsGet()[key()] || {}; N.incidents = o.incidents || []; N.approvals = o.approvals || []; N.audit = o.audit || []; N.esc = o.esc || []; N.seq = o.seq || 0; N.runs = o.runs || {}; }
function save() { var a = lsGet(); a[key()] = { incidents: N.incidents.slice(0, 200), approvals: N.approvals.slice(0, 200), audit: N.audit.slice(0, 300), esc: N.esc.slice(0, 200), seq: N.seq, runs: slimRuns() }; lsPut(a); }
function slimRuns() { var o = {}; Object.keys(N.runs).forEach(function (k) { o[k] = N.runs[k].slice(0, 12); }); return o; }
function aud(what, who) { N.audit.unshift({ t: Date.now(), who: who || "you", what: what }); save(); }

/* ===== simulated telemetry (SAMPLE ONLY; clearly labelled, never presented as live) ===== */
var CFGS = function (o) { return Object.assign({ ntp: "time.example.net", dns: "10.0.0.53", snmp: "v3", telnet: false, ssh: true, syslog: "10.0.9.5", mtu: 1500, stp: "rstp", acl: "restricted" }, o || {}); };
var BASE = [
  { id: "internet", name: "Internet", type: "internet", ip: "", m: { latencyMs: 18, lossPct: 0.1 }, links: [] },
  { id: "edge-rtr-01", name: "EDGE-RTR-01", type: "router", ip: "203.0.113.1", m: { latencyMs: 22, lossPct: 2.4, cpu: 41, mem: 44, bwInMbps: 640, bwOutMbps: 420, bwCapMbps: 1000 }, links: [{ to: "internet", utilPct: 64, capMbps: 1000 }, { to: "fw-01", utilPct: 58, capMbps: 10000 }], cfg: CFGS({ snmp: "v2c public", ntp: "time.example.net" }) },
  { id: "fw-01", name: "FW-01", type: "firewall", ip: "10.0.0.2", m: { latencyMs: 3, lossPct: 0, cpu: 58, mem: 62 }, links: [{ to: "core-sw-01", utilPct: 47, capMbps: 10000 }, { to: "aws-vpc-prod", utilPct: 45, capMbps: 1000 }], cfg: CFGS({ acl: "permit any any (rule 40)" }) },
  { id: "core-sw-01", name: "CORE-SW-01", type: "switch", ip: "10.0.0.3", m: { latencyMs: 1, lossPct: 0, cpu: 33, mem: 40 }, links: [{ to: "dist-sw-01", utilPct: 52, capMbps: 10000 }, { to: "dist-sw-02", utilPct: 91, capMbps: 10000 }, { to: "app-srv-01", utilPct: 36, capMbps: 10000 }, { to: "db-srv-01", utilPct: 41, capMbps: 10000 }, { to: "dns-srv-01", utilPct: 12, capMbps: 1000 }, { to: "esx-host-01", utilPct: 58, capMbps: 10000 }, { to: "backup-nas-01", utilPct: 0, capMbps: 1000 }], cfg: CFGS({ mtu: 9000 }) },
  { id: "dist-sw-01", name: "DIST-SW-01", type: "switch", ip: "10.0.1.2", m: { latencyMs: 2, lossPct: 0, cpu: 28, mem: 35 }, links: [{ to: "demo-ws01", utilPct: 94, capMbps: 1000 }, { to: "wifi-ap-01", utilPct: 22, capMbps: 1000 }], cfg: CFGS() },
  { id: "dist-sw-02", name: "DIST-SW-02", type: "switch", ip: "10.0.2.2", m: { latencyMs: 4, lossPct: 0.2, cpu: 62, mem: 51 }, links: [{ to: "ws-floor2", utilPct: 38, capMbps: 1000 }, { to: "demo-srv02", utilPct: 27, capMbps: 1000 }], cfg: CFGS({ ntp: "pool.ntp.org", stp: "pvst" }) },
  { id: "app-srv-01", name: "APP-SRV-01", type: "server", ip: "10.0.10.11", m: { latencyMs: 4, lossPct: 0, cpu: 88, mem: 71, disk: 54 }, links: [], cfg: CFGS({ telnet: true }) },
  { id: "db-srv-01", name: "DB-SRV-01", type: "server", ip: "10.0.10.12", m: { latencyMs: 3, lossPct: 0, cpu: 47, mem: 83, disk: 93 }, links: [], cfg: CFGS(), diskTrend: 0.35 },
  { id: "dns-srv-01", name: "DNS-SRV-01", type: "server", ip: "10.0.0.53", m: { latencyMs: 140, lossPct: 3.5, cpu: 22, mem: 38, disk: 41 }, links: [], cfg: CFGS({ dns: "10.0.0.54" }) },
  { id: "esx-host-01", name: "ESX-HOST-01", type: "hypervisor", ip: "10.0.10.20", m: { latencyMs: 2, lossPct: 0, cpu: 74, mem: 86, disk: 61 }, links: [], vms: 14, cfg: CFGS() },
  { id: "backup-nas-01", name: "BACKUP-NAS-01", type: "storage", ip: "10.0.10.30", up: false, m: {}, links: [], cfg: CFGS() },
  { id: "aws-vpc-prod", name: "AWS-VPC-PROD", type: "cloud", ip: "", m: { latencyMs: 38, lossPct: 0.1, cpu: 36, mem: 44 }, links: [], cfg: CFGS() },
  { id: "demo-ws01", name: "DEMO-WS01", type: "endpoint", ip: "10.0.1.45", m: { latencyMs: 6, lossPct: 0, bwInMbps: 40, bwOutMbps: 940, bwCapMbps: 1000 }, links: [], cfg: CFGS() },
  { id: "demo-srv02", name: "DEMO-SRV02", type: "server", ip: "10.0.2.30", m: { latencyMs: 5, lossPct: 0, cpu: 52, mem: 58, disk: 49 }, links: [], cfg: CFGS() },
  { id: "ws-floor2", name: "WS-FLOOR2-POOL", type: "endpoint", ip: "10.0.2.0/24", m: { latencyMs: 12, lossPct: 0.4, bwInMbps: 210, bwOutMbps: 90, bwCapMbps: 1000 }, links: [], cfg: CFGS() },
  { id: "wifi-ap-01", name: "WIFI-AP-01", type: "accesspoint", ip: "10.0.1.50", m: { latencyMs: 8, lossPct: 0.2, cpu: 19 }, links: [], cfg: CFGS({ ntp: "time.example.net" }) }
];
var seed = 7;
function rnd() { seed = (seed * 16807) % 2147483647; return seed / 2147483647; }
function jit(v, p) { return v == null ? v : Math.max(0, v * (1 + (rnd() - 0.5) * p)); }
function sampleSnap(b, t, back) {
  var m = Object.assign({}, b.m), o = {};
  ["latencyMs", "lossPct", "cpu", "mem", "bwInMbps", "bwOutMbps"].forEach(function (k) { if (m[k] != null) m[k] = r1(jit(m[k], k === "lossPct" ? 0.3 : 0.06)); });
  if (m.disk != null) m.disk = r1(m.disk - (b.diskTrend || 0.02) * back);
  if (m.cpu != null) m.cpu = Math.min(100, m.cpu); if (m.mem != null) m.mem = Math.min(100, m.mem);
  o = { t: t, latencyMs: m.latencyMs, lossPct: m.lossPct, cpu: m.cpu, mem: m.mem, disk: m.disk, bwMbps: m.bwInMbps != null ? Math.max(m.bwInMbps, m.bwOutMbps || 0) : undefined };
  return { m: m, h: o };
}
function initSample() {
  seed = 7; N.mode = "sample"; N.devices = []; N.hist = {};
  var now = Date.now();
  BASE.forEach(function (b) {
    var h = [];
    for (var i = 47; i >= 0; i--) { h.push(sampleSnap(b, now - i * 1800000, i).h); }
    var cur = sampleSnap(b, now, 0);
    N.devices.push({ id: b.id, name: b.name, type: b.type, ip: b.ip, up: b.up !== false, metrics: b.up === false ? {} : cur.m, links: b.links, vms: b.vms, config: b.cfg, history: h, receivedAt: now, collector: "SIMULATED" });
  });
}
function simTick() {
  if (N.mode !== "sample") return; var now = Date.now(); N.tick++;
  N.devices.forEach(function (d) { var b = BASE.filter(function (x) { return x.id === d.id; })[0]; if (!d.up) return; var c = sampleSnap(b, now, 0); d.metrics = c.m; d.receivedAt = now; if (N.tick % 20 === 0) d.history.push(c.h); if (d.history.length > 120) d.history.shift(); });
}

/* ===== live telemetry from the backend ===== */
function tok() { try { return sessionStorage.getItem("socToken") || ""; } catch (e) { return ""; } }
async function api(method, path, body) {
  var h = {}, t = tok(); if (t) h.Authorization = "Bearer " + t; var init = { method: method, headers: h };
  if (body != null) { h["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  var ctl = new AbortController(), to = setTimeout(function () { ctl.abort(); }, 12000); init.signal = ctl.signal;
  try { var res = await fetch("/api/soc" + path, init), ct = res.headers.get("content-type") || ""; if (ct.indexOf("json") < 0) { var e = new Error("No backend at this address."); e.nobackend = true; throw e; }
    var j = await res.json(); if (!res.ok) { var er = new Error(j.error || ("Request failed (" + res.status + ")")); er.status = res.status; throw er; } return j; } finally { clearTimeout(to); }
}
function normLive(rows) { return rows.map(function (d) { return { id: d.id, name: d.name, type: d.type, ip: d.ip || "", up: d.up !== false, metrics: d.metrics || {}, links: d.links || [], vms: undefined, config: d.config, history: (d.history || []).map(function (s) { return Object.assign({}, s, { t: Date.parse(s.t) }); }), receivedAt: Date.parse(d.receivedAt), collector: d.collector }; }); }
async function probe() {
  N.err = "";
  try { await api("GET", "/me"); N.probe = "ok"; try { var ov0 = await api("GET", "/noc/overview"); if (ov0.sources.length || ov0.devices.length) { setReal(ov0); return finishProbe(); } } catch (e0) { if (e0.status === 401 || e0.nobackend) throw e0; }
    var rows = await api("GET", "/noc/devices"); if (rows.length) { N.mode = "live"; N.devices = normLive(rows); N.live = Date.now(); } else { N.mode = "sample"; N.probe = "empty"; initSample(); } }
  catch (e) { N.probe = e.nobackend || !e.status ? "none" : e.status === 401 ? "auth" : "error"; N.err = e.message; N.mode = "sample"; initSample(); }
  return finishProbe();
}
async function finishProbe() {
  load();
  try { N.socInc = []; if (N.probe === "ok") { N.socMode = "live"; N.socInc = (await api("GET", "/incidents")).filter(function (i) { return i.status !== "closed"; }); } else { N.socMode = "sample"; N.socInc = (window.SparkSOC && SparkSOC.sample()) || []; } } catch (e) { N.socMode = "sample"; N.socInc = (window.SparkSOC && SparkSOC.sample()) || []; }
}
async function poll() {
  if (N.mode !== "live" || document.hidden || curView() !== "noc") return;
  try { if (N.real) { setReal(await api("GET", "/noc/overview")); N.polled = Date.now(); paintAll(); return; } var rows = await api("GET", "/noc/devices"); N.devices = normLive(rows); N.live = Date.now(); N.polled = Date.now(); paintAll(); } catch (e) { N.err = e.message; paintMode(); }
}

/* ===== topology helpers ===== */
function byId(id) { return N.devices.filter(function (d) { return d.id === id; })[0]; }
function ST(d) { return statusOf(d); }
function edges() {
  var seen = {}, out = [];
  N.devices.forEach(function (d) { (d.links || []).forEach(function (l) { if (!byId(l.to)) return; var k = [d.id, l.to].sort().join("|"); if (seen[k]) return; seen[k] = 1; var a = d, b = byId(l.to), util = l.utilPct != null ? l.utilPct : Math.max(bwUtil(a.metrics) || 0, bwUtil(b.metrics) || 0) || undefined; var lv = util == null ? 0 : util >= TH.util[2] ? 3 : util >= TH.util[1] ? 2 : util >= TH.util[0] ? 1 : 0, st = !a.up || !b.up ? "offline" : RANK[lv]; out.push({ a: a.id, b: l.to, util: util, cap: l.capMbps, status: st }); }); });
  return out;
}
function neighbors(id) { var o = []; edges().forEach(function (e) { if (e.a === id) o.push({ id: e.b, e: e }); else if (e.b === id) o.push({ id: e.a, e: e }); }); return o; }
function pathToInternet(id) {
  var root = N.devices.filter(function (d) { return d.type === "internet"; })[0] || N.devices.filter(function (d) { return d.type === "router"; })[0]; if (!root) return null;
  var prev = {}, q = [id], seen = {}; seen[id] = 1;
  while (q.length) { var c = q.shift(); if (c === root.id) break; neighbors(c).forEach(function (n) { if (!seen[n.id]) { seen[n.id] = 1; prev[n.id] = c; q.push(n.id); } }); }
  if (!seen[root.id]) return null; var p = [root.id], c2 = root.id; while (c2 !== id) { c2 = prev[c2]; p.push(c2); } return p.reverse();
}
function layout() {
  var root = N.devices.filter(function (d) { return d.type === "internet"; })[0] || N.devices.filter(function (d) { return d.type === "router"; })[0] || N.devices[0]; if (!root) return {};
  var lv = {}, q = [root.id]; lv[root.id] = 0; while (q.length) { var c = q.shift(); neighbors(c).forEach(function (n) { if (lv[n.id] == null) { lv[n.id] = lv[c] + 1; q.push(n.id); } }); }
  var mx = 0; Object.keys(lv).forEach(function (k) { mx = Math.max(mx, lv[k]); }); N.devices.forEach(function (d) { if (lv[d.id] == null) lv[d.id] = mx + 1; }); mx = 0; Object.keys(lv).forEach(function (k) { mx = Math.max(mx, lv[k]); });
  var cols = {}; N.devices.forEach(function (d) { (cols[lv[d.id]] = cols[lv[d.id]] || []).push(d.id); });
  var pos = {}; Object.keys(cols).forEach(function (L) { var ids = cols[L]; ids.forEach(function (id, i) { pos[id] = { x: 70 + (Number(L) / Math.max(1, mx)) * 860, y: 40 + ((i + 0.5) / ids.length) * 560 }; }); });
  return pos;
}

/* ===== detection engine (rules over the telemetry in view; every finding carries its evidence and a reason) ===== */
var CATS = { availability: "Availability", latency: "Latency", loss: "Packet loss", capacity: "Capacity / bandwidth", resource: "Server resources", traffic: "Abnormal traffic", config: "Configuration" };
function median(a) { var s = a.slice().sort(function (x, y) { return x - y; }); return s.length ? s[Math.floor(s.length / 2)] : 0; }
function sevOf(k, d) { if (k === 3) return d.type === "endpoint" || d.type === "accesspoint" ? "high" : "critical"; return k === 2 ? "medium" : "low"; }
function detect() {
  var out = [];
  N.devices.forEach(function (d) {
    var s = ST(d), m = d.metrics;
    if (!d.up) { out.push({ id: d.id + "|availability", dev: d.id, cat: "availability", rule: "NOC-AVAIL-001", sev: ["firewall", "router", "switch", "server", "hypervisor"].indexOf(d.type) >= 0 ? "critical" : "high", title: d.name + " is DOWN", why: "The monitoring source reports no response from this " + d.type + ". Anything that depends on it is unreachable or unprotected.", ev: ["up = false", "last report " + (d.receivedAt ? ago(d.receivedAt) : "unknown")] }); return; }
    s.items.forEach(function (it) {
      var cat = it.m === "latencyMs" ? "latency" : it.m === "lossPct" ? "loss" : it.m === "util" ? "capacity" : "resource", rule = { latencyMs: "NOC-LAT-001", lossPct: "NOC-LOSS-001", util: "NOC-BW-001", cpu: "NOC-CPU-001", mem: "NOC-MEM-001", disk: "NOC-DISK-001" }[it.m];
      out.push({ id: d.id + "|" + cat + "|" + it.m, dev: d.id, cat: cat, rule: rule, sev: sevOf(it.k, d), title: d.name + ": " + it.label + " " + it.v + (it.unit || ""), why: it.label + " is " + it.v + (it.unit || "") + ", above the " + RANK[it.k] + " threshold of " + it.t + (it.unit || "") + ".", ev: [it.m + " = " + it.v, "threshold " + it.t] });
    });
    // abnormal traffic: current throughput far above this device's own history, or an endpoint saturating its uplink outbound
    var h = (d.history || []).map(function (x) { return x.bwMbps; }).filter(function (v) { return v != null; }), cur = m.bwInMbps != null ? Math.max(m.bwInMbps, m.bwOutMbps || 0) : null;
    if (cur != null && h.length >= 8) { var med = median(h); if (med > 0 && cur >= med * 3 && cur >= 100) out.push({ id: d.id + "|traffic|spike", dev: d.id, cat: "traffic", rule: "NOC-TRAF-001", sev: "medium", title: d.name + ": traffic is " + r1(cur / med) + "x its usual level", why: "Current throughput " + r1(cur) + " Mbps is at least 3x the median of its own recent history (" + r1(med) + " Mbps).", ev: ["bw now " + r1(cur) + " Mbps", "history median " + r1(med) + " Mbps", h.length + " samples"] }); }
    if (d.type === "endpoint" && m.bwOutMbps != null && m.bwCapMbps && m.bwOutMbps / m.bwCapMbps >= 0.85 && m.bwOutMbps > 3 * (m.bwInMbps || 1)) out.push({ id: d.id + "|traffic|upload", dev: d.id, cat: "traffic", rule: "NOC-TRAF-002", sev: "high", title: d.name + ": endpoint is sending far more than it receives", why: "Outbound " + r1(m.bwOutMbps) + " Mbps is " + Math.round(m.bwOutMbps / m.bwCapMbps * 100) + "% of its link and over 3x inbound. Endpoints rarely do this; it can be a backup, a large upload, or data theft, so the SOC should look.", ev: ["out " + r1(m.bwOutMbps) + " Mbps", "in " + r1(m.bwInMbps || 0) + " Mbps", "link capacity " + m.bwCapMbps + " Mbps"], soc: true });
  });
  edges().forEach(function (e) { if (e.status === "offline") return; if (e.util != null && e.util >= TH.util[0]) { var k = e.util >= TH.util[2] ? 3 : e.util >= TH.util[1] ? 2 : 1; out.push({ id: e.a + "|" + e.b + "|link", dev: e.a, cat: "capacity", rule: "NOC-LINK-001", sev: k === 3 ? "high" : k === 2 ? "medium" : "low", title: "Link " + nm(e.a) + " ↔ " + nm(e.b) + " at " + r1(e.util) + "% utilization", why: "Link utilization " + r1(e.util) + "% is above " + TH.util[k - 1] + "%. Queues build, latency and drops follow.", ev: ["util = " + r1(e.util) + "%", e.cap ? "capacity " + e.cap + " Mbps" : "capacity unknown"] }); } });
  var o = { critical: 0, high: 1, medium: 2, low: 3 }; return out.sort(function (a, b) { return o[a.sev] - o[b.sev]; });
}
function nm(id) { var d = byId(id); return d ? d.name : id; }
var SEVB = { critical: "b-c", high: "b-h", medium: "b-m", low: "b-l" };
function sevBadge(s) { return '<span class="nbadge ' + (SEVB[s] || "b-l") + '">' + esc(String(s).toUpperCase()) + "</span>"; }

/* ===== NOC agents ===== */
var AG = {
  manager: { n: "NOC Supervisor", c: "#ffb454", d: "Coordinates the NOC team, oversees monitoring sources and open incidents, prioritizes outages, and reports status to administrators.", resp: ["Coordinate all NOC agents", "Assign incidents to the right agent", "Watch monitoring source health", "Prioritize outages", "Summarize status for administrators", "Coordinate with the SOC when security affects the network"], def: "Prioritize today's network issues and assign owners" },
  monitor: { n: "Network Monitoring Agent", c: "#4de2a1", d: "Watches availability, bandwidth, latency, packet loss and traffic patterns.", resp: ["Network availability", "Bandwidth utilization", "Latency", "Packet loss", "Network health score", "Abnormal traffic patterns"], def: "Scan all devices and links for availability, latency, loss and traffic" },
  trouble: { n: "Network Engineer", c: "#5cc8ff", d: "Investigates routers, switches, firewalls and access points: connectivity, interface state, errors and drops, packet loss and latency. It only reads monitoring data; it runs no commands.", resp: ["Router and switch health", "Interface status, errors and drops", "Connectivity problems", "Packet loss and latency analysis", "Troubleshooting procedures"], def: "Investigate the worst connectivity problem" },
  infra: { n: "Server Administrator", c: "#b48cff", d: "Watches Windows and Linux servers and virtual machines: CPU, memory, disk, uptime and restarts.", resp: ["Server health", "CPU, memory and disk", "Uptime and recent restarts", "Virtualization hosts and VMs", "Resource problems"], def: "Review server, hypervisor and cloud health" },
  incident: { n: "Incident Responder", c: "#ff7a90", d: "Works open incidents from real alerts: severity, probable cause (hypothesis), recommendations and progress.", resp: ["Review open incidents", "Assign severity", "Probable root cause (hypothesis)", "Recommended corrective actions", "Track progress to verified resolution"], def: "Open or update tickets from current detections" },
  perf: { n: "Performance Analyst", c: "#ffd43b", d: "Analyzes stored history for trends, busy links and capacity risks. No forecasting beyond the data stored.", resp: ["Performance trends", "Bandwidth utilization", "Bottlenecks", "Capacity risks", "Improvement recommendations"], def: "Find bottlenecks and capacity risks" },
  config: { n: "Automation Engineer", c: "#ff9f43", d: "Proposes only administrator-registered automation (Zabbix scripts, webhooks). It NEVER runs anything itself: every action needs an administrator approval and its result is verified with fresh data.", resp: ["Registered automation actions", "Approval requests", "Execution results", "Verification with fresh data", "Approval before any change"], def: "Review all device configurations" }
};
var ORDER = ["manager", "trouble", "infra", "perf", "incident", "config"];
var VERB = { manager: "prioritizing issues", monitor: "scanning the network", trouble: "tracing the problem", infra: "reviewing servers", incident: "updating tickets", perf: "analyzing performance", config: "reviewing configurations" };
function R(head, sev) { return { head: head, sev: sev || "low", findings: [], table: null, recs: [], limits: [], handoff: null }; }
function F(R_, sev, t, ev) { R_.findings.push({ sev: sev, t: t, ev: ev || [] }); }
function top(sev) { var o = ["low", "medium", "high", "critical"], m = "low"; sev.forEach(function (s) { if (o.indexOf(s) > o.indexOf(m)) m = s; }); return m; }
function slope(h, key) { // least squares slope per hour over the history, null if not enough points
  var p = h.filter(function (x) { return x[key] != null; }); if (p.length < 6) return null; var n = p.length, sx = 0, sy = 0, sxy = 0, sxx = 0, t0 = p[0].t;
  p.forEach(function (x) { var t = (x.t - t0) / 3600000; sx += t; sy += x[key]; sxy += t * x[key]; sxx += t * t; }); var den = n * sxx - sx * sx; return den === 0 ? null : (n * sxy - sx * sy) / den;
}
var SRVT = ["server", "hypervisor", "cloud", "storage"];

// Each agent = ordered list of REAL steps. A step is a function that computes something; the run loop times it. Progress = steps done / steps total.
var BUILD = {
  monitor: function (task, ctx, H) {
    var st = { a: [] }; return [
      ["Read the telemetry snapshot", function () { st.n = N.devices.length; st.age = N.devices.length ? Math.max.apply(null, N.devices.map(function (d) { return Date.now() - d.receivedAt; })) : 0; return st.n + " devices, newest report " + ago(Date.now() - st.age); }],
      ["Check availability of every device", function () { st.down = N.devices.filter(function (d) { return !d.up; }); return st.down.length + " down of " + st.n; }],
      ["Evaluate latency and packet loss", function () { st.ll = N.devices.filter(function (d) { var s = ST(d); return s.items.some(function (i) { return i.m === "latencyMs" || i.m === "lossPct"; }); }); return st.ll.length + " device(s) above a latency or loss threshold"; }],
      ["Evaluate bandwidth utilization per link", function () { st.hot = edges().filter(function (e) { return e.util != null && e.util >= TH.util[0]; }); return st.hot.length + " of " + edges().length + " links at 80%+"; }],
      ["Compare traffic with each device's own history", function () { st.tr = detect().filter(function (a) { return a.cat === "traffic"; }); return st.tr.length + " abnormal traffic pattern(s)"; }],
      ["Score network health and write the result", function () {
        var tot = N.devices.length || 1, sc = 100; N.devices.forEach(function (d) { var s = ST(d).status; sc -= s === "offline" ? 14 : s === "critical" ? 10 : s === "degraded" ? 5 : s === "warning" ? 2 : 0; }); sc = Math.max(0, Math.round(sc));
        var r = R("Network health " + sc + "/100: " + st.down.length + " down, " + st.ll.length + " with latency/loss, " + st.hot.length + " hot link(s), " + st.tr.length + " traffic anomaly(ies).", top(st.down.map(function () { return "critical"; }).concat(st.hot.map(function () { return "medium"; })).concat(st.tr.map(function (a) { return a.sev; }))));
        st.down.forEach(function (d) { F(r, "critical", d.name + " is down.", ["up = false"]); });
        st.ll.forEach(function (d) { F(r, "medium", d.name + ": " + ST(d).reasons.join("; ") + ".", ["latencyMs=" + d.metrics.latencyMs, "lossPct=" + d.metrics.lossPct]); });
        st.hot.forEach(function (e) { F(r, e.util >= TH.util[1] ? "high" : "medium", "Link " + nm(e.a) + " ↔ " + nm(e.b) + " at " + r1(e.util) + "%.", ["util=" + r1(e.util)]); });
        st.tr.forEach(function (a) { F(r, a.sev, a.title + ". " + a.why, a.ev); if (a.soc) r.handoff = { to: "SOC", dev: a.dev, text: a.title }; });
        r.table = { title: "Device health", cols: ["Device", "Type", "Status", "Latency", "Loss", "Why"], rows: N.devices.map(function (d) { var s = ST(d); return [d.name, d.type, STL[s.status], d.metrics.latencyMs != null ? d.metrics.latencyMs + " ms" : "-", d.metrics.lossPct != null ? d.metrics.lossPct + "%" : "-", s.reasons.join("; ") || "within thresholds"]; }) };
        r.score = sc; if (!r.findings.length) F(r, "low", "Nothing is outside its thresholds in the telemetry in view.", []);
        r.limits.push("Based only on the telemetry shown above. Nothing is probed by this page.", "Thresholds are fixed defaults (see the Status rules note).");
        H.r = r; return "Health score " + sc + "/100"; }]
    ];
  },
  trouble: function (task, ctx, H) {
    var st = {}; return [
      ["Choose what to investigate", function () { var want = ctx.dev && byId(ctx.dev); if (want) st.t = [want]; else { var al = detect().filter(function (a) { return ["availability", "latency", "loss"].indexOf(a.cat) >= 0; }); var seen = {}; st.t = []; al.forEach(function (a) { if (!seen[a.dev] && byId(a.dev)) { seen[a.dev] = 1; st.t.push(byId(a.dev)); } }); st.t = st.t.slice(0, 4); } return st.t.length ? st.t.map(function (d) { return d.name; }).join(", ") : "no connectivity problems detected"; }],
      ["Trace the path from each target to the Internet", function () { st.p = st.t.map(function (d) { var p = pathToInternet(d.id); return { d: d, p: p }; }); return st.p.map(function (x) { return x.d.name + ": " + (x.p ? x.p.length - 1 + " hop(s)" : "no path in the topology"); }).join("; ") || "nothing to trace"; }],
      ["Find the first unhealthy hop on each path", function () { st.f = st.p.map(function (x) { if (!x.p) return { x: x, hop: null }; var hop = null; for (var i = x.p.length - 1; i >= 0; i--) { var dv = byId(x.p[i]); if (dv && ST(dv).status !== "healthy") { hop = dv; break; } } return { x: x, hop: hop }; }); return st.f.map(function (z) { return z.x.d.name + " → " + (z.hop ? z.hop.name : "none"); }).join("; ") || "-"; }],
      ["Check DNS indicators", function () { st.dns = N.devices.filter(function (d) { return /dns/i.test(d.name) || (d.config && d.config.role === "dns"); }); st.dnsBad = st.dns.filter(function (d) { return ST(d).status !== "healthy"; }); return st.dns.length ? st.dnsBad.length + " of " + st.dns.length + " DNS server(s) unhealthy" : "no DNS server in the telemetry"; }],
      ["Check routing and redundancy", function () { st.red = st.t.map(function (d) { var ns = neighbors(d.id).filter(function (n) { var nd = byId(n.id); return nd && nd.up; }); return { d: d, up: ns.length }; }); return st.red.map(function (z) { return z.d.name + ": " + z.up + " live neighbor(s)"; }).join("; ") || "-"; }],
      ["Write findings and troubleshooting procedures", function () {
        var r = R("", "low"), sv = [];
        st.f.forEach(function (z) { var d = z.x.d, s = ST(d); if (s.status === "healthy" && d.up) return; var sev = !d.up ? "critical" : s.status === "critical" ? "high" : "medium"; sv.push(sev);
          F(r, sev, d.name + " is " + STL[s.status].toLowerCase() + ": " + (s.reasons.join("; ") || "no response") + (z.hop && z.hop.id !== d.id ? ". First unhealthy hop on the way to the Internet: " + z.hop.name + " (" + STL[ST(z.hop).status] + ")." : z.x.p ? ". Every other hop on its path is healthy, so the problem is at this device or its own link." : ". No path to the Internet in the topology."), ["path " + (z.x.p ? z.x.p.map(nm).join(" > ") : "none")]);
          r.recs.push({ p: sev === "critical" ? "P1" : "P2", t: "From a management host run: ping " + (d.ip || d.name) + " (50 packets) and traceroute to " + (d.ip || d.name) + "; compare loss and latency per hop with what is shown here." }); });
        st.dnsBad.forEach(function (d) { var s = ST(d); sv.push("medium"); F(r, "medium", "DNS server " + d.name + " is " + STL[s.status].toLowerCase() + " (" + s.reasons.join("; ") + "). Slow or lossy DNS shows up as slow websites and 'cannot connect' errors even when the network is fine.", ["latencyMs=" + d.metrics.latencyMs, "lossPct=" + d.metrics.lossPct]); r.recs.push({ p: "P2", t: "Test resolution from a client: nslookup <internal name> " + (d.ip || d.name) + " and a public name; try the secondary resolver; check the DNS service logs and CPU." }); });
        st.red.forEach(function (z) { if (z.up <= 1 && z.d.up && ["router", "firewall", "switch", "server", "hypervisor"].indexOf(z.d.type) >= 0) { F(r, "medium", z.d.name + " has only " + z.up + " live neighbor, so there is no alternate path if it fails.", ["neighbors=" + z.up]); sv.push("medium"); } });
        r.sev = top(sv); r.head = st.t.length ? "Investigated " + st.t.length + " device(s): " + (sv.length ? sv.length + " finding(s), worst " + r.sev + "." : "no connectivity problem found.") : "No connectivity problem is visible in the telemetry.";
        if (!r.findings.length) F(r, "low", "Latency, loss and availability are inside their thresholds on every device checked.", []);
        r.limits.push("Reads telemetry only. It does not ping, trace or query DNS. The commands above are for a person to run.", "Path tracing follows the topology links in the telemetry, which may differ from real routing."); H.r = r; return r.findings.length + " finding(s)"; }]
    ];
  },
  infra: function (task, ctx, H) {
    var st = {}; return [
      ["List servers, hypervisors, cloud and storage", function () { st.s = N.devices.filter(function (d) { return SRVT.indexOf(d.type) >= 0 || (d.type === "endpoint" && d.metrics.cpu != null); }); return st.s.length + " infrastructure device(s)"; }],
      ["Evaluate CPU, memory and disk against thresholds", function () { st.b = st.s.filter(function (d) { return ST(d).items.some(function (i) { return ["cpu", "mem", "disk"].indexOf(i.m) >= 0; }); }); return st.b.length + " over a threshold"; }],
      ["Project disk exhaustion from each disk's own trend", function () { st.proj = []; st.s.forEach(function (d) { if (d.metrics.disk == null) return; var sl = slope(d.history || [], "disk"); if (sl != null && sl > 0.001) { var hrs = (100 - d.metrics.disk) / sl; st.proj.push({ d: d, perDay: sl * 24, days: hrs / 24 }); } }); return st.proj.length ? st.proj.length + " disk(s) growing" : "no disk is growing"; }],
      ["Check virtualization and cloud", function () { st.v = N.devices.filter(function (d) { return d.type === "hypervisor"; }); st.c = N.devices.filter(function (d) { return d.type === "cloud"; }); return st.v.length + " hypervisor(s), " + st.c.length + " cloud environment(s)"; }],
      ["Write findings and recommendations", function () {
        var r = R("", "low"), sv = [];
        st.s.forEach(function (d) { var s = ST(d); if (!d.up) { sv.push("critical"); F(r, "critical", d.name + " (" + d.type + ") is down.", ["up=false"]); r.recs.push({ p: "P1", t: "Check power, link and the management interface of " + d.name + "; if it is a backup target, backups are not running." }); return; } s.items.filter(function (i) { return ["cpu", "mem", "disk"].indexOf(i.m) >= 0; }).forEach(function (i) { var sev = sevOf(i.k, d); sv.push(sev); F(r, sev, d.name + ": " + i.label + " " + i.v + i.unit + " (" + RANK[i.k] + ").", [i.m + "=" + i.v]); r.recs.push({ p: i.k >= 2 ? "P1" : "P2", t: i.m === "disk" ? "Free or expand disk space on " + d.name + "; find the largest growth directories and logs." : i.m === "cpu" ? "Find the busiest processes on " + d.name + " and check for runaway jobs or a missing scale-out node." : "Check memory consumers on " + d.name + "; look for leaks or an undersized VM allocation." }); }); });
        st.proj.forEach(function (x) { if (x.days < 30) { sv.push(x.days < 7 ? "high" : "medium"); F(r, x.days < 7 ? "high" : "medium", x.d.name + " disk is growing about " + r1(x.perDay) + " points per day and would be full in about " + Math.max(1, Math.round(x.days)) + " day(s) at that rate.", ["slope=" + r1(x.perDay) + "/day", "now " + x.d.metrics.disk + "%", (x.d.history || []).length + " samples"]); } });
        st.v.forEach(function (d) { if (d.up && d.metrics.mem >= 80 && d.vms) { F(r, "medium", d.name + " runs " + d.vms + " VMs with host memory at " + d.metrics.mem + "%. Memory overcommit risks ballooning and swapping.", ["vms=" + d.vms, "mem=" + d.metrics.mem]); sv.push("medium"); r.recs.push({ p: "P2", t: "Migrate one or two VMs off " + d.name + " or add memory before the next peak." }); } });
        st.c.forEach(function (d) { var s = ST(d); F(r, s.status === "healthy" ? "low" : "medium", d.name + " (cloud) is " + STL[s.status].toLowerCase() + (s.reasons.length ? ": " + s.reasons.join("; ") : "") + ". Only what the monitoring source reports is known.", ["latencyMs=" + d.metrics.latencyMs]); });
        r.sev = top(sv); r.head = st.s.length ? st.b.length + " of " + st.s.length + " infrastructure device(s) over a threshold" + (st.proj.some(function (x) { return x.days < 30; }) ? ", " + st.proj.filter(function (x) { return x.days < 30; }).length + " disk(s) trending to full within 30 days." : ".") : "No infrastructure telemetry in view.";
        r.table = { title: "Server health", cols: ["Device", "Type", "CPU", "Memory", "Disk", "Status"], rows: st.s.map(function (d) { return [d.name, d.type, d.metrics.cpu != null ? d.metrics.cpu + "%" : "-", d.metrics.mem != null ? d.metrics.mem + "%" : "-", d.metrics.disk != null ? d.metrics.disk + "%" : "-", STL[ST(d).status]]; }) };
        r.limits.push("Disk projections are straight-line fits to the samples in view and can be wrong if usage is bursty.", "Cloud health is limited to what the monitoring source reports; no cloud API is called."); H.r = r; return r.findings.length + " finding(s)"; }]
    ];
  },
  perf: function (task, ctx, H) {
    var st = {}; return [
      ["Rank links by utilization", function () { st.l = edges().filter(function (e) { return e.util != null; }).sort(function (a, b) { return b.util - a.util; }); return st.l.length ? "busiest: " + nm(st.l[0].a) + " ↔ " + nm(st.l[0].b) + " at " + r1(st.l[0].util) + "%" : "no utilization data"; }],
      ["Look for bottlenecks (hot links next to idle ones, saturated uplinks)", function () { st.b = st.l.filter(function (e) { return e.util >= TH.util[0]; }); return st.b.length + " bottleneck candidate(s)"; }],
      ["Project bandwidth growth from history", function () { st.g = []; N.devices.forEach(function (d) { var sl = slope(d.history || [], "bwMbps"); if (sl != null && d.metrics.bwCapMbps && sl > 0.5) { var cur = Math.max(d.metrics.bwInMbps || 0, d.metrics.bwOutMbps || 0), hrs = (d.metrics.bwCapMbps * 0.9 - cur) / sl; st.g.push({ d: d, perHour: sl, days: hrs / 24, cur: cur }); } }); return st.g.length + " device(s) with growing traffic"; }],
      ["Check CPU and memory headroom on network devices", function () { st.h = N.devices.filter(function (d) { return ["router", "firewall", "switch"].indexOf(d.type) >= 0 && ((d.metrics.cpu || 0) >= TH.cpu[0] || (d.metrics.mem || 0) >= TH.mem[0]); }); return st.h.length + " network device(s) with little headroom"; }],
      ["Write recommendations", function () {
        var r = R("", "low"), sv = [];
        st.b.forEach(function (e) { var sev = e.util >= TH.util[1] ? "high" : "medium"; sv.push(sev); F(r, sev, "Link " + nm(e.a) + " ↔ " + nm(e.b) + " is at " + r1(e.util) + "% of " + (e.cap ? e.cap + " Mbps" : "its capacity") + ".", ["util=" + r1(e.util)]); r.recs.push({ p: sev === "high" ? "P1" : "P2", t: "Relieve " + nm(e.a) + " ↔ " + nm(e.b) + ": add a parallel link (LACP), move heavy hosts to another uplink, or apply QoS to protect business traffic." }); });
        st.g.forEach(function (x) { if (x.days < 60) { sv.push("medium"); F(r, "medium", x.d.name + " traffic is growing about " + r1(x.perHour) + " Mbps per hour; it would reach 90% of its link in roughly " + Math.max(1, Math.round(x.days)) + " day(s).", ["slope=" + r1(x.perHour) + " Mbps/h", "now " + r1(x.cur) + " Mbps"]); } });
        st.h.forEach(function (d) { sv.push("medium"); F(r, "medium", d.name + " has little CPU/memory headroom (" + ST(d).reasons.join("; ") + ").", ["cpu=" + d.metrics.cpu, "mem=" + d.metrics.mem]); r.recs.push({ p: "P2", t: "Plan a capacity upgrade or traffic offload for " + d.name + "." }); });
        r.sev = top(sv); r.head = st.b.length + " bottleneck(s), " + st.g.filter(function (x) { return x.days < 60; }).length + " growth risk(s), " + st.h.length + " device(s) low on headroom.";
        r.table = { title: "Link utilization", cols: ["Link", "Utilization", "Capacity", "Status"], rows: st.l.map(function (e) { return [nm(e.a) + " ↔ " + nm(e.b), r1(e.util) + "%", e.cap ? e.cap + " Mbps" : "-", STL[e.status]]; }) };
        if (!r.findings.length) F(r, "low", "No bottleneck or capacity risk is visible in the telemetry in view.", []);
        r.limits.push("Recommendations are general engineering advice based on the numbers above; they are not tested against your network."); H.r = r; return r.findings.length + " finding(s)"; }]
    ];
  },
  config: function (task, ctx, H) {
    var st = {}; return [
      ["Collect configuration data", function () { st.c = N.devices.filter(function (d) { return d.config && Object.keys(d.config).length; }); return st.c.length + " of " + N.devices.length + " devices have configuration data"; }],
      ["Compare NTP, DNS, STP and MTU across devices", function () { st.inc = []; ["ntp", "dns", "stp", "mtu"].forEach(function (k) { var vals = {}; st.c.forEach(function (d) { if (d.config[k] != null && ["switch", "router", "firewall"].concat(k === "ntp" ? ["server", "accesspoint"] : []).indexOf(d.type) >= 0) (vals[d.config[k]] = vals[d.config[k]] || []).push(d.name); }); var ks = Object.keys(vals); if (ks.length > 1) st.inc.push({ k: k, vals: vals }); }); return st.inc.length + " inconsistent setting(s)"; }],
      ["Check for risky settings (Telnet, SNMP v1/v2c, permit-any ACL, no syslog)", function () { st.mis = []; st.c.forEach(function (d) { var c = d.config; if (c.telnet === true) st.mis.push({ d: d, sev: "high", t: "Telnet is enabled on " + d.name + ". It sends passwords in clear text.", fix: "Disable Telnet and use SSH only", ev: "telnet=true" }); if (/^v?[12]c?\b/i.test(String(c.snmp)) || /public/i.test(String(c.snmp))) st.mis.push({ d: d, sev: "high", t: d.name + " uses SNMP " + c.snmp + ". Community strings are shared secrets and 'public' is the well-known default.", fix: "Move to SNMPv3 with authentication and encryption", ev: "snmp=" + c.snmp }); if (/permit any any/i.test(String(c.acl))) st.mis.push({ d: d, sev: "high", t: d.name + " has an allow-all firewall rule (" + c.acl + ").", fix: "Replace the permit-any rule with specific allowed flows", ev: "acl=" + c.acl }); if (!c.syslog) st.mis.push({ d: d, sev: "medium", t: d.name + " sends no syslog, so events from it cannot be investigated later.", fix: "Configure syslog to the central collector", ev: "syslog=unset" }); }); return st.mis.length + " risky setting(s)"; }],
      ["Write findings and change proposals", function () {
        var r = R("", "low"), sv = [];
        if (!st.c.length) { r.head = "No configuration data was received, so nothing can be reviewed."; F(r, "low", "The monitoring source did not send configuration data for any device. This agent will not guess.", []); r.limits.push("Send a `config` object per device to the telemetry API to enable this review."); H.r = r; return "no configuration data"; }
        st.inc.forEach(function (x) { var ks = Object.keys(x.vals), maj = ks.sort(function (a, b) { return x.vals[b].length - x.vals[a].length; })[0]; sv.push("medium"); F(r, "medium", x.k.toUpperCase() + " differs between devices: " + ks.map(function (v) { return v + " on " + x.vals[v].join(", "); }).join("; ") + ".", ["setting=" + x.k]); ks.slice(1).forEach(function (v) { x.vals[v].forEach(function (name) { r.recs.push({ p: "P3", t: "Align " + x.k.toUpperCase() + " on " + name + " to " + maj + (x.vals[maj].length > x.vals[v].length ? " (the most common value)." : " (values are split evenly; confirm which one is correct first)."), type: "config_change", target: name, approval: true }); }); }); });
        st.mis.forEach(function (x) { sv.push(x.sev); F(r, x.sev, x.t, [x.ev]); r.recs.push({ p: x.sev === "high" ? "P1" : "P2", t: x.fix + " on " + x.d.name + ".", type: "config_change", target: x.d.name, approval: true }); });
        r.sev = top(sv); r.head = st.inc.length + " inconsistency(ies) and " + st.mis.length + " risky setting(s) across " + st.c.length + " device(s). Changes below need human approval and are never applied by Spark.";
        if (!r.findings.length) F(r, "low", "No inconsistency or risky setting found in the configuration data received.", []);
        r.limits.push("Reviews only the settings the monitoring source reported. It cannot see full running configs.", "Spark never pushes configuration. An approved change must be applied by an engineer."); H.r = r; return r.findings.length + " finding(s)"; }]
    ];
  },
  incident: function (task, ctx, H) {
    var st = {}; return [
      ["Run detection rules on the current telemetry", function () { st.a = detect(); return st.a.length + " detection(s)"; }],
      ["Match detections to existing tickets (low-severity detections stay alerts, no ticket)", function () { st.new = []; st.upd = []; st.open = N.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) < 0; }); st.a.forEach(function (a) { if (a.sev === "low") return; var t = N.incidents.filter(function (i) { return i.key === a.id && ["Resolved", "Closed"].indexOf(i.status) < 0; })[0]; if (t) st.upd.push({ t: t, a: a }); else st.new.push(a); }); return st.new.length + " new, " + st.upd.length + " existing"; }],
      ["Create tickets and set severity", function () { st.made = []; st.new.forEach(function (a) { N.seq++; var tk = { id: "NOC-" + (1000 + N.seq), key: a.id, title: a.title, severity: a.sev, status: "New", owner: ownerFor(a), team: "NOC", dev: a.dev, cat: a.cat, why: a.why, ev: a.ev, createdAt: Date.now(), log: [{ t: Date.now(), who: "agent:incident", what: "Ticket created from rule " + a.rule + "." }], esc: [] }; if (a.soc) tk.socSuggested = true; N.incidents.unshift(tk); st.made.push(tk); }); save(); return st.made.length + " ticket(s) created"; }],
      ["Resolve tickets whose condition has cleared", function () { st.cl = []; st.open.forEach(function (i) { if (!st.a.some(function (a) { return a.id === i.key; })) { i.status = "Resolved"; i.resolvedAt = Date.now(); i.log.push({ t: Date.now(), who: "agent:incident", what: "Telemetry is back within thresholds; ticket resolved automatically." }); st.cl.push(i); } }); save(); return st.cl.length + " resolved"; }],
      ["Escalate unresolved critical/high tickets", function () { st.es = []; N.incidents.forEach(function (i) { if (["Resolved", "Closed"].indexOf(i.status) >= 0 || (i.severity !== "critical" && i.severity !== "high") || i.esc.length) return; var min = (Date.now() - i.createdAt) / 60000; if (min >= 15 || i.status === "New" && i.severity === "critical") { i.esc.push({ t: Date.now(), to: "NOC Manager", why: i.severity + " ticket " + (min >= 15 ? "unresolved for " + Math.round(min) + " min" : "is critical and still New") }); i.log.push({ t: Date.now(), who: "agent:incident", what: "Escalated to the NOC Manager (" + i.esc[0].why + ")." }); st.es.push(i); } }); save(); return st.es.length + " escalated"; }],
      ["Write the ticket summary", function () {
        var r = R("", "low"), op = N.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) < 0; });
        r.head = st.made.length + " ticket(s) opened, " + st.cl.length + " resolved, " + st.es.length + " escalated; " + op.length + " open.";
        st.made.forEach(function (t) { F(r, t.severity, t.id + " opened: " + t.title + ". Owner: " + (AG[t.owner] ? AG[t.owner].n : t.owner) + ".", t.ev); });
        st.cl.forEach(function (t) { F(r, "low", t.id + " resolved: " + t.title + " is back within thresholds.", []); }); st.es.forEach(function (t) { F(r, "high", t.id + " escalated to the NOC Manager: " + t.esc[0].why + ".", []); });
        r.sev = top(op.map(function (i) { return i.severity; })); if (!r.findings.length) F(r, "low", "No change: every detection already has a ticket.", []);
        r.limits.push("Tickets live in this browser (and are labeled with their data source). A shared ticketing backend is not built yet."); H.r = r; return op.length + " open"; }]
    ];
  },
  manager: function (task, ctx, H) {
    var st = {}; return [
      ["Run detection across the network", function () { st.a = detect(); return st.a.length + " detection(s)"; }],
      ["Prioritize outages and incidents", function () { var w = { critical: 0, high: 1, medium: 2, low: 3 }; st.p = st.a.slice().sort(function (x, y) { return (w[x.sev] - w[y.sev]) || (x.cat === "availability" ? -1 : 1); }).slice(0, 8); return "top: " + (st.p[0] ? st.p[0].title : "none"); }],
      ["Assign each issue to the right agent", function () { st.as = st.p.map(function (a) { return { a: a, to: ownerFor(a) }; }); return st.as.length + " assignment(s)"; }],
      ["Check for SOC correlation (security incidents on the same devices)", function () { st.soc = []; st.p.forEach(function (a) { var d = byId(a.dev); socFor(d).forEach(function (s) { st.soc.push({ a: a, s: s }); }); }); return st.soc.length + " SOC incident(s) touch affected devices"; }],
      ["Review team activity", function () { st.perf = ORDER.map(function (k) { var rs = N.runs[k] || []; return { k: k, n: rs.length, last: rs[0] && rs[0].at }; }); return st.perf.filter(function (x) { return x.n; }).length + " of " + ORDER.length + " agents have run"; }],
      ["Write the executive summary", function () {
        var r = R("", "low"), crit = st.a.filter(function (a) { return a.sev === "critical"; }).length, hi = st.a.filter(function (a) { return a.sev === "high"; }).length, down = N.devices.filter(function (d) { return !d.up; }).length;
        r.head = (crit ? crit + " critical" : "No critical") + (hi ? ", " + hi + " high" : "") + " network issue(s); " + down + " device(s) down; " + N.devices.filter(function (d) { return ST(d).status === "healthy"; }).length + "/" + N.devices.length + " healthy.";
        r.sev = crit ? "critical" : hi ? "high" : st.a.length ? "medium" : "low";
        st.as.forEach(function (x) { F(r, x.a.sev, x.a.title + " → assign to " + AG[x.to].n + ". " + x.a.why, x.a.ev); r.recs.push({ p: x.a.sev === "critical" ? "P1" : x.a.sev === "high" ? "P1" : "P2", t: "Assign \"" + x.a.title + "\" to the " + AG[x.to].n + " (use the Assign task box in that agent's workspace)." }); });
        st.soc.forEach(function (x) { F(r, "medium", "SOC incident " + x.s.id + " (" + x.s.severity + ") also involves " + nm(x.a.dev) + ". Coordinate: a security cause could explain the network symptom, and vice versa.", ["soc=" + x.s.id]); r.handoff = r.handoff || { to: "SOC", dev: x.a.dev, text: "Shared device " + nm(x.a.dev) }; });
        r.table = { title: "Team activity", cols: ["Agent", "Runs in this browser", "Last run"], rows: st.perf.map(function (x) { return [AG[x.k].n, x.n, x.last ? ago(x.last) : "never"]; }) };
        if (!r.findings.length) F(r, "low", "No issues to prioritize in the telemetry in view.", []);
        r.limits.push("Assignments are recommendations; the manager does not start other agents by itself except in the full workflow run.", "Team performance counts only runs made in this browser."); H.r = r; return "summary ready"; }]
    ];
  }
};
function ownerFor(a) { return a.cat === "availability" ? "trouble" : a.cat === "latency" || a.cat === "loss" ? "trouble" : a.cat === "capacity" ? "perf" : a.cat === "resource" ? "infra" : a.cat === "config" ? "config" : a.cat === "traffic" ? "monitor" : "manager"; }
function socFor(d) { if (!d) return []; return (N.socInc || []).filter(function (s) { return s.host && (String(s.host).toLowerCase() === d.name.toLowerCase() || String(s.host).toLowerCase() === d.id); }); }

/* ===== agent run engine (every step is executed for real; progress = steps done / steps total) ===== */
var AS = {}; // per-agent run state
function ag(k) { return AS[k] = AS[k] || { status: "Idle", running: false, steps: [], done: 0, total: 0, log: [], res: null, queue: [], err: "", task: "" }; }
function note(k, text, sev) { var a = ag(k); a.log.unshift({ t: Date.now(), text: text, sev: sev }); a.log = a.log.slice(0, 80); N.feed.unshift({ t: Date.now(), agent: k, text: text }); N.feed = N.feed.slice(0, 120); }
async function runAgent(k, task, ctx, quiet) {
  if (N.real) return runAgentReal(k, task, ctx);
  var a = ag(k); if (a.running) { a.queue.push({ task: task, ctx: ctx }); note(k, "Task queued: " + (task || AG[k].def)); paintAgent(); return a.res; }
  var H = {}, defs = BUILD[k](task, ctx || {}, H), my = (a.tok = (a.tok || 0) + 1); a.running = true; a.err = ""; a.task = task || AG[k].def; a.steps = defs.map(function (d) { return { name: d[0], status: "waiting" }; }); a.done = 0; a.total = defs.length; a.status = "Running"; a.res = null; a.started = Date.now(); a.simnote = N.mode === "sample";
  note(k, "Started: " + a.task); paintAgent(); paintAgentsBar(); paintWf();
  try {
    for (var i = 0; i < defs.length; i++) {
      if (a.tok !== my) return null; a.steps[i].status = "running"; paintAgent(); await sleep(quiet ? 60 : 280);
      var t0 = performance.now(), out = defs[i][1](); a.steps[i].status = "done"; a.steps[i].ms = Math.round(performance.now() - t0); a.steps[i].detail = out; a.steps[i].t = Date.now(); a.done = i + 1; note(k, "Step " + (i + 1) + "/" + defs.length + ": " + defs[i][0] + " — " + out); paintAgent(); paintWf();
    }
    a.res = H.r || null;
  } catch (e) { a.status = "Failed"; a.running = false; a.err = String(e && e.message || e); a.steps.forEach(function (s) { if (s.status === "running") { s.status = "failed"; s.detail = a.err; } }); note(k, "FAILED: " + a.err, "high"); paintAgent(); paintAgentsBar(); paintWf(); throw e; }
  a.running = false; a.status = "Completed"; a.finished = Date.now();
  var rec = { at: Date.now(), task: a.task, head: a.res ? a.res.head : "", sev: a.res ? a.res.sev : "low", steps: a.total, ms: a.finished - a.started, mode: N.mode }; (N.runs[k] = N.runs[k] || []).unshift(rec); save();
  note(k, "Completed in " + (a.finished - a.started) + " ms: " + (a.res ? a.res.head : "")); aud("Agent run: " + AG[k].n + " — " + rec.head, "agent:" + k);
  paintAgent(); paintAgentsBar(); paintWf();
  var nx = a.queue.shift(); if (nx) setTimeout(function () { runAgent(k, nx.task, nx.ctx); }, 100);
  return a.res;
}
/* ===== workflow: Monitoring -> Detection -> Analysis -> Troubleshooting -> Resolution -> Reporting ===== */
var STEPS = {}; Object.keys(BUILD).forEach(function (k) { STEPS[k] = BUILD[k]({}, {}, {}).length; });
var WF = [{ k: "infra", s: "Detection" }, { k: "perf", s: "Analysis" }, { k: "trouble", s: "Troubleshooting" }, { k: "incident", s: "Resolution" }, { k: "config", s: "Automation" }, { k: "manager", s: "Reporting" }];
async function runWorkflow() {
  if (N.real) return runWorkflowReal();
  if (N.wf && N.wf.running) return; var w = N.wf = { running: true, stage: 0, st: WF.map(function () { return "Waiting"; }), t0: Date.now(), msgs: [], err: "" }; paintWf();
  for (var i = 0; i < WF.length; i++) {
    w.stage = i; w.st[i] = "Running"; ag(WF[i].k).done = 0; paintWf(); var prev = i ? WF[i - 1].k : null; if (prev) w.msgs.unshift({ t: Date.now(), from: prev, to: WF[i].k, text: (AS[prev] && AS[prev].res ? AS[prev].res.head : "") }); flyMsg(prev, WF[i].k);
    try { await runAgent(WF[i].k, "Workflow: " + WF[i].s, {}, true); w.st[i] = "Completed"; } catch (e) { w.st[i] = "Failed"; w.err = AG[WF[i].k].n + " failed: " + e.message; break; }
    paintWf();
  }
  w.running = false; w.t1 = Date.now(); aud("NOC workflow run " + (w.err ? "failed" : "completed"), "you"); paintWf(); paintAll();
}

/* ===== approvals (config changes are only ever PROPOSED) ===== */
function riskOf(type) { return type === "config_change" ? { level: "medium", why: "Changing a network device's configuration can interrupt traffic for everyone behind it.", ifYes: "An engineer must apply the change in a maintenance window (Spark does not push it).", ifNo: "The misconfiguration stays in place." } : { level: "medium", why: "Unclassified change.", ifYes: "An engineer must carry it out.", ifNo: "No change." }; }
async function propose(rec, fromAgent, evidence) {
  var d = byId(rec.target) || N.devices.filter(function (x) { return x.name === rec.target; })[0];
  var p = { id: "chg_" + Date.now().toString(36), status: "proposed", type: rec.type || "config_change", target: rec.target, device: d ? d.name : rec.target, user: "", description: "[NOC] " + rec.t, evidence: evidence || [], by: "agent:" + fromAgent, createdAt: Date.now(), risk: riskOf(rec.type || "config_change"), where: N.mode === "live" ? "backend" : "this browser (sample)" };
  if (N.mode === "live") { try { var res = await api("POST", "/actions", { type: "other", target: p.target, description: p.description, rationale: "Proposed by the " + AG[fromAgent].n + " from NOC telemetry. A human must approve and apply it." }); p.remoteId = res.id; } catch (e) { p.where = "this browser (backend refused: " + e.message + ")"; } }
  N.approvals.unshift(p); aud("Change proposed: " + p.description + " (" + p.target + ")", "agent:" + fromAgent); save(); paintApprovals(); return p;
}
async function decide(id, what) {
  var p = N.approvals.filter(function (x) { return x.id === id; })[0]; if (!p || p.status !== "proposed") return;
  if (p.remoteId) { try { await api("POST", "/actions/" + p.remoteId + "/" + what, {}); } catch (e) { alert("The backend refused the decision: " + e.message); return; } }
  p.status = what === "approve" ? "approved" : "rejected"; p.decidedBy = N.mode === "live" ? "you (signed-in token)" : "you (this browser, sample)"; p.decidedAt = Date.now(); aud("Change " + p.status + ": " + p.description, p.decidedBy); save(); paintApprovals();
}

/* ===== cross-team (NOC <-> SOC) ===== */
function esca(rec) { N.esc.unshift(Object.assign({ t: Date.now() }, rec)); aud("Escalation " + rec.from + " → " + rec.to + ": " + rec.text, "you"); save(); paintShared(); }
async function socToNoc(sid) {
  var s = N.socInc.filter(function (x) { return x.id === sid; })[0]; if (!s) return; var d = N.devices.filter(function (x) { return x.name.toLowerCase() === String(s.host).toLowerCase() || x.id === String(s.host).toLowerCase(); })[0];
  esca({ from: "SOC", to: "NOC", ref: sid, text: "SOC incident on " + s.host + " (" + s.severity + "): check network impact." });
  if (!d) { esca({ from: "NOC", to: "SOC", ref: sid, text: "Host " + s.host + " is not in the NOC telemetry, so its network impact cannot be assessed." }); return; }
  var res = await runAgent("trouble", "Network impact of SOC incident " + sid + " on " + d.name, { dev: d.id }); var st = ST(d), ne = neighbors(d.id).map(function (n) { return nm(n.id) + " " + (n.e.util != null ? r1(n.e.util) + "%" : "-"); }).join(", ");
  esca({ from: "NOC", to: "SOC", ref: sid, text: d.name + " is " + STL[st.status] + (st.reasons.length ? " (" + st.reasons.join("; ") + ")" : "") + "; links: " + (ne || "none") + (d.metrics.bwOutMbps != null ? "; outbound " + r1(d.metrics.bwOutMbps) + " Mbps" : "") + ". " + (res ? res.head : "") });
}
function nocToSoc(tid) {
  var t = N.incidents.filter(function (x) { return x.id === tid; })[0]; if (!t) return; var d = byId(t.dev), hits = socFor(d);
  esca({ from: "NOC", to: "SOC", ref: tid, text: t.title + ". " + (t.cat === "traffic" ? "Unusual traffic: please check for compromise or data exfiltration." : "Please evaluate security implications.") + (hits.length ? " SOC already tracks " + hits.map(function (h) { return h.id; }).join(", ") + " on this host." : " No SOC incident currently references this device.") });
  t.log.push({ t: Date.now(), who: "you", what: "Escalated to the SOC." }); t.esc.push({ t: Date.now(), to: "SOC", why: "manual escalation" }); save(); paintShared();
}

/* ===== rendering ===== */
function curView() { return document.body.getAttribute("data-view"); }
var SH = { router: "c", switch: "s", firewall: "fw", server: "r", hypervisor: "r", cloud: "cl", internet: "cl", endpoint: "e", accesspoint: "ap", storage: "r" };
function icon(type, col) {
  var s = 'stroke="' + col + '" stroke-width="2" fill="rgba(5,6,8,.92)"';
  if (type === "internet" || type === "cloud") return '<path d="M-22 8 a9 9 0 0 1 3-17 a12 12 0 0 1 22-3 a10 10 0 0 1 5 20 z" ' + s + "/>";
  if (type === "firewall") return '<path d="M-17 -15 h34 v22 l-17 10 l-17 -10 z" ' + s + '/><path d="M-9 -4 h18 M-9 3 h18" stroke="' + col + '" stroke-width="1.5"/>';
  if (type === "server" || type === "hypervisor" || type === "storage") return '<rect x="-17" y="-18" width="34" height="36" rx="5" ' + s + '/><path d="M-11 -8 h22 M-11 0 h22 M-11 8 h22" stroke="' + col + '" stroke-width="1.5"/>';
  if (type === "switch") return '<rect x="-24" y="-11" width="48" height="22" rx="5" ' + s + '/><path d="M-15 0 h30 M-10 -5 l-5 5 l5 5 M10 -5 l5 5 l-5 5" stroke="' + col + '" stroke-width="1.5" fill="none"/>';
  if (type === "router") return '<circle r="19" ' + s + '/><path d="M-10 0 h20 M0 -10 v20 M-6 -6 l-4 6 l4 6 M6 -6 l4 6 l-4 6" stroke="' + col + '" stroke-width="1.4" fill="none"/>';
  if (type === "accesspoint") return '<circle r="14" ' + s + '/><path d="M-9 -3 a13 13 0 0 1 18 0 M-5 2 a7 7 0 0 1 10 0" stroke="' + col + '" stroke-width="1.6" fill="none"/><circle cy="7" r="1.8" fill="' + col + '"/>';
  return '<rect x="-17" y="-13" width="34" height="22" rx="3" ' + s + '/><path d="M-8 14 h16 M0 9 v5" stroke="' + col + '" stroke-width="1.6"/>';
}
var PK = [], raf = 0, POS = {}, lastDev = "";
function paintTopo() {
  var svg = $("noc-topo"); if (!svg) return; POS = layout(); var ed = edges(), h = "";
  ed.forEach(function (e) { var a = POS[e.a], b = POS[e.b]; if (!a || !b) return; var c = COL[e.status]; h += '<line x1="' + a.x + '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y + '" stroke="' + c + '" stroke-opacity="' + (e.status === "offline" ? 0.35 : 0.4) + '" stroke-width="' + (e.status === "offline" ? 1.5 : 2.2) + '"' + (e.status === "offline" ? ' stroke-dasharray="5 6"' : "") + "/>"; if (e.util != null && e.status !== "offline" && e.status !== "healthy") h += '<text x="' + (a.x + b.x) / 2 + '" y="' + ((a.y + b.y) / 2 - 5) + '" class="el" fill="' + c + '">' + r1(e.util) + "%</text>"; });
  h += '<g id="noc-pk"></g>';
  N.devices.forEach(function (d) { var p = POS[d.id]; if (!p) return; var s = ST(d).status, c = COL[s]; h += '<g class="nn' + (N.sel === d.id ? " sel" : "") + '" data-id="' + esc(d.id) + '" transform="translate(' + p.x + "," + p.y + ')" tabindex="0" role="button" aria-label="' + esc(d.name + ", " + STL[s]) + '" style="--c:' + c + '"><circle r="30" fill="' + c + '" opacity=".10"/>' + icon(d.type, c) + '<text y="38" class="nl2">' + esc(d.name) + '</text><circle cx="20" cy="-18" r="5" fill="' + c + '" stroke="#050608" stroke-width="1.5"/></g>'; });
  svg.innerHTML = h; PK = []; ed.forEach(function (e) { if (e.status === "offline" || !POS[e.a] || !POS[e.b]) return; var n = e.util != null && e.util > 60 ? 3 : 2; for (var i = 0; i < n; i++) PK.push({ e: e, t: i / n, v: 0.0035 + (e.util || 30) / 100 * 0.004, rev: i % 2 === 1 }); });
  var g = $("noc-pk"); if (g) PK.forEach(function (p) { var c = document.createElementNS("http://www.w3.org/2000/svg", "circle"); c.setAttribute("r", 3.2); c.setAttribute("fill", COL[p.e.status]); c.setAttribute("class", "pk"); p.el = c; g.appendChild(c); });
  startAnim();
}
function startAnim() { if (raf || (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches)) { stepPk(0); return; } raf = requestAnimationFrame(loop); }
function stepPk(dtm) { PK.forEach(function (p) { var a = POS[p.e.a], b = POS[p.e.b]; if (!a || !b || !p.el) return; p.t = (p.t + p.v * dtm) % 1; var t = p.rev ? 1 - p.t : p.t; p.el.setAttribute("cx", a.x + (b.x - a.x) * t); p.el.setAttribute("cy", a.y + (b.y - a.y) * t); }); }
var lt = 0; function loop(ts) { raf = 0; if (curView() !== "noc" || !$("noc-topo")) return; var dtm = Math.min(50, ts - (lt || ts)) / 16; lt = ts; stepPk(dtm); raf = requestAnimationFrame(loop); }
function spark(vals, col, w, h) { vals = vals.filter(function (v) { return v != null; }); if (vals.length < 2) return '<span class="nmut">not enough history</span>'; var mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals), rg = mx - mn || 1, pts = vals.map(function (v, i) { return r1(i / (vals.length - 1) * w) + "," + r1(h - 3 - (v - mn) / rg * (h - 6)); }).join(" "); return '<svg class="spark" viewBox="0 0 ' + w + " " + h + '" width="' + w + '" height="' + h + '"><polyline points="' + pts + '" fill="none" stroke="' + col + '" stroke-width="1.8"/></svg>'; }
function series(key) { var n = 0, out = []; N.devices.forEach(function (d) { (d.history || []).forEach(function (s, i) { if (s[key] != null) { out[i] = out[i] || { s: 0, c: 0 }; out[i].s += s[key]; out[i].c++; } }); }); return out.map(function (o) { return o ? o.s / o.c : null; }); }
function paintMode() {
  var b = $("noc-mode"), bn = $("noc-banner"); if (!b) return; var live = N.mode === "live";
  if (N.real) { var L = realLabel(), ov = N.real; b.textContent = L[0]; b.className = "nbadge " + L[1]; $("noc-sub").textContent = "Real monitoring data stored by your backend · refreshed " + ago(N.live) + " (polls every 10 s)."; var msg2 = "", bad = ov.sources.filter(function (x) { return x.status !== "CONNECTED"; }); if (!ov.sources.length) msg2 = '<div class="nban demo"><b>Devices exist but no monitoring source is registered.</b> They came from the generic telemetry API.</div>'; else if (bad.length) msg2 = '<div class="nban bad"><b>' + bad.length + " monitoring source(s) not healthy:</b> " + bad.map(function (x) { return esc(x.name) + " is " + esc(x.status) + " — " + esc(x.detail); }).join(" · ") + ". Values below from these sources are HISTORICAL (last collection " + (ov.sources[0].lastSyncAt ? esc(iso(Date.parse(ov.sources[0].lastSyncAt))) : "never") + ").</div>"; else msg2 = '<div class="nban ok"><b>Live.</b> Every value comes from your monitoring source; fields it does not provide say <i>no data</i>.</div>'; if (N.err) msg2 += '<div class="nban bad">' + esc(N.err) + "</div>"; bn.innerHTML = msg2; return; }
  b.textContent = live ? "LIVE TELEMETRY" : "DEMO DATA · SIMULATED"; b.className = "nbadge " + (live ? "b-live" : "b-demo");
  $("noc-sub").textContent = live ? "Telemetry from your monitoring source" + (N.live ? " · updated " + ago(N.live) : "") + ". The dashboard polls the backend every 10 s." : "Every number, device and status here is generated by the page for demonstration. Nothing is being monitored.";
  var msg = "";
  if (!live) { msg = '<div class="nban demo"><b>You are looking at SIMULATED data.</b> No monitoring source is connected. The topology, metrics, incidents and agent results below are computed from made-up telemetry so you can explore the NOC. ' + (N.probe === "ok" || N.probe === "empty" ? "Your backend is reachable but has received no NOC telemetry: send devices to <code>POST /api/soc/noc/telemetry</code>." : N.probe === "auth" ? 'A backend exists but needs a sign-in. <form id="noc-tokform" class="nform"><input type="password" id="noc-tok" placeholder="API token" autocomplete="off"><button class="nmini" type="submit">Connect</button></form>' : "No backend is connected to this site. See the setup notes at the bottom of this page.") + "</div>"; }
  else msg = '<div class="nban ok"><b>Connected.</b> Showing telemetry received by your backend. Devices not reporting are shown as offline.</div>';
  if (N.err && live) msg += '<div class="nban bad">' + esc(N.err) + "</div>";
  bn.innerHTML = msg; var f = $("noc-tokform"); if (f) f.onsubmit = function (e) { e.preventDefault(); try { sessionStorage.setItem("socToken", $("noc-tok").value.trim()); } catch (x) {} boot(); };
}
function kpis() {
  if (N.real) return kpisReal();
  var D = N.devices, up = D.filter(function (d) { return d.up; }).length, lat = D.filter(function (d) { return d.up && d.metrics.latencyMs != null; }).map(function (d) { return d.metrics.latencyMs; }), loss = D.filter(function (d) { return d.up && d.metrics.lossPct != null; }).map(function (d) { return d.metrics.lossPct; });
  var avg = function (a) { return a.length ? a.reduce(function (x, y) { return x + y; }, 0) / a.length : null; }, ed = edges().filter(function (e) { return e.util != null; }), bw = avg(ed.map(function (e) { return e.util; }));
  var op = N.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) < 0; }).length, srv = D.filter(function (d) { return SRVT.indexOf(d.type) >= 0 && ST(d).status !== "healthy"; }).length, sc = 100; D.forEach(function (d) { var s = ST(d).status; sc -= s === "offline" ? 14 : s === "critical" ? 10 : s === "degraded" ? 5 : s === "warning" ? 2 : 0; }); sc = Math.max(0, Math.round(sc));
  return [["Network health", sc + "/100", sc >= 85 ? "healthy" : sc >= 70 ? "warning" : sc >= 50 ? "degraded" : "critical"], ["Availability", D.length ? r1(up / D.length * 100) + "%" : "-", up === D.length ? "healthy" : "degraded", up + " of " + D.length + " up"], ["Avg latency", avg(lat) != null ? r1(avg(lat)) + " ms" : "-", avg(lat) > TH.latencyMs[0] ? "warning" : "healthy"], ["Avg packet loss", avg(loss) != null ? r1(avg(loss)) + "%" : "-", avg(loss) > TH.lossPct[0] ? "warning" : "healthy"], ["Avg link utilization", bw != null ? r1(bw) + "%" : "-", bw >= TH.util[0] ? "warning" : "healthy"], ["Servers needing attention", String(srv), srv ? "degraded" : "healthy"], ["Open NOC incidents", String(op), op ? "warning" : "healthy"]];
}
function paintKpis() { $("noc-kpis").innerHTML = kpis().map(function (k) { return '<div class="nk" style="--c:' + COL[k[2]] + '"><span>' + esc(k[0]) + "</span><b>" + esc(k[1]) + "</b>" + (k[3] ? "<small>" + esc(k[3]) + "</small>" : "") + "</div>"; }).join(""); }
function paintCharts() {
  var L = series("latencyMs"), P = series("lossPct"), B = series("bwMbps");
  $("noc-charts").innerHTML = '<div class="nch"><h4>Latency (avg of devices)</h4>' + spark(L, "#5cc8ff", 260, 56) + "<small>" + (L.length ? "now " + r1(L[L.length - 1]) + " ms" : "") + '</small></div><div class="nch"><h4>Packet loss (avg)</h4>' + spark(P, "#ff9f43", 260, 56) + "<small>" + (P.length ? "now " + r1(P[P.length - 1]) + "%" : "") + '</small></div><div class="nch"><h4>Throughput (sum of devices)</h4>' + spark(series2("bwMbps"), "#4de2a1", 260, 56) + "<small>Mbps, from devices that report it</small></div>";
  var sv = N.devices.filter(function (d) { return SRVT.indexOf(d.type) >= 0 && d.up && d.metrics.cpu != null; });
  var bar = function (v, k) { if (v == null) return ""; var kk = v >= TH[k][2] ? 3 : v >= TH[k][1] ? 2 : v >= TH[k][0] ? 1 : 0, c = COL[RANK[kk]]; return '<div class="bar"><i style="width:' + Math.min(100, v) + "%;background:" + c + '"></i><span>' + r1(v) + "%</span></div>"; };
  $("noc-servers").innerHTML = sv.length ? '<table class="ntb"><tr><th>Server</th><th>CPU</th><th>Memory</th><th>Disk</th></tr>' + sv.map(function (d) { return "<tr><td>" + esc(d.name) + "</td><td>" + bar(d.metrics.cpu, "cpu") + "</td><td>" + bar(d.metrics.mem, "mem") + "</td><td>" + bar(d.metrics.disk, "disk") + "</td></tr>"; }).join("") + "</table>" : '<div class="nempty">No server telemetry.</div>';
  $("noc-avail").innerHTML = N.devices.map(function (d) { var s = ST(d).status; return '<span class="ndot" style="--c:' + COL[s] + '" title="' + esc(ST(d).reasons.join("; ") || STL[s]) + '"></span><span class="nav">' + esc(d.name) + " <small>" + STL[s] + "</small></span>"; }).join("");
  $("noc-lat").innerHTML = N.devices.filter(function (d) { return d.up && d.metrics.latencyMs != null; }).sort(function (a, b) { return b.metrics.latencyMs - a.metrics.latencyMs; }).slice(0, 6).map(function (d) { return '<div class="nrow"><span>' + esc(d.name) + "</span><b>" + d.metrics.latencyMs + " ms</b><span class=\"nmut\">loss " + (d.metrics.lossPct != null ? d.metrics.lossPct + "%" : "-") + "</span></div>"; }).join("");
}
function series2(key) { var out = []; N.devices.forEach(function (d) { (d.history || []).slice(-48).forEach(function (s, i) { if (s[key] != null) out[i] = (out[i] || 0) + s[key]; }); }); return out; }
function paintAgentsBar() {
  $("noc-agents").innerHTML = ORDER.map(function (k) { var a = ag(k), A = AG[k]; return '<button type="button" class="nag' + (N.agent === k ? " on" : "") + '" data-ag="' + k + '" style="--c:' + A.c + '"><svg viewBox="0 0 64 64" class="bot" aria-hidden="true"><rect x="14" y="16" width="36" height="30" rx="10" fill="rgba(5,6,8,.9)" stroke="' + A.c + '" stroke-width="2.4"/><circle cx="25" cy="30" r="4.2" fill="' + A.c + '"/><circle cx="39" cy="30" r="4.2" fill="' + A.c + '"/><path d="M26 39 h12" stroke="' + A.c + '" stroke-width="2.4" stroke-linecap="round"/><path d="M32 16 v-7" stroke="' + A.c + '" stroke-width="2.4"/><circle cx="32" cy="8" r="3" fill="' + A.c + '"/><path d="M20 49 h24 v6 h-24 z" fill="none" stroke="' + A.c + '" stroke-width="2"/></svg><b>' + esc(A.n) + '</b><span class="sts s-' + a.status.toLowerCase() + '">' + esc(a.status) + "</span></button>"; }).join("");
}
function paintWf() {
  if (N.real) return paintWfReal();
  var el = $("noc-wf"); if (!el) return; var w = N.wf, tot = 0, done = 0;
  WF.forEach(function (s, i) { tot += STEPS[s.k]; if (w && w.st[i] !== "Waiting" && AS[s.k]) done += Math.min(AS[s.k].done, STEPS[s.k]); });
  var pct = tot ? Math.round(done / tot * 100) : 0;
  var h = '<div class="nwf">' + WF.map(function (s, i) { var stt = w ? w.st[i] : "Waiting", a = AS[s.k], c = AG[s.k].c; return '<div class="nst" data-ag="' + s.k + '" style="--c:' + c + '"><small>' + esc(s.s) + '</small><b>' + esc(AG[s.k].n.replace(" Agent", "")) + '</b><span class="sts s-' + stt.toLowerCase() + '">' + stt + "</span><em>" + (a && a.total && stt !== "Waiting" ? a.done + "/" + a.total + " steps" : "") + "</em></div>" + (i < WF.length - 1 ? '<div class="nlnk" id="nlk' + i + '"><i></i></div>' : ""); }).join("") + "</div>";
  h += '<div class="nprog"><div class="nbar"><i style="width:' + (w ? pct : 0) + '%"></i></div><span>' + (w ? done + " of " + tot + " steps done \u00b7 " + pct + "% \u00b7 " + (w.running ? "Running" : w.err ? "Failed" : "Completed") : "Not run yet. Progress shown here is steps actually completed, never an estimate.") + "</span></div>";
  if (w && w.err) h += '<div class="nban bad">' + esc(w.err) + "</div>";
  if (w && w.msgs.length) h += '<div class="nmsgs">' + w.msgs.slice(0, 4).map(function (m) { return "<div><small>" + hms(m.t) + "</small> <b>" + esc(AG[m.from].n) + "</b> → <b>" + esc(AG[m.to].n) + "</b>: " + esc(String(m.text).slice(0, 150)) + "</div>"; }).join("") + "</div>";
  el.innerHTML = h; var go = $("noc-wfgo"); if (go) go.disabled = !!(w && w.running);
}
function flyMsg(from, to) { if (!from) return; var i = WF.map(function (s) { return s.k; }).indexOf(to) - 1, lk = $("nlk" + i); if (lk) { lk.classList.remove("fly"); void lk.offsetWidth; lk.classList.add("fly"); } }
function paintFeed() { $("noc-feed").innerHTML = N.feed.slice(0, 14).map(function (f) { return '<div><small>' + hms(f.t) + '</small> <b style="color:' + AG[f.agent].c + '">' + esc(AG[f.agent].n) + "</b> " + esc(f.text) + "</div>"; }).join("") || '<div class="nempty">No agent activity yet. Run the workflow or open an agent.</div>'; }
function paintIncidents() {
  if (N.real) return paintIncidentsReal();
  var SO = { critical: 0, high: 1, medium: 2, low: 3 }, op = N.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) < 0; }).sort(function (a, b) { return SO[a.severity] - SO[b.severity] || b.createdAt - a.createdAt; }), cl = N.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) >= 0; });
  $("noc-inc").innerHTML = op.length ? op.map(function (i) { return '<div class="nrow inc"><span>' + sevBadge(i.severity) + '</span><span class="t"><b>' + esc(i.id) + "</b> " + esc(i.title) + '<small>' + esc(i.status) + " · owner " + esc(AG[i.owner] ? AG[i.owner].n : i.owner) + " · opened " + ago(i.createdAt) + (i.esc.length ? " · escalated to " + esc(i.esc.map(function (e) { return e.to; }).join(", ")) : "") + "</small></span></div>"; }).join("") : '<div class="nempty">No open NOC incidents. Run the Incident Management Agent (or the workflow) to open tickets from detections.</div>';
  $("noc-hist").innerHTML = cl.length ? cl.slice(0, 8).map(function (i) { return '<div class="nrow"><span>' + esc(i.id) + '</span><span class="t">' + esc(i.title) + "<small>" + esc(i.status) + (i.resolvedAt ? " · " + dt(i.resolvedAt) : "") + "</small></span></div>"; }).join("") : '<div class="nempty">No resolved incidents yet.</div>';
}
function paintShared() {
  var rows = N.incidents.map(function (i) { return { team: "NOC", id: i.id, sev: i.severity, st: i.status, owner: AG[i.owner] ? AG[i.owner].n : i.owner, dev: nm(i.dev), t: i.title, e: i }; }).concat(N.socInc.slice(0, 12).map(function (s) { return { team: "SOC", id: s.id, sev: s.severity, st: s.displayStatus || s.status, owner: s.owner || "unassigned", dev: s.host, t: s.title, s: s }; }));
  var o = { critical: 0, high: 1, medium: 2, low: 3 }; rows.sort(function (a, b) { return (o[a.sev] - o[b.sev]) || (a.team < b.team ? 1 : -1); });
  $("noc-shared").innerHTML = '<div class="nban ' + (N.socMode === "live" ? "ok" : "demo") + '">SOC incidents shown here are ' + (N.socMode === "live" ? "read from your SOC backend." : "SAMPLE incidents from the SOC demo data (not real).") + " Escalation history below is stored in this browser.</div>" + (rows.length ? '<div class="ntbw"><table class="ntb"><tr><th>Team</th><th>ID</th><th>Severity</th><th>Status</th><th>Owner</th><th>Device</th><th>Issue</th><th></th></tr>' + rows.slice(0, 16).map(function (r) { var act = r.team === "SOC" ? '<button type="button" class="nmini" data-s2n="' + esc(r.id) + '">Ask NOC to check network impact</button>' : '<button type="button" class="nmini" data-n2s="' + esc(r.id) + '">Escalate to SOC</button>' + (r.e && r.e.socSuggested ? ' <span class="nbadge b-m">SOC suggested</span>' : ""); return '<tr><td><span class="nbadge ' + (r.team === "SOC" ? "b-soc" : "b-noc") + '">' + r.team + "</span></td><td>" + esc(r.id) + "</td><td>" + sevBadge(r.sev) + "</td><td>" + esc(r.st) + "</td><td>" + esc(r.owner) + "</td><td>" + esc(r.dev) + "</td><td>" + esc(r.t) + "</td><td>" + act + "</td></tr>"; }).join("") + "</table></div>" : '<div class="nempty">No incidents on either team.</div>') + "<h4>Escalation history</h4>" + (N.esc.length ? N.esc.slice(0, 10).map(function (e) { return '<div class="nrow"><small>' + dt(e.t) + '</small><span class="t"><b>' + esc(e.from) + " → " + esc(e.to) + "</b> (" + esc(e.ref) + ") " + esc(e.text) + "</span></div>"; }).join("") : '<div class="nempty">No cross-team escalations yet.</div>') + '<div class="nacts"><button type="button" class="nmini" id="noc-opensoc">Open the SOC Analyst workspace</button></div>';
}
function paintApprovals() {
  if (N.real) return paintApprovalsReal();
  var p = N.approvals.filter(function (x) { return x.status === "proposed"; }), h = N.approvals.filter(function (x) { return x.status !== "proposed"; });
  var card = function (a, done) { return '<div class="ncard"><div><span class="nbadge b-m">' + esc(a.risk.level.toUpperCase()) + " RISK</span> <b>" + esc(a.device) + "</b> <small>" + esc(a.id) + " · proposed by " + esc(a.by) + " (an AI agent cannot approve its own proposal) · " + dt(a.createdAt) + " · stored in " + esc(a.where) + "</small></div><p>" + esc(a.description.replace(/^\[NOC\] /, "")) + "</p><p class=\"nmut\"><b>Risk:</b> " + esc(a.risk.why) + "<br><b>If approved:</b> " + esc(a.risk.ifYes) + "<br><b>If not:</b> " + esc(a.risk.ifNo) + "</p>" + (a.evidence && a.evidence.length ? '<p class="nmut"><b>Evidence:</b> ' + a.evidence.map(esc).join("; ") + "</p>" : "") + (done ? '<p><b>' + esc(a.status.toUpperCase()) + "</b> by " + esc(a.decidedBy) + " at " + dt(a.decidedAt) + "</p>" : '<div><button type="button" class="nmini" data-dec="approve" data-id="' + esc(a.id) + '">Approve (record decision)</button> <button type="button" class="nmini" data-dec="reject" data-id="' + esc(a.id) + '">Reject</button></div>') + "</div>"; };
  $("noc-apv").innerHTML = '<div class="nban demo">Approving only records the decision. Spark does not connect to or change any network device; an engineer applies approved changes.</div><h4>Pending (' + p.length + ")</h4>" + (p.length ? p.map(function (a) { return card(a, false); }).join("") : '<div class="nempty">Nothing waiting. The Network Configuration Agent proposes changes when it finds problems.</div>') + "<h4>History (" + h.length + ")</h4>" + (h.length ? h.slice(0, 8).map(function (a) { return card(a, true); }).join("") : '<div class="nempty">No decisions yet.</div>');
  $("noc-audit").innerHTML = N.audit.slice(0, 8).map(function (a) { return "<div><small>" + dt(a.t) + "</small> <b>" + esc(a.who) + "</b> " + esc(a.what) + "</div>"; }).join("") || '<div class="nempty">No actions recorded yet.</div>';
}
function paintIntegrations() {
  if (N.real) { var ov = N.real, z = ov.sources.filter(function (x) { return x.type === "zabbix"; }), zs = z.some(function (x) { return x.status === "CONNECTED"; }) ? "connected" : z.length ? "not_connected" : "not_connected"; var rowsI = [["Zabbix (API pull or bridge push)", zs, z.length ? z.map(function (x) { return x.name + ": " + x.status; }).join("; ") : "No Zabbix source added yet."], ["Alert webhooks (Zabbix, Grafana, Alertmanager)", ov.events.some(function (e) { return e.origin !== "system"; }) ? "connected" : "not_connected", "POST /api/soc/noc/alerts with the ingest token. Connected once an alert has arrived."], ["SNMPv3, ICMP, Agent 2, HTTP checks, syslog", z.length ? "ready" : "not_connected", "Collected by Zabbix and read through it. Spark has no separate SNMP poller."], ["Prometheus / Grafana", "ready", "Alerts only, through the webhook. Metric scraping is not built."], ["AI agents", ov.counts.devices ? "ready" : "not_connected", "Rule-based analysis over stored data; AI text only when ANTHROPIC_API_KEY is set on the server."]], lb2 = { connected: "CONNECTED", not_connected: "NOT CONNECTED", ready: "VIA ZABBIX / RULES" }; $("noc-integ").innerHTML = rowsI.map(function (x) { return '<div class="nig"><span class="nbadge ' + (x[1] === "connected" ? "b-live" : x[1] === "ready" ? "b-m" : "b-off") + '">' + lb2[x[1]] + "</span><span><b>" + esc(x[0]) + '</b><br><span class="nmut">' + esc(x[2]) + "</span></span></div>"; }).join(""); return; }
  var live = N.mode === "live", names = [["Generic telemetry API (POST /api/soc/noc/telemetry)", live ? "connected" : "not_connected", live ? "Receiving telemetry from " + N.devices.length + " device(s)." : "No telemetry received yet."], ["SNMP polling", "not_built", "No SNMP poller is built. Send SNMP data through the telemetry API from your own poller."], ["Syslog", "not_built", "Network syslog is not collected. (Windows event logs are handled by the SOC collector.)"], ["Zabbix", "not_built", "Planned adapter. Not built."], ["PRTG", "not_built", "Planned adapter. Not built."], ["Nagios", "not_built", "Planned adapter. Not built."], ["Prometheus / Grafana", "not_built", "Planned adapter. Not built."], ["Cloud monitoring (CloudWatch, Azure Monitor, GCP)", "not_built", "Planned. No cloud API is called."], ["AI agents", "ready", "Agents use rule-based analysis over the telemetry in view. They never claim a live network when the data is simulated."]];
  var lb = { connected: "CONNECTED", not_connected: "NOT CONNECTED", not_built: "NOT BUILT YET", ready: "RULES ONLY" };
  $("noc-integ").innerHTML = names.map(function (x) { return '<div class="nig"><span class="nbadge ' + (x[1] === "connected" ? "b-live" : x[1] === "ready" ? "b-m" : "b-off") + '">' + lb[x[1]] + "</span><span><b>" + esc(x[0]) + '</b><br><span class="nmut">' + esc(x[2]) + "</span></span></div>"; }).join("");
}
function paintNode() {
  var d = byId(N.sel), el = $("noc-node"); if (!el) return; if (!d) { el.innerHTML = '<div class="nempty">Click any device in the topology to see its details.</div>'; return; }
  var s = ST(d), m = d.metrics, ns = neighbors(d.id), socs = socFor(d), an = detect().filter(function (a) { return a.dev === d.id; });
  var row = function (k, v) { return v == null ? "" : '<div class="nrow"><span class="nmut">' + k + "</span><b>" + esc(v) + "</b></div>"; };
  el.innerHTML = '<div class="nnh" style="--c:' + COL[s.status] + '"><span class="ndot" style="--c:' + COL[s.status] + '"></span><b>' + esc(d.name) + "</b> <span class=\"sts\" style=\"border-color:" + COL[s.status] + ";color:" + COL[s.status] + '">' + STL[s.status] + "</span></div><p class=\"nmut\">" + esc(d.type) + (d.ip ? " · " + esc(d.ip) : "") + " · " + (N.mode === "live" ? "reported " + ago(d.receivedAt) + " by " + esc(d.collector) : "SIMULATED") + "</p>"
    + (s.reasons.length ? '<div class="nban demo"><b>Why this status:</b> ' + s.reasons.map(esc).join("; ") + ".</div>" : "")
    + row("Latency", m.latencyMs != null ? m.latencyMs + " ms" : null) + row("Packet loss", m.lossPct != null ? m.lossPct + "%" : null) + row("CPU", m.cpu != null ? m.cpu + "%" : null) + row("Memory", m.mem != null ? m.mem + "%" : null) + row("Disk", m.disk != null ? m.disk + "%" : null) + row("Traffic in/out", m.bwInMbps != null ? r1(m.bwInMbps) + " / " + r1(m.bwOutMbps || 0) + " Mbps of " + (m.bwCapMbps || "?") : null) + row("Virtual machines", d.vms)
    + "<h5>Connections</h5>" + (ns.length ? ns.map(function (n) { return '<div class="nrow"><span>' + esc(nm(n.id)) + '</span><span class="nmut">' + (n.e.util != null ? r1(n.e.util) + "% used" : "-") + '</span><span class="ndot" style="--c:' + COL[n.e.status] + '"></span></div>'; }).join("") : '<div class="nempty">None</div>')
    + "<h5>Detections on this device</h5>" + (an.length ? an.map(function (a) { return "<div>" + sevBadge(a.sev) + " " + esc(a.title) + '<br><small class="nmut">Why: ' + esc(a.why) + "</small></div>"; }).join("") : '<div class="nempty">None</div>')
    + (socs.length ? "<h5>SOC</h5>" + socs.map(function (x) { return "<div>" + sevBadge(x.severity) + " " + esc(x.id) + ": " + esc(x.title) + "</div>"; }).join("") : "")
    + "<h5>Trend</h5>" + (m.latencyMs != null ? '<div class="nrow"><span class="nmut">latency</span>' + spark((d.history || []).map(function (x) { return x.latencyMs; }), "#5cc8ff", 160, 34) + "</div>" : "") + (m.cpu != null ? '<div class="nrow"><span class="nmut">CPU</span>' + spark((d.history || []).map(function (x) { return x.cpu; }), "#b48cff", 160, 34) + "</div>" : "") + (m.disk != null ? '<div class="nrow"><span class="nmut">disk</span>' + spark((d.history || []).map(function (x) { return x.disk; }), "#ff9f43", 160, 34) + "</div>" : "")
    + '<div class="nacts"><button type="button" class="nmini" data-inv="' + esc(d.id) + '">Investigate with Troubleshooting Agent</button></div>';
}
function paintAgent() {
  var k = N.agent, el = $("noc-ws"); if (!el) return; if (!k) { el.hidden = true; return; } el.hidden = false; var a = ag(k), A = AG[k], r = a.res;
  var h = '<div class="nwh" style="--c:' + A.c + '"><b>' + esc(A.n) + '</b> <span class="sts s-' + a.status.toLowerCase() + '">' + esc(a.status) + '</span><button type="button" class="nmini" id="noc-wsx">Close</button></div><p class="nmut">' + esc(A.d) + "</p>";
  h += '<div class="ngr"><div><h5>Responsibilities</h5><ul class="nul">' + A.resp.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul></div><div><h5>Assign a task</h5><div class=\"nform\"><input id=\"noc-task\" placeholder=\"" + esc(A.def) + "\" value=\"" + esc(N.taskTxt || "") + "\"><select id=\"noc-tdev\"><option value=\"\">Any device</option>" + N.devices.map(function (d) { return '<option value="' + esc(d.id) + '"' + (N.taskDev === d.id ? " selected" : "") + ">" + esc(d.name) + "</option>"; }).join("") + '</select></div><div class="nacts"><button type="button" class="nbtn" id="noc-run"' + (a.running ? " disabled" : "") + ">Assign and run</button> <button type=\"button\" class=\"nmini\" id=\"noc-start\">Start investigation</button></div>" + (a.queue.length ? "<p class=\"nmut\">Queued tasks: " + a.queue.length + "</p>" : "") + '</div></div>';
  h += N.real ? '<div class="nban ok">This agent runs <b>on the backend</b> over data stored in the database. Each step below was timed by the server. An agent counts as operational only after a run has completed and been stored.</div>' : '<div class="nban demo">' + (N.mode === "live" ? "Analysis runs in your browser over the live telemetry above." : "SIMULATED telemetry.") + " Every step below is really computed; progress is steps completed out of steps total. A short pause between steps lets you watch. This is rule-based analysis, not an AI verdict.</div>";
  if (a.total) h += '<div class="nprog"><div class="nbar"><i style="width:' + Math.round(a.done / a.total * 100) + '%"></i></div><span>' + a.done + " of " + a.total + " steps · " + Math.round(a.done / a.total * 100) + "% · " + esc(a.status) + "</span></div><ol class=\"nsteps\">" + a.steps.map(function (s) { return '<li class="' + s.status + '"><b>' + esc(s.name) + "</b>" + (s.detail ? "<small>" + esc(s.detail) + (s.ms != null ? " · " + s.ms + " ms" : "") + "</small>" : "") + "</li>"; }).join("") + "</ol>";
  if (a.err) h += '<div class="nban bad">' + esc(a.err) + ' <button type="button" class="nmini" id="noc-retry">Retry</button></div>';
  if (r) {
    h += '<h5>Result</h5><p>' + sevBadge(r.sev) + " <b>" + esc(r.head) + "</b></p>" + r.findings.map(function (f) { return '<div class="nfd">' + sevBadge(f.sev) + " " + esc(f.t) + (f.ev && f.ev.length ? '<br><small class="nmut">Evidence: ' + f.ev.map(esc).join("; ") + "</small>" : "") + "</div>"; }).join("");
    if (r.table) h += "<h5>" + esc(r.table.title) + '</h5><div class="ntbw"><table class="ntb"><tr>' + r.table.cols.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") + "</tr>" + r.table.rows.map(function (x) { return "<tr>" + x.map(function (c) { return "<td>" + esc(c) + "</td>"; }).join("") + "</tr>"; }).join("") + "</table></div>";
    if (r.recs.length) h += "<h5>Recommendations <span class=\"nmut\">(none executed)</span></h5>" + r.recs.map(function (x, i) { var pr = N.approvals.filter(function (p) { return p.description === "[NOC] " + x.t; })[0]; return '<div class="nfd"><span class="nbadge b-l">' + esc(x.p) + "</span> " + esc(x.t) + (x.approval ? (pr ? ' <span class="nbadge b-live">' + esc(pr.status.toUpperCase()) + " (see Approvals)</span>" : ' <button type="button" class="nmini" data-prop="' + i + '">Request approval</button>') : "") + "</div>"; }).join("");
    if (r.handoff) h += '<div class="nban demo"><b>Hand-off to ' + esc(r.handoff.to) + ':</b> ' + esc(r.handoff.text) + ' <button type="button" class="nmini" id="noc-ho">Send to SOC</button></div>';
    if (r.limits.length) h += "<h5>Limits</h5><ul class=\"nul\">" + r.limits.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>";
  }
  h += "<h5>Live activity</h5><div class=\"nlog\">" + (a.log.map(function (l) { return "<div><small>" + hms(l.t) + "</small> " + esc(l.text) + "</div>"; }).join("") || '<div class="nempty">No activity yet.</div>') + "</div>";
  if (N.real) { var rh = N.real.activities.filter(function (x) { return x.agent === RR[k]; }); h += "<h5>Execution history <span class=\"nmut\">(database)</span></h5>" + (rh.length ? rh.slice(0, 8).map(function (x) { return '<div class="nrow"><small>' + dt(Date.parse(x.startedAt)) + '</small><span class="t">' + esc(x.task) + "<small>" + esc(x.result ? x.result.head : x.error || x.status) + " · " + x.steps.length + " steps · " + esc(x.status) + " · by " + esc(x.actor) + "</small></span></div>"; }).join("") : '<div class="nempty">This agent has not run yet, so it is not shown as operational.</div>'); } else { var hist = N.runs[k] || []; h += "<h5>Execution history <span class=\"nmut\">(this browser)</span></h5>" + (hist.length ? hist.slice(0, 8).map(function (x) { return '<div class="nrow"><small>' + dt(x.at) + "</small><span class=\"t\">" + esc(x.task) + "<small>" + esc(x.head) + " · " + x.steps + " steps in " + x.ms + " ms · " + (x.mode === "live" ? "live data" : "simulated") + "</small></span></div>"; }).join("") : '<div class="nempty">No runs yet.</div>'); }
  h += '<h5>Ask this agent (AI)</h5><div class="nform"><input id="noc-q" placeholder="e.g. What is the most likely cause of the DNS slowness?"><button type="button" class="nmini" id="noc-ask">Ask</button></div><div id="noc-ans" class="nmut"></div>';
  var keep = document.activeElement && document.activeElement.id; el.innerHTML = h; if (keep && $(keep) && (keep === "noc-task" || keep === "noc-q")) { var f = $(keep); f.focus(); }
  ag(k).dirtyTask = false;
}
function paintAll() { paintConn(); if (N.real) { paintEventsReal(); paintIfacesReal(); } paintMode(); paintKpis(); paintTopo(); paintCharts(); paintAgentsBar(); paintWf(); paintFeed(); paintIncidents(); paintShared(); paintApprovals(); paintIntegrations(); paintNode(); if (N.agent && !ag(N.agent).running) paintAgent(); }

/* ===== AI (optional; only labelled hypotheses over the telemetry in view) ===== */
async function askAI(k, q) {
  var out = $("noc-ans"); out.textContent = "Thinking…"; var snap = N.devices.map(function (d) { return { name: d.name, type: d.type, up: d.up, status: ST(d).status, why: ST(d).reasons, metrics: d.metrics }; });
  var sys = "You are the " + AG[k].n + " in a NOC. Answer ONLY from the telemetry JSON below. Cite device names. Label conclusions as hypotheses. If the telemetry does not show it, say so. Be brief. " + (N.mode === "sample" ? "The telemetry is SIMULATED; say so." : "");
  try { var tx; if (typeof claude !== "undefined" && claude && claude.use) { var s = await claude.use("sample"); tx = (await s(sys + "\n\nTELEMETRY:\n" + JSON.stringify(snap).slice(0, 18000) + "\n\nQUESTION: " + q, { modelTier: "complex", cache: false })).text; } else { var res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "analyst", text: sys + "\n\nTELEMETRY:\n" + JSON.stringify(snap).slice(0, 18000) + "\n\nQUESTION: " + q, context: "sample" }) }); tx = await res.text(); if (!res.ok) throw new Error("The AI service is not available on this site yet."); } out.innerHTML = '<div class="nban demo"><b>AI answer (hypothesis, based on the telemetry shown):</b><br>' + esc(tx).replace(/\n/g, "<br>") + "</div>"; }
  catch (e) { out.textContent = "AI is not available here: " + (e.message || e); }
}

/* ===== REAL monitoring mode (data comes from the backend database; nothing here is generated) ===== */
function setReal(ov) {
  N.real = ov; N.mode = "live"; N.live = Date.now();
  N.incidents = ov.incidents.map(function (i) { return { id: i.id, title: i.title, severity: i.severity, status: i.status, owner: RK[i.assignedAgent], dev: i.deviceId || i.host, cat: i.category, createdAt: Date.parse(i.createdAt), resolvedAt: i.resolvedAt ? Date.parse(i.resolvedAt) : undefined, esc: [] }; });
  N.devices = ov.devices.map(function (d) { return { id: d.id, name: d.name, type: d.type, ip: d.ip || "", up: d.stale ? false : d.up !== false, stale: !!d.stale, known: d.known !== false, metrics: d.metrics || {}, links: d.links || [], config: d.config, unsupported: d.unsupported || [], uptimeSec: d.uptimeSec, groups: d.groups || [], history: (d.history || []).map(function (s) { return Object.assign({}, s, { t: Date.parse(s.t) }); }), receivedAt: Date.parse(d.receivedAt), collector: d.collector }; });
  Object.keys(ov.agents).forEach(function (k) { var key = RK[k], a = ag(key); if (!a.running) { a.status = ov.agents[k].operational ? "Completed" : "Idle"; a.finished = ov.agents[k].lastRun ? Date.parse(ov.agents[k].lastRun) : a.finished; } });
  if (!N.rsel && ov.incidents.length) N.rsel = ov.incidents[0].id;
}
var RK = { supervisor: "manager", engineer: "trouble", server: "infra", performance: "perf", responder: "incident", automation: "config" }, RR = {}; Object.keys(RK).forEach(function (k) { RR[RK[k]] = k; });
var SSB = { CONNECTED: "b-live", DISCONNECTED: "b-off", CONNECTING: "b-m", "AUTHENTICATION FAILED": "b-h", "NO DATA": "b-demo", ERROR: "b-h" };
function iso(t) { return t ? new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "never"; }
function isAdminHint() { return true; }
function paintConn() {
  var el = $("noc-conn"); if (!el) return; var ov = N.real, src = ov ? ov.sources : [];
  var h = '<div class="nban ' + (src.length ? "ok" : "demo") + '">' + (src.length ? "Status is computed by the backend from real test and sync results. A source that stops sending data turns DISCONNECTED automatically." : "<b>No monitoring source is configured.</b> Nothing on this page is live until you add one and it reports CONNECTED. Credentials are sent to the backend once, stored encrypted there, and never shown again.") + "</div>";
  if (src.length) h += '<div class="ntbw"><table class="ntb"><tr><th>Source</th><th>Status</th><th>Type / mode</th><th>Server address</th><th>Last successful sync</th><th>Devices</th><th>Interfaces</th><th>Last event</th><th>API health</th><th></th></tr>' + src.map(function (s) { return '<tr><td><b>' + esc(s.name) + '</b></td><td><span class="nbadge ' + (SSB[s.status] || "b-l") + '">' + esc(s.status) + '</span></td><td>' + esc(s.type) + " · " + esc(s.mode) + (s.version ? " · v" + esc(s.version) : "") + '</td><td>' + esc(s.url) + '</td><td>' + esc(s.lastSyncAt ? iso(Date.parse(s.lastSyncAt)) + " (" + ago(Date.parse(s.lastSyncAt)) + ")" : "never") + '</td><td>' + s.deviceCount + '</td><td>' + s.interfaceCount + '</td><td>' + esc(s.lastEventAt ? iso(Date.parse(s.lastEventAt)) : "none received") + '</td><td class="nmut">' + esc(s.detail) + (s.lastTestAt ? " (tested " + ago(Date.parse(s.lastTestAt)) + ")" : "") + '</td><td>' + (s.mode === "pull" ? '<button type="button" class="nmini" data-rsrc="test" data-id="' + esc(s.id) + '">Test</button> <button type="button" class="nmini" data-rsrc="sync" data-id="' + esc(s.id) + '">Sync now</button> ' : "") + '<button type="button" class="nmini" data-rsrc="del" data-id="' + esc(s.id) + '">Remove</button></td></tr>'; }).join("") + "</table></div>";
  h += '<details class="nguide"' + (src.length ? "" : " open") + '><summary>Add a monitoring source (administrator)</summary><form id="noc-srcform" class="nform" style="flex-wrap:wrap"><input name="name" placeholder="Name, e.g. Zabbix main" required><select name="type"><option value="zabbix">Zabbix</option></select><select name="mode"><option value="pull">pull: backend calls Zabbix directly</option><option value="push">push: bridge inside my network</option></select><input name="url" placeholder="http://zabbix.example.lan (pull only)"><input name="token" type="password" autocomplete="off" placeholder="Zabbix API token"><button class="nmini" type="submit">Add source</button></form><p class="nmut">Needs an administrator token and <code>NOC_SECRET_KEY</code> on the backend. A private-network Zabbix cannot be reached from the internet: use <b>push</b> with the bridge in <code>collector/zabbix</code>. SNMP, Prometheus, Grafana, syslog and HTTP checks reach Spark through Zabbix items or by posting alerts to <code>/api/soc/noc/alerts</code>.</p><div id="noc-srcmsg" class="nmut"></div></details>';
  if (ov) h += '<details class="nguide"><summary>Automation actions agents may propose (' + ov.actions.length + ")</summary>" + (ov.actions.length ? ov.actions.map(function (a) { return '<div class="nrow"><span class="nbadge b-m">' + esc(a.risk.toUpperCase()) + '</span><span class="t"><b>' + esc(a.name) + "</b> " + esc(a.kind) + "<small>" + esc(a.description) + "</small></span></div>"; }).join("") : '<div class="nempty">None registered. Agents cannot run anything until an administrator registers an action (<code>POST /api/soc/noc/actions</code>).</div>') + "</details>";
  el.innerHTML = h;
}
function realLabel() { var ov = N.real; if (!ov) return ["DEMO DATA", "b-demo"]; if (!ov.devices.length) return ["NO DATA", "b-demo"]; var st = ov.sources.filter(function (s) { return s.status === "CONNECTED"; }).length; return st ? [ov.devices.some(function (d) { return d.stale; }) ? "LIVE · SOME STALE" : "LIVE", "b-live"] : ["HISTORICAL · SOURCE DISCONNECTED", "b-off"]; }
function kpisReal() {
  var c = N.real.counts, n = function (v, u) { return v == null ? "no data" : r1(v) + (u || ""); };
  return [["Total devices", String(c.devices), "healthy"], ["Connected", String(c.connected), c.connected === c.devices ? "healthy" : "warning"], ["Disconnected", String(c.disconnected), c.disconnected ? "critical" : "healthy"], ["Critical alerts", String(c.critical), c.critical ? "critical" : "healthy"], ["Warning alerts", String(c.warning), c.warning ? "warning" : "healthy"], ["Active incidents", String(c.activeIncidents), c.activeIncidents ? "warning" : "healthy"], ["Availability", n(c.availabilityPct, "%"), c.availabilityPct == null ? "warning" : c.availabilityPct >= 99 ? "healthy" : "degraded"], ["Avg CPU", n(c.avgCpu, "%"), "healthy"], ["Avg memory", n(c.avgMem, "%"), "healthy"], ["Traffic in / out", c.bwInMbps == null ? "no data" : r1(c.bwInMbps) + " / " + r1(c.bwOutMbps) + " Mbps", "healthy"], ["Healthy / warn / crit", c.healthy + " / " + c.warn + " / " + c.crit, c.crit ? "critical" : c.warn ? "warning" : "healthy"], ["Approvals waiting", String(c.pendingApprovals), c.pendingApprovals ? "warning" : "healthy"]];
}
function paintIncidentsReal() {
  var ov = N.real, op = ov.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) < 0; }), cl = ov.incidents.filter(function (i) { return ["Resolved", "Closed"].indexOf(i.status) >= 0; });
  var rowI = function (i) { return '<div class="nrow inc" data-rinc="' + esc(i.id) + '" style="cursor:pointer"><span>' + sevBadge(i.severity) + '</span><span class="t"><b>' + esc(i.id) + "</b> " + esc(i.title) + "<small>" + esc(i.status) + " · " + esc(i.host) + " · " + esc(AG[RK[i.assignedAgent]].n) + " · opened " + ago(Date.parse(i.createdAt)) + (i.verification ? " · verification: " + esc(i.verification.status) : "") + "</small></span></div>"; };
  $("noc-inc").innerHTML = op.length ? op.map(rowI).join("") : '<div class="nempty">No open incidents. Incidents are created only from real alerts.</div>';
  $("noc-hist").innerHTML = cl.length ? cl.slice(0, 10).map(rowI).join("") : '<div class="nempty">No resolved incidents yet.</div>';
}
function paintApprovalsReal() {
  var ov = N.real, p = ov.approvals.filter(function (x) { return x.status === "proposed"; }), h = ov.approvals.filter(function (x) { return x.status !== "proposed"; });
  var exOf = function (a) { return ov.executions.filter(function (e) { return e.id === a.executionId; })[0]; };
  var card = function (a, done) { var ex = exOf(a); return '<div class="ncard"><div><span class="nbadge b-m">' + esc(a.risk.level.toUpperCase()) + " RISK</span> <b>" + esc(a.target) + "</b> <small>" + esc(a.id) + " · proposed by " + esc(a.proposedBy) + " (an AI agent cannot approve) · " + iso(Date.parse(a.createdAt)) + "</small></div><p>" + esc(a.description) + '</p><p class="nmut"><b>Risk:</b> ' + esc(a.risk.why) + "<br><b>If approved:</b> " + esc(a.risk.ifApproved) + "<br><b>If not:</b> " + esc(a.risk.ifIgnored) + "</p>" + (a.evidence.length ? '<p class="nmut"><b>Evidence:</b> ' + a.evidence.map(esc).join("; ") + "</p>" : "") + (done ? "<p><b>" + esc(a.status.toUpperCase()) + "</b> by " + esc(a.decidedBy) + " at " + iso(Date.parse(a.decidedAt)) + (ex ? "<br><b>Execution " + esc(ex.status.toUpperCase()) + "</b> (" + esc(ex.mode) + ")" + (ex.error ? " — " + esc(ex.error) : "") + (ex.verification ? "<br>Verification: <b>" + esc(ex.verification.status) + "</b> — " + esc(ex.verification.detail) : "") : "") + "</p>" : '<div><button type="button" class="nmini" data-rdec="approve" data-id="' + esc(a.id) + '">Approve and execute</button> <button type="button" class="nmini" data-rdec="reject" data-id="' + esc(a.id) + '">Reject</button></div>') + "</div>"; };
  $("noc-apv").innerHTML = '<div class="nban demo">Approving makes the <b>backend</b> run the registered action once, then re-read fresh monitoring data. A result is shown as succeeded only if the executor confirmed it, and as resolved only if fresh data shows the problem cleared.</div><h4>Pending (' + p.length + ")</h4>" + (p.length ? p.map(function (a) { return card(a, false); }).join("") : '<div class="nempty">Nothing waiting.</div>') + "<h4>History (" + h.length + ")</h4>" + (h.length ? h.slice(0, 10).map(function (a) { return card(a, true); }).join("") : '<div class="nempty">No decisions yet.</div>');
  $("noc-audit").innerHTML = (N.raudit || []).slice(0, 10).map(function (a) { return "<div><small>" + iso(Date.parse(a.time)) + "</small> <b>" + esc(a.actor) + "</b> " + esc(a.action) + " " + esc(a.target || "") + "</div>"; }).join("") || '<div class="nempty">No audit entries visible to your role.</div>';
}
function paintWfReal() {
  var el = $("noc-wf"), ov = N.real, wf = ov.workflows.filter(function (w) { return w.incidentId === N.rsel; })[0], inc = ov.incidents.filter(function (i) { return i.id === N.rsel; })[0], h = "";
  if (!inc || !wf) { el.innerHTML = '<div class="nempty">No incident selected. When a real alert arrives, its 14-step workflow appears here with the real time each step took.</div>'; var g0 = $("noc-wfgo"); if (g0) g0.disabled = false; return; }
  var done = wf.steps.filter(function (s) { return s.status === "done" || s.status === "skipped"; }).length;
  h += '<p><b>' + esc(inc.id) + "</b> " + esc(inc.title) + " " + sevBadge(inc.severity) + ' <span class="nmut">' + esc(inc.status) + " · agent: " + esc(AG[RK[inc.assignedAgent]].n) + '</span></p><div class="nprog"><div class="nbar"><i style="width:' + Math.round(done / 14 * 100) + '%"></i></div><span>' + done + " of 14 steps complete · workflow " + esc(wf.status) + "</span></div><ol class=\"nsteps\">" + wf.steps.map(function (s) { return '<li class="' + (s.status === "waiting" ? "waiting" : s.status === "skipped" ? "done" : s.status) + '"><b>' + s.n + ". " + esc(s.name) + "</b> <span class=\"nmut\">[" + esc(s.status) + "]</span>" + (s.detail || s.error ? "<small>" + esc(s.error || s.detail) + (s.ms != null ? " · " + s.ms + " ms" : "") + "</small>" : "") + "</li>"; }).join("") + "</ol>";
  if (inc.analysis) h += "<h5>Analysis <span class=\"nmut\">(" + esc(inc.analysis.method === "ai+rules" ? "AI + rules, hypotheses" : "rule-based; AI not used") + ")</span></h5><p>" + esc(inc.analysis.summary) + "</p>" + (inc.analysis.aiText ? '<p class="nmut">AI: ' + esc(inc.analysis.aiText) + "</p>" : "") + (inc.analysis.evidence.length ? '<p class="nmut">Evidence: ' + inc.analysis.evidence.map(esc).join(" | ") + "</p>" : "");
  if (inc.rootCause) h += "<h5>Probable root cause <span class=\"nbadge b-m\">HYPOTHESIS · " + esc(inc.rootCause.confidence) + " confidence</span></h5><p>" + esc(inc.rootCause.text) + "</p>";
  if (inc.recommendations.length) h += "<h5>Recommendations <span class=\"nmut\">(none executed)</span></h5>" + inc.recommendations.map(function (r) { return '<div class="nfd"><span class="nbadge b-l">' + esc(r.p) + "</span> " + esc(r.text) + "</div>"; }).join("");
  if (inc.verification) h += '<div class="nban ' + (inc.verification.status === "resolved" ? "ok" : "demo") + '"><b>Verification: ' + esc(inc.verification.status) + "</b> — " + esc(inc.verification.detail) + (inc.status === "Verifying" ? ' <button type="button" class="nmini" data-rverify="' + esc(inc.id) + '">Fetch fresh data now</button>' : "") + "</div>";
  el.innerHTML = h; var g = $("noc-wfgo"); if (g) g.disabled = !!(N.wf && N.wf.running);
}
function paintEventsReal() { var el = $("noc-rev"); if (!el) return; var ov = N.real; el.innerHTML = ov.events.length ? '<div class="ntbw"><table class="ntb"><tr><th>Received</th><th>Host</th><th>Severity</th><th>Event</th><th>State</th><th>Origin</th></tr>' + ov.events.slice(0, 20).map(function (e) { return "<tr><td>" + iso(Date.parse(e.receivedAt)) + "</td><td>" + esc(e.host) + "</td><td>" + sevBadge(e.severity) + "</td><td>" + esc(e.title) + "</td><td>" + esc(e.status) + "</td><td>" + esc(e.origin) + "</td></tr>"; }).join("") + "</table></div>" : '<div class="nempty">No events received from any source.</div>'; }
function paintIfacesReal() { var el = $("noc-rif"); if (!el) return; var ov = N.real, nmOf = {}; ov.devices.forEach(function (d) { nmOf[d.id] = d.name; }); el.innerHTML = ov.interfaces.length ? '<div class="ntbw"><table class="ntb"><tr><th>Device</th><th>Interface</th><th>State</th><th>In</th><th>Out</th><th>Util</th><th>Errors</th><th>Drops</th></tr>' + ov.interfaces.slice(0, 60).map(function (i) { var bps = function (v) { return v == null ? "no data" : r1(v / 1e6) + " Mbps"; }, nd = function (a, b) { return a == null && b == null ? "no data" : (a || 0) + (b || 0); }; return "<tr><td>" + esc(nmOf[i.deviceId] || i.deviceId) + "</td><td>" + esc(i.name) + "</td><td>" + (i.up == null ? "no data" : i.up ? "up" : "DOWN") + "</td><td>" + bps(i.inBps) + "</td><td>" + bps(i.outBps) + "</td><td>" + (i.utilPct == null ? "no data" : i.utilPct + "%") + "</td><td>" + nd(i.errorsIn, i.errorsOut) + "</td><td>" + nd(i.dropsIn, i.dropsOut) + "</td></tr>"; }).join("") + "</table></div>" : '<div class="nempty">No interface data. Interfaces appear when Zabbix collects net.if.* items (SNMP) for a device.</div>'; }
async function loadRealAudit() { try { N.raudit = (await api("GET", "/audit?limit=60")).filter(function (a) { return /^noc\./.test(a.action); }); } catch (e) { N.raudit = []; } }
async function runAgentReal(k, task, ctx) {
  var a = ag(k); if (a.running) return a.res; a.running = true; a.err = ""; a.task = task || AG[k].def; a.status = "Running"; a.steps = [{ name: "Waiting for the backend to run this agent over stored data", status: "running" }]; a.done = 0; a.total = 1; a.res = null; a.started = Date.now(); note(k, "Requested server-side run: " + a.task); paintAgent(); paintAgentsBar();
  try {
    var r = await api("POST", "/noc/agents/" + RR[k] + "/run", { task: a.task, incidentId: ctx && ctx.incident });
    var act = r.activity; a.steps = act.steps.map(function (s) { return { name: s.name, status: s.status, ms: s.ms, detail: s.detail || s.error }; }); a.done = a.total = a.steps.length; a.status = act.status === "completed" ? "Completed" : "Failed"; a.err = act.error || ""; a.finished = Date.now();
    a.res = act.result ? { head: act.result.head, sev: act.result.sev, findings: act.result.findings, table: act.result.table || null, recs: act.result.recs.map(function (x) { return { p: x.p, t: x.t }; }), limits: act.result.limits || [], handoff: null } : null;
    note(k, (act.status === "completed" ? "Completed: " : "FAILED: ") + (a.res ? a.res.head : a.err), act.status === "completed" ? undefined : "high");
    setReal(await api("GET", "/noc/overview"));
  } catch (e) { a.status = "Failed"; a.err = e.message; a.steps = [{ name: "Backend run", status: "failed", detail: e.message }]; note(k, "FAILED: " + e.message, "high"); }
  a.running = false; paintAll(); return a.res;
}
async function runWorkflowReal() { if (N.wf && N.wf.running) return; var w = N.wf = { running: true, stage: 0, st: WF.map(function () { return "Waiting"; }), t0: Date.now(), msgs: [], err: "" }; paintWf(); for (var i = 0; i < WF.length; i++) { w.stage = i; w.st[i] = "Running"; paintWf(); await runAgentReal(WF[i].k, "Workflow: " + WF[i].s, {}); w.st[i] = ag(WF[i].k).status === "Completed" ? "Completed" : "Failed"; if (w.st[i] === "Failed") { w.err = AG[WF[i].k].n + " failed: " + ag(WF[i].k).err; break; } } w.running = false; paintWf(); }
async function realAct(path, method, body, msgEl) { try { var r = await api(method, path, body); setReal(await api("GET", "/noc/overview")); await loadRealAudit(); paintAll(); return r; } catch (e) { if (msgEl && $(msgEl)) $(msgEl).textContent = e.message; else N.err = e.message; paintAll(); return null; } }

/* ===== events ===== */
function openAgent(k) { N.agent = k; paintAgentsBar(); paintAgent(); var w = $("noc-ws"); if (w && w.scrollIntoView) w.scrollIntoView({ behavior: "smooth", block: "nearest" }); }
document.addEventListener("click", function (ev) {
  var t = ev.target; if (!t.closest || !t.closest("#noc")) return; var c;
  if ((c = t.closest("[data-ag]"))) { openAgent(c.dataset.ag); return; }
  if ((c = t.closest(".nn"))) { N.sel = c.dataset.id; paintTopo(); paintNode(); return; }
  if ((c = t.closest("[data-rsrc]"))) { var op = c.dataset.rsrc, sid = c.dataset.id; if (op === "del" && !confirm("Remove this monitoring source? Stored devices and history stay.")) return; c.disabled = true; realAct("/noc/sources/" + sid + (op === "del" ? "" : "/" + op), op === "del" ? "DELETE" : "POST", op === "del" ? undefined : {}, "noc-srcmsg"); return; }
  if ((c = t.closest("[data-rdec]"))) { c.disabled = true; realAct("/noc/approvals/" + c.dataset.id + "/" + c.dataset.rdec, "POST", {}); return; }
  if ((c = t.closest("[data-rinc]"))) { N.rsel = c.dataset.rinc; paintWf(); var w2 = $("noc-wf"); if (w2 && w2.scrollIntoView) w2.scrollIntoView({ behavior: "smooth", block: "nearest" }); return; }
  if ((c = t.closest("[data-rverify]"))) { c.disabled = true; realAct("/noc/incidents/" + c.dataset.rverify + "/verify", "POST", {}); return; }
  if (t.closest("#noc-wsx")) { N.agent = null; paintAgentsBar(); paintAgent(); return; }
  if (t.closest("#noc-wfgo")) { runWorkflow(); return; }
  if (t.closest("#noc-run")) { var k = N.agent, tx = $("noc-task").value.trim(); N.taskTxt = ""; N.taskDev = $("noc-tdev").value; runAgent(k, tx || AG[k].def, { dev: N.taskDev || undefined }); return; }
  if (t.closest("#noc-start")) { var k2 = N.agent; runAgent(k2, AG[k2].def, { dev: ($("noc-tdev") || {}).value || undefined }); return; }
  if (t.closest("#noc-retry")) { var k3 = N.agent; runAgent(k3, ag(k3).task, {}); return; }
  if ((c = t.closest("[data-prop]"))) { var k4 = N.agent, rec = ag(k4).res.recs[Number(c.dataset.prop)], ev2 = (ag(k4).res.findings || []).slice(0, 2).map(function (f) { return f.t.slice(0, 120); }); propose(rec, k4, ev2).then(paintAgent); return; }
  if ((c = t.closest("[data-dec]"))) { decide(c.dataset.id, c.dataset.dec); return; }
  if ((c = t.closest("[data-inv]"))) { N.agent = "trouble"; paintAgentsBar(); paintAgent(); runAgent("trouble", "Investigate " + nm(c.dataset.inv), { dev: c.dataset.inv }); return; }
  if ((c = t.closest("[data-s2n]"))) { c.disabled = true; socToNoc(c.dataset.s2n).then(function () { N.agent = "trouble"; paintAgentsBar(); paintAgent(); }); return; }
  if ((c = t.closest("[data-n2s]"))) { nocToSoc(c.dataset.n2s); return; }
  if (t.closest("#noc-ho")) { var h = ag(N.agent).res.handoff, tk = N.incidents.filter(function (i) { return i.dev === h.dev && i.cat === "traffic"; })[0]; if (tk) nocToSoc(tk.id); else esca({ from: "NOC", to: "SOC", ref: nm(h.dev), text: h.text }); return; }
  if (t.closest("#noc-opensoc")) { var hb = document.querySelector('.soc-hot[data-role="analyst"]'); if (hb) hb.click(); return; }
  if (t.closest("#noc-ask")) { var q = $("noc-q").value.trim(); if (q) askAI(N.agent, q); return; }
  if (t.closest("#noc-reset")) { if (confirm("Clear this browser's stored NOC tickets, approvals, escalations and history for " + (N.mode === "live" ? "live" : "sample") + " data?")) { var a = lsGet(); delete a[key()]; lsPut(a); load(); N.runs = {}; AS = {}; paintAll(); } return; }
});
document.addEventListener("submit", function (ev) { var f = ev.target; if (!f || f.id !== "noc-srcform") return; ev.preventDefault(); var fd = new FormData(f), b = { name: fd.get("name"), type: fd.get("type"), mode: fd.get("mode"), url: fd.get("url") || undefined, token: fd.get("token") || undefined }; var m = $("noc-srcmsg"); m.textContent = "Saving…"; realAct("/noc/sources", "POST", b, "noc-srcmsg").then(function (r) { if (r) { f.reset(); if (!N.real) probe().then(paintAll); } }); });
document.addEventListener("keydown", function (ev) { if ((ev.key === "Enter" || ev.key === " ") && ev.target.classList && ev.target.classList.contains("nn")) { ev.preventDefault(); N.sel = ev.target.dataset.id; paintTopo(); paintNode(); } });
document.addEventListener("input", function (ev) { if (ev.target.id === "noc-task") N.taskTxt = ev.target.value; });

/* ===== boot ===== */
var started = false, timers = [];
async function boot() {
  await probe(); if (N.real) await loadRealAudit(); paintAll();
  timers.forEach(clearInterval); timers = [setInterval(function () { if (curView() !== "noc" || document.hidden) return; if (N.mode === "sample") { simTick(); paintKpis(); paintTopo(); paintCharts(); paintNode(); paintMode(); } }, 3000), setInterval(poll, 10000)];
}
window.SparkNOC = { show: function () { if (!started) { started = true; boot(); } else { paintAll(); } }, state: function () { return N; }, detect: detect, run: runAgent, workflow: runWorkflow };
function sync() { if (curView() === "noc") window.SparkNOC.show(); }
window.addEventListener("hashchange", function () { setTimeout(sync, 0); });
document.addEventListener("sparkview", sync);
setTimeout(sync, 0);
})();
