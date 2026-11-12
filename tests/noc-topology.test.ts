import { TestStore } from "./test-store";
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore } from "../lib/soc/store";
import { handleSoc } from "../lib/soc/api";
import { parseTargets, inScope } from "../lib/noc/topo";
import { redact, lineDiff } from "../lib/noc/changes";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890", NOC_SECRET_KEY: "k".repeat(40) });
const AD = "admin-token-1234567890", IN = "ingest-token-1234567890", AN = "analyst-token-1234567890", VW = "viewer-token-1234567890";
const mk = (s: TestStore) => (method: string, path: string, tok: string, body?: unknown) => handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store: s, model: null } as any);
const J = async (r: Response) => (await r.json()) as any;

test("target parsing: cidr, range, host, single; oversize and public-wide rejected", () => {
  const t = parseTargets(["192.168.1.0/24", "10.0.0.5-10.0.0.9", "10.1.1.1", "sw.lan"]);
  assert.equal(inScope(t, "192.168.1.77"), true); assert.equal(inScope(t, "192.168.2.1"), false); assert.equal(inScope(t, "10.0.0.7"), true); assert.equal(inScope(t, "10.0.0.10"), false);
  assert.equal(inScope(t, undefined, "SW.lan"), true);
  assert.throws(() => parseTargets(["10.0.0.0/8"])); assert.throws(() => parseTargets(["999.1.1.1"])); assert.throws(() => parseTargets([]));
});

test("scope needs explicit authorization and admin role; scan lifecycle; out-of-scope hosts rejected", async () => {
  const s = new TestStore(), call = mk(s);
  assert.equal((await call("POST", "noc/scopes", AD, { name: "LAN", targets: ["192.168.1.0/24"] })).status, 400, "no authorization flag");
  assert.equal((await call("POST", "noc/scopes", AN, { name: "LAN", targets: ["192.168.1.0/24"], authorized: true })).status, 403);
  const sc = await J(await call("POST", "noc/scopes", AD, { name: "LAN", targets: ["192.168.1.0/24"], authorized: true })); assert.equal(sc.size, 256);
  assert.equal((await call("POST", "noc/scans", AD, { scopeId: "nope" })).status, 404);
  const scan = await J(await call("POST", "noc/scans", AD, { scopeId: sc.id, options: { methods: ["icmp", "arp", "snmp"], intensity: "low", timeoutMs: 1000 } })); assert.equal(scan.status, "queued");
  assert.equal((await call("POST", "noc/scans", AD, { scopeId: sc.id })).status, 409, "no duplicate active scan");
  assert.equal((await call("GET", "noc/scans/pending", VW)).status, 403);
  const cl = await J(await call("GET", "noc/scans/pending?agent=lab-agent", IN)); assert.equal(cl.scan.id, scan.id); assert.deepEqual(cl.scan.targets, ["192.168.1.0/24"]); assert.equal(cl.scan.maxPerSecond, 10);
  assert.equal(JSON.stringify(cl).includes("community"), false);
  const rep = await J(await call("POST", `noc/scans/${scan.id}/progress`, IN, { done: 100, hosts: [
    { ip: "192.168.1.1", mac: "00:1e:bd:11:22:33", hostname: "core-rtr", sysDescr: "Cisco IOS Router", up: true, rttMs: 1, methods: ["icmp", "snmp"], neighbors: [{ localPort: "Gi0/1", remoteName: "core-sw", remoteIp: "192.168.1.2", remotePort: "Gi0/24", proto: "lldp" }] },
    { ip: "192.168.1.2", mac: "00:1e:bd:44:55:66", hostname: "core-sw", sysDescr: "Cisco IOS Switch", up: true, methods: ["icmp", "snmp"] },
    { ip: "192.168.1.50", mac: "aa:bb:cc:00:00:50", hostname: "ws-50", up: true, ports: [3389] },
    { ip: "8.8.8.8", up: true }] }));
  assert.equal(rep.rejected, 1, "out-of-scope host refused"); assert.equal(rep.accepted, 3);
  await call("POST", `noc/scans/${scan.id}/complete`, IN, {});
  const disc = await J(await call("GET", "noc/discovery", VW)); assert.equal(disc.scans[0].status, "completed"); assert.equal(disc.agents.length, 1);
  const topo = await J(await call("GET", "noc/topology", VW)); assert.equal(topo.nodes.length, 3); assert.equal(topo.nodes.some((n: any) => n.ip === "8.8.8.8"), false);
  assert.equal(topo.links.length, 1); assert.equal(topo.nodes.find((n: any) => n.ip === "192.168.1.1").type, "router");
  assert.equal(JSON.stringify(topo).match(/community|password/i), null);
  // re-scan merges by mac, not duplicates
  const sc2 = await J(await call("POST", "noc/scans", AD, { scopeId: sc.id })); await call("GET", "noc/scans/pending?agent=lab-agent", IN);
  await call("POST", `noc/scans/${sc2.id}/progress`, IN, { hosts: [{ ip: "192.168.1.51", mac: "aa:bb:cc:00:00:50", hostname: "ws-50", up: true }] });
  assert.equal((await J(await call("GET", "noc/topology", VW))).nodes.length, 3, "same MAC merged");
});

test("map saves only change the overlay; versions, conflicts, restore; rbac", async () => {
  const s = new TestStore(), call = mk(s);
  const maps = await J(await call("GET", "noc/maps", VW)); const id = maps[0].id;
  assert.equal((await call("POST", `noc/maps/${id}/save`, VW, { doc: {} })).status, 403);
  const r1 = await J(await call("POST", `noc/maps/${id}/save`, AN, { baseVersion: 0, doc: { nodes: {}, manualNodes: [{ id: "m1", name: "Planned FW", type: "firewall", x: 10, y: 20 }], manualLinks: [], hiddenLinks: [], groups: [{ kind: "vlan", name: "VLAN 10" }] } }));
  assert.equal(r1.version, 1); assert.match(r1.note, /no network device was touched/i);
  assert.equal((await call("POST", `noc/maps/${id}/save`, AN, { baseVersion: 0, doc: {} })).status, 409, "stale base");
  await call("POST", `noc/maps/${id}/save`, AN, { baseVersion: 1, doc: { nodes: {}, manualNodes: [], manualLinks: [], hiddenLinks: [], groups: [] } });
  assert.equal((await J(await call("GET", `noc/maps/${id}/versions`, VW))).length, 2);
  await call("POST", `noc/maps/${id}/restore`, AN, { version: 1 });
  const t = await J(await call("GET", `noc/topology?map=${id}`, VW)); assert.ok(t.nodes.find((n: any) => n.name === "Planned FW" && n.manual));
  assert.equal(await s.select("noc_changes", {}).then((x) => x.length), 0, "no change proposals created by map edits");
});

test("impact analysis: root cause and downstream; SOC overlay and unmanaged asset", async () => {
  const s = new TestStore(), call = mk(s);
  const sc = await J(await call("POST", "noc/scopes", AD, { name: "LAN", targets: ["10.0.0.0/24"], authorized: true }));
  const scan = await J(await call("POST", "noc/scans", AD, { scopeId: sc.id })); await call("GET", "noc/scans/pending?agent=a", IN);
  await call("POST", `noc/scans/${scan.id}/progress`, IN, { hosts: [
    { ip: "10.0.0.1", hostname: "fw1", sysDescr: "firewall", up: true, neighbors: [{ localPort: "1", remoteName: "sw1", remoteIp: "10.0.0.2" }] },
    { ip: "10.0.0.2", hostname: "sw1", sysDescr: "switch", up: true, neighbors: [{ localPort: "2", remoteName: "web1", remoteIp: "10.0.0.10" }] },
    { ip: "10.0.0.10", hostname: "web1", up: true }] });
  await call("POST", `noc/scans/${scan.id}/complete`, IN, {});
  let t = await J(await call("GET", "noc/topology", VW)); const ids = Object.fromEntries(t.nodes.map((n: any) => [n.name, n.id]));
  assert.ok(t.nodes.every((n: any) => n.unmanaged), "discovered but not in any monitoring source = unmanaged"); assert.ok(t.nodes.every((n: any) => n.status === "discovered"), "a scan alone never proves health");
  assert.equal((await call("POST", `noc/devices/${ids.sw1}/adopt`, AN)).status, 403); assert.equal((await call("POST", `noc/devices/${ids.sw1}/adopt`, AD)).status, 200);
  // sw1 goes offline via push ingest
  const dev: any = await s.get("noc_devices", ids.sw1); dev.up = false; dev.receivedAt = new Date().toISOString(); await s.upsert("noc_devices", [dev]);
  t = await J(await call("GET", "noc/topology", VW)); const sw = t.nodes.find((n: any) => n.name === "sw1"), web = t.nodes.find((n: any) => n.name === "web1");
  assert.equal(sw.rootCause, true); assert.equal(web.affected, true); assert.ok(!t.nodes.find((n: any) => n.name === "fw1").affected);
  assert.ok(!t.nodes.find((n: any) => n.name === "fw1").affected);
  await s.upsert("soc_incidents", [{ id: "INC-1", title: "Ransomware behaviour", severity: "critical", status: "open", host: "web1" }]);
  t = await J(await call("GET", "noc/topology", VW)); const w2 = t.nodes.find((n: any) => n.name === "web1"); assert.equal(w2.compromised, true); assert.equal(w2.soc[0].id, "INC-1");
});

test("config change: redaction, diff, confirm by name, unverified vs applied, rollback, audit", async () => {
  assert.equal(redact("snmp-server community public RO\nhostname r1\nusername admin secret 5 abc"), "snmp-server community <redacted>\nhostname r1\nusername admin secret <redacted>");
  for (const [l, leak] of [["enable secret 9 $9$abc", "$9$abc"], ["snmp-server community hunter2 RO", "hunter2"], ["crypto isakmp key MyKey address 1.1.1.1", "MyKey"], ["snmp-server user u g v3 auth sha AUTHPASS priv aes PRIVPASS", "AUTHPASS"], ["tacacs-server key tackey", "tackey"]]) assert.ok(!redact(l).includes(leak), l);
  assert.equal(redact("description Key switch"), "description Key switch"); assert.equal(redact("hostname r1"), "hostname r1");
  const d = lineDiff("hostname r1\nntp server 1.1.1.1", "hostname r1\nntp server 9.9.9.9"); assert.deepEqual(d.added, ["ntp server 9.9.9.9"]); assert.deepEqual(d.removed, ["ntp server 1.1.1.1"]);
  const s = new TestStore(), call = mk(s);
  const sc = await J(await call("POST", "noc/scopes", AD, { name: "LAN", targets: ["10.0.0.0/24"], authorized: true })); const scan = await J(await call("POST", "noc/scans", AD, { scopeId: sc.id })); await call("GET", "noc/scans/pending?agent=a", IN);
  await call("POST", `noc/scans/${scan.id}/progress`, IN, { hosts: [{ ip: "10.0.0.1", hostname: "r1", sysDescr: "router", up: true }] }); const id = (await J(await call("GET", "noc/topology", VW))).nodes[0].id;
  assert.equal((await call("POST", `noc/backups/${id}`, VW, { config: "x" })).status, 403);
  await J(await call("POST", `noc/backups/${id}`, AN, { config: "hostname r1\nntp server 1.1.1.1\nenable secret hunter2" }));
  const bl = JSON.stringify(await J(await call("GET", `noc/backups/${id}`, AN))); assert.equal(bl.includes("hunter2"), false);
  const ch = await J(await call("POST", "noc/changes", AN, { deviceId: id, title: "Change NTP", proposed: "hostname r1\nntp server 9.9.9.9" })); assert.equal(ch.status, "proposed"); assert.deepEqual(ch.diff.added, ["ntp server 9.9.9.9"]);
  assert.equal(JSON.stringify(ch).includes("proposedRaw"), false);
  const chs = await J(await call("POST", "noc/changes", AN, { deviceId: id, title: "SNMP", proposed: "snmp-server community hunter2 RO\nenable secret 9 $9$zzz" })); assert.equal(JSON.stringify([chs, await J(await call("GET", "noc/changes", VW))]).match(/hunter2|\$9\$zzz/), null, "no secret in API output");
  await call("POST", `noc/changes/${chs.id}/reject`, AD, {});
  assert.equal((await call("POST", `noc/changes/${ch.id}/approve`, AN, { confirm: "r1" })).status, 403);
  assert.equal((await call("POST", `noc/changes/${ch.id}/approve`, AD, { confirm: "wrong" })).status, 400);
  assert.equal((await J(await call("GET", "noc/changes/pending", IN))).changes.length, 0, "nothing runs before approval");
  assert.equal((await J(await call("POST", `noc/changes/${ch.id}/approve`, AD, { confirm: "r1" }))).status, "queued");
  const pend = await J(await call("GET", "noc/changes/pending", IN)); assert.equal(pend.changes[0].proposed, "hostname r1\nntp server 9.9.9.9");
  await call("POST", `noc/changes/${ch.id}/backup`, IN, { config: "hostname r1\nntp server 1.1.1.1" });
  // executor claims success but running config lacks the line -> UNVERIFIED, never "applied"
  const r = await J(await call("POST", `noc/changes/${ch.id}/result`, IN, { ok: true, runningConfig: "hostname r1\nntp server 1.1.1.1" })); assert.equal(r.status, "unverified");
  assert.equal((await call("POST", `noc/changes/${ch.id}/result`, IN, { ok: true })).status, 409, "result only once");
  const ch2 = await J(await call("POST", "noc/changes", AN, { deviceId: id, title: "NTP again", proposed: "ntp server 9.9.9.9" }));
  await call("POST", `noc/changes/${ch2.id}/approve`, AD, { confirm: "r1" }); await call("GET", "noc/changes/pending", IN); await call("POST", `noc/changes/${ch2.id}/backup`, IN, { config: "ntp server 1.1.1.1" });
  assert.equal((await J(await call("POST", `noc/changes/${ch2.id}/result`, IN, { ok: true, runningConfig: "ntp server 9.9.9.9\nhostname r1" }))).status, "applied");
  const rb = await J(await call("POST", `noc/changes/${ch2.id}/rollback`, AD)); assert.equal(rb.status, "rollback_proposed"); assert.deepEqual(rb.diff.added, ["ntp server 1.1.1.1"]);
  assert.equal((await J(await call("GET", "noc/changes/pending", IN))).changes.length, 0, "rollback needs its own approval");
  const ch3 = await J(await call("POST", "noc/changes", AN, { deviceId: id, title: "fail", proposed: "x" })); await call("POST", `noc/changes/${ch3.id}/approve`, AD, { confirm: "r1" }); await call("GET", "noc/changes/pending", IN);
  assert.equal((await J(await call("POST", `noc/changes/${ch3.id}/result`, IN, { ok: false, error: "timeout" }))).status, "failed");
  const au = JSON.stringify(await s.select("soc_audit", {})); for (const a of ["noc.scope.create", "noc.change.propose", "noc.change.approve", "noc.change.applied", "noc.change.unverified", "noc.backup.add"]) assert.ok(au.includes(a), a);
});
