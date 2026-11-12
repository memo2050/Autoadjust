import { TestStore } from "./test-store";
import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore } from "../lib/soc/store";
import { handleSoc } from "../lib/soc/api";
import { categorize, redactless } from "./wazuh-helpers";
import type { WazuhCfg } from "../lib/soc/wazuh";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890" });
delete process.env.WAZUH_API_URL;
const AD = "admin-token-1234567890", IN = "ingest-token-1234567890", AN = "analyst-token-1234567890", VW = "viewer-token-1234567890";
const CFG: WazuhCfg = { apiUrl: "https://wazuh.lan:55000", apiUser: "spark-ro", apiPassword: "S3cret-Pass!", indexerUrl: "https://wazuh.lan:9200", indexerUser: "spark-idx", indexerPassword: "Idx-S3cret!", index: "wazuh-alerts-*", minLevel: 7 };
const mk = (s: TestStore, extra: any = {}) => async (m: string, p: string, t: string, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: m, headers: { Authorization: "Bearer " + t, "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), { store: s, model: null, ...extra } as any);
const J = async (r: Response) => (await r.json()) as any;
const iso = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

const win = (id: number, t: string, ed: any, rule = { id: "60122", level: 5, description: "Logon Failure - Unknown user or bad password", groups: ["windows", "windows_security", "authentication_failed"] }, ch = "Security") => ({ id: "w" + Math.random(), "@timestamp": t, agent: { id: "001", name: "WS-FIN-07", ip: "10.0.0.7" }, rule, data: { win: { system: { eventID: String(id), channel: ch, providerName: "Microsoft-Windows-Security-Auditing", systemTime: t, computer: "WS-FIN-07.corp.local", eventRecordID: String(Math.floor(Math.random() * 1e9)) }, eventdata: ed } } });
const unix = (rule: any, extra: any = {}, t = iso(2)) => ({ id: "u" + Math.random(), "@timestamp": t, agent: { id: "002", name: "web01", ip: "10.0.0.10" }, rule, ...extra });
function alertSet() {
  const a: any[] = [];
  for (let i = 0; i < 8; i++) a.push(win(4625, iso(20 - i), { targetUserName: "administrator", ipAddress: "203.0.113.9", logonType: "3" }));
  a.push(win(4688, iso(9), { subjectUserName: "jdoe", newProcessName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", commandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" }, { id: "92027", level: 8, description: "Powershell process spawned with encoded command", groups: ["windows", "sysmon"] }));
  for (let i = 0; i < 4; i++) a.push(unix({ id: "5760", level: 5, description: "sshd: authentication failed.", groups: ["syslog", "sshd", "authentication_failed"] }, { data: { srcip: "198.51.100.77", dstuser: "root" } }, iso(15 - i)));
  a.push(unix({ id: "5712", level: 10, description: "sshd: brute force trying to get access to the system. Authentication failed.", groups: ["syslog", "sshd", "authentication_failures"], mitre: { id: ["T1110"], technique: ["Brute Force"], tactic: ["Credential Access"] } }, { data: { srcip: "198.51.100.77" } }, iso(14)));
  a.push(unix({ id: "550", level: 7, description: "Integrity checksum changed.", groups: ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"], mitre: { id: ["T1565.001"], technique: ["Stored Data Manipulation"], tactic: ["Impact"] } }, { syscheck: { path: "/etc/shadow", event: "modified", sha256_after: "ab".repeat(32), uname_after: "root", changed_attributes: ["size", "sha256"] } }, iso(8)));
  a.push(unix({ id: "87105", level: 12, description: "VirusTotal: Alert - /tmp/x.exe - 12 engines detected this file", groups: ["virustotal"] }, { data: { virustotal: { positives: 12 } } }, iso(7)));
  a.push(unix({ id: "5402", level: 8, description: "Successful sudo to ROOT executed.", groups: ["syslog", "sudo"] }, { data: { srcuser: "bob", dstuser: "root" } }, iso(6)));
  a.push(unix({ id: "86601", level: 9, description: "Suricata: Alert - ET SCAN Potential SSH Scan", groups: ["ids", "suricata"], mitre: { id: ["T1046"], technique: ["Network Service Discovery"], tactic: ["Discovery"] } }, { data: { srcip: "198.51.100.77" } }, iso(5)));
  a.push(unix({ id: "5501", level: 3, description: "PAM: Login session opened.", groups: ["syslog", "pam", "authentication_success"] }, {}, iso(4)));
  return a;
}
interface Fake { recorded: string[]; alerts: any[]; mode?: "ok" | "401" | "adminrole" | "noalerts" }
function fakeWazuh(st: Fake): typeof fetch {
  return (async (url: any, init: any = {}) => {
    const u = new URL(String(url)), m = (init.method ?? "GET").toUpperCase(); st.recorded.push(`${m} ${u.pathname}`);
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (u.port === "55000") {
      if (u.pathname === "/security/user/authenticate") return st.mode === "401" ? json({ title: "Unauthorized" }, 401) : new Response("jwt.token.value", { status: 200 });
      if (init.headers?.Authorization !== "Bearer jwt.token.value") return json({}, 401);
      if (u.pathname === "/manager/info") return json({ data: { affected_items: [{ version: "v4.9.0", name: "wazuh-manager" }] } });
      if (u.pathname === "/security/users/me") return json({ data: { affected_items: [{ username: "spark-ro", roles: [st.mode === "adminrole" ? "administrator" : "readonly"] }] } });
      if (u.pathname === "/agents") return json({ data: { affected_items: [{ id: "001", name: "WS-FIN-07", ip: "10.0.0.7", status: "active", os: { name: "Microsoft Windows 11", version: "10.0" }, version: "Wazuh v4.9.0", lastKeepAlive: iso(0.2), group: ["default"] }, { id: "002", name: "web01", ip: "10.0.0.10", status: "active", os: { name: "Ubuntu" }, version: "Wazuh v4.9.0", lastKeepAlive: iso(0.1) }, { id: "003", name: "old-pc", ip: "10.0.0.30", status: "disconnected", lastKeepAlive: iso(3000) }, { id: "004", name: "new-pc", status: "never_connected" }] } });
    }
    if (u.port === "9200") {
      if (!String(init.headers?.Authorization).startsWith("Basic ")) return json({}, 401);
      if (u.pathname === "/_cluster/health") return json({ status: "green", number_of_nodes: 1 });
      if (u.pathname.endsWith("/_search")) { const body = JSON.parse(init.body); const gte = body.query?.range?.["@timestamp"]?.gte; const list = st.mode === "noalerts" ? [] : st.alerts.filter((a) => !gte || /^now/.test(gte) || a["@timestamp"] >= gte).sort((a, b) => (a["@timestamp"] < b["@timestamp"] ? -1 : 1)); const out = body.sort?.[0]?.["@timestamp"] === "desc" ? list.slice(-1) : list.slice(0, body.size); return json({ hits: { hits: out.map((a) => ({ _id: a.id, _source: a })) } }); }
    }
    return json({}, 404);
  }) as any;
}

test("not configured: honest status, nothing contacted, nothing marked live", async () => {
  const s = new TestStore(), call = mk(s);
  const st = await J(await call("GET", "wazuh/status", VW)); assert.equal(st.status, "not_connected"); assert.equal(st.eventsLive, 0);
  assert.equal((await call("POST", "wazuh/sync", AD)).status, 409);
  const t = await J(await call("POST", "wazuh/test/connection", AD)); assert.equal(t.ok, false); assert.match(t.steps[0].detail, /Nothing was contacted/);
  const integ = (await J(await call("GET", "integrations", VW))).integrations.find((x: any) => x.id === "wazuh"); assert.equal(integ.status, "not_connected");
});

test("direct sync: agents, alerts, MITRE, categories, detections, read-only, idempotent, no secret leaks", async () => {
  const s = new TestStore(), f: Fake = { recorded: [], alerts: alertSet() }, call = mk(s, { fetcher: fakeWazuh(f), wazuhCfg: CFG });
  assert.equal((await call("POST", "wazuh/sync", VW)).status, 403);
  const r = await J(await call("POST", "wazuh/sync", AD)); assert.equal(r.accepted, f.alerts.length); assert.equal(r.readOnly, true);
  assert.ok(f.recorded.every((x) => /^GET /.test(x) || x === "POST /security/user/authenticate" || /^POST \/wazuh-alerts-\*\/_search$/.test(x)), "only reads: " + f.recorded.join(" | "));
  const status = await J(await call("GET", "wazuh/status", VW)); assert.equal(status.status, "healthy"); assert.equal(status.mode, "direct"); assert.equal(status.manager, "v4.9.0"); assert.deepEqual([status.agents.total, status.agents.active, status.agents.disconnected, status.agents.never], [4, 2, 1, 1]); assert.equal(status.eventsLive, f.alerts.length);
  const col = await J(await call("GET", "collectors", VW)); const by = Object.fromEntries(col.map((c: any) => [c.host, c.status])); assert.equal(by["WS-FIN-07"], "connected"); assert.equal(by["old-pc"], "offline"); assert.equal(by["new-pc"], "offline");
  const al = await J(await call("GET", "alerts?limit=100", VW)); const titles: string[] = (Array.isArray(al) ? al : al.alerts).map((a: any) => a.title);
  for (const need of ["Brute force", "File integrity change", "Malware indicator", "Privilege escalation", "Suspicious network activity", "Suspicious PowerShell"]) assert.ok(titles.some((t) => t.startsWith(need)), `${need} detection missing in ${titles.join(" | ")}`);
  assert.ok(titles.some((t) => /failed logons|Brute force|password/i.test(t) && !t.startsWith("Wazuh")), "existing Windows brute-force rule also ran on Wazuh-delivered Windows events");
  const all: any[] = Array.isArray(al) ? al : al.alerts, fim = all.find((a) => a.title.startsWith("File integrity")); assert.equal(fim.severity, "high"); assert.match(fim.reasoning, /sensitive system location/); assert.match(fim.reasoning, /abab/);
  const br = all.find((a) => a.ruleId === "WZH-5712"); assert.equal(br.mitre[0].id, "T1110"); assert.match(br.reasoning, /comes from the Wazuh rule/); assert.equal(br.source, "live");
  assert.ok(!all.some((a) => a.title.includes("Login session opened")), "level-3 info alerts do not become detections");
  const again = await J(await call("POST", "wazuh/sync", AD)); const ev1 = (await s.select("soc_events", {})).length; await call("POST", "wazuh/sync", AD); assert.equal((await s.select("soc_events", {})).length, ev1, "re-sync does not duplicate");
  assert.ok(again.accepted >= 1);
  const leak = JSON.stringify([status, col, await s.select("soc_meta", {}), await s.select("soc_audit", {})]); assert.ok(!leak.includes("S3cret") && !leak.includes("Idx-S3cret") && !leak.includes("jwt.token"), "no credentials or tokens stored or returned");
  assert.deepEqual(redactless, undefined);
});

test("failed login: wrong password is an error status, not a fake connection", async () => {
  const s = new TestStore(), f: Fake = { recorded: [], alerts: [], mode: "401" }, call = mk(s, { fetcher: fakeWazuh(f), wazuhCfg: CFG });
  const r = await call("POST", "wazuh/sync", AD); assert.equal(r.status, 502); assert.match((await J(r)).error, /rejected the credentials/);
  const st = await J(await call("GET", "wazuh/status", VW)); assert.equal(st.status, "error"); assert.equal(st.eventsLive, 0);
  const t = await J(await call("POST", "wazuh/test/connection", AD)); assert.equal(t.ok, false); assert.equal(t.steps.find((x: any) => x.name === "Manager API login").ok, false);
});

test("connection health check: all steps pass; an administrator-role account is flagged; empty index is reported", async () => {
  const s = new TestStore(), f: Fake = { recorded: [], alerts: alertSet() }, call = mk(s, { fetcher: fakeWazuh(f), wazuhCfg: CFG });
  assert.equal((await call("POST", "wazuh/test/connection", AN)).status, 403);
  let t = await J(await call("POST", "wazuh/test/connection", AD)); assert.equal(t.ok, true, JSON.stringify(t.steps.filter((x: any) => !x.ok))); assert.equal(t.steps.length, 7); assert.equal((await J(await call("GET", "wazuh/status", VW))).lastTest.ok, true);
  f.mode = "adminrole"; t = await J(await call("POST", "wazuh/test/connection", AD)); assert.equal(t.ok, false); assert.match(t.steps.find((x: any) => x.name === "Account is read-only").detail, /administrator/);
  f.mode = "noalerts"; t = await J(await call("POST", "wazuh/test/connection", AD)); assert.match(t.steps.find((x: any) => x.name === "Alerts index").detail, /nothing to import/);
});

test("bridge mode: ingest role pushes, others cannot; cursor; status shows bridge", async () => {
  const s = new TestStore(), call = mk(s), body = { agents: [{ id: "001", name: "WS-FIN-07", ip: "10.0.0.7", status: "active", lastKeepAlive: iso(0.1) }], alerts: alertSet().slice(0, 12), manager: { version: "v4.9.0" }, bridge: { name: "lab-bridge", version: "1" } };
  assert.equal((await call("POST", "ingest/wazuh", VW, body)).status, 403); assert.equal((await call("POST", "ingest/wazuh", AN, body)).status, 403);
  const r = await J(await call("POST", "ingest/wazuh", IN, body)); assert.equal(r.accepted, 12, JSON.stringify(r));
  const st = await J(await call("GET", "wazuh/status", VW)); assert.equal(st.mode, "bridge"); assert.equal(st.bridge.name, "lab-bridge"); assert.equal(st.status, "healthy");
  assert.ok((await J(await call("GET", "wazuh/cursor", IN))).cursor);
  await call("POST", "wazuh/bridge-test", IN, { ok: false, steps: [{ name: "Indexer reachable", ok: false, detail: "timeout" }] }); assert.equal((await J(await call("GET", "wazuh/status", VW))).lastTest.mode, "bridge");
  const bad = await J(await call("POST", "ingest/wazuh", IN, { alerts: [{ "@timestamp": "nope", agent: { name: "x" } }, { "@timestamp": iso(1) }] })); assert.equal(bad.accepted, 0); assert.equal(bad.rejected.length, 2);
});

test("security event test is labelled demo, never touches live state, and cleans up", async () => {
  const s = new TestStore(), call = mk(s);
  assert.equal((await call("POST", "wazuh/test/event", AN)).status, 403);
  const r = await J(await call("POST", "wazuh/test/event", AD)); assert.equal(r.ok, true, JSON.stringify(r)); assert.match(r.label, /TEST DATA/);
  const st = await J(await call("GET", "wazuh/status", VW)); assert.equal(st.status, "not_connected", "a self-test must not make Wazuh look connected"); assert.equal(st.eventsLive, 0); assert.equal(st.eventsTest, 1);
  assert.ok((await s.select<any>("soc_alerts", {})).every((a) => a.source === "demo"));
  await call("POST", "wazuh/test/cleanup", AD); assert.equal((await s.select("soc_events", {})).length + (await s.select("soc_alerts", {})).length + (await s.select("soc_incidents", {})).length, 0);
});

test("AI agents work on Wazuh data: SOC Analyst task cites Wazuh source failures; wazuh events labelled live", async () => {
  const s = new TestStore(), f: Fake = { recorded: [], alerts: alertSet() }, call = mk(s, { fetcher: fakeWazuh(f), wazuhCfg: CFG });
  await call("POST", "wazuh/sync", AD);
  const t = await J(await call("POST", "tasks", AN, { role: "analyst", task: "Triage failed logons" })); let task = t;
  for (let i = 0; i < 12 && task.status !== "completed" && task.status !== "failed"; i++) task = await J(await call("POST", `tasks/${t.id}/next`, AN));
  assert.equal(task.status, "completed", JSON.stringify(task.steps?.map((x: any) => x.status + ":" + x.name))); const txt = JSON.stringify(task.result);
  assert.ok(txt.includes("198.51.100.77") || txt.includes("203.0.113.9"), "findings cite the real source addresses from Wazuh data"); assert.equal(task.result.source ?? "live", "live");
});
