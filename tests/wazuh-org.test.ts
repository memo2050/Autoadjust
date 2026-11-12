// Phase 2: per-organization Wazuh integration over a REAL HTTP socket against a MOCK Wazuh (see tests/mock-wazuh.ts). Run: npx tsx --test tests/wazuh-org.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { T } from "../lib/soc/store";
import { startMockWazuh, routeFetch, type MockWazuh } from "./mock-wazuh";
import { assertSafeTarget, blockedAddress, enrollment } from "../lib/soc/wazuh-config";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); process.env.WAZUH_ALLOW_HTTP = "1";
delete process.env.WAZUH_API_URL; delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(h + "." + p).digest("base64url")}`; };
const U = { a: "aaaaaaaa-0000-4000-8000-00000000000a", an: "cccccccc-0000-4000-8000-00000000000c", b: "bbbbbbbb-0000-4000-8000-00000000000b" };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const tok = { a: jwt(U.a, "a@x.io"), an: jwt(U.an, "an@x.io"), b: jwt(U.b, "b@x.io") };
const publicResolver = async (h: string) => (h.endsWith(".test") ? ["93.184.216.34"] : ["10.1.2.3"]);   // wazuh-a.test -> a public address

async function world() {
  const s = new TestStore();
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a" }, { id: ORG_B, name: "Org B", slug: "org-b" }] as any);
  const m = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await m(ORG_A, U.a, "owner"); await m(ORG_A, U.an, "security_analyst"); await m(ORG_B, U.b, "owner");
  return s;
}
const iso = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
const win = (id: number, t: string, ed: any, rule: any = { id: "60122", level: 5, description: "Logon Failure - Unknown user or bad password", groups: ["windows", "windows_security", "authentication_failed"] }, host = "WS-FIN-07") => ({ id: "w" + Math.random(), "@timestamp": t, agent: { id: "001", name: host, ip: "10.0.0.7" }, rule, data: { win: { system: { eventID: String(id), channel: "Security", providerName: "Microsoft-Windows-Security-Auditing", systemTime: t, computer: host + ".corp.local", eventRecordID: String(Math.floor(Math.random() * 1e9)) }, eventdata: ed } } });
const unix = (rule: any, extra: any = {}, t = iso(2), host = "web01") => ({ id: "u" + Math.random(), "@timestamp": t, agent: { id: "002", name: host, ip: "10.0.0.10" }, rule, ...extra });
const setA = () => { const a: any[] = []; for (let i = 0; i < 8; i++) a.push(win(4625, iso(20 - i), { targetUserName: "administrator", ipAddress: "203.0.113.9", logonType: "3" }));
  a.push(unix({ id: "5712", level: 10, description: "sshd: brute force trying to get access to the system. Authentication failed.", groups: ["syslog", "sshd", "authentication_failures"], mitre: { id: ["T1110"], technique: ["Brute Force"], tactic: ["Credential Access"] } }, { data: { srcip: "198.51.100.77" } }, iso(14)));
  a.push(unix({ id: "550", level: 7, description: "Integrity checksum changed.", groups: ["ossec", "syscheck"], mitre: { id: ["T1565.001"], technique: ["Stored Data Manipulation"], tactic: ["Impact"] } }, { syscheck: { path: "/etc/shadow", event: "modified", sha256_after: "ab".repeat(32), uname_after: "root" } }, iso(8))); return a; };
const setB = () => [unix({ id: "87105", level: 12, description: "VirusTotal: Alert - /tmp/b.exe - 9 engines detected this file", groups: ["virustotal"] }, { data: { virustotal: { positives: 9 } } }, iso(7), "ORGB-HOST")];
const agentsA = [{ id: "001", name: "WS-FIN-07", ip: "10.0.0.7", status: "active", os: { name: "Microsoft Windows 11" }, version: "Wazuh v4.9.2" }, { id: "002", name: "web01", ip: "10.0.0.10", status: "disconnected", os: { name: "Ubuntu" }, version: "Wazuh v4.9.2" }];

let env: { s: TestStore; A: MockWazuh; B: MockWazuh; deps: any; call: (m: string, p: string, t: string, b?: unknown, org?: string) => Promise<Response> };
const J = async (r: Response) => r.json() as Promise<any>;
async function setup() {
  const s = await world(), A = await startMockWazuh({ alerts: setA(), agents: agentsA, user: "ro-a", pass: "pass-a-1234567" }), B = await startMockWazuh({ alerts: setB(), agents: [{ id: "010", name: "ORGB-HOST", status: "active" }], user: "ro-b", pass: "pass-b-1234567" });
  const model = async (_s: string, user: string) => { const ids = [...user.matchAll(/"id":\s*"(evt_[a-f0-9]+)"/g)].map((m) => m[1]); return { text: JSON.stringify({ summary: "Repeated failed logons from one address.", analysis: "## Assessment\n- Failed logons.", findings: [{ claim: "Failed logons occurred", evidence_ids: ids.slice(0, 1), confidence: "medium" }], recommendations: [{ action: "Block 203.0.113.9 at the firewall", priority: "P1", disruptive: true }], limitations: [] }), model: "stub" }; };
  const deps = { store: s, model, fetcher: routeFetch({ "wazuh-a.test": A.port, "wazuh-b.test": B.port }), resolver: publicResolver };
  const call = (m: string, p: string, t: string, b?: unknown, org?: string) => handleSoc(new Request("http://x/api/soc/" + p, { method: m, headers: { authorization: "Bearer " + t, "content-type": "application/json", ...(org ? { "x-org-id": org } : {}) }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), deps as any);
  opened.push(A, B); env = { s, A, B, deps, call };
  const cfg = (host: string, u: string, p: string) => ({ apiUrl: `http://${host}:55000`, apiUser: u, apiPassword: p, indexerUrl: `http://${host}:9200`, indexerUser: u, indexerPassword: p, minLevel: 7, agentManager: host });
  assert.equal((await call("PUT", "wazuh/config", tok.a, cfg("wazuh-a.test", "ro-a", "pass-a-1234567"))).status, 200);
  assert.equal((await call("PUT", "wazuh/config", tok.b, cfg("wazuh-b.test", "ro-b", "pass-b-1234567"))).status, 200);
  return env;
}
const opened: MockWazuh[] = [];
test.after(async () => { for (const m of opened) await m.close(); });

test("SSRF guard: loopback, metadata, private ranges, credentials in URL, paths, http and unresolvable hosts are refused", async () => {
  const bad = ["https://127.0.0.1:55000", "https://localhost:55000", "https://169.254.169.254", "https://10.0.0.5:55000", "https://[::1]:55000", "https://user:pw@wazuh.example.com", "https://wazuh.example.com/evil/path", "https://wazuh.example.com/?x=1", "ftp://wazuh.example.com", "not a url"];
  const pub = async (h: string) => (h === "localhost" ? ["127.0.0.1"] : h === "wazuh.example.com" ? ["93.184.216.34"] : []);
  for (const u of bad) await assert.rejects(() => assertSafeTarget(u, "URL", {}, pub), (e: any) => e.status === 400, u);
  await assert.rejects(() => assertSafeTarget("http://wazuh.example.com:55000", "URL", {}, pub), /https/, "plain http refused by default");
  await assert.rejects(() => assertSafeTarget("https://rebind.example.com", "URL", {}, async () => ["192.168.1.9"]), /private network/, "name resolving to a private address");
  await assert.rejects(() => assertSafeTarget("https://rebind.example.com", "URL", {}, async () => ["8.8.8.8", "169.254.169.254"]), /metadata/, "any bad address among several");
  assert.equal(await assertSafeTarget("https://wazuh.example.com:55000", "URL", {}, pub), "https://wazuh.example.com:55000");
  assert.equal(await assertSafeTarget("https://10.0.0.5:55000", "URL", { WAZUH_ALLOW_PRIVATE_TARGETS: "1" }, pub), "https://10.0.0.5:55000", "operator may allow private labs");
  assert.ok(blockedAddress("127.0.0.1", true) && blockedAddress("169.254.169.254", true), "loopback and metadata are never allowed, even in private mode");
});

test("connection settings: owner/IT only, passwords encrypted at rest and never returned, SSRF checked through the API", async () => {
  const { s, call } = await setup();
  assert.equal((await call("PUT", "wazuh/config", tok.an, { apiUrl: "https://x.example.com" })).status, 403, "analyst cannot configure");
  const g = await J(await call("GET", "wazuh/config", tok.a)); assert.equal(g.apiUser, "ro-a"); assert.equal(g.passwordsStored, true);
  assert.ok(!JSON.stringify(g).includes("pass-a-1234567"), "password never returned");
  const rows = JSON.stringify(await s.select("soc_meta", { where: { id: `${ORG_A}:wazuh-config` } as any })); assert.ok(rows.includes("v1.") && !rows.includes("pass-a-1234567"), "stored encrypted");
  const bad = await call("PUT", "wazuh/config", tok.a, { apiUrl: "https://169.254.169.254", apiUser: "u", apiPassword: "p", indexerUrl: "https://x.example.com", indexerUser: "u", indexerPassword: "p" }); assert.equal(bad.status, 400);
  assert.match((await J(bad)).error, /metadata/);
  assert.equal((await J(await call("GET", "wazuh/config", tok.a))).apiUrl, "http://wazuh-a.test:55000", "failed save changed nothing");
  const audit = await J(await call("GET", "audit", tok.a)); assert.ok(audit.some((e: any) => e.action === "wazuh.config.save")); assert.ok(!JSON.stringify(audit).includes("pass-a-1234567"), "no secret in audit");
  delete process.env.NOC_SECRET_KEY; try { assert.equal((await call("PUT", "wazuh/config", tok.b, { apiUrl: "http://wazuh-b.test:55000", apiUser: "u", apiPassword: "p", indexerUrl: "http://wazuh-b.test:9200", indexerUser: "u", indexerPassword: "p" })).status, 409, "refuses to store secrets without an encryption key"); } finally { process.env.NOC_SECRET_KEY = "n".repeat(40); }
});

test("connection test and sync over real HTTP: only read calls, real events/alerts/incidents/assets, each organization gets only its own Wazuh data", async () => {
  const { A, B, call } = await setup();
  const t = await J(await call("POST", "wazuh/test/connection", tok.a)); assert.equal(t.ok, true, JSON.stringify(t.steps.filter((x: any) => !x.ok)));
  const r = await J(await call("POST", "wazuh/sync", tok.a)); assert.ok(r.accepted >= 10 && r.newAlerts > 0, JSON.stringify(r)); assert.equal(r.readOnly, true);
  const bad = A.requests.filter((x) => !(x.startsWith("GET ") || x === "POST /security/user/authenticate" || x === "POST /wazuh-alerts-*/_search")); assert.deepEqual(bad, [], "only read requests reached Wazuh");
  const alerts = await J(await call("GET", "alerts", tok.a)), incidents = await J(await call("GET", "incidents", tok.a)), assets = JSON.stringify(await J(await call("GET", "overview", tok.a)));
  assert.ok(alerts.length >= 3 && incidents.length >= 1, `alerts ${alerts.length} incidents ${incidents.length}`);
  assert.ok(alerts.some((x: any) => x.mitre?.some((m: any) => m.id === "T1110")), "MITRE mapping carried through"); assert.ok(alerts.every((x: any) => x.source === "live"), "all labelled live");
  assert.ok(assets.includes("WS-FIN-07".toLowerCase()) || assets.toLowerCase().includes("ws-fin-07"), "agents became assets");
  // B has not synced yet and sees nothing of A; B syncs ITS Wazuh and gets only its data
  assert.equal((await J(await call("GET", "alerts", tok.b))).length, 0);
  assert.ok((await J(await call("POST", "wazuh/sync", tok.b))).accepted === 1);
  const bAlerts = await J(await call("GET", "alerts", tok.b)); assert.ok(bAlerts.length >= 1 && JSON.stringify(bAlerts).includes("VirusTotal") && !JSON.stringify(bAlerts).includes("brute force"));
  assert.ok(!JSON.stringify(await J(await call("GET", "alerts", tok.a))).includes("VirusTotal"), "A never sees B's alerts");
  assert.ok(B.requests.length > 0 && !B.requests.some((x) => x.includes("ro-a")));
  assert.equal((await J(await call("GET", "wazuh/status", tok.a))).status, "healthy"); assert.equal((await J(await call("GET", "wazuh/status", tok.b))).agents.total, 1);
});

test("organization without a Wazuh connection cannot sync, and cannot borrow the server-wide one", async () => {
  const { s, call } = await setup(); process.env.WAZUH_API_URL = "https://platform-wazuh.example.com:55000";
  try {
    await s.upsert("organizations", [{ id: "c0000000-0000-4000-8000-0000000000c1", name: "Org C", slug: "org-c" }] as any); const cU = "dddddddd-0000-4000-8000-00000000000d";
    await s.upsert("org_members", [{ orgId: "c0000000-0000-4000-8000-0000000000c1", userId: cU, role: "owner" }] as any, "org_id,user_id");
    const c = jwt(cU, "c@x.io"); const r = await call("POST", "wazuh/sync", c); assert.equal(r.status, 409);
    assert.equal((await J(await call("GET", "wazuh/config", c))).configured, false, "environment settings are not shown to customer organizations");
    assert.equal((await J(await call("GET", "wazuh/status", c))).status, "not_connected");
  } finally { delete process.env.WAZUH_API_URL; }
});

test("incremental sync (cursor), wrong credentials, and DNS rebinding after save", async () => {
  const { A, s, call, deps } = await setup();
  const first = await J(await call("POST", "wazuh/sync", tok.a)); const before = (await J(await call("GET", "events?limit=1000", tok.a))).length;
  A.alerts.push(unix({ id: "5712", level: 11, description: "sshd: brute force trying to get access to the system. Authentication failed.", groups: ["sshd", "authentication_failures"] }, { data: { srcip: "198.51.100.99" } }, iso(0.2)));
  const second = await J(await call("POST", "wazuh/sync", tok.a)); assert.ok(second.accepted >= 1 && second.accepted <= 3, "only new alerts re-read: " + JSON.stringify(second));
  assert.equal((await J(await call("GET", "events?limit=1000", tok.a))).length, before + 1, "exactly one new event; no duplicates (first " + first.accepted + ")");
  A.pass = "rotated-password-9999";
  const bad = await call("POST", "wazuh/sync", tok.a); assert.equal(bad.status, 502); assert.match((await J(bad)).error, /credentials/i);
  const st = await J(await call("GET", "wazuh/status", tok.a)); assert.equal(st.status, "error"); assert.ok(!JSON.stringify(st).includes("pass-a-1234567"));
  assert.ok((await J(await call("GET", "audit", tok.a))).some((e: any) => e.action === "wazuh.sync.error"));
  A.pass = "pass-a-1234567";
  (deps as any).resolver = async () => ["10.9.9.9"];   // the name now points at an internal address
  const reb = await call("POST", "wazuh/sync", tok.a); assert.equal(reb.status, 400); assert.match((await J(reb)).error, /private network/);
  (deps as any).resolver = publicResolver; assert.ok(s);
});

test("AI investigation is evidence based and org-scoped; the six agents run measured steps on this organization's data only", async () => {
  const { call } = await setup(); await call("POST", "wazuh/sync", tok.a); await call("POST", "wazuh/sync", tok.b);
  const al = (await J(await call("GET", "alerts", tok.a)))[0];
  const run = (await J(await call("POST", "agents/run", tok.a, { agent: "soc_analyst", alertId: al.id, question: "investigate" }))).run; assert.ok(run, "run recorded");
  assert.equal(run.status, "ok"); assert.equal(run.output.findings.length, 1, "finding kept because it cites stored evidence"); assert.equal(run.model, "stub");
  const runs = await J(await call("GET", "agent-runs", tok.a)); assert.ok(runs.length >= 1); assert.equal((await J(await call("GET", "agent-runs", tok.b))).length, 0, "B sees none of A's runs");
  const roles = ["analyst", "engineer", "hunter", "responder", "siem", "ciso"], done: any = {};
  for (const role of roles) {
    let t = await J(await call("POST", "tasks", tok.a, { role, task: "review current activity" })); const id = t.id, steps = t.stepsTotal;
    assert.equal(t.stepsDone, 0, role + " starts at 0 progress"); let guard = 0;
    while (t.status === "running" && guard++ < 40) { const before = t.stepsDone; t = await J(await call("POST", `tasks/${id}/next`, tok.a)); assert.ok(t.stepsDone >= before && t.progress === Math.round((t.stepsDone / t.stepsTotal) * 100) || t.status !== "running", "progress equals steps done / total"); }
    assert.equal(t.status, "completed", role + " completed: " + (t.error ?? "")); assert.equal(t.stepsDone, steps); assert.ok(t.steps.every((x: any) => x.status === "done" && typeof x.durationMs === "number"), "every step timed by the server");
    assert.ok(t.result?.head, role + " produced a result"); done[role] = t;
  }
  assert.ok(!JSON.stringify(done).includes("VirusTotal") && !JSON.stringify(done).toLowerCase().includes("orgb-host"), "no agent output mentions org B's data");
  const rec = await J(await call("GET", "actions", tok.a)); assert.ok(rec.every((x: any) => ["proposed", "approved", "rejected", "done"].includes(x.status)));
  assert.ok(rec.length >= 1 && rec.every((x: any) => x.status === "proposed"), "disruptive recommendations are only PROPOSED, nothing executed");
  const prop = rec.find((x: any) => x.status === "proposed");
  assert.ok(prop); { assert.equal((await call("POST", `actions/${prop.id}/approve`, tok.an, {})).status, 403, "analyst cannot approve"); assert.equal((await call("POST", `actions/${prop.id}/approve`, tok.b, {})).status, 404, "other organization cannot approve"); assert.equal((await J(await call("GET", "actions", tok.a))).find((x: any) => x.id === prop.id).status, "proposed", "still waiting for a human"); }
  assert.equal((await J(await call("GET", "audit/verify", tok.a))).ok, true);
});

test("AI cannot invent evidence: invented evidence ids are stripped and the finding is flagged unsupported", async () => {
  const { call, deps } = await setup(); await call("POST", "wazuh/sync", tok.a); const al = (await J(await call("GET", "alerts", tok.a)))[0];
  (deps as any).model = async () => ({ text: JSON.stringify({ summary: "x", analysis: "", findings: [{ claim: "Made-up finding", evidence_ids: ["evt_doesnotexist"], confidence: "high" }], recommendations: [], limitations: [] }), model: "stub" });
  const run = (await J(await call("POST", "agents/run", tok.a, { agent: "soc_analyst", alertId: al.id, question: "investigate" }))).run;
  const f = run.output.findings[0]; assert.equal(f.supported, false, "flagged unsupported"); assert.deepEqual(f.evidenceIds, [], "invented id removed"); assert.equal(f.confidence, "low", "confidence forced down"); assert.deepEqual(run.invalidEvidenceIds, ["evt_doesnotexist"], "recorded on the run"); assert.ok(run.output.limitations.some((x: string) => /unsupported/.test(x)), "disclosed to the reader");
});

test("agent enrollment commands: official packages, address required, injection sanitized", async () => {
  const { call } = await setup();
  const w = await J(await call("GET", "wazuh/enrollment?os=windows&version=4.9.2&name=PC-01", tok.a)); const code = JSON.stringify(w);
  assert.match(code, /packages\.wazuh\.com\/4\.x\/windows\/wazuh-agent-4\.9\.2-1\.msi/); assert.match(code, /WAZUH_MANAGER='wazuh-a\.test'/); assert.match(code, /WAZUH_AGENT_NAME='PC-01'/);
  const dn = JSON.stringify(await J(await call("GET", "wazuh/enrollment?os=linux-deb&version=4.9.2&name=x%27;rm%20-rf%20/", tok.a))); assert.ok(!dn.includes("rm -rf") && !dn.includes(";rm"), "agent name sanitized");
  assert.match(JSON.stringify(await J(await call("GET", "wazuh/enrollment?os=linux-rpm&version=4.9.2", tok.a))), /wazuh-agent-4\.9\.2-1\.x86_64\.rpm/);
  assert.equal((await call("GET", "wazuh/enrollment?os=solaris&version=4.9.2", tok.a)).status, 400); assert.equal((await call("GET", "wazuh/enrollment?os=windows&version=latest", tok.a)).status, 400);
  assert.throws(() => enrollment("windows", "evil.com'; calc", "4.9.2"), /agent connection address/);
  assert.equal((await call("GET", "wazuh/enrollment?os=windows&version=4.9.2", tok.b)).status, 200);
  assert.match(JSON.stringify(await J(await call("GET", "wazuh/enrollment?os=windows&version=4.9.2", tok.b))), /wazuh-b\.test/, "each organization gets its own manager address");
});
