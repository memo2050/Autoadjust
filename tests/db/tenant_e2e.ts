// End-to-end tenant test against a REAL Postgres + PostgREST (Supabase-compatible), using the production SupabaseStore.
// Needs: DB with migrations 0100-0106, PostgREST behind a /rest/v1 proxy on :3397, auth.users rows 1..9. See tests/db/README-tenant.md.
import { readFileSync } from "node:fs";
import { createHmac } from "node:crypto";
import assert from "node:assert/strict";
import { SupabaseStore } from "../../lib/soc/store";
import { handleSoc } from "../../lib/soc/api";
import { apiKeyHash } from "../../lib/tenant/auth";
import { sha256 } from "../../lib/soc/util";

const SECRET = readFileSync("/tmp/pgrst/secret.txt", "utf8").trim();
process.env.NOC_SECRET_KEY = "k".repeat(40); process.env.SUPABASE_JWT_SECRET = SECRET; process.env.SOC_ADMIN_TOKEN = "legacy-admin-token-1234567890";
const URL_ = "http://127.0.0.1:3397";
const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (c: Record<string, unknown>) => { const h = b({ alg: "HS256", typ: "JWT" }), p = b({ exp: Math.floor(Date.now() / 1000) + 600, ...c }); return `${h}.${p}.${createHmac("sha256", SECRET).update(h + "." + p).digest("base64url")}`; };
const uid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const user = (n: number) => sign({ sub: uid(n), email: `u${n}@example.com`, role: "authenticated", aud: "authenticated" });
const raw = new SupabaseStore(URL_, sign({ role: "service_role" }));
const call = (method: string, path: string, tok: string, body?: unknown, org?: string) =>
  handleSoc(new Request("http://x/api/soc/" + path, { method, headers: { authorization: "Bearer " + tok, ...(org ? { "x-org-id": org } : {}), "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }), path.split("?")[0].split("/"), { store: raw, model: null });
const J = async (r: Response) => r.json() as Promise<any>;
let n = 0; const ok = (c: unknown, m: string) => { assert.ok(c, m); console.log(`PASS ${++n} | ${m}`); };
const eq = (a: unknown, e: unknown, m: string) => { assert.deepEqual(a, e, m + ` (got ${JSON.stringify(a)})`); console.log(`PASS ${++n} | ${m}`); };

const t0 = Math.floor(Date.now() / 60000) * 60000 - 3 * 3600_000; let rec = 1;
const w = (host: string, id: number, min: number, data: Record<string, string>) => ({ Id: id, RecordId: rec++, TimeCreated: new Date(t0 + min * 60000).toISOString(), ProviderName: "Microsoft-Windows-Security-Auditing", LogName: "Security", MachineName: host, Data: data });
const attack = (host: string) => { const e: unknown[] = []; for (let i = 0; i < 6; i++) e.push(w(host, 4625, i, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "3" })); e.push(w(host, 4624, 7, { TargetUserName: "administrator", IpAddress: "203.0.113.9", LogonType: "10" })); return { host, events: e }; };

(async () => {
  const [alice, bob, carol] = [user(1), user(2), user(3)];
  const A = await J(await call("POST", "org/create", alice, { name: "Org A", slug: "org-a" })), B = await J(await call("POST", "org/create", bob, { name: "Org B", slug: "org-b" }));
  ok(A.id && B.id && A.id !== B.id, "two organizations created through the API (real rows in organizations + org_members)");
  eq((await call("POST", "org/create", bob, { name: "Org A again", slug: "org-a" })).status, 409, "duplicate slug refused");
  const keyA = (await J(await call("POST", "org/keys", alice, { name: "fleet-a" }))).key, keyB = (await J(await call("POST", "org/keys", bob, { name: "fleet-b" }))).key;
  eq((await call("POST", "ingest/windows", keyA, attack("WS01"))).status, 200, "org A collector key ingests (host WS01)");
  eq((await call("POST", "ingest/windows", keyB, attack("WS01"))).status, 200, "org B collector key ingests the SAME host name WS01 (primary-key collision case)");
  const ea = await J(await call("GET", "events?limit=1000", alice)), eb = await J(await call("GET", "events?limit=1000", bob));
  ok(ea.length === 7 && eb.length === 7, "each organization sees exactly its own 7 events");
  ok(ea.every((e: any) => !String(e.id).includes(":")) && !JSON.stringify(ea).includes(B.id), "ids returned to clients are clean and contain no other organization's id");
  eq((await call("GET", "me", bob, undefined, A.id)).status, 403, "bob cannot select organization A with x-org-id");
  eq((await call("POST", "ingest/windows", keyA, attack("ALICE-DC1"))).status, 200, "org A ingests a host only A has");
  const incs = await J(await call("GET", "incidents", alice)); const inc = incs.find((i: any) => JSON.stringify(i).includes("ALICE-DC1") || JSON.stringify(i).toLowerCase().includes("alice-dc1")); ok(inc, "A has an incident for its private host");
  ok(!JSON.stringify(await J(await call("GET", "incidents", bob))).toLowerCase().includes("alice-dc1"), "B's incident list never mentions A's private host");
  eq((await call("GET", `incidents/${inc.id}`, bob)).status, 404, "bob cannot read alice's incident by id");
  eq((await call("PATCH", `incidents/${inc.id}`, bob, { owner: "mallory" })).status, 404, "bob cannot modify alice's incident");
  // invitations + roles on the real tables (including DB triggers)
  const iv = await J(await call("POST", "org/invitations", alice, { email: "u3@example.com", role: "security_analyst" }));
  eq((await call("POST", "org/invitations/accept", user(4), { token: iv.token })).status, 403, "invitation for another email refused");
  eq((await call("POST", "org/invitations/accept", carol, { token: iv.token })).status, 200, "invitee accepts and joins org A");
  eq((await J(await call("GET", "me", carol))).orgRole, "security_analyst", "carol is a security_analyst in A");
  eq((await call("PATCH", `incidents/${inc.id}`, carol, { owner: "carol" })).status, 200, "analyst may update SOC incidents");
  eq((await call("POST", "noc/maps", carol, { name: "x" })).status, 403, "analyst may not write NOC");
  eq((await call("PATCH", `org/members/${uid(1)}`, alice, { role: "it_admin" })).status, 409, "last owner cannot be demoted (app + DB trigger)");
  const v = await J(await call("GET", "audit/verify", alice)); console.log(JSON.stringify(v).slice(0,400)); ok(v.ok === true, "organization A audit chain verifies on the real database");
  eq((await J(await call("GET", "audit/verify", bob))).ok, true, "organization B audit chain verifies");
  // Phase 2: per-organization Wazuh connection stored in the real soc_meta table (encrypted, namespaced per organization)
  const wz = { apiUrl: "https://93.184.216.34:55000", apiUser: "ro", apiPassword: "S3cret-A-pass", indexerUrl: "https://93.184.216.34:9200", indexerUser: "ro", indexerPassword: "S3cret-A-pass", agentManager: "wazuh.acme.example" };
  eq((await call("PUT", "wazuh/config", alice, wz)).status, 200, "org A saves its Wazuh connection (real soc_meta row)");
  eq((await J(await call("GET", "wazuh/config", alice))).apiUser, "ro", "org A reads it back (no password in the response)");
  eq((await J(await call("GET", "wazuh/config", bob))).configured, false, "org B sees no Wazuh connection of A");
  eq((await call("POST", "wazuh/sync", bob)).status, 409, "org B cannot sync using A's connection");
  eq((await call("PUT", "wazuh/config", alice, { ...wz, apiUrl: "https://169.254.169.254" })).status, 400, "metadata address refused");
  // ---- Phase 5: controlled diagnostics on the REAL database path (migration 0108, SupabaseStore, PostgREST) ----
  {
    const devs = (h: string, ip: string) => ({ source: "t", devices: [{ id: h, name: h, type: "server", ip, up: true, metrics: { cpu: 12, mem: 30, disk: 40 } }] });
    eq((await call("POST", "noc/telemetry", keyA, devs("web01", "10.0.0.5"))).status, 200, "org A reports device web01 (real rows)");
    const keysRes = await J(await call("GET", "org/keys", alice)); const keysA = Array.isArray(keysRes) ? keysRes : keysRes.keys; const kid = keysA.find((k: any) => k.name === "fleet-a").id;
    eq((await call("POST", "noc/exec/executors", alice, { hostId: "web01", keyId: kid, os: "linux" })).status, 201, "executor registered (noc_executors row with org_id)");
    eq((await call("POST", "noc/exec/executors", alice, { hostId: "web01", keyId: kid, os: "linux" })).status, 409, "one enabled executor per host (application check; unique index is the second lock)");
    eq((await call("POST", "noc/diag", alice, { hostId: "web01", template: "sys.uptime" })).status, 409, "execution is OFF by default in the real database");
    eq((await call("PUT", "noc/exec/settings", bob, { enabled: true })).status, 200 /* bob owns org B only */, "bob can switch on HIS organization only");
    eq((await J(await call("GET", "noc/exec/settings", alice))).enabled, false, "...which did not switch on organization A");
    eq((await call("PUT", "noc/exec/settings", alice, { enabled: true })).status, 200, "owner A switches execution on (soc_meta row, org-namespaced)");
    const job = await J(await call("POST", "noc/diag", alice, { hostId: "web01", template: "log.tail", params: { unit: "cron.service", n: 7 }, reason: "check cron" })); eq(job.status, "queued", "job queued (params jsonb, nonce, timestamps stored)");
    const row = (await raw.select<any>("noc_diag_jobs", { where: { orgId: A.id } as any }))[0]; ok(row && row.orgId === A.id && row.params.n === "7" && row.status === "queued", "stored row carries org_id of A and the validated params");
    const poll = await J(await call("GET", "noc/executor/jobs?host=web01", keyA)); ok(poll.jobs.length === 1 && poll.jobs[0].orgId === A.id, "executor (org A key) leases the job");
    const jb = poll.jobs[0], kh = apiKeyHash(keyA);
    const sig = createHmac("sha256", kh).update(["v1", jb.id, jb.orgId, jb.hostId, jb.template, "n=7&unit=cron.service", jb.expiresAt, jb.nonce, jb.leaseId].join("|")).digest("hex"); eq(sig, jb.sig, "job signature verifies against the key-derived secret (real stored hash)");
    const out = "-- cron log --\npassword=hunter2\n"; const rs = createHmac("sha256", kh).update(["v1result", jb.id, jb.leaseId, 0, 0, sha256(out)].join("|")).digest("hex");
    eq((await call("POST", `noc/executor/jobs/${jb.id}/result`, keyA, { leaseId: jb.leaseId, exitCode: 0, timedOut: false, output: out, sig: rs })).status, 200, "result accepted once");
    eq((await call("POST", `noc/executor/jobs/${jb.id}/result`, keyA, { leaseId: jb.leaseId, exitCode: 0, timedOut: false, output: out, sig: rs })).status, 409, "duplicate result refused (real DB state)");
    const done = await J(await call("GET", `noc/diag/${jb.id}`, alice)); ok(done.status === "succeeded" && done.exitCode === 0 && !done.output.includes("hunter2") && done.requestedBy === "u1@example.com", "persisted result: succeeded, exit_code integer, secret redacted, requester recorded");
    eq((await call("GET", `noc/diag/${jb.id}`, bob)).status, 404, "org B cannot read A's job");
    eq((await J(await call("GET", "noc/diag", bob))).length, 0, "org B's job list is empty");
    eq((await call("GET", "noc/executor/jobs?host=web01", keyB)).status, 403, "org B's key is not bound to any executor on that host");
    const st = await J(await call("GET", "noc/exec/stats", alice)); ok(st.history.length === 1 && st.rates[0].successRatePct === 100, "dashboard stats computed from real rows");
    const aiN = await call("POST", "noc/ai/analyze", alice, { deviceId: "web01" }); eq(aiN.status, 200, "AI NOC analysis runs over real rows"); ok(!JSON.stringify(await J(aiN)).includes(B.id), "...and contains nothing from organization B");
    eq((await call("POST", "noc/ai/analyze", bob, { deviceId: "web01" })).status, 404, "org B cannot analyze A's device name");
    const aiS = await call("POST", "ai/analyze", alice, {}); eq(aiS.status, 200, "AI SOC analysis runs over real rows");
    const audit = (await J(await call("GET", "audit?limit=500", alice))); ok(JSON.stringify(audit).includes("noc.diag.request") && JSON.stringify(audit).includes("noc.diag.result") && JSON.stringify(audit).includes("noc.exec.enabled"), "request, execution result and the enable switch are in the audit chain");
  }
  // direct, human-level API access with a user JWT (what a malicious browser client could try with the public anon URL)
  const direct = async (tok: string, path: string, init: RequestInit = {}) => fetch(URL_ + "/rest/v1/" + path, { ...init, headers: { apikey: "x", authorization: "Bearer " + tok, "content-type": "application/json", ...(init.headers ?? {}) } });
  for (const t of ["soc_events", "soc_audit", "noc_devices", "noc_diag_jobs", "noc_executors", "org_api_keys", "soc_meta", "soc_kev", "app_records"]) { const r = await direct(bob, t + "?select=*"); const body = r.ok ? await r.json() : null; ok(!r.ok || (Array.isArray(body) && body.length === 0), `direct API with bob's JWT: ${t} returns nothing (${r.status})`); }
  const mem = await (await direct(bob, "org_members?select=org_id,user_id")).json(); ok(Array.isArray(mem) && mem.every((m: any) => m.org_id === B.id), "RLS: bob sees only organization B's members directly");
  const orgs = await (await direct(bob, "organizations?select=id")).json(); eq(orgs.map((o: any) => o.id), [B.id], "RLS: bob sees only organization B");
  const ins = await direct(bob, "org_members", { method: "POST", body: JSON.stringify({ org_id: A.id, user_id: uid(2), role: "owner" }) }); ok(!ins.ok, `RLS: bob cannot add himself to org A (${ins.status})`);
  const key = await direct(bob, "org_api_keys?select=*"); ok(!key.ok, "org_api_keys is not exposed to signed-in users");
  const anon = await fetch(URL_ + "/rest/v1/org_members?select=*", { headers: { apikey: "x" } }); ok(!anon.ok || (await anon.json()).length === 0, "anonymous caller sees no members");
  console.log(`E2E OK: ${n} checks`);
})().catch((e) => { console.error("FAIL", e.message); process.exit(1); });
