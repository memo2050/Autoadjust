// Phase 5 – controlled execution framework. The server side runs for real (handleSoc + ScopedStore + audit chain); the host side is simulated here
// with an executor implementing the same crypto; the REAL bash executor is tested separately in tests/live/executor-e2e.ts.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { ScopedStore } from "../lib/tenant/scoped-store";
import { apiKeyHash } from "../lib/tenant/auth";
import * as XJ from "../lib/noc/exec/jobs";
import { CATALOG, auditCatalog, validateParams, forbiddenTarget, DENY_PROGRAMS, type Template } from "../lib/noc/exec/catalog";
import { redact } from "../lib/noc/exec/redact";
import { sha256 } from "../lib/soc/util";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const U = { owner: "", admin: "", noc: "", sec: "", ro: "", bOwner: "" }; const tok = { ...U }; let worldNo = 0;
function freshIdentities() { worldNo++; for (const k of Object.keys(U) as Array<keyof typeof U>) { U[k] = randomUUID(); tok[k] = jwt(U[k], `${k}${worldNo}@x.io`); } }   // new names per test: the API rate limiter is keyed by user
const J = async (r: Response) => r.json() as Promise<any>;

async function world() {
  freshIdentities(); const s = new TestStore();
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a" }, { id: ORG_B, name: "Org B", slug: "org-b" }] as any);
  const m = (orgId: string, userId: string, role: string) => s.upsert("org_members", [{ orgId, userId, role }] as any, "org_id,user_id");
  await m(ORG_A, U.owner, "owner"); await m(ORG_A, U.admin, "it_admin"); await m(ORG_A, U.noc, "noc_operator"); await m(ORG_A, U.sec, "security_analyst"); await m(ORG_A, U.ro, "executive_readonly"); await m(ORG_B, U.bOwner, "owner");
  const call = (m: string, p: string, t: string, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method: m, headers: { authorization: "Bearer " + t, "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("?")[0].split("/"), { store: s, model: null } as any);
  const mkKey = async (t: string, name: string) => { const r = await J(await call("POST", "org/keys", t, { name })); return { raw: r.key as string, id: r.id as string }; };
  const kA = await mkKey(tok.owner, "exec-a"), kA2 = await mkKey(tok.owner, "exec-a-other"), kB = await mkKey(tok.bOwner, "exec-b");
  for (const [k, ip, nm] of [[kA, "10.0.0.5", "web01"], [kA, "10.0.0.6", "db01"]] as const) await call("POST", "noc/telemetry", k.raw, { source: "t", devices: [{ id: nm, name: nm, type: "server", ip, up: true, metrics: { cpu: 10 } }] });
  await call("POST", "noc/telemetry", kB.raw, { source: "t", devices: [{ id: "web01", name: "web01", type: "server", ip: "10.9.9.5", up: true, metrics: { cpu: 10 } }] });
  const reg = (t: string, hostId: string, key: { id: string }, os = "linux") => call("POST", "noc/exec/executors", t, { hostId, keyId: key.id, os });
  // a simulated executor with the same crypto as the real one
  const exe = (key: { raw: string }, hostId: string) => ({
    poll: async () => J(await call("GET", `noc/executor/jobs?host=${hostId}`, key.raw)),
    verify: (j: any) => createHmac("sha256", apiKeyHash(key.raw)).update(["v1", j.id, j.orgId, j.hostId, j.template, Object.keys(j.params).sort().map((k) => `${k}=${j.params[k]}`).join("&"), j.expiresAt, j.nonce, j.leaseId].join("|")).digest("hex") === j.sig,
    report: (j: any, o: { exit?: number; out?: string; timedOut?: boolean; sig?: string; lease?: string }) => { const out = o.out ?? "ok\n", exit = o.exit ?? 0, to = o.timedOut ?? false;
      const sig = o.sig ?? createHmac("sha256", apiKeyHash(key.raw)).update(["v1result", j.id, j.leaseId, exit, to ? 1 : 0, sha256(out)].join("|")).digest("hex");
      return call("POST", `noc/executor/jobs/${j.id}/result`, key.raw, { leaseId: o.lease ?? j.leaseId, exitCode: exit, timedOut: to, output: out, sig, startedAt: new Date().toISOString() }); },
  });
  const xc = (org: string, name = "test", pr?: any, now?: () => number) => ({ store: new ScopedStore(s, org), actor: { name, role: "admin" }, orgId: org, pr, now }) as XJ.ExecCtx;
  return { s, call, kA, kA2, kB, reg, exe, xc };
}
const enable = (w: any) => w.call("PUT", "noc/exec/settings", tok.owner, { enabled: true });
const ask = (w: any, t: string, body: any) => w.call("POST", "noc/diag", t, body);

test("catalog: passes its own safety audit; unsafe catalogs are rejected; deny-list covers shells, restarts, firewall, accounts, deletion", () => {
  assert.deepEqual(auditCatalog(), []);
  assert.equal(CATALOG.length, 11); assert.ok(!CATALOG.some((t) => t.id === "sec.logons"), "sec.logons is deferred to a later phase"); assert.ok(CATALOG.every((t) => t.tier === "R0"));
  const mk = (over: Partial<Template> & { linux?: any }): Template => ({ id: "x.y", title: "x", tier: "R0", params: {}, timeoutSec: 5, maxLines: 5, maxBytes: 500, ...over });
  assert.ok(auditCatalog([mk({ linux: { argv: ["bash", "-c", "id"] } })]).length, "shell");
  assert.ok(auditCatalog([mk({ linux: { argv: ["/bin/sh", "x"] } })]).length, "path-qualified shell");
  assert.ok(auditCatalog([mk({ linux: { argv: ["systemctl", "restart", "nginx"] } })]).length, "restart");
  assert.ok(auditCatalog([mk({ linux: { argv: ["iptables", "-F"] } })]).length, "firewall");
  assert.ok(auditCatalog([mk({ linux: { argv: ["useradd", "x"] } })]).length, "accounts");
  assert.ok(auditCatalog([mk({ linux: { argv: ["rm", "-rf", "/"] } })]).length, "deletion");
  assert.ok(auditCatalog([mk({ linux: { argv: ["ls", "a;b"] } })]).length, "metachar");
  assert.ok(auditCatalog([mk({ windows: { ps: "Restart-Service x" } })]).length, "PowerShell Restart-");
  assert.ok(auditCatalog([mk({ windows: { ps: "Get-Process | Stop-Process" } })]).length, "PowerShell Stop-");
  assert.ok(auditCatalog([mk({ windows: { ps: "iex $env:AA_P_X" } })]).length, "iex");
  assert.ok(auditCatalog([mk({ timeoutSec: 600 })]).length, "timeout above hard max");
  assert.ok(auditCatalog([mk({ tier: "R1" as any })]).length, "tier R1 not allowed in v1");
  for (const p of ["shutdown", "reboot", "curl", "wget", "sudo", "ssh", "nft", "chmod"]) assert.ok(DENY_PROGRAMS.includes(p), p);
  for (const t of CATALOG) for (const os of ["linux", "windows"] as const) { const c: any = (t as any)[os]; if (c?.argv) assert.ok(!DENY_PROGRAMS.includes(c.argv[0]), t.id); }
});

test("parity: the executor script and the server catalog agree on templates, timeouts, line and byte limits", () => {
  const sh = readFileSync(new URL("../collector/noc-agent/auto-adjust-linux-agent.sh", import.meta.url), "utf8");
  const grab = (name: string) => Object.fromEntries([...sh.match(new RegExp(`declare -A ${name}=\\(([^)]*)\\)`))![1].matchAll(/\[([a-z._]+)\]=(\d+)/g)].map((m) => [m[1], Number(m[2])]));
  const to = grab("T_TIMEOUT"), ln = grab("T_LINES"), by = grab("T_BYTES");
  assert.deepEqual(Object.keys(to).sort(), CATALOG.map((t) => t.id).sort());
  for (const t of CATALOG) { assert.equal(to[t.id], t.timeoutSec, t.id + " timeout"); assert.equal(ln[t.id], t.maxLines, t.id + " lines"); assert.equal(by[t.id], t.maxBytes, t.id + " bytes"); }
  for (const t of CATALOG) { const c: any = t.linux; if (c?.argv) assert.ok(sh.includes(c.argv[0]), t.id + " program present in executor"); if (c?.fallback) assert.ok(sh.includes("proc_listen") && sh.includes("__proc_listen"), t.id + " fallback is implemented in the executor"); }
  assert.ok(!/policy_has target ['"]?\*/.test(sh) && /policy_targets_ok/.test(sh), "no wildcard target acceptance remains in the Linux executor; wildcard rules are rejected");
});

test("parameter validation: injection corpus is rejected for every parameter type", () => {
  const evil = ["; rm -rf /", "$(id)", "`id`", "a b", "a\nb", "a|b", "a&&b", "../../etc/passwd", "-rf", "--help", "a\u0000b", "ａｄｍｉｎ", "x".repeat(300), "a>b", "a'b", 'a"b', "${IFS}x", "nginx.service;id"];
  const unit = CATALOG.find((t) => t.id === "svc.status")!, ping = CATALOG.find((t) => t.id === "net.ping")!, tail = CATALOG.find((t) => t.id === "log.tail")!, reach = CATALOG.find((t) => t.id === "net.reach")!, dns = CATALOG.find((t) => t.id === "dns.lookup")!;
  for (const e of evil) { assert.throws(() => validateParams(unit, "linux", { unit: e }), e); assert.throws(() => validateParams(ping, "linux", { host: e }), e); assert.throws(() => validateParams(dns, "linux", { name: e }), e); assert.throws(() => validateParams(tail, "linux", { unit: e, n: 10 }), e); }
  for (const n of [0, 201, -1, "1e3", "10;id", 1.5, "0x10"]) assert.throws(() => validateParams(tail, "linux", { unit: "nginx", n }), String(n));
  for (const p of [0, 65536, "80;id", -1, "abc"]) assert.throws(() => validateParams(reach, "linux", { host: "10.0.0.5", port: p }), String(p));
  assert.throws(() => validateParams(unit, "linux", { unit: "nginx", extra: "x" }), "unknown parameter");
  assert.throws(() => validateParams(tail, "linux", { unit: "nginx", n: 5, log: "System" }), "log is Windows-only");
  assert.throws(() => validateParams(tail, "windows", { log: "Security", n: 5 }), "only Application/System");
  assert.deepEqual(validateParams(tail, "linux", { unit: "nginx.service", n: "50" }), { unit: "nginx.service", n: "50" });
  assert.deepEqual(validateParams(tail, "windows", { log: "System", n: 5 }), { log: "System", n: "5" });
  for (const bad of ["127.0.0.1", "127.9.9.9", "169.254.169.254", "0.0.0.0", "224.0.0.1", "localhost", "foo.localhost"]) assert.ok(forbiddenTarget(bad), bad);
  assert.equal(forbiddenTarget("10.0.0.5"), null);
});

test("secrets are redacted from host output, audit details and reasons", () => {
  const raw = "token=abc123SECRETvalue\npassword: hunter2\nAuthorization: Bearer eyJhbGciOi.eyJzdWIiOiIx.abcdefgh12345\nkey aa_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\nAKIAABCDEFGHIJKLMNOP\npostgres://user:s3cr3t@db:5432/x\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nnormal line cpu 12%";
  const r = redact(raw); for (const leak of ["abc123SECRETvalue", "hunter2", "eyJhbGciOi", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "AKIAABCDEFGHIJKLMNOP", "s3cr3t", "MIIabc"]) assert.ok(!r.includes(leak), "leaked " + leak);
  assert.ok(r.includes("normal line cpu 12%"));
});

test("execution is OFF by default; dry-run still works; only the organization OWNER can switch it on", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA);
  assert.equal((await J(await w.call("GET", "noc/exec/settings", tok.noc))).enabled, false);
  let r = await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" }); assert.equal(r.status, 409, "live request refused while off");
  r = await ask(w, tok.noc, { hostId: "web01", template: "svc.status", params: { unit: "nginx.service" }, dryRun: true }); assert.equal(r.status, 201); const d = await J(r);
  assert.equal(d.status, "dry_run_done"); assert.match(d.argvPreview, /systemctl show nginx\.service/); assert.ok(d.policy.length >= 3);
  for (const who of ["admin", "noc", "sec", "ro"] as const) assert.equal((await w.call("PUT", "noc/exec/settings", tok[who], { enabled: true })).status, 403, who + " cannot enable");
  assert.equal((await w.call("PUT", "noc/exec/settings", w.kA.raw, { enabled: true })).status, 403, "an API key cannot enable");
  assert.equal((await w.call("PUT", "noc/exec/settings", tok.owner, { enabled: "yes" })).status, 400);
  assert.equal((await enable(w)).status, 200); assert.equal((await J(await w.call("GET", "noc/exec/settings", tok.ro))).enabled, true);
  const dry = await J(await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime", dryRun: true })); assert.equal((await w.s.select<any>("noc_diag_jobs", {})).filter((x: any) => x.status === "queued").length, 0, "dry-run never queues");
  assert.ok(dry.id);
});

test("role matrix: read-only role may dry-run but not run; operators and analysts may request read-only diagnostics; admin registers executors", async () => {
  const w = await world(); assert.equal((await w.reg(tok.noc, "web01", w.kA)).status, 403); assert.equal((await w.reg(tok.sec, "web01", w.kA)).status, 403); assert.equal((await w.reg(tok.ro, "web01", w.kA)).status, 403);
  assert.equal((await w.reg(tok.admin, "web01", w.kA)).status, 201); await enable(w);
  assert.equal((await ask(w, tok.ro, { hostId: "web01", template: "sys.uptime" })).status, 403);
  assert.equal((await ask(w, tok.ro, { hostId: "web01", template: "sys.uptime", dryRun: true })).status, 201);
  assert.equal((await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" })).status, 201);
  assert.equal((await ask(w, tok.sec, { hostId: "web01", template: "sys.mem" })).status, 201);
  assert.equal((await ask(w, w.kA.raw, { hostId: "web01", template: "sys.mem" })).status, 403, "a collector key cannot request diagnostics");
  assert.equal((await ask(w, "bad", { hostId: "web01", template: "sys.mem" })).status, 401);
});

test("policy engine: unknown template, unknown host, unregistered / loopback / metadata targets, shell strings are all refused (and audited)", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  const bad = async (body: any, code = 400) => assert.equal((await ask(w, tok.noc, body)).status, code, JSON.stringify(body));
  await bad({ hostId: "web01", template: "rm -rf /" }); await bad({ hostId: "web01", template: "svc.restart", params: { unit: "x" } }); await bad({ hostId: "web01", template: "sys.uptime", params: { x: 1 } });
  await bad({ hostId: "nohost", template: "sys.uptime" }, 404); await bad({ hostId: "web01", template: "net.ping", params: { host: "127.0.0.1" } }); await bad({ hostId: "web01", template: "net.ping", params: { host: "169.254.169.254" } });
  await bad({ hostId: "web01", template: "net.ping", params: { host: "8.8.8.8" } }); await bad({ hostId: "web01", template: "net.reach", params: { host: "10.0.0.6", port: "22;id" } }); await bad({ hostId: "web01", template: "svc.status", params: { unit: "nginx; reboot" } });
  assert.equal((await ask(w, tok.noc, { hostId: "web01", template: "net.ping", params: { host: "10.0.0.6" } })).status, 201, "registered device is a valid target");
  assert.equal((await ask(w, tok.noc, { hostId: "web01", template: "net.reach", params: { host: "db01", port: 5432 } })).status, 201, "registered by name");
  const audits = (await w.s.select<any>("soc_audit", {})).map((a: any) => a.action); assert.ok(audits.includes("noc.diag.rejected_by_policy"));
});

test("full flow: request -> signed job -> executor verifies -> result -> history; incident is NOT resolved by a successful command", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  const store = new ScopedStore(w.s, ORG_A); await store.upsert("noc_incidents", [{ id: "inc1", title: "High CPU", severity: "high", status: "Investigating", host: "web01", sourceId: "native", eventIds: [], executionIds: [], assignedAgent: "server", category: "server", createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" }] as any);
  const job = await J(await ask(w, tok.noc, { hostId: "web01", template: "sys.cpu_top", incidentId: "inc1", reason: "CPU alert" })); assert.equal(job.status, "queued"); assert.ok(job.expiresAt);
  const e = w.exe(w.kA, "web01"), p = await e.poll(); assert.equal(p.jobs.length, 1); const j = p.jobs[0]; assert.equal(j.template, "sys.cpu_top"); assert.ok(e.verify(j), "signature verifies with the key-derived secret"); assert.equal(j.orgId, ORG_A);
  assert.equal((await e.poll()).jobs.length, 0, "one job per host at a time / no double lease");
  const res = await J(await e.report(j, { out: "PID %CPU\n1 99.0 init\n" })); assert.equal(res.status, "succeeded");
  const done = await J(await w.call("GET", `noc/diag/${job.id}`, tok.noc)); assert.equal(done.status, "succeeded"); assert.match(done.requestedBy, /^noc\d+@x\.io$/); assert.ok(done.requestedAt && done.leasedAt && done.endedAt); assert.match(done.note, /not proof/);
  const inc = await store.get<any>("noc_incidents", "inc1"); assert.equal(inc.status, "Investigating", "a completed command never resolves an incident");
  const list = await J(await w.call("GET", "noc/diag?incident=inc1", tok.ro)); assert.equal(list.length, 1);
  const st = await J(await w.call("GET", "noc/exec/stats", tok.ro)); assert.equal(st.history.length, 1); assert.equal(st.rates[0].successRatePct, 100); assert.equal(st.executors[0].online, true);
  const audits = (await w.s.select<any>("soc_audit", {})).filter((a: any) => a.action.startsWith("noc.diag.")); const acts = audits.map((a: any) => a.action); for (const a of ["noc.diag.request", "noc.diag.lease", "noc.diag.result"]) assert.ok(acts.includes(a), a);
  assert.ok(/noc\d+@x\.io/.test(JSON.stringify(audits)), "requester recorded in audit"); assert.ok(!JSON.stringify(audits).includes(w.kA.raw), "API key never in audit");
});

test("replay, duplicate and tamper protection: result accepted once; wrong lease / bad signature / other key / expired job refused", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" }); const e = w.exe(w.kA, "web01"); const j = (await e.poll()).jobs[0];
  assert.equal((await e.report(j, { sig: "0".repeat(64) })).status, 403, "bad signature"); assert.equal((await e.report(j, { lease: "other" })).status, 403, "wrong lease");
  assert.equal((await w.exe(w.kA2, "web01").report(j, {})).status, 403, "a different key (even same org) is not bound to this host");
  assert.equal((await w.exe(w.kB, "web01").report(j, {})).status, 404, "another organization cannot even see the job");
  assert.equal((await e.report(j, {})).status, 200); assert.equal((await e.report(j, {})).status, 409, "duplicate result");
  assert.equal((await e.report(j, { out: "tampered" })).status, 409);
  assert.equal((await e.poll()).jobs.length, 0, "a finished job is never handed out again");
  const rejected = (await w.s.select<any>("soc_audit", {})).filter((a: any) => a.action === "noc.diag.result_rejected"); assert.ok(rejected.length >= 4);
});

test("tampered output is detected: the signature covers the output hash", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w); await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" });
  const e = w.exe(w.kA, "web01"); const j = (await e.poll()).jobs[0];
  const goodSig = createHmac("sha256", apiKeyHash(w.kA.raw)).update(["v1result", j.id, j.leaseId, 0, 0, sha256("original")].join("|")).digest("hex");
  assert.equal((await e.report(j, { out: "modified in transit", sig: goodSig })).status, 403);
  assert.equal((await e.report(j, { out: "original", sig: goodSig })).status, 200);
});

test("expiry: queued jobs expire; a leased job whose executor never reports expires and a late result is refused", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w); const e = w.exe(w.kA, "web01");
  const q = await J(await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" })); await XJ.expireStale(w.xc(ORG_A, "sys", undefined, () => Date.parse(q.expiresAt) + 1000));
  assert.equal((await J(await w.call("GET", `noc/diag/${q.id}`, tok.noc))).status, "expired"); assert.equal((await e.poll()).jobs.length, 0, "expired job not handed out");
  const q2 = await J(await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" })); const j = (await e.poll()).jobs[0]; assert.equal(j.id, q2.id);
  await XJ.expireStale(w.xc(ORG_A, "sys", undefined, () => Date.now() + 10 * 60_000));
  assert.equal((await J(await w.call("GET", `noc/diag/${q2.id}`, tok.noc))).status, "expired"); assert.equal((await e.report(j, {})).status, 409, "late result after lease expiry");
});

test("kill switch: turning execution off stops job delivery immediately; revoking executor binding stops the host", async () => {
  const w = await world(); const reg = await J(await w.reg(tok.owner, "web01", w.kA)); await enable(w); await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" }); const e = w.exe(w.kA, "web01");
  await w.call("PUT", "noc/exec/settings", tok.owner, { enabled: false }); let p = await e.poll(); assert.equal(p.jobs.length, 0); assert.equal(p.executionEnabled, false);
  await enable(w); await w.call("POST", `noc/exec/executors/${reg.id}/disable`, tok.admin); assert.equal((await w.call("GET", "noc/executor/jobs?host=web01", w.kA.raw)).status, 403);
});

test("AI agents can only PROPOSE: a human must confirm; an agent can never approve; proposals expire", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  const agent = w.xc(ORG_A, "agent:noc-analyst"); const prop = await XJ.requestDiag(agent, { hostId: "web01", template: "sys.disk", reason: "disk alert", evidenceIds: ["nev_1"] });
  assert.equal(prop.status, "proposed"); assert.equal(prop.requestedByKind, "agent"); assert.equal((await w.exe(w.kA, "web01").poll()).jobs.length, 0, "proposal is not deliverable");
  await assert.rejects(() => XJ.confirmJob(agent, prop.id, "approve"), /AI agent can never/);
  const ok = await J(await w.call("POST", `noc/diag/${prop.id}/approve`, tok.noc, {})); assert.equal(ok.status, "queued"); assert.match(ok.approvedBy, /^noc\d+@x\.io$/); assert.equal(ok.requestedBy, "agent:noc-analyst");
  assert.equal((await w.exe(w.kA, "web01").poll()).jobs.length, 1);
  const p2 = await XJ.requestDiag(agent, { hostId: "web01", template: "sys.mem" }); assert.equal((await w.call("POST", `noc/diag/${p2.id}/approve`, tok.ro, {})).status, 403, "read-only role cannot confirm");
  assert.equal((await w.call("POST", `noc/diag/${p2.id}/reject`, tok.noc, { note: "not needed" })).status, 200);
  const p3 = await XJ.requestDiag(agent, { hostId: "web01", template: "sys.load" }); const late = w.xc(ORG_A, "human@x", undefined, () => Date.now() + 40 * 60_000);
  await assert.rejects(() => XJ.confirmJob(late, p3.id, "approve"), /expired/);
});

test("two-person rule for change-type (future R1) requests: requester cannot approve; another human can; AI never; read-only/other roles blocked (mechanism test with an injected template)", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  const r1: Template = { id: "test.change", title: "future change", tier: "R1", params: {}, timeoutSec: 10, maxLines: 5, maxBytes: 500, linux: { argv: ["uptime"] } };
  const cat = [...CATALOG, r1]; const mk = (name: string) => ({ ...w.xc(ORG_A, name), catalog: cat });
  const req = await XJ.requestDiag(mk("alice@x"), { hostId: "web01", template: "test.change" }); assert.equal(req.status, "awaiting_approval");
  assert.equal((await w.exe(w.kA, "web01").poll()).jobs.length, 0, "unapproved change is never delivered");
  await assert.rejects(() => XJ.confirmJob(mk("alice@x"), req.id, "approve"), /Two-person rule/);
  await assert.rejects(() => XJ.confirmJob(mk("agent:noc-analyst"), req.id, "approve"), /AI agent/);
  const done = await XJ.confirmJob(mk("bob@x"), req.id, "approve"); assert.equal(done.status, "queued"); assert.equal(done.approvedBy, "bob@x"); assert.equal(done.requestedBy, "alice@x");
});

test("limits: 5 pending per host, then 429; unknown/over-limit never reach the executor", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w);
  for (let i = 0; i < 5; i++) assert.equal((await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" })).status, 201);
  assert.equal((await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" })).status, 429);
});

test("results: output is redacted again on the server and capped by lines and bytes; non-zero exit = failed; timeout = timed_out", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await enable(w); const e = w.exe(w.kA, "web01");
  await ask(w, tok.noc, { hostId: "web01", template: "sys.load" }); let j = (await e.poll()).jobs[0]; // maxLines 5
  await e.report(j, { out: Array.from({ length: 50 }, (_, i) => `line ${i} password=hunter2`).join("\n") });
  let g = await J(await w.call("GET", `noc/diag/${j.id}`, tok.noc)); assert.equal(g.output.split("\n").length, 5); assert.ok(g.truncated); assert.ok(!g.output.includes("hunter2"));
  await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" }); j = (await e.poll()).jobs[0]; await e.report(j, { exit: 3, out: "boom" });
  g = await J(await w.call("GET", `noc/diag/${j.id}`, tok.noc)); assert.equal(g.status, "failed"); assert.match(g.error, /code 3/);
  await ask(w, tok.noc, { hostId: "web01", template: "sys.mem" }); j = (await e.poll()).jobs[0]; await e.report(j, { exit: 124, timedOut: true, out: "" });
  g = await J(await w.call("GET", `noc/diag/${j.id}`, tok.noc)); assert.equal(g.status, "timed_out");
  const st = await J(await w.call("GET", "noc/exec/stats", tok.noc)); assert.equal(st.rates[0].finished, 3); assert.equal(st.rates[0].succeeded, 1); assert.equal(st.rates[0].failed, 1); assert.equal(st.rates[0].timedOut, 1);
});

test("organization isolation: B cannot read, approve, cancel or poll A's jobs/executors; keys cannot be bound across organizations; stats are per organization", async () => {
  const w = await world(); const reg = await J(await w.reg(tok.owner, "web01", w.kA)); await enable(w); const job = await J(await ask(w, tok.noc, { hostId: "web01", template: "sys.uptime" }));
  assert.equal((await w.call("GET", `noc/diag/${job.id}`, tok.bOwner)).status, 404); assert.equal((await w.call("POST", `noc/diag/${job.id}/cancel`, tok.bOwner)).status, 404); assert.equal((await w.call("POST", `noc/diag/${job.id}/approve`, tok.bOwner, {})).status, 404);
  assert.equal((await w.call("POST", `noc/exec/executors/${reg.id}/disable`, tok.bOwner)).status, 404);
  assert.deepEqual(await J(await w.call("GET", "noc/diag", tok.bOwner)), []); assert.equal((await J(await w.call("GET", "noc/exec/stats", tok.bOwner))).executors.length, 0);
  assert.equal((await w.reg(tok.bOwner, "web01", w.kA)).status, 404, "B cannot bind A's key");
  assert.equal((await w.call("POST", "noc/exec/executors", tok.bOwner, { hostId: "web01", keyId: w.kB.id, os: "linux" })).status, 201);
  assert.equal((await w.call("GET", "noc/executor/jobs?host=web01", w.kB.raw)).status, 200); assert.equal((await J(await w.call("GET", "noc/executor/jobs?host=web01", w.kB.raw))).jobs.length, 0, "B's executor on the same host name gets nothing of A's");
  assert.equal((await J(await w.call("GET", "noc/executor/jobs?host=web01", w.kB.raw))).executionEnabled, false, "B has not enabled execution");
  assert.equal((await ask(w, tok.bOwner, { hostId: "web01", template: "net.ping", params: { host: "10.0.0.5" } })).status, 400, "policy runs before the on/off check: A's address is not B's device");
  await w.call("PUT", "noc/exec/settings", tok.bOwner, { enabled: true }); assert.equal((await ask(w, tok.bOwner, { hostId: "web01", template: "net.ping", params: { host: "10.0.0.5" } })).status, 400, "A's device address is not a valid target for B");
});

test("the production catalog contains no change-type or restart capability", () => {
  const all = JSON.stringify(CATALOG); for (const w of ["restart", "start ", "stop", "kill", "shutdown", "reboot", "iptables", "netsh", "useradd", "rm -", "Set-", "Remove-"]) assert.ok(!all.toLowerCase().includes(w.toLowerCase()) || w === "start " || w === "stop", w);
  assert.ok(!CATALOG.some((t) => /restart|reboot|firewall|account/i.test(t.id)));
});

test("owner decisions: sec.logons is gone; Windows log.tail can never read the Security log; net.* targets are same-org registered devices only; unsupported is never success", async () => {
  const w = await world(); await w.reg(tok.owner, "web01", w.kA); await w.reg(tok.owner, "db01", w.kA2); await enable(w);
  // 1. sec.logons: not in catalog, API refuses it (and it is audited), nothing queued
  const r1 = await ask(w, tok.noc, { hostId: "web01", template: "sec.logons" }); assert.ok(r1.status >= 400, "sec.logons refused"); assert.equal((await J(await w.call("GET", "noc/diag", tok.noc))).filter((j: any) => j.status === "queued").length, 0);
  assert.ok(!readFileSync(new URL("../collector/noc-agent/auto-adjust-linux-agent.sh", import.meta.url), "utf8").includes("sec.logons"), "linux agent has no sec.logons");
  const ps = readFileSync(new URL("../collector/noc-agent/Auto-Adjust-Windows-Agent.ps1", import.meta.url), "utf8"); assert.ok(!ps.includes("sec.logons") && !/LogName\s*=\s*'Security'/i.test(ps) && !/'Security'/.test(ps.split("$XT = @{")[1].split("$RE_UNIT")[0]), "windows agent has no Security log read");
  // 2. log.tail on Windows: only Application / System
  const lt = CATALOG.find((t) => t.id === "log.tail")!;
  assert.deepEqual(validateParams(lt, "windows", { log: "System", n: 5 }), { log: "System", n: "5" }); assert.deepEqual(validateParams(lt, "windows", { log: "Application", n: 200 }), { log: "Application", n: "200" });
  for (const bad of ["Security", "security", "Microsoft-Windows-PowerShell/Operational", "System; Security", "*", ""]) assert.throws(() => validateParams(lt, "windows", { log: bad, n: 5 }), /./, bad);
  assert.throws(() => validateParams(lt, "windows", { log: "System", n: 201 })); assert.throws(() => validateParams(lt, "windows", { log: "System", n: 5, unit: "x" }), /./, "linux-only param on windows");
  // 3. net.ping / net.reach: wildcard and unregistered targets refused; registered same-org device accepted; other org's device refused
  for (const host of ["*", "10.0.0.0/24", "10.0.0.*", "all", "8.8.8.8", "10.9.9.5", "127.0.0.1", "169.254.169.254"]) { const r = await ask(w, tok.noc, { hostId: "web01", template: "net.ping", params: { host } }); assert.ok(r.status >= 400, `net.ping ${host} refused`); }
  const okr = await ask(w, tok.noc, { hostId: "web01", template: "net.ping", params: { host: "10.0.0.6" } }); assert.ok(okr.status < 300, "registered same-org device accepted");
  // 4. unsupported: executor says tool missing -> status unsupported, never succeeded; a bare exit 127 without the executor's marker stays failed
  const e = w.exe(w.kA2, "db01");
  const j2 = await J(await ask(w, tok.noc, { hostId: "db01", template: "net.listen" })); const p2 = (await e.poll()).jobs[0]; assert.ok(p2);
  const r2 = await J(await e.report(p2, { exit: 127, out: "UNSUPPORTED: the required tool 'ss' is not installed on this host. Nothing was run.\n" })); assert.equal(r2.status, "unsupported");
  const g = await J(await w.call("GET", `noc/diag/${j2.id}`, tok.noc)); assert.equal(g.status, "unsupported"); assert.match(g.error, /NOT a success/);
  const j3 = await J(await ask(w, tok.noc, { hostId: "db01", template: "net.listen" })); const p3 = (await e.poll()).jobs[0];
  assert.equal((await J(await e.report(p3, { exit: 127, out: "something else\n" }))).status, "failed");
  const st = await J(await w.call("GET", "noc/exec/stats", tok.ro)); assert.equal(st.rates[0].succeeded, 0); assert.equal(st.rates[0].unsupported, 1);
});
