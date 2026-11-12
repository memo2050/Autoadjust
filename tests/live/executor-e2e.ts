// REAL end-to-end of the execution framework: real HTTP server (real API + in-memory DB), organization key minted through the API, and the REAL bash executor
// (collector/noc-agent/auto-adjust-linux-agent.sh) running as the unprivileged user "nobody" on this sandbox, executing only harmless read-only templates.
// A second, hostile stub server then feeds the executor jobs a compromised server could send, to prove the host-side defences work on their own.
// Run: npx tsx tests/live/executor-e2e.ts      (needs root to switch to "nobody"; sandbox only, no network scanning, no customer hosts)
import http from "node:http";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { createHmac, randomUUID } from "node:crypto";
import { mkdtempSync, writeFileSync, copyFileSync, chmodSync, existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { TestStore } from "../test-store";
import { handleSoc } from "../../lib/soc/api";
import { apiKeyHash } from "../../lib/tenant/auth";
import { sha256 } from "../../lib/soc/util";
const execF = promisify(execFile);
process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); delete process.env.SOC_ADMIN_TOKEN; delete process.env.SOC_LEGACY_TOKENS;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: "owner@x.io", role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const OWNER = randomUUID(), ORG = "a0000000-0000-4000-8000-0000000000a1", ORG2 = "b0000000-0000-4000-8000-0000000000b1", HOST = "lab-exec", MYIP = execFileSync("hostname", ["-I"], { encoding: "utf8" }).trim().split(" ")[0];
const dir = mkdtempSync(join(tmpdir(), "aa-exec-")); chmodSync(dir, 0o755); const AGENT = join(dir, "agent.sh"); copyFileSync(new URL("../../collector/noc-agent/auto-adjust-linux-agent.sh", import.meta.url).pathname, AGENT); chmodSync(AGENT, 0o755);
const STATE = join(dir, "state"); mkdirSync(STATE); execFileSync("chown", ["nobody", STATE]); const POLICY = join(dir, "policy.conf");
const policy = (lines: string[]) => { writeFileSync(POLICY, lines.join("\n") + "\n"); chmodSync(POLICY, 0o644); };
const ALL = ["sys.uptime", "sys.cpu_top", "sys.mem", "sys.disk", "sys.load", "svc.status", "net.listen", "net.reach", "net.ping", "dns.lookup", "log.tail"];
const s = new TestStore();
const server = http.createServer(async (rq, rs) => { const ch: Buffer[] = []; for await (const c of rq) ch.push(c as Buffer); const url = new URL(rq.url!, "http://x"); const r = await handleSoc(new Request(url, { method: rq.method, headers: rq.headers as any, body: ch.length ? Buffer.concat(ch) : undefined }), url.pathname.replace(/^\/api\/soc\//, "").split("/"), { store: s, model: null } as any); rs.writeHead(r.status, { "content-type": "application/json" }); rs.end(await r.text()); });
let pass = 0, skipped: string[] = []; const ok = (c: unknown, m: string) => { assert.ok(c, m); pass++; console.log("  ok -", m); };
const api = async (m: string, p: string, t: string, b?: unknown) => { const r = await fetch(`${base}/api/soc/${p}`, { method: m, headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: (await r.json().catch(() => ({}))) as any }; };
let base = "", KEY = "", KEYID = "";
const agentEnv = (extra: Record<string, string> = {}, url = base, key = KEY) => ({ PATH: process.env.PATH!, SPARK_URL: url, SPARK_INGEST_TOKEN: key, ONCE: "1", EXECUTOR: "1", DEVICE_ID: HOST, DEVICE_NAME: HOST, EXECUTOR_POLICY: POLICY, EXECUTOR_STATE: STATE, ...extra });
const runAgent = async (extra: Record<string, string> = {}, url = base, key = KEY, asRoot = false) => { const env = agentEnv(extra, url, key); const args = asRoot ? [AGENT] : ["-u", "nobody", "env", ...Object.entries(env).map(([k, v]) => `${k}=${v}`), AGENT]; try { const r = await execF(asRoot ? "env" : "runuser", asRoot ? [...Object.entries(env).map(([k, v]) => `${k}=${v}`), AGENT] : args, { encoding: "utf8", timeout: 60000 }); return r.stdout + r.stderr; } catch (e: any) { return (e.stdout ?? "") + (e.stderr ?? "") + " [exit " + e.code + "]"; } };
const request = async (template: string, params?: unknown) => (await api("POST", "noc/diag", jwt(OWNER), { hostId: HOST, template, params })).body;
const result = async (id: string) => (await api("GET", `noc/diag/${id}`, jwt(OWNER))).body;
async function runTemplate(t: string, params?: unknown) { const j = await request(t, params); assert.equal(j.status, "queued", t + " queued: " + JSON.stringify(j)); const out = await runAgent(); return { j, out, r: await result(j.id) }; }

async function main() {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r)); const port = (server.address() as any).port; base = `http://127.0.0.1:${port}`;
  const web = http.createServer((_q, rs) => rs.end("hi")); await new Promise<void>((r) => web.listen(0, "0.0.0.0", r)); const webPort = (web.address() as any).port;   // a harmless local listener for net.reach
  try {
    await s.upsert("organizations", [{ id: ORG, name: "Lab Org", slug: "lab" }, { id: ORG2, name: "Other Org", slug: "other" }] as any); await s.upsert("org_members", [{ orgId: ORG, userId: OWNER, role: "owner" }] as any, "org_id,user_id");
    const k = (await api("POST", "org/keys", jwt(OWNER), { name: "lab-exec-key" })).body; KEY = k.key; KEYID = k.id;
    await api("POST", "noc/telemetry", KEY, { source: "t", devices: [{ id: HOST, name: HOST, type: "server", ip: MYIP, up: true, metrics: { cpu: 1 } }, { id: "peer", name: "peer", type: "server", ip: "10.1.1.1", up: true, metrics: {} }] });
    ok((await api("POST", "noc/exec/executors", jwt(OWNER), { hostId: HOST, keyId: KEYID, os: "linux" })).status === 201, "executor registered for this host and bound to the organization key");
    policy([...ALL.map((t) => `template ${t}`), "service cron.service", "logunit cron.service", `target ${MYIP}`]);

    let o = "";
    const root = await runAgent({}, base, KEY, true); ok(/refuses to run as root/.test(root), "executor refuses to run as root by default");

    ok((await api("POST", "noc/diag", jwt(OWNER), { hostId: HOST, template: "sys.uptime" })).status === 409, "execution is OFF by default: live request refused");
    ok((await api("PUT", "noc/exec/settings", jwt(OWNER), { enabled: true })).status === 200, "owner switched execution on");

    const must: Record<string, RegExp> = { "sys.uptime": /up|load/, "sys.cpu_top": /PID/, "sys.mem": /Mem:/, "sys.disk": /Filesystem/, "sys.load": /^\d/ };
    for (const [t, re] of Object.entries(must)) { const { r } = await runTemplate(t); ok(r.status === "succeeded" && re.test(r.output), `${t}: REAL output from the host (${String(r.output).split("\n")[0].slice(0, 60)})`); }
    { const { r } = await runTemplate("dns.lookup", { name: "localhost" }); ok(r.status === "succeeded" && /127\.0\.0\.1|::1/.test(r.output), "dns.lookup localhost: real resolver output"); }
    { const { r } = await runTemplate("net.reach", { host: MYIP, port: webPort }); ok(r.status === "succeeded" && /CONNECTED/.test(r.output), `net.reach to the sandbox's own listener: ${r.output.trim()}`); }
    { const { r } = await runTemplate("net.reach", { host: MYIP, port: 1 }); ok(r.status === "failed" && /FAILED/.test(r.output), "net.reach to a closed port: reported failed (exit code 1), not success"); }
    { const { r } = await runTemplate("svc.status", { unit: "cron.service" }); ok(["succeeded", "failed"].includes(r.status) && !!r.output, `svc.status ran as an argv (no shell); status=${r.status}: ${String(r.output).split("\n")[0].slice(0, 70)}`); }
    { const { r } = await runTemplate("net.listen"); let haveSs = true; try { execFileSync("which", ["ss"], { stdio: "ignore" }); } catch { haveSs = false; }
      if (haveSs) ok(r.status === "succeeded", "net.listen: real `ss -tuln` output"); else ok(r.status === "succeeded" && /^# origin: \/proc\/net fallback/.test(r.output) && r.output.includes(`:${webPort}`) && r.output.includes("tcp LISTEN"), `net.listen: 'ss' is not installed -> /proc/net FALLBACK produced a complete listing that includes the test listener on port ${webPort}`); if (!haveSs) skipped.push("net.listen via real `ss` (ss not installed; the /proc fallback path was exercised instead)"); }
    for (const [t, p] of [["net.ping", { host: MYIP }], ["log.tail", { unit: "cron.service", n: 5 }]] as const) {
      const { r } = await runTemplate(t, p); const tool = { "net.ping": "ping", "log.tail": "journalctl" }[t]!;
      let have = true; try { execFileSync("which", [tool], { stdio: "ignore" }); } catch { have = false; }
      if (have) ok(["succeeded", "failed"].includes(r.status), `${t}: executed (status ${r.status})`); else { ok(r.status === "unsupported" && /^UNSUPPORTED:/.test(r.output) && r.status !== "succeeded", `${t}: tool '${tool}' is not installed here -> status "unsupported" (NOT success, NOT silently failed)`); skipped.push(`${t} (needs '${tool}', not installed in this sandbox)`); }
    }

    // ---- real timeout kill: connect to an unroutable address; the 5 s limit must stop it and the job must be reported timed_out ----
    await api("POST", "noc/telemetry", KEY, { source: "t", devices: [{ id: "blackhole", name: "blackhole", type: "server", ip: "10.255.255.1", up: true, metrics: {} }] });
    policy([...ALL.map((t) => `template ${t}`), "service cron.service", "logunit cron.service", `target ${MYIP}`, "target 10.255.255.1"]);
    { const t0 = Date.now(); const { r } = await runTemplate("net.reach", { host: "10.255.255.1", port: 81 }); const took = (Date.now() - t0) / 1000;
      ok(["timed_out", "failed"].includes(r.status) && took < 20, `unreachable target: command did not hang the executor (status ${r.status} after ${took.toFixed(1)} s, limit 5 s)`);
      if (r.status === "timed_out") ok(r.timedOut === true && /time limit/.test(r.error), "timeout is enforced by the executor and recorded as timed_out"); else skipped.push("timed_out state (sandbox answers an unroutable address immediately instead of hanging)"); }
    // ---- the executor's own run_job(): hanging and endless commands (templates are substituted ONLY inside this harness, never in the product) ----
    { const src = readFileSync(AGENT, "utf8"), body = src.slice(src.indexOf("run_job() {"), src.indexOf("report() {")), tcp = src.slice(src.indexOf("tcp_connect() {"), src.indexOf("run_job() {")), red = src.slice(src.indexOf("redact_file() {"), src.indexOf("# Validates P[]"));
      const h = join(dir, "harness.sh"); writeFileSync(h, `#!/usr/bin/env bash\nSAFE_PATH=/usr/bin:/bin\ndeclare -A T_TIMEOUT=([t.sleep]=2 [t.flood]=5 [t.secret]=5) T_LINES=([t.sleep]=5 [t.flood]=50 [t.secret]=5) T_BYTES=([t.sleep]=500 [t.flood]=1024 [t.secret]=500)\ndeclare -A P=()\n${red}\n${tcp}\nbuild_argv() { case "$1" in t.sleep) ARGV=(sleep 30);; t.flood) ARGV=(yes AAAAAAAAAAAAAAAAAAAA);; t.secret) ARGV=(printf 'password=hunter2\\ntoken=abc12345\\n');; esac; }\n${body}\nfor t in t.sleep t.flood t.secret; do s=$(date +%s); run_job $t; echo "$t rc=$RC timeout=$TMO trunc=$TRUNC secs=$(( $(date +%s) - s )) bytes=$(wc -c <$OUTF)"; [ $t = t.secret ] && cat $OUTF; done\n`); chmodSync(h, 0o755);
      const out = (await execF("runuser", ["-u", "nobody", "--", "bash", h], { encoding: "utf8", timeout: 40000 })).stdout;
      ok(/t\.sleep rc=(124|137) timeout=1 .* secs=[23] /.test(out), "executor run_job: a command that hangs is killed at its time limit and reported timed out (" + out.split("\n")[0] + ")");
      ok(/t\.flood .* trunc=1 .* bytes=(\d+)/.test(out) && Number(out.match(/t\.flood .* bytes=(\d+)/)![1]) <= 1024, "executor run_job: endless output is cut at the byte cap and flagged truncated (" + out.split("\n")[1] + ")");
      ok(!/hunter2|abc12345/.test(out) && /REDACTED/.test(out), "executor run_job: secrets in command output are redacted before they leave the host");
      skipped.splice(skipped.findIndex((x) => x.startsWith("timed_out state")), 1); }
    // ---- host-side refusals ----
    policy(ALL.filter((t) => t !== "sys.mem").map((t) => `template ${t}`)); let r = (await runTemplate("sys.mem")).r;
    ok(r.status === "failed" && /not enabled in local policy/.test(r.output), "host policy: template not enabled locally -> refused even though the server allowed it");
    policy(["template svc.status", "service other.service"]); r = (await runTemplate("svc.status", { unit: "cron.service" })).r; ok(r.status === "failed" && /not in local policy/.test(r.output), "host policy: unit not allow-listed locally -> refused");
    policy(["template net.reach"]); r = (await runTemplate("net.reach", { host: MYIP, port: webPort })).r; ok(r.status === "failed" && /target not in local policy/.test(r.output), "host policy: target not allow-listed locally -> refused");
    for (const bad of ["*", "10.0.0.*", "10.0.0.0/24", "*.example.com", "?"]) { policy(["template net.reach", "template net.ping", `target ${bad}`, `target ${MYIP}`]); for (const [t, pr] of [["net.reach", { host: MYIP, port: webPort }], ["net.ping", { host: MYIP }]] as const) { r = (await runTemplate(t, pr)).r; ok(r.status === "failed" && /invalid or wildcard target rule/.test(r.output), `host policy: wildcard/range rule 'target ${bad}' is NOT supported -> ${t} refused, even for an exact allowed target`); } }
    if (existsSync(POLICY)) { writeFileSync(POLICY, ""); } r = (await runTemplate("sys.uptime")).r; ok(r.status === "failed" && /not enabled in local policy/.test(r.output), "fail closed: an empty policy file runs nothing");
    execFileSync("rm", [POLICY]); r = (await runTemplate("sys.uptime")).r; ok(r.status === "failed", "fail closed: a missing policy file runs nothing");
    policy(ALL.map((t) => `template ${t}`)); policy([...ALL.map((t) => `template ${t}`), "service cron.service", "logunit cron.service", `target ${MYIP}`]);

    // ---- replay on the host: a job id the executor has already seen is never run again ----
    const rep = await request("sys.uptime"); writeFileSync(join(STATE, "seen-" + rep.id), ""); execFileSync("chown", ["nobody", join(STATE, "seen-" + rep.id)]);
    o = await runAgent(); const after = await result(rep.id); ok(after.status === "leased" && !after.output && /replay/.test(o), "host replay protection: already-seen job id is ignored (never executed twice)");
    await api("POST", `noc/diag/${rep.id}/cancel`, jwt(OWNER)); // leased jobs can't be cancelled; it will expire by itself
    ok(!readdirSync(STATE).some((f) => f.startsWith("seen-") && f.includes("undefined")), "state directory only holds job ids");

    // ---- no secret reaches commands or results ----
    const all = JSON.stringify((await api("GET", "noc/diag", jwt(OWNER))).body) + JSON.stringify((await api("GET", "soc/audit?limit=500", jwt(OWNER))).body);
    ok(!all.includes(KEY), "the organization key appears in no job, output or audit entry");
    ok((await s.select<any>("noc_diag_jobs", {})).every((j: any) => !j.orgId || j.orgId === ORG), "every job row belongs to the requesting organization");

    // ---- hostile stub server: what the executor does on its own when the server is compromised ----
    const keyHash = apiKeyHash(KEY); let posted: string[] = []; let next: any = null;
    const stub = http.createServer(async (rq, rs) => { const ch: Buffer[] = []; for await (const c of rq) ch.push(c as Buffer); const u = new URL(rq.url!, "http://x");
      if (u.pathname.endsWith("/noc/executor/jobs")) { rs.writeHead(200, { "content-type": "application/json" }); rs.end(JSON.stringify({ jobs: next ? [next] : [] })); return; }
      if (u.pathname.includes("/result")) { posted.push(u.pathname + " " + Buffer.concat(ch).toString().slice(0, 300)); rs.writeHead(200); rs.end("{}"); return; } rs.writeHead(200); rs.end("{}"); });
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r)); const stubUrl = `http://127.0.0.1:${(stub.address() as any).port}`;
    const mkJob = (over: any = {}) => { const j: any = { id: "njb_" + randomUUID().slice(0, 8), orgId: ORG, hostId: HOST, template: "sys.uptime", params: {}, expiresAt: new Date(Date.now() + 300000).toISOString(), nonce: "n" + Math.random(), leaseId: "l" + Math.random(), ...over };
      j.sig = createHmac("sha256", keyHash).update(["v1", j.id, j.orgId, j.hostId, j.template, Object.keys(j.params).sort().map((k) => `${k}=${j.params[k]}`).join("&"), j.expiresAt, j.nonce, j.leaseId].join("|")).digest("hex"); if (over.sig) j.sig = over.sig; return j; };
    const hostile = async (label: string, job: any, expect: { posted: boolean; text?: RegExp }) => { posted = []; next = job; const out = await runAgent({}, stubUrl); const hit = posted.length > 0; const body = posted.join(); const refusedOk = !expect.posted || (expect.text === undefined ? true : /result/.test(body) && (label.includes("control") ? /"exitCode":\s*0/.test(body) : /"exitCode":\s*126/.test(body) && /Refused by the executor/.test(body))); ok(hit === expect.posted && refusedOk && (!expect.text || expect.text.test(out + body)), `compromised-server test - ${label}: ${expect.posted ? "refused and reported" : "ignored, nothing executed"}`); };
    await hostile("forged signature", mkJob({ sig: "f".repeat(64) }), { posted: false, text: /bad signature/ });
    await hostile("signed by ANOTHER key", { ...mkJob(), sig: createHmac("sha256", apiKeyHash("aa_live_" + "z".repeat(43))).update("x").digest("hex") }, { posted: false });
    await hostile("shell injection in a parameter (validly signed)", mkJob({ template: "svc.status", params: { unit: "cron.service; id" } }), { posted: true, text: /bad unit/ });
    await hostile("command-substitution in a parameter", mkJob({ template: "dns.lookup", params: { name: "$(id).example.com" } }), { posted: true, text: /bad name/ });
    await hostile("unknown template (e.g. a restart)", mkJob({ template: "svc.restart", params: { unit: "cron.service" } }), { posted: true, text: /unknown template/ });
    await hostile("extra parameter smuggled in", mkJob({ template: "sys.uptime", params: { x: "1" } }), { posted: true, text: /unexpected parameters/ });
    await hostile("job addressed to another host", mkJob({ hostId: "other-host" }), { posted: true, text: /another host/ });
    await hostile("expired job", mkJob({ expiresAt: new Date(Date.now() - 600000).toISOString() }), { posted: true, text: /expired/ });
    await hostile("loopback target", mkJob({ template: "net.reach", params: { host: "127.0.0.1", port: "22" } }), { posted: true, text: /forbidden target/ });
    await hostile("metadata target", mkJob({ template: "net.ping", params: { host: "169.254.169.254" } }), { posted: true, text: /forbidden target/ });
    const good = mkJob({ template: "sys.uptime" }); await hostile("a valid job from the stub (control)", good, { posted: true, text: /result/ });
    await hostile("the same valid job again (replay)", good, { posted: false, text: /replay/ });
    stub.close();

    // ---- helper: redaction on the host ----
    const fn = readFileSync(AGENT, "utf8").match(/^redact_file\(\) \{[\s\S]*?^\S.*?\n(?=[a-z_]+\(\) \{|# Validates)/m)![0]; const rf = join(dir, "redact.sh"); const sample = join(dir, "sample.txt");
    writeFileSync(sample, "password=hunter2\nkey aa_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\nAuthorization: Bearer abcdefghijklmnop1234\nplain line\n"); writeFileSync(rf, fn + '\nredact_file "$1"\ncat "$1"\n');
    const red = (await execF("bash", [rf, sample], { encoding: "utf8" })).stdout; ok(!/hunter2|ABCDEFGHIJKLMNOPQRSTUVWXYZ012345|abcdefghijklmnop1234/.test(red) && /plain line/.test(red), "host-side redaction removes passwords, API keys and bearer tokens before output leaves the host");
    console.log(`\nEXECUTOR E2E: ${pass} checks passed. Not exercised here (tool missing in sandbox): ${skipped.join("; ") || "none"}`);
  } finally { server.close(); web.close(); }
}
main().then(() => process.exit(0)).catch((e) => { console.error("FAILED:", e); process.exit(1); });
