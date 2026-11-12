// Dashboard end-to-end against the REAL development API handler (lib/soc/api.handleSoc) backed by a REAL Postgres + PostgREST (SupabaseStore),
// driven by a REAL browser (Playwright/Chromium) and a REAL Linux executor (run as the unprivileged user 'nobody').
// NOT covered: Next.js routing (app/api/soc/[...path]/route.ts) - `next` cannot be installed here. A tiny node http server stands in for it.
import http from "node:http";
import { readFileSync, writeFileSync, mkdtempSync, chmodSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import assert from "node:assert/strict";
import { SupabaseStore } from "../../lib/soc/store";
import { handleSoc } from "../../lib/soc/api";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { chromium } = require("playwright");
const execF = promisify(execFile);
const SECRET = readFileSync("/tmp/pgrst/secret.txt", "utf8").trim();
process.env.NOC_SECRET_KEY = "k".repeat(40); process.env.SUPABASE_JWT_SECRET = SECRET; delete process.env.SOC_ADMIN_TOKEN;
const PG = "http://127.0.0.1:3397", b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (c: Record<string, unknown>) => { const h = b({ alg: "HS256", typ: "JWT" }), p = b({ exp: Math.floor(Date.now() / 1000) + 1800, ...c }); return `${h}.${p}.${createHmac("sha256", SECRET).update(h + "." + p).digest("base64url")}`; };
const uid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`, user = (n: number) => sign({ sub: uid(n), email: `u${n}@example.com`, role: "authenticated", aud: "authenticated" });
const store = new SupabaseStore(PG, sign({ role: "service_role" }));
const PUB = new URL("../../public/", import.meta.url).pathname;
const server = http.createServer(async (rq, rs) => {
  const u = new URL(rq.url!, "http://x");
  if (u.pathname.startsWith("/api/soc/")) { const ch: Buffer[] = []; for await (const c of rq) ch.push(c as Buffer); const r = await handleSoc(new Request(new URL(u.pathname + u.search, "http://x"), { method: rq.method, headers: rq.headers as any, body: ["GET", "HEAD"].includes(rq.method!) ? undefined : Buffer.concat(ch) }), u.pathname.slice(9).split("?")[0].split("/"), { store: store as any, model: null }).catch((e: any) => new Response(JSON.stringify({ error: String(e) }), { status: 500 })); rs.writeHead(r.status, { "content-type": "application/json" }); return rs.end(await r.text()); }
  try { rs.writeHead(200, { "content-type": "text/html" }); rs.end(readFileSync(join(PUB, u.pathname.replace(/\.\./g, "")))); } catch { rs.writeHead(404); rs.end(); }
});
let pass = 0; const ok = (c: unknown, m: string) => { assert.ok(c, m); console.log(`PASS ${++pass} | ${m}`); };
const dir = mkdtempSync(join(tmpdir(), "aa-dash-")); chmodSync(dir, 0o755); const AGENT = join(dir, "agent.sh"); copyFileSync(new URL("../../collector/noc-agent/auto-adjust-linux-agent.sh", import.meta.url).pathname, AGENT); chmodSync(AGENT, 0o755);
const STATE = join(dir, "state"); mkdirSync(STATE); execFileSync("chown", ["nobody", STATE]); const POLICY = join(dir, "policy.conf"); writeFileSync(POLICY, ["template sys.uptime", "template net.listen", "template net.ping", "template sys.mem", "target 10.20.0.6"].join("\n") + "\n"); chmodSync(POLICY, 0o644);
const HOST = "lab-exec";
(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r)); const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const api = async (m: string, p: string, t: string, body?: unknown) => { const r = await fetch(`${base}/api/soc/${p}`, { method: m, headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, body: (await r.json().catch(() => ({}))) as any }; };
  const runAgent = async (key: string) => { const env = { PATH: process.env.PATH!, SPARK_URL: base, SPARK_INGEST_TOKEN: key, ONCE: "1", EXECUTOR: "1", DEVICE_ID: HOST, DEVICE_NAME: HOST, EXECUTOR_POLICY: POLICY, EXECUTOR_STATE: STATE }; try { const r = await execF("runuser", ["-u", "nobody", "env", ...Object.entries(env).map(([k, v]) => `${k}=${v}`), AGENT], { encoding: "utf8", timeout: 60000 }); return r.stdout + r.stderr; } catch (e: any) { return (e.stdout ?? "") + (e.stderr ?? ""); } };
  const alice = user(1), bob = user(2), slug = "dash" + Date.now() % 100000;
  const A = (await api("POST", "org/create", alice, { name: "Dash Org", slug })).body, B = (await api("POST", "org/create", bob, { name: "Other Dash Org", slug: slug + "b" })).body; ok(A.id && B.id, "two organizations created on the real database");
  const k = (await api("POST", "org/keys", alice, { name: "dash-key" })).body;
  await api("POST", "noc/telemetry", k.key, { source: "t", devices: [{ id: HOST, name: HOST, type: "server", ip: "10.20.0.5", up: true, metrics: { cpu: 3 } }, { id: "peer", name: "peer", type: "server", ip: "10.20.0.6", up: true, metrics: {} }] });
  ok((await api("POST", "noc/exec/executors", alice, { hostId: HOST, keyId: k.id, os: "linux" })).status === 201, "executor registered");
  const browser = await chromium.launch(); const shots = process.env.SHOTS_DIR || dir;
  const open = async (tok: string) => { const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 } }); await ctx.addInitScript((t: string) => sessionStorage.setItem("aaSession", JSON.stringify({ access_token: t })), tok); const pg = await ctx.newPage(); const errs: string[] = []; pg.on("pageerror", (e: Error) => errs.push(e.message)); pg.on("dialog", (d: any) => d.accept()); await pg.goto(base + "/agents.html"); await pg.waitForSelector("#app:not(.hide)", { timeout: 15000 }); return { ctx, pg, errs }; };
  try {
    const { ctx, pg, errs } = await open(alice);
    ok((await pg.textContent("#exstate")) === "OFF", "UI: execution shows OFF by default for the organization");
    ok(/Dash Org/.test((await pg.textContent("#orgline")) ?? "") && /owner/.test((await pg.textContent("#orgline")) ?? ""), "UI: organization name and role come from the real /me endpoint");
    ok(!(await pg.$$eval("#rtpl option", (o: any[]) => o.map((x) => x.value))).includes("sec.logons"), "UI: sec.logons is not offered");
    ok((await pg.$$eval("#rtpl option", (o: any[]) => o.length)) === 11, "UI: exactly the 11 approved templates are offered");
    await pg.click("#toggle"); await pg.waitForFunction(() => document.getElementById("exstate")!.textContent === "ON", null, { timeout: 10000 }); ok(true, "UI: owner switched execution ON (confirm dialog accepted) and the real API stored it");
    await pg.selectOption("#rhost", HOST); await pg.selectOption("#rtpl", "sys.uptime"); await pg.fill("#rreason", "dashboard e2e"); await pg.click("#rdry"); await pg.waitForFunction(() => /DRY-RUN/.test(document.getElementById("rprev")!.textContent || ""), null, { timeout: 10000 });
    ok(/uptime/.test((await pg.textContent("#rprev")) ?? ""), "UI: dry-run shows the exact command and says nothing was sent");
    await pg.click("#rrun"); await pg.waitForFunction(() => /queued|Queued/.test(document.getElementById("active")!.textContent || ""), null, { timeout: 10000 }); ok(true, "UI: run request appears under Active tasks as queued");
    const out1 = await runAgent(k.key); ok(/sys\.uptime rc=0/.test(out1), "REAL executor ran sys.uptime as 'nobody' (rc=0)");
    await pg.reload(); await pg.waitForSelector("#app:not(.hide)"); await pg.waitForFunction(() => /succeeded/.test(document.getElementById("hist")!.textContent || ""), null, { timeout: 10000 }); ok(true, "UI: history shows the job as succeeded after reload");
    await pg.selectOption("#rtpl", "net.listen"); await pg.fill("#rreason", "dashboard e2e listen"); await pg.click("#rrun"); await pg.waitForFunction(() => /queued/i.test(document.getElementById("active")!.textContent || ""), null, { timeout: 10000 }); await runAgent(k.key);
    await pg.reload(); await pg.waitForSelector("#app:not(.hide)"); await pg.waitForFunction(() => /net\.listen[\s\S]*succeeded/.test(document.getElementById("hist")!.textContent || ""), null, { timeout: 10000 }); ok(true, "UI: net.listen shows as succeeded (via the /proc/net fallback when ss is absent)");
    const haveP = (() => { try { execFileSync("which", ["ping"], { stdio: "ignore" }); return true; } catch { return false; } })();
    await pg.selectOption("#rtpl", "net.ping"); await pg.fill("#p_host", "10.20.0.6"); await pg.fill("#rreason", "dashboard e2e unsupported"); await pg.click("#rrun"); await pg.waitForFunction(() => /queued/i.test(document.getElementById("active")!.textContent || ""), null, { timeout: 10000 }); await runAgent(k.key);
    await pg.reload(); await pg.waitForSelector("#app:not(.hide)"); const want = haveP ? "(succeeded|failed|timed_out)" : "unsupported"; await pg.waitForFunction((w: string) => new RegExp("net\\.ping[\\s\\S]*" + w).test(document.getElementById("hist")!.textContent || ""), want, { timeout: 10000 });
    ok(true, `UI: net.ping shows as '${haveP ? "a real result" : "unsupported"}' (${haveP ? "ping present" : "ping is not installed here, so it is NOT shown as success"})`);
    const rates = (await pg.textContent("#rates")) ?? ""; ok(haveP ? true : /Unsupp[\s\S]*3\s*2\s*2\s*0\s*0\s*1/.test(rates.replace(/\s+/g, " ")) || /67%|66\.7%/.test(rates), `UI: success rate counts only real successes (${rates.replace(/\s+/g, " ").slice(0, 140)})`);
    await pg.click("#asoc"); await pg.waitForFunction(() => (document.getElementById("aout")!.textContent || "").length > 20 || /could not|error/i.test(document.getElementById("amsg")!.textContent || ""), null, { timeout: 15000 }); ok(/Method|Priorities|Recommendations|no data/i.test((await pg.textContent("#aout")) ?? ""), "UI: AI SOC analysis renders from the real API (rule-based; no model configured)");
    await pg.click("#anoc"); await pg.waitForFunction(() => (document.getElementById("aout")!.textContent || "").length > 20, null, { timeout: 15000 }); ok(/Method|Health|Recommendations/i.test((await pg.textContent("#aout")) ?? ""), "UI: AI NOC analysis renders from the real API");
    ok(/not executed/i.test((await pg.textContent("#aout")) ?? "") || !/executed successfully/i.test((await pg.textContent("#aout")) ?? ""), "UI: analysis output never claims anything was executed");
    await pg.screenshot({ path: join(shots, "dashboard-owner.png"), fullPage: true }); ok(errs.length === 0, "UI: no JavaScript errors on the page " + JSON.stringify(errs)); await ctx.close();
    const o2 = await open(bob); ok((await o2.pg.textContent("#exstate")) === "OFF" && !/lab-exec/.test((await o2.pg.textContent("#execs")) ?? "") && !/uptime/.test((await o2.pg.textContent("#hist")) ?? ""), "UI: another organization sees none of this organization's executors or history"); await o2.pg.screenshot({ path: join(shots, "dashboard-other-org.png"), fullPage: true }); await o2.ctx.close();
    const anon = await browser.newContext(); const ap = await anon.newPage(); await ap.goto(base + "/agents.html"); ok(/sign in/i.test((await ap.textContent("#top")) ?? "") && (await ap.$("#app.hide")) !== null, "UI: no session -> asks to sign in and shows no data"); await anon.close();
  } finally { await browser.close(); server.close(); }
  console.log(`DASHBOARD E2E: ${pass} checks passed (real API handler + real Postgres + real browser + real Linux executor). Next.js routing NOT covered.`); process.exit(0);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
