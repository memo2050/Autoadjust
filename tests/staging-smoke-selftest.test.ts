// Self-test of scripts/staging-smoke.mjs against an in-memory harness (NOT staging). Proves the script's checks work and that it refuses non-staging targets.
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, aal: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: sub.slice(0, 6) + "@x.io", role: "authenticated", aud: "authenticated", aal, exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
async function harness(env: Record<string, string>) {
  const store = new TestStore(), srv = createServer(async (rq, rs) => { const chunks: Buffer[] = []; for await (const c of rq) chunks.push(c as Buffer); const body = Buffer.concat(chunks);
    if (!rq.url!.startsWith("/api/soc/")) { rs.writeHead(200, { "x-content-type-options": "nosniff" }); return rs.end("ok"); }
    const p = rq.url!.slice(9).split("?")[0]; const r = await handleSoc(new Request("http://localhost" + rq.url, { method: rq.method, headers: rq.headers as any, body: ["GET", "HEAD"].includes(rq.method!) ? undefined : body }), p.split("/"), { store, model: null, env } as any);
    const hd: Record<string, string> = {}; r.headers.forEach((v: string, k: string) => { hd[k] = v; }); rs.writeHead(r.status, hd); rs.end(Buffer.from(await r.arrayBuffer())); });
  await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok)); return { srv, url: `http://127.0.0.1:${(srv.address() as any).port}` };
}
const smoke = (url: string, env: Record<string, string>) => new Promise<{ code: number; out: string }>((res) => { const { spawn } = require("node:child_process"); const c = spawn("node", ["scripts/staging-smoke.mjs"], { env: { PATH: process.env.PATH, STAGING_URL: url, ...env } }); let out = ""; c.stdout.on("data", (d: Buffer) => (out += d)); c.stderr.on("data", (d: Buffer) => (out += d)); c.on("close", (code: number) => res({ code, out })); });
test("smoke script: all checks pass against the harness with MFA off; MFA-on run asserts the enforcement path", async () => {
  const off = await harness({ MFA_ENFORCE: "off" }); const r1 = await smoke(off.url, { SMOKE_TOKEN_A: jwt(randomUUID(), "aal1"), SMOKE_TOKEN_B: jwt(randomUUID(), "aal1") }); off.srv.close();
  assert.equal(r1.code, 0, r1.out); assert.match(r1.out, /PASS {2}rate limiter returns 429/); assert.match(r1.out, /PASS {2}user A cannot act inside organization B/); assert.doesNotMatch(r1.out, /FAIL/);
  const on = await harness({ MFA_ENFORCE: "on" }); const r2 = await smoke(on.url, { SMOKE_TOKEN_A: jwt(randomUUID(), "aal1"), SMOKE_TOKEN_B: jwt(randomUUID(), "aal1") }); on.srv.close();
  assert.equal(r2.code, 0, r2.out); assert.match(r2.out, /PASS {2}MFA enforced/);
});
test("smoke script refuses to run against a non-staging address", () => {
  for (const u of ["https://autoadjust.net", "https://www.autoadjust.net"]) { const r = spawnSync("node", ["scripts/staging-smoke.mjs"], { env: { PATH: process.env.PATH, STAGING_URL: u }, encoding: "utf8" }); assert.equal(r.status, 2); assert.match(r.stderr, /Refusing/); }
});
