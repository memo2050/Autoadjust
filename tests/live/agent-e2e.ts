// REAL end-to-end: a real HTTP server running the real API (in-memory DB), an organization key minted through the API,
// and the real Linux agent script (real /proc metrics, real curl over a real socket). Run: npx tsx tests/live/agent-e2e.ts
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const execF = promisify(execFile);
import { createHmac } from "node:crypto";
import assert from "node:assert/strict";
import { TestStore } from "../test-store";
import { handleSoc } from "../../lib/soc/api";
process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; process.env.NOC_SECRET_KEY = "n".repeat(40); delete process.env.SOC_ADMIN_TOKEN; delete process.env.SOC_LEGACY_TOKENS;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: "o@x.io", role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const U = "aaaaaaaa-0000-4000-8000-00000000000a", ORG = "a0000000-0000-4000-8000-0000000000a1", ORG2 = "b0000000-0000-4000-8000-0000000000b1";
const s = new TestStore();
const server = http.createServer(async (rq, rs) => {
  const chunks: Buffer[] = []; for await (const c of rq) chunks.push(c as Buffer);
  const url = new URL(rq.url!, "http://x"), path = url.pathname.replace(/^\/api\/soc\//, "").split("/");
  const r = await handleSoc(new Request(url, { method: rq.method, headers: rq.headers as any, body: chunks.length ? Buffer.concat(chunks) : undefined }), path, { store: s, model: null } as any);
  rs.writeHead(r.status, { "content-type": "application/json" }); rs.end(await r.text());
});
async function main() {
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r)); const port = (server.address() as any).port, base = `http://127.0.0.1:${port}`;
const api = async (m: string, p: string, t: string, b?: unknown) => { const r = await fetch(`${base}/api/soc/${p}`, { method: m, headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: (await r.json()) as any }; };
let pass = 0; const ok = (c: unknown, m: string) => { assert.ok(c, m); pass++; console.log("  ok -", m); };
try {
  await s.upsert("organizations", [{ id: ORG, name: "Org A", slug: "org-a" }, { id: ORG2, name: "Org B", slug: "org-b" }] as any);
  await s.upsert("org_members", [{ orgId: ORG, userId: U, role: "owner" }] as any, "org_id,user_id");
  const key = (await api("POST", "org/keys", jwt(U), { name: "linux-agent-test" })).body.key; ok(/^aa_live_/.test(key), "organization key minted through the API");
  const run = async (extra: Record<string, string> = {}, token = key) => { try { return (await execF("/home/claude/dev/spark-dev/collector/noc-agent/auto-adjust-linux-agent.sh", [], { env: { PATH: process.env.PATH!, SPARK_URL: base, SPARK_INGEST_TOKEN: token, ONCE: "1", DEVICE_NAME: "lab-linux-01", PING_TARGETS: `127.0.0.1:${port} 127.0.0.1:1`, ...extra }, encoding: "utf8" })).stdout; } catch (e: any) { return "ERR " + (e.stderr || e.message); } };
  const out = await run(); ok(/sent \d+ bytes/.test(out), "real agent sent a real sample over HTTP: " + out.trim().slice(0, 110));
  const devs = (await api("GET", "noc/devices", jwt(U))).body as any[]; const me = devs.find((d) => d.id === "lab-linux-01");
  ok(me && me.metrics.cpu >= 0 && me.metrics.mem > 0 && me.metrics.disk > 0, `device stored with REAL metrics (cpu ${me?.metrics.cpu}%, mem ${me?.metrics.mem}%, disk ${me?.metrics.disk}%)`);
  const up = devs.find((d) => d.id.includes(`127.0.0.1-${port}`)), dn = devs.find((d) => d.id.endsWith("127.0.0.1-1"));
  ok(up?.up === true && dn?.up === false, "TCP probe: reachable port reported up, closed port reported down");
  const inc = (await s.select<any>("noc_incidents", { where: { orgId: ORG } as any })).map((x) => x.title); ok(inc.some((t: string) => /is down/.test(t)), "the unreachable target raised a real incident: " + inc.join(" | "));
  ok((await api("POST", "noc/telemetry", "aa_live_" + "x".repeat(43), { devices: [] })).status === 401, "wrong key rejected");
  ok((await run({}, "aa_live_" + "y".repeat(43))).startsWith("ERR"), "agent exits with an error when the key is rejected");
  const av = (await api("GET", "noc/availability?hours=1", jwt(U))).body; ok(av.devices.length >= 3 && av.devices.some((d: any) => d.availabilityPct === 0), "availability computed from stored samples: " + av.devices.map((d: any) => `${d.name}=${d.availabilityPct}%`).join(", "));
  const other = (await s.select<any>("noc_metrics", {})).filter((r: any) => r.orgId && r.orgId !== ORG); ok(other.length === 0, "no sample landed in any other organization");
  console.log(`\nLIVE AGENT E2E: ${pass} checks passed`);
} finally { server.close(); }
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
