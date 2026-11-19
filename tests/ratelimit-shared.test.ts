import test from "node:test";
import assert from "node:assert/strict";
import { createRateLimiters, sharedEnabled } from "../lib/ratelimit/shared";
import { createSupportHandlers } from "../lib/support/handlers";
import { anthropicComplete } from "../lib/support/assistant";

const ENV = { RATE_LIMIT_STORE: "supabase", SUPABASE_URL: "https://x.supabase.test", SUPABASE_SERVICE_ROLE_KEY: "svc-test-placeholder" } as NodeJS.ProcessEnv;
// Fake PostgREST: emulates public.rate_limit_hit (fixed windows, atomic count). `maxWindow` 3600 = migration 0112 only, 86400 = after 0117.
function fakeDb(maxWindow = 86400) {
  const rows = new Map<string, number>(); const seen: any[] = []; let down = false;
  const f = (async (url: string, init: any) => {
    if (down) throw new TypeError("fetch failed"); assert.match(String(url), /\/rest\/v1\/rpc\/rate_limit_hit$/); assert.equal(init.headers.apikey, "svc-test-placeholder");
    const b = JSON.parse(init.body); seen.push(b); if (b.p_window > maxWindow) return new Response(JSON.stringify({ message: "invalid rate limit arguments" }), { status: 400 });
    const k = b.p_key + "@" + Math.floor(Date.now() / 1000 / b.p_window); rows.set(k, (rows.get(k) ?? 0) + 1); return new Response(JSON.stringify(rows.get(k)), { status: 200 });
  }) as unknown as typeof fetch;
  return { f, rows, seen, setDown: (v: boolean) => { down = v; } };
}
test("disabled by default: pure in-memory behaviour, no network", async () => {
  assert.equal(sharedEnabled({} as any), false); const rl = createRateLimiters({ env: {} as any, fetch: (() => { throw new Error("no network expected"); }) as any }); assert.equal(rl.mode(), "memory");
  const l = rl("t", 2, 1e9, 3600_000); assert.deepEqual([await l("a"), await l("a"), await l("a"), await l("b")], [true, true, false, true]);
});
test("shared mode: counters are shared by separate app instances and survive a restart", async () => {
  const db = fakeDb(); const mk = () => createRateLimiters({ env: ENV, fetch: db.f }); const A = mk()("ai-anon", 10, 1e9, 3600_000), B = mk()("ai-anon", 10, 1e9, 3600_000);   // two instances
  const r: boolean[] = []; for (let i = 0; i < 6; i++) r.push(await A("ip1")); for (let i = 0; i < 6; i++) r.push(await B("ip1"));
  assert.equal(r.filter(Boolean).length, 10);   // 12 attempts across two instances: only 10 allowed
  const C = mk()("ai-anon", 10, 1e9, 3600_000); assert.equal(await C("ip1"), false);   // "restart": fresh process, same persistent counter
  assert.equal(await C("ip2"), true);   // other clients unaffected
  assert.ok(db.seen.every((b) => /^ai-anon:[0-9a-f]{32}$/.test(b.p_key)) && !JSON.stringify(db.seen).includes("ip1"));   // client keys are hashed, never stored raw
});
test("shared global cap across instances; limit semantics preserved", async () => {
  const db = fakeDb(); const mk = () => createRateLimiters({ env: ENV, fetch: db.f })("ai-day", 1e9, 5, 86_400_000); const a = mk(), b = mk(); const r: boolean[] = [];
  for (let i = 0; i < 4; i++) { r.push(await a("global")); r.push(await b("global")); } assert.equal(r.filter(Boolean).length, 5);
});
test("store outage or missing 0117: falls back to per-instance memory, limit never removed, no errors", async () => {
  const db = fakeDb(); const rl = createRateLimiters({ env: ENV, fetch: db.f }); const l = rl("ai-anon", 3, 1e9, 3600_000); db.setDown(true);
  assert.deepEqual([await l("k"), await l("k"), await l("k"), await l("k")], [true, true, true, false]); assert.ok(rl.sharedFailures() >= 4);
  const old = fakeDb(3600); const day = createRateLimiters({ env: ENV, fetch: old.f })("ai-day", 1e9, 2, 86_400_000); assert.deepEqual([await day("g"), await day("g"), await day("g")], [true, true, false]);   // 0112-only database rejects 24 h windows -> memory fallback still enforces the cap
});
test("end to end: two app instances share the support-chat quota through the same database", async () => {
  const db = fakeDb(); let calls = 0; const prov = (async () => { calls++; return new Response(JSON.stringify({ content: [{ type: "text", text: "Pro is $199/month. Payments are not enabled yet." }] }), { status: 200 }); }) as unknown as typeof fetch;
  const env = { ...ENV, ANTHROPIC_API_KEY: "sk-ant-placeholder" } as NodeJS.ProcessEnv; const mk = () => createSupportHandlers({ env, complete: anthropicComplete(env, prov), rl: createRateLimiters({ env, fetch: db.f }) } as any);
  const req = () => new Request("https://app.test/api/support/chat", { method: "POST", headers: { host: "app.test", origin: "https://app.test", "content-type": "application/json", "x-forwarded-for": "203.0.113.9" }, body: JSON.stringify({ message: "What is the Pro plan price?" }) });
  const h1 = mk(), h2 = mk(); const modes: string[] = []; for (let i = 0; i < 12; i++) modes.push(((await ((i % 2 ? h1 : h2).chat(req()).then((r) => r.json()))) as any).mode);
  assert.equal(modes.filter((m) => m === "ai").length, 10); assert.equal(modes.filter((m) => m === "limited").length, 2); assert.equal(calls, 10);
});
