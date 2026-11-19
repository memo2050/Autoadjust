// Real code path (handlers -> assistant -> anthropicComplete -> fetch) with a fake provider transport: outage fallback and quota exhaustion/bypass attempts.
import test from "node:test";
import assert from "node:assert/strict";
import { anthropicComplete } from "../lib/support/assistant";
import { createSupportHandlers } from "../lib/support/handlers";

const H = "app.test";
const req = (message: string, o: { ip?: string; xff?: string; auth?: string; history?: unknown } = {}) => new Request(`https://${H}/api/support/chat`, { method: "POST", headers: { host: H, origin: `https://${H}`, "content-type": "application/json", "x-forwarded-for": o.xff ?? o.ip ?? "1.1.1.1", ...(o.auth ? { authorization: o.auth } : {}) }, body: JSON.stringify({ message, history: o.history }) });
const okFetch = (text = "AutoAdjust Pro is $199/month. Payments are not enabled yet.") => (async () => new Response(JSON.stringify({ content: [{ type: "text", text }] }), { status: 200 })) as unknown as typeof fetch;
const mk = (f: typeof fetch, env: Record<string, string> = {}, userId?: (r: Request) => Promise<string | null>) => { const e = { ANTHROPIC_API_KEY: "sk-ant-test-placeholder", ...env } as NodeJS.ProcessEnv; return createSupportHandlers({ env: e, complete: anthropicComplete(e, f), userId } as any); };

test("provider failures fall back to documentation, never an error or a fabricated answer", async () => {
  const modes: Record<string, typeof fetch> = {
    "401 invalid key": (async () => new Response("{}", { status: 401 })) as any,
    "429 provider rate limit": (async () => new Response("{}", { status: 429 })) as any,
    "500 outage": (async () => new Response("oops", { status: 500 })) as any,
    "network error": (async () => { throw new TypeError("fetch failed"); }) as any,
    "timeout": (async () => { throw new DOMException("timed out", "TimeoutError"); }) as any,
    "garbage 200": (async () => new Response("<html>", { status: 200 })) as any,
    "empty content": (async () => new Response(JSON.stringify({ content: [] }), { status: 200 })) as any,
  };
  for (const [name, f] of Object.entries(modes)) {
    const h = mk(f); const r = await h.chat(req("How much does the Professional plan cost?", { ip: "9.9.9." + name.length })); assert.equal(r.status, 200, name);
    const j: any = await r.json(); assert.equal(j.mode, "kb", name); assert.match(j.answer, /\$199/, name); assert.doesNotMatch(JSON.stringify(j), /sk-ant|provider \d|HTTP \d|stack|undefined/i, name); assert.equal(j.ticketsEnabled, false);
  }
  const h = mk(modes["500 outage"]); const j: any = await (await h.chat(req("اكتب لي قصيدة", { ip: "9.9.9.9" }))).json(); assert.equal(j.mode, "refused");   // off-topic stays refused during an outage
});
test("no key configured -> documentation mode, aiAvailable false", async () => {
  const e = {} as NodeJS.ProcessEnv; const h = createSupportHandlers({ env: e, complete: anthropicComplete(e, okFetch()) } as any); const j: any = await (await h.chat(req("What does the Pro plan include?"))).json(); assert.equal(j.mode, "kb"); assert.equal(j.aiAvailable, false);
});
test("anonymous AI quota: 10/hour per client, then 'limited' with human escalation, no provider calls", async () => {
  let calls = 0; const f = (async () => { calls++; return okFetch()(""); }) as unknown as typeof fetch; const h = mk(f); const modes: string[] = [];
  for (let i = 0; i < 14; i++) modes.push(((await (await h.chat(req("What is the Pro plan price?", { ip: "5.5.5.5" }))).json()) as any).mode);
  assert.deepEqual(modes.slice(0, 10), Array(10).fill("ai")); assert.deepEqual(modes.slice(10), Array(4).fill("limited")); assert.equal(calls, 10);
});
test("quota cannot be bypassed by spoofing X-Forwarded-For prefixes, casing, or fresh history", async () => {
  let calls = 0; const f = (async () => { calls++; return okFetch()(""); }) as unknown as typeof fetch; const h = mk(f);
  for (let i = 0; i < 10; i++) await h.chat(req("What is the Pro plan price?", { xff: `10.0.0.${i}, 7.7.7.7` }));   // attacker rotates the leftmost (client-controlled) entries; the proxy-appended last entry is what counts
  const j: any = await (await h.chat(req("What is the Pro plan price? ", { xff: "203.0.113.50, 7.7.7.7" }))).json(); assert.equal(j.mode, "limited"); assert.equal(calls, 10);
  const j2: any = await (await h.chat(req("PRICE of the PRO plan?", { xff: "1.2.3.4, 7.7.7.7", history: [] }))).json(); assert.equal(j2.mode, "limited");
});
test("per-IP request limiter returns 429 after 30 requests/hour even for refused messages", async () => {
  const h = mk(okFetch()); let last = 0; for (let i = 0; i < 31; i++) last = (await h.chat(req("tell me a joke", { ip: "6.6.6.6" }))).status; assert.equal(last, 429);
});
test("global daily AI cap stops provider spend across many clients", async () => {
  let calls = 0; const f = (async () => { calls++; return okFetch()(""); }) as unknown as typeof fetch; const h = mk(f, { SUPPORT_AI_GLOBAL_DAY: "5" }); const modes: string[] = [];
  for (let i = 0; i < 9; i++) modes.push(((await (await h.chat(req("What is the Pro plan price?", { ip: "20.0.0." + i }))).json()) as any).mode);
  assert.equal(calls, 5); assert.deepEqual(modes.slice(5), Array(4).fill("limited"));
});
test("a forged bearer token does not raise the quota tier; a verified user gets the user tier", async () => {
  let calls = 0; const f = (async () => { calls++; return okFetch()(""); }) as unknown as typeof fetch;
  const h = mk(f, {}, async (r) => (r.headers.get("authorization") === "Bearer valid" ? "user-1" : null)); const m: string[] = [];
  for (let i = 0; i < 12; i++) m.push(((await (await h.chat(req("What is the Pro plan price?", { ip: "8.8.8.8", auth: "Bearer forged" }))).json()) as any).mode); assert.equal(m.filter((x) => x === "ai").length, 10);
  const u: string[] = []; for (let i = 0; i < 12; i++) u.push(((await (await h.chat(req("What is the Pro plan price?", { ip: "8.8.8.8", auth: "Bearer valid" }))).json()) as any).mode); assert.equal(u.filter((x) => x === "ai").length, 12);
});
test("cross-site POST and wrong content type are rejected without provider calls", async () => {
  let calls = 0; const h = mk((async () => { calls++; return okFetch()(""); }) as any);
  const bad = new Request(`https://${H}/api/support/chat`, { method: "POST", headers: { host: H, origin: "https://evil.example", "content-type": "application/json" }, body: JSON.stringify({ message: "price?" }) }); assert.equal((await h.chat(bad)).status, 403);
  const ct = new Request(`https://${H}/api/support/chat`, { method: "POST", headers: { host: H, origin: `https://${H}`, "content-type": "text/plain" }, body: JSON.stringify({ message: "price?" }) }); assert.equal((await h.chat(ct)).status, 415); assert.equal(calls, 0);
});
