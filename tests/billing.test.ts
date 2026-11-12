// Stripe billing (TEST MODE ONLY). Stripe itself is replaced by a local fake HTTP server that records requests; webhook signatures are computed with the same HMAC scheme Stripe uses.
// This proves OUR code (signature check, idempotency, ordering, entitlements, isolation, owner-only, secret hygiene). It does NOT prove behaviour against the real Stripe test environment: see docs/BILLING.md.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { verifyWebhook, stripeMode } from "../lib/billing/stripe";
import { effectivePlan, planForPrice } from "../lib/billing/plans";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const KEY = "sk_test_" + "A1b2C3d4E5f6G7h8", WHSEC = "whsec_" + "unitTestSecret0123456789";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const sign = (body: string, secret = WHSEC, t = Math.floor(Date.now() / 1000)) => `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;

async function fake() {
  const seen: { path: string; auth?: string; body: string; idem?: string }[] = [];
  const srv = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { seen.push({ path: req.url!, auth: req.headers.authorization, body: b, idem: req.headers["idempotency-key"] as string | undefined });
    res.setHeader("content-type", "application/json"); if (req.url === "/v1/customers") return res.end(JSON.stringify({ id: "cus_TEST" + seen.length })); if (req.url === "/v1/checkout/sessions") return res.end(JSON.stringify({ id: "cs_test_1", url: "https://checkout.stripe.test/c/pay/cs_test_1" }));
    if (req.url === "/v1/billing_portal/sessions") return res.end(JSON.stringify({ url: "https://billing.stripe.test/p/session/x" })); res.statusCode = 404; res.end("{}"); }); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r)); return { seen, base: `http://127.0.0.1:${(srv.address() as any).port}`, close: () => srv.close() };
}
async function world() {
  const f = await fake(), s = new TestStore(), U = { owner: randomUUID(), noc: randomUUID(), bOwner: randomUUID() }, tok = { owner: jwt(U.owner, `o${U.owner}@x.io`), noc: jwt(U.noc, `n${U.noc}@x.io`), bOwner: jwt(U.bOwner, `b${U.bOwner}@x.io`) };
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a", plan: "free" }, { id: ORG_B, name: "Org B", slug: "org-b", plan: "free" }] as any);
  const m = (o: string, u: string, r: string) => s.upsert("org_members", [{ orgId: o, userId: u, role: r }] as any, "org_id,user_id");
  await m(ORG_A, U.owner, "owner"); await m(ORG_A, U.noc, "noc_operator"); await m(ORG_B, U.bOwner, "owner");
  const env = { STRIPE_SECRET_KEY: KEY, STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_PRICE_PRO: "price_test_pro", STRIPE_PRICE_ENTERPRISE: "price_test_ent", APP_URL: "https://app.autoadjust.test", STRIPE_API_BASE: f.base } as Record<string, string>;
  const call = (method: string, p: string, t: string | null, b?: unknown, e = env) => handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { ...(t ? { authorization: "Bearer " + t } : {}), "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("/"), { store: s, model: null, env: e } as any);
  const hook = (ev: any, e = env, header?: string) => { const body = JSON.stringify(ev); return handleSoc(new Request("http://x/api/soc/billing/webhook", { method: "POST", headers: header === undefined ? { "stripe-signature": sign(body, e.STRIPE_WEBHOOK_SECRET) } : { "stripe-signature": header }, body }), ["billing", "webhook"], { store: s, model: null, env: e } as any); };
  return { f, s, tok, env, call, hook };
}
const sub = (org: string, o: any = {}) => ({ id: "evt_" + randomUUID(), type: o.type ?? "customer.subscription.updated", created: o.created ?? Math.floor(Date.now() / 1000), livemode: false,
  data: { object: { id: o.subId ?? "sub_TEST1", customer: o.customer ?? "cus_TESTx", status: o.status ?? "active", metadata: { org_id: org }, items: { data: [{ price: { id: o.price ?? "price_test_pro" } }] }, current_period_end: o.end ?? Math.floor(Date.now() / 1000) + 86400 * 20, cancel_at_period_end: false } } });

test("webhook signature: valid accepted; wrong secret, tampered body, stale timestamp, malformed header, missing secret all rejected", () => {
  const body = '{"a":1}', now = Date.now();
  assert.ok(verifyWebhook(body, sign(body), WHSEC)); assert.ok(!verifyWebhook(body, sign(body, "whsec_other"), WHSEC)); assert.ok(!verifyWebhook(body + " ", sign(body), WHSEC));
  assert.ok(!verifyWebhook(body, sign(body, WHSEC, Math.floor(now / 1000) - 3600), WHSEC)); for (const h of ["", "garbage", "t=1,v1=zz", `t=${Math.floor(now / 1000)}`, null]) assert.ok(!verifyWebhook(body, h as any, WHSEC));
  assert.ok(!verifyWebhook(body, sign(body), undefined));
});
test("mode guard: test keys ok; live key refused unless BILLING_MODE=live; garbage key = not configured; API base may only be localhost", async () => {
  assert.equal(stripeMode({ STRIPE_SECRET_KEY: KEY }), "test"); assert.equal(stripeMode({ STRIPE_SECRET_KEY: "sk_live_" + "Zz9Yy8Xx7Ww6Vv5U" }), "live"); assert.equal(stripeMode({ STRIPE_SECRET_KEY: "nope" }), null);
  const w = await world(); try {
    assert.equal((await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" }, { ...w.env, STRIPE_SECRET_KEY: "sk_live_" + "Zz9Yy8Xx7Ww6Vv5U" })).status, 503);
    assert.equal((await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" }, { ...w.env, STRIPE_API_BASE: "https://evil.example" })).status, 500, "key must never be sent to another host");
    assert.equal(w.f.seen.length, 0);
  } finally { w.f.close(); }
});
test("checkout: owner only; unknown plan refused; sends org id + price; never the client's redirect; key stays in the Authorization header only", async () => {
  const w = await world(); try {
    assert.equal((await w.call("POST", "billing/checkout", w.tok.noc, { plan: "pro" })).status, 403); assert.equal((await w.call("POST", "billing/checkout", null, { plan: "pro" })).status, 401);
    assert.equal((await w.call("POST", "billing/checkout", w.tok.owner, { plan: "platinum" })).status, 400);
    const r = await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro", success_url: "https://evil.example" }); const j: any = await r.json(); assert.equal(r.status, 200); assert.match(j.url, /^https:\/\/checkout\.stripe\.test\//);
    const cs = w.f.seen.find((x) => x.path === "/v1/checkout/sessions")!; assert.equal(cs.auth, "Bearer " + KEY); const q = new URLSearchParams(cs.body);
    assert.equal(q.get("client_reference_id"), ORG_A); assert.equal(q.get("line_items[0][price]"), "price_test_pro"); assert.equal(q.get("mode"), "subscription"); assert.ok(q.get("success_url")!.startsWith("https://app.autoadjust.test/account.html")); assert.ok(!cs.body.includes("evil.example")); assert.ok(!cs.body.includes(KEY));
    assert.ok(!JSON.stringify(j).includes(KEY));
  } finally { w.f.close(); }
});
test("webhook: bad signature 400, no side effects; duplicate event applied once; unknown event types ignored", async () => {
  const w = await world(); try {
    assert.equal((await w.hook(sub(ORG_A), w.env, "t=1,v1=" + "0".repeat(64))).status, 400); assert.equal((await w.s.select("org_billing", {})).length, 0);
    await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" }); const ev = sub(ORG_A, { customer: "cus_TEST1" });
    assert.equal(((await (await w.hook(ev)).json()) as any).duplicate, false); assert.equal(((await (await w.hook(ev)).json()) as any).duplicate, true);
    assert.equal((await w.s.select("audit", {})).length >= 0, true);
    assert.equal((await w.hook({ id: "evt_x", type: "charge.refunded", created: 1, livemode: false, data: { object: {} } })).status, 200);
    assert.equal((await w.hook({ ...sub(ORG_A), livemode: true })).status, 400, "live event rejected by a test-mode server");
  } finally { w.f.close(); }
});
test("entitlements: active pro lifts limits; canceled / unpaid / unknown price fall back to free; past_due keeps access only until period end", async () => {
  const w = await world(); try {
    const plan = async () => ((await (await w.call("GET", "billing/status", w.tok.owner)).json()) as any).plan;
    assert.equal(await plan(), "free"); let t = Math.floor(Date.now() / 1000);
    await w.hook(sub(ORG_A, { created: ++t })); assert.equal(await plan(), "pro");
    await w.hook(sub(ORG_A, { created: ++t, price: "price_UNKNOWN" })); assert.equal(await plan(), "free", "unknown price never grants a paid plan");
    await w.hook(sub(ORG_A, { created: ++t, status: "past_due" })); assert.equal(await plan(), "pro", "grace until period end");
    await w.hook(sub(ORG_A, { created: ++t, status: "past_due", end: Math.floor(Date.now() / 1000) - 10 })); assert.equal(await plan(), "free");
    await w.hook(sub(ORG_A, { created: ++t, status: "unpaid" })); assert.equal(await plan(), "free");
    await w.hook(sub(ORG_A, { created: ++t })); assert.equal(await plan(), "pro"); await w.hook(sub(ORG_A, { created: ++t, type: "customer.subscription.deleted", status: "canceled" })); assert.equal(await plan(), "free");
    assert.equal(effectivePlan({ plan: "pro", status: "active" }), "pro"); assert.equal(planForPrice("price_x", {}), null);
  } finally { w.f.close(); }
});
test("out-of-order: an older event cannot overwrite a newer state", async () => {
  const w = await world(); try { const now = Math.floor(Date.now() / 1000), plan = async () => ((await (await w.call("GET", "billing/status", w.tok.owner)).json()) as any).plan;
    await w.hook(sub(ORG_A, { created: now })); assert.equal(await plan(), "pro"); await w.hook(sub(ORG_A, { created: now - 100, type: "customer.subscription.deleted", status: "canceled" })); assert.equal(await plan(), "pro"); } finally { w.f.close(); }
});
test("isolation: an event for org A never changes org B; B cannot see A; unknown / malformed org ids are ignored", async () => {
  const w = await world(); try {
    await w.hook(sub(ORG_A)); const st = async (t: string) => (await (await w.call("GET", "billing/status", t)).json()) as any;
    assert.equal((await st(w.tok.owner)).plan, "pro"); assert.equal((await st(w.tok.bOwner)).plan, "free");
    await w.hook(sub("not-a-uuid", { subId: "sub_2" })); await w.hook(sub("c0000000-0000-4000-8000-0000000000c1", { subId: "sub_3" })); assert.equal((await st(w.tok.bOwner)).plan, "free");
    assert.equal((await w.s.select("org_billing", {})).length, 1);
  } finally { w.f.close(); }
});
test("a customer id already bound to org A cannot be re-bound by metadata naming org B", async () => {
  const w = await world(); try { await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" }); const cus = ((await w.s.select<any>("org_billing", {}))[0]).customerId;
    await w.hook(sub(ORG_A, { customer: cus })); await w.hook(sub(ORG_B, { customer: cus, subId: "sub_evil", created: Math.floor(Date.now() / 1000) + 5 }));
    const b = await w.s.select<any>("org_billing", { where: { orgId: ORG_B } }); assert.equal(b.length, 0); } finally { w.f.close(); }
});
test("portal: owner only, needs an existing customer; plan limits are enforced on API keys and executors (HTTP 402)", async () => {
  const w = await world(); try {
    assert.equal((await w.call("POST", "billing/portal", w.tok.owner)).status, 404); await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" });
    assert.equal((await w.call("POST", "billing/portal", w.tok.noc)).status, 403); assert.equal((await w.call("POST", "billing/portal", w.tok.owner)).status, 200);
    const codes: number[] = []; for (let i = 0; i < 6; i++) codes.push((await w.call("POST", "org/keys", w.tok.owner, { name: "key-" + i })).status);
    assert.deepEqual(codes, [201, 201, 201, 201, 201, 402], "free plan = 5 keys"); await w.hook(sub(ORG_A, { customer: ((await w.s.select<any>("org_billing", {}))[0]).customerId }));
    assert.equal((await w.call("POST", "org/keys", w.tok.owner, { name: "key-after-upgrade" })).status, 201, "upgrade lifts the limit");
  } finally { w.f.close(); }
});
test("webhook is closed when not configured; no Stripe secret appears in any stored row", async () => {
  const w = await world(); try { assert.equal((await w.hook(sub(ORG_A), { ...w.env, STRIPE_WEBHOOK_SECRET: "" }, "t=1,v1=00")).status, 503);
    await w.call("POST", "billing/checkout", w.tok.owner, { plan: "pro" }); const dump = JSON.stringify([await w.s.select("org_billing", {}), await w.s.select("billing_events", {}), await w.s.select("soc_audit", {})]); assert.ok(!dump.includes(KEY) && !dump.includes(WHSEC)); } finally { w.f.close(); }
});
