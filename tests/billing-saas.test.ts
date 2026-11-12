// SaaS billing: configurable plans, trials, usage, annual billing, plan change, cancel/resume, invoices, refunds, grace period, admin controls, isolation.
// Runs against a LOCAL fake Stripe only. It proves our logic; it does NOT prove behaviour against the real Stripe test environment.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHmac, randomUUID } from "node:crypto";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";

const ADMIN = randomUUID();
process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN; process.env.BILLING_ENFORCE = "1"; process.env.PLATFORM_ADMIN_USER_IDS = ADMIN;
const KEY = "sk_test_" + "A1b2C3d4E5f6G7h8", WHSEC = "whsec_" + "unitTestSecret0123456789", DAY = 86400000;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, email: string) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email, role: "authenticated", aud: "authenticated", exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const ORG_A = "a0000000-0000-4000-8000-0000000000a1", ORG_B = "b0000000-0000-4000-8000-0000000000b1";
const sign = (body: string) => { const t = Math.floor(Date.now() / 1000); return `t=${t},v1=${createHmac("sha256", WHSEC).update(`${t}.${body}`).digest("hex")}`; };

async function fake() {
  const seen: { method: string; path: string; body: string }[] = [];
  const srv = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { seen.push({ method: req.method!, path: req.url!, body: b }); res.setHeader("content-type", "application/json");
    const u = req.url!; if (u === "/v1/customers") return res.end(JSON.stringify({ id: "cus_T" + seen.length })); if (u === "/v1/checkout/sessions") return res.end(JSON.stringify({ id: "cs_test_1", url: "https://checkout.stripe.test/c/1" }));
    if (u.startsWith("/v1/subscriptions/")) return res.end(JSON.stringify({ id: "sub_T1", items: { data: [{ id: "si_1" }] } })); if (u === "/v1/coupons") return res.end(JSON.stringify({ id: "COUPON25" })); if (u === "/v1/refunds") return res.end(JSON.stringify({ id: "re_1" }));
    res.statusCode = 404; res.end("{}"); }); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r)); return { seen, base: `http://127.0.0.1:${(srv.address() as any).port}`, close: () => srv.close() };
}
async function world() {
  const f = await fake(), s = new TestStore(), U = { owner: randomUUID(), bOwner: randomUUID() };
  const tok = { owner: jwt(U.owner, "o@x.io"), bOwner: jwt(U.bOwner, "b@x.io"), admin: jwt(ADMIN, "admin@x.io") };
  await s.upsert("organizations", [{ id: ORG_A, name: "Org A", slug: "org-a", plan: "free" }, { id: ORG_B, name: "Org B", slug: "org-b", plan: "free" }] as any);
  const m = (o: string, u: string, r: string) => s.upsert("org_members", [{ orgId: o, userId: u, role: r }] as any, "org_id,user_id");
  await m(ORG_A, U.owner, "owner"); await m(ORG_B, U.bOwner, "owner"); await m(ORG_A, ADMIN, "owner");
  const env = { STRIPE_SECRET_KEY: KEY, STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_PRICE_PRO: "price_pro_m", STRIPE_PRICE_PRO_ANNUAL: "price_pro_y", STRIPE_PRICE_ENTERPRISE: "price_ent_m", APP_URL: "https://app.autoadjust.test", STRIPE_API_BASE: f.base, BILLING_ENFORCE: "1" } as Record<string, string>;
  const call = (method: string, p: string, t: string | null, b?: unknown) => handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { ...(t ? { authorization: "Bearer " + t } : {}), "content-type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) }), p.split("/"), { store: s, model: null, env } as any);
  const J = async (method: string, p: string, t: string, b?: unknown) => { const r = await call(method, p, t, b); return { status: r.status, body: (await r.json()) as any }; };
  const hook = (ev: any) => { const body = JSON.stringify(ev); return handleSoc(new Request("http://x/api/soc/billing/webhook", { method: "POST", headers: { "stripe-signature": sign(body) }, body }), "billing/webhook".split("/"), { store: s, model: null, env } as any); };
  return { f, s, tok, env, call, J, hook };
}
const ev = (type: string, object: any, created = Math.floor(Date.now() / 1000)) => ({ id: "evt_" + randomUUID(), type, created, livemode: false, data: { object } });
const sub = (org: string, o: any = {}) => ev(o.type ?? "customer.subscription.updated", { id: "sub_T1", customer: o.customer ?? "cus_X1", status: o.status ?? "active", metadata: { org_id: org }, items: { data: [{ price: { id: o.price ?? "price_pro_m" } }] }, current_period_end: o.end ?? Math.floor(Date.now() / 1000) + 30 * 86400 }, o.created);
const inv = (org: string, id: string, o: any = {}) => ev(o.type ?? "invoice.paid", { id, customer: "cus_X1", number: "INV-" + id, status: o.status ?? "paid", amount_due: 4900, amount_paid: o.paid ?? 4900, currency: "usd", payment_intent: o.pi ?? "pi_" + id, subscription_details: { metadata: { org_id: org } }, hosted_invoice_url: "https://invoice.stripe.test/" + id, period_start: 1, period_end: 2, created: Math.floor(Date.now() / 1000) });

test("plans are configurable by the platform admin only; invalid values rejected; change is visible in status; per-org overrides do not leak", async () => {
  const w = await world(); try {
    assert.equal((await w.J("GET", "billing/admin/plans", w.tok.owner)).status, 403); assert.equal((await w.J("PUT", "billing/admin/plans/pro", w.tok.owner, { maxDevices: 1 })).status, 403);
    assert.equal((await w.J("PUT", "billing/admin/plans/pro", w.tok.admin, { maxDevices: -5 })).status, 400); assert.equal((await w.J("PUT", "billing/admin/plans/bogus", w.tok.admin, {})).status, 404);
    const u = await w.J("PUT", "billing/admin/plans/free", w.tok.admin, { maxDevices: 30, trialDays: 21 }); assert.equal(u.status, 200);
    const st = await w.J("GET", "billing/status", w.tok.owner); assert.equal(st.body.entitlements.maxDevices, 30); assert.equal(st.body.trial.daysLeft, 21);
    assert.equal((await w.J("PUT", `billing/admin/orgs/${ORG_B}/overrides`, w.tok.admin, { maxDevices: 7 })).status, 200);
    assert.equal((await w.J("GET", "billing/status", w.tok.bOwner)).body.entitlements.maxDevices, 7); assert.equal((await w.J("GET", "billing/status", w.tok.owner)).body.entitlements.maxDevices, 30, "org A unaffected");
    assert.equal((await w.J("PUT", `billing/admin/orgs/${ORG_B}/overrides`, w.tok.admin, { reset: true })).body.overrides.maxDevices, undefined);
  } finally { w.f.close(); }
});
test("trial: starts at 14 days, expires into 'restricted' (nothing new, nothing deleted), admin can grant a promotional trial", async () => {
  const w = await world(); try {
    const st = await w.J("GET", "billing/status", w.tok.owner); assert.deepEqual([st.body.trial.state, st.body.trial.daysLeft, st.body.restricted], ["active", 14, false]);
    await w.J("POST", "noc/telemetry", w.tok.owner, { devices: [{ id: "d1", type: "server", metrics: { cpu: 5 } }] });
    const b = (await w.s.select<any>("org_billing", { where: { orgId: ORG_A } }))[0]; await w.s.upsert("org_billing", [{ ...b, trialEndsAt: new Date(Date.now() - DAY).toISOString() }] as any, "org_id");
    const ex = await w.J("GET", "billing/status", w.tok.owner); assert.deepEqual([ex.body.trial.state, ex.body.restricted], ["expired", true]);
    const k = await w.J("POST", "org/keys", w.tok.owner, { name: "after-trial" }); assert.equal(k.status, 402); assert.equal(k.body.code, "trial_expired"); assert.equal(k.body.upgradeUrl, "/account.html#billing");
    const t = await w.J("POST", "noc/telemetry", w.tok.owner, { devices: [{ id: "d1", type: "server", metrics: { cpu: 9 } }, { id: "d2", type: "server" }] }); assert.equal(t.body.received, 1, "existing d1 still updates"); assert.equal(t.body.deviceLimitSkipped, 1, "new d2 refused");
    assert.equal((await w.s.select<any>("noc_devices", {})).length, 1, "nothing deleted");
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/trial`, w.tok.owner, { days: 5 })).status, 403);
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/trial`, w.tok.admin, { days: 30 })).status, 200);
    assert.equal((await w.J("GET", "billing/status", w.tok.owner)).body.restricted, false); assert.equal((await w.J("POST", "org/keys", w.tok.owner, { name: "after-grant" })).status, 201);
  } finally { w.f.close(); }
});
test("usage: used / limit / remaining per organization, limit-reached flag, never negative", async () => {
  const w = await world(); try {
    await w.J("POST", "noc/telemetry", w.tok.owner, { devices: [{ id: "a", type: "server" }, { id: "b", type: "server" }] });
    const u = (await w.J("GET", "billing/usage", w.tok.owner)).body; assert.deepEqual([u.devices.used, u.devices.limit, u.devices.remaining], [2, 25, 23]); assert.equal(u.devices.reached, false);
    await w.J("PUT", `billing/admin/orgs/${ORG_A}/overrides`, w.tok.admin, { maxDevices: 1 }); const v = (await w.J("GET", "billing/usage", w.tok.owner)).body; assert.deepEqual([v.devices.remaining, v.devices.overLimit, v.devices.reached], [0, true, true]);
    assert.equal((await w.J("GET", "billing/usage", w.tok.bOwner)).body.devices.used, 0, "org B sees only its own");
  } finally { w.f.close(); }
});
test("annual checkout, plan change, cancel and resume go through Stripe with our subscription id; only the webhook changes state", async () => {
  const w = await world(); try {
    assert.equal((await w.J("POST", "billing/change", w.tok.owner, { plan: "pro" })).status, 409, "no subscription yet");
    assert.equal((await w.J("POST", "billing/checkout", w.tok.owner, { plan: "pro", interval: "year" })).status, 200);
    assert.ok(w.f.seen.some((x) => x.path === "/v1/checkout/sessions" && x.body.includes("price_pro_y")), "annual price used"); assert.equal((await w.J("POST", "billing/checkout", w.tok.owner, { plan: "enterprise", interval: "year" })).status, 400, "unconfigured price refused");
    const cus = ((await w.s.select<any>("org_billing", {}))[0]).customerId; await w.hook(sub(ORG_A, { price: "price_pro_y", customer: cus })); const st = (await w.J("GET", "billing/status", w.tok.owner)).body; assert.deepEqual([st.plan, st.subscription.interval], ["pro", "year"]);
    assert.equal((await w.J("POST", "billing/change", w.tok.owner, { plan: "enterprise", interval: "month" })).status, 200);
    const post = w.f.seen.filter((x) => x.method === "POST" && x.path === "/v1/subscriptions/sub_T1").pop()!; assert.ok(post.body.includes("price_ent_m") && post.body.includes("si_1") && post.body.includes("proration_behavior"));
    assert.equal((await w.J("GET", "billing/status", w.tok.owner)).body.plan, "pro", "plan only changes when the signed webhook arrives");
    assert.equal((await w.J("POST", "billing/cancel", w.tok.owner)).status, 200); assert.ok(w.f.seen.some((x) => x.body === "cancel_at_period_end=true")); assert.equal((await w.J("POST", "billing/resume", w.tok.owner)).status, 200);
    assert.equal((await w.J("POST", "billing/cancel", w.tok.bOwner)).status, 409, "org B has no subscription and cannot touch org A's");
    await w.hook(sub(ORG_A, { price: "price_pro_m", customer: cus, status: "active", created: Math.floor(Date.now() / 1000) + 5 })); const d = (await w.J("GET", "billing/status", w.tok.owner)).body; assert.equal(d.subscription.interval, "month");
    const dev = await w.J("PUT", `billing/admin/orgs/${ORG_A}/overrides`, w.tok.admin, {}); assert.equal(dev.status, 200);
  } finally { w.f.close(); }
});
test("invoices and payments: recorded per organization from signed webhooks, owner-only, isolated; failed payment recorded; refund recorded; admin refund request", async () => {
  const w = await world(); try {
    await w.hook(sub(ORG_A)); await w.hook(inv(ORG_A, "in_1")); await w.hook(inv(ORG_A, "in_2", { type: "invoice.payment_failed", status: "open", paid: 0 }));
    const I = (await w.J("GET", "billing/invoices", w.tok.owner)).body.invoices, P = (await w.J("GET", "billing/payments", w.tok.owner)).body.payments;
    assert.deepEqual(I.map((i: any) => i.id).sort(), ["in_1", "in_2"]); assert.equal(P.find((x: any) => x.id === "pi_in_1").status, "succeeded"); assert.equal(P.find((x: any) => x.id === "pi_in_2").status, "failed");
    assert.ok((await w.J("GET", "billing/status", w.tok.owner)).body.subscription.paymentFailedAt, "failure surfaced");
    assert.equal((await w.J("GET", "billing/invoices", w.tok.bOwner)).body.invoices.length, 0, "org B sees none of A's invoices");
    await w.hook(inv(ORG_A, "in_3")); assert.equal((await w.J("GET", "billing/status", w.tok.owner)).body.subscription.paymentFailedAt, null, "cleared by a later successful payment");
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/refund`, w.tok.owner, { paymentId: "pi_in_1" })).status, 403);
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_B}/refund`, w.tok.admin, { paymentId: "pi_in_1" })).status, 404, "a payment of org A cannot be refunded through org B");
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/refund`, w.tok.admin, { paymentId: "pi_in_1", amountCents: 1000 })).status, 200); assert.ok(w.f.seen.some((x) => x.path === "/v1/refunds" && x.body.includes("payment_intent=pi_in_1") && x.body.includes("amount=1000")));
    await w.hook(ev("charge.refunded", { id: "ch_1", customer: "cus_X1", payment_intent: "pi_in_1", amount_refunded: 1000, amount: 4900, currency: "usd", metadata: { org_id: ORG_A } }));
    assert.equal((await w.J("GET", "billing/payments", w.tok.owner)).body.payments.find((x: any) => x.id === "pi_in_1").refunded, 1000);
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/refund`, w.tok.admin, { paymentId: "pi_in_1", amountCents: 999999 })).status, 400, "cannot refund more than was paid");
  } finally { w.f.close(); }
});
test("grace period is configurable: past_due keeps the plan for period end + grace days, then drops to free", async () => {
  const w = await world(); try {
    await w.hook(sub(ORG_A, { status: "past_due", end: Math.floor((Date.now() - 2 * DAY) / 1000) }));
    const plan = async () => (await w.J("GET", "billing/status", w.tok.owner)).body.plan; assert.equal(await plan(), "pro", "default 7 grace days");
    assert.equal((await w.J("PUT", "billing/admin/settings", w.tok.admin, { graceDays: 0 })).status, 200); assert.equal(await plan(), "free");
    await w.J("PUT", "billing/admin/settings", w.tok.admin, { graceDays: 5 }); assert.equal(await plan(), "pro"); assert.equal((await w.J("PUT", "billing/admin/settings", w.tok.admin, { graceDays: 999 })).status, 400);
  } finally { w.f.close(); }
});
test("admin: coupons / discounts / org list / stats; non-admins refused; no secrets in any response", async () => {
  const w = await world(); try {
    await w.hook(sub(ORG_A, { price: "price_pro_y" })); await w.hook(inv(ORG_A, "in_9"));
    assert.equal((await w.J("POST", "billing/admin/coupons", w.tok.owner, { percentOff: 25 })).status, 403);
    const c = await w.J("POST", "billing/admin/coupons", w.tok.admin, { percentOff: 25, duration: "once" }); assert.equal(c.body.couponId, "COUPON25");
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/discount`, w.tok.admin, { couponId: "bad id!" })).status, 400);
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_A}/discount`, w.tok.admin, { couponId: "COUPON25" })).status, 200); assert.ok(w.f.seen.some((x) => x.body.includes("discounts%5B0%5D%5Bcoupon%5D=COUPON25")));
    assert.equal((await w.J("POST", `billing/admin/orgs/${ORG_B}/discount`, w.tok.admin, { couponId: "COUPON25" })).status, 409, "org B has no subscription");
    const o = (await w.J("GET", "billing/admin/orgs", w.tok.admin)).body; assert.equal(o.organizations.length, 2); assert.equal(o.organizations.find((x: any) => x.id === ORG_A).plan, "pro");
    const s = (await w.J("GET", "billing/admin/stats", w.tok.admin)).body; assert.deepEqual([s.paidSubscriptions, s.estimatedMrrCents, s.revenueTotalCents], [1, Math.round(49000 / 12), 4900]);
    assert.equal((await w.J("GET", "billing/admin/orgs", w.tok.owner)).status, 403);
    const all = JSON.stringify([o, s, (await w.J("GET", "billing/status", w.tok.owner)).body]); assert.ok(!all.includes(KEY) && !all.includes(WHSEC));
  } finally { w.f.close(); }
});
test("enforcement preview: read-only, per organization usage vs limits, violations listed, admin only, nothing written or blocked", async () => {
  const w = await world(); try {
    delete (w.env as any).BILLING_ENFORCE;                                           // the server is NOT enforcing; the preview must still show what would happen
    const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ id: ORG_A + ":p" + i, orgId: ORG_A, type: "server", up: true, metrics: {}, links: [], history: [], source: "live", receivedAt: new Date().toISOString() }));
    await w.s.upsert("noc_devices", mk(30) as any); const before = JSON.stringify([await w.s.select("org_billing", {}), await w.s.select("noc_devices", {})]);
    assert.equal((await w.J("GET", "billing/admin/preview", w.tok.owner)).status, 403);
    const r = (await w.J("GET", "billing/admin/preview", w.tok.admin)).body, a = r.organizations.find((x: any) => x.id === ORG_A), b = r.organizations.find((x: any) => x.id === ORG_B);
    assert.equal(r.readOnly, true); assert.equal(r.enforcedOnServer, false); assert.deepEqual([a.used.devices, a.limits.devices], [30, 25]); assert.ok(a.violations[0].startsWith("devices: 30 used")); assert.deepEqual(b.violations, [], "org B unaffected by org A's devices");
    assert.equal(a.trial, "would start a fresh trial"); assert.equal(r.summary.withViolations, 1);
    assert.equal(JSON.stringify([await w.s.select("org_billing", {}), await w.s.select("noc_devices", {})]), before, "preview wrote nothing (no trial started, no device touched)");
    const t = await w.J("POST", "noc/telemetry", w.tok.owner, { devices: [{ id: "new1", type: "server" }] }); assert.equal(t.body.deviceLimitSkipped, undefined, "and the server still does not enforce");
  } finally { w.f.close(); }
});
