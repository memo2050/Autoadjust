// Subscriptions: plans, trials, usage, checkout, plan changes, billing portal, invoices, refunds, webhook processing, entitlements, platform-admin controls.
// Uses the RAW (service-role) store because Stripe's webhook has no organization login; the organization is established ONLY from data we put into Stripe
// ourselves (client_reference_id / metadata.org_id) and from the stored customer id. Frontend claims about plans are never trusted.
import type { Store } from "../soc/store";
import { audit, HttpError } from "../soc/pipeline";
import { ScopedStore, UUID_RE } from "../tenant/scoped-store";
import type { Principal } from "../tenant/auth";
import { assertConfigured, stripeGet, stripeMode, stripePost, verifyWebhook } from "./stripe";
import { billingEnforced, DEFAULT_PLANS, effectivePlan, PLAN_IDS, priceFor, priceInfo, validLimits, type Entitlements, type Interval, type Overrides, type PlanDef, type PlanId } from "./plans";

export interface BillingRow { orgId: string; customerId?: string | null; subscriptionId?: string | null; plan: string; status: string; currentPeriodEnd?: string | null; cancelAtPeriodEnd?: boolean; lastEventAt?: number; updatedAt?: string;
  billingInterval?: Interval | null; trialStartedAt?: string | null; trialEndsAt?: string | null; overrides?: Overrides | null; lastPaymentFailedAt?: string | null }
type Env = Record<string, string | undefined>;
const TB = "org_billing", TE = "billing_events", TP = "billing_plans", TS = "billing_settings", TI = "billing_invoices", TY = "billing_payments";
const SYSTEM = { name: "stripe-webhook", role: "system" };
const DAY = 86400000, UPGRADE = "/account.html#billing";
// If a billing table does not exist yet (migrations not applied) or cannot be read, the organization is treated as FREE with code defaults: the most restrictive plan, never a paid one.
const getRow = async (raw: Store, orgId: string) => { try { return (await raw.select<BillingRow>(TB, { where: { orgId }, limit: 1 }))[0] ?? null; } catch { return null; } };
const saveRow = (raw: Store, r: BillingRow) => raw.upsert(TB, [{ ...r, updatedAt: new Date().toISOString() } as any], "org_id");

/** Plan definition: code defaults overlaid with what the platform administrator saved in billing_plans. */
export async function loadPlan(raw: Store, id: PlanId): Promise<PlanDef> {
  try { const r = (await raw.select<any>(TP, { where: { id }, limit: 1 }))[0]; if (!r) return DEFAULT_PLANS[id];
    const d = DEFAULT_PLANS[id], num = (v: any, f: number | null) => (v === null || v === undefined ? f : Number(v));
    return { id, name: r.name ?? d.name, maxDevices: num(r.maxDevices, d.maxDevices)!, maxApiKeys: num(r.maxApiKeys, d.maxApiKeys)!, maxExecutors: num(r.maxExecutors, d.maxExecutors)!, retentionDays: num(r.retentionDays, d.retentionDays)!, trialDays: num(r.trialDays, d.trialDays)!,
      priceMonthlyCents: num(r.priceMonthlyCents, d.priceMonthlyCents), priceAnnualCents: num(r.priceAnnualCents, d.priceAnnualCents), features: Array.isArray(r.features) ? r.features.map(String) : d.features, active: r.active !== false };
  } catch { return DEFAULT_PLANS[id]; }
}
export const listPlans = async (raw: Store) => Promise.all(PLAN_IDS.map((id) => loadPlan(raw, id)));
export async function graceDays(raw: Store): Promise<number> { try { const r = (await raw.select<{ value: string }>(TS, { where: { key: "graceDays" }, limit: 1 }))[0]; const n = Number(r?.value); return Number.isInteger(n) && n >= 0 && n <= 90 ? n : 7; } catch { return 7; } }
export const trialState = (b: BillingRow | null, plan: PlanId, now: number): "none" | "active" | "expired" => (plan !== "free" || !b?.trialEndsAt ? "none" : Date.parse(b.trialEndsAt) > now ? "active" : "expired");

/** Starts the free trial the first time an organization is seen while enforcement is on (existing organizations get a full trial from that moment, not from when they were created). */
async function ensureTrial(raw: Store, orgId: string, b: BillingRow | null, plan: PlanId, env: Env, now: number): Promise<BillingRow | null> {
  if (!billingEnforced(env) || plan !== "free" || b?.trialStartedAt || b?.subscriptionId) return b;
  const days = (await loadPlan(raw, "free")).trialDays; if (!days) return b;
  const row: BillingRow = { ...(b ?? { orgId, plan: "free", status: "none" }), orgId, trialStartedAt: new Date(now).toISOString(), trialEndsAt: new Date(now + days * DAY).toISOString() };
  try { await saveRow(raw, row); await audit(new ScopedStore(raw, orgId), SYSTEM, "billing.trial.start", orgId, { days }); return row; } catch { return b; }
}
export async function getEntitlements(raw: Store, orgId: string, now = Date.now(), env: Env = process.env): Promise<Entitlements> {
  let b = await getRow(raw, orgId); const plan = effectivePlan(b, now, await graceDays(raw));
  if (!billingEnforced(env)) return { plan, enforced: false, restricted: false, maxExecutors: null, maxApiKeys: null, maxDevices: null, retentionDays: null, aiAnalyst: true };
  b = await ensureTrial(raw, orgId, b, plan, env, now);
  const d = await loadPlan(raw, plan), o = b?.overrides ?? {}, pick = (k: keyof Overrides, base: number) => (o[k] === undefined ? base : o[k] as number | null);
  const restricted = trialState(b, plan, now) === "expired" && !b?.subscriptionId;     // trial over, never subscribed: keep everything, add nothing new
  return { plan, enforced: true, restricted, maxExecutors: restricted ? 0 : pick("maxExecutors", d.maxExecutors), maxApiKeys: restricted ? 0 : pick("maxApiKeys", d.maxApiKeys), maxDevices: restricted ? 0 : pick("maxDevices", d.maxDevices), retentionDays: pick("retentionDays", d.retentionDays), aiAnalyst: true };
}
const LABEL = { executors: "executors", keys: "API keys", devices: "monitored devices" } as const;
export function limitError(e: Entitlements, what: keyof typeof LABEL, max: number, current: number) {
  const why = e.restricted ? "Your free trial has ended. Your existing devices and monitoring keep working, but nothing new can be added until you upgrade." : `Your ${e.plan} plan allows ${max} ${LABEL[what]}. Upgrade the subscription to add more.`;
  return new HttpError(402, why, { code: e.restricted ? "trial_expired" : "plan_limit", limit: what, max, current, plan: e.plan, upgradeUrl: UPGRADE });
}
export async function requireRoom(raw: Store, orgId: string, what: "executors" | "keys", current: number, env: Env = process.env) {
  const e = await getEntitlements(raw, orgId, Date.now(), env), max = what === "executors" ? e.maxExecutors : e.maxApiKeys;
  if (max !== null && current >= max) throw limitError(e, what, max, current);
}
/** Monitored-device limit for the organization, or null (unlimited / not enforced). Only NEW devices are ever refused; existing ones are never touched. */
export const deviceLimit = async (raw: Store, orgId: string, env: Env = process.env) => (await getEntitlements(raw, orgId, Date.now(), env)).maxDevices;
export async function usage(raw: Store, orgId: string, env: Env = process.env) {
  const e = await getEntitlements(raw, orgId, Date.now(), env), sc = new ScopedStore(raw, orgId);
  const devices = (await sc.select("noc_devices", { limit: 100000 })).length, keys = (await raw.select<{ revokedAt?: string | null }>("org_api_keys", { where: { orgId }, limit: 10000 })).filter((k) => !k.revokedAt).length;
  const executors = (await sc.select<{ enabled?: boolean }>("noc_executors", { limit: 10000 })).filter((x) => x.enabled).length;
  const row = (used: number, limit: number | null) => ({ used, limit, remaining: limit === null ? null : Math.max(0, limit - used), overLimit: limit !== null && used > limit, reached: limit !== null && used >= limit });
  return { enforced: e.enforced, devices: row(devices, e.maxDevices), apiKeys: row(keys, e.maxApiKeys), executors: row(executors, e.maxExecutors), retentionDays: e.retentionDays, note: "Existing devices and data are never deleted when a limit is reached or lowered; only adding new ones is blocked." };
}
export async function status(raw: Store, orgId: string, env: Env = process.env) {
  const e = await getEntitlements(raw, orgId, Date.now(), env), b = await getRow(raw, orgId), plans = await listPlans(raw), now = Date.now();
  return { configured: !!stripeMode(env), mode: stripeMode(env), plan: e.plan, enforced: e.enforced, restricted: e.restricted, entitlements: e, plans: plans.filter((p) => p.active), planDef: plans.find((p) => p.id === e.plan),
    trial: { state: trialState(b, e.plan, now), startedAt: b?.trialStartedAt ?? null, endsAt: b?.trialEndsAt ?? null, daysLeft: b?.trialEndsAt ? Math.max(0, Math.ceil((Date.parse(b.trialEndsAt) - now) / DAY)) : null },
    subscription: b && b.status !== "none" ? { status: b.status, interval: b.billingInterval ?? null, currentPeriodEnd: b.currentPeriodEnd ?? null, cancelAtPeriodEnd: !!b.cancelAtPeriodEnd, paymentFailedAt: b.lastPaymentFailedAt ?? null } : null,
    usage: await usage(raw, orgId, env) };
}
function ownerOnly(p: Principal) { if (p.kind !== "user" || p.orgRole !== "owner") throw new HttpError(403, "Only an organization owner can manage billing."); }
function returnUrl(body: any, env: Record<string, string | undefined>): string {
  const base = env.APP_URL; if (!base) throw new HttpError(503, "APP_URL is not configured."); const u = new URL(base);
  if (u.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(u.hostname)) throw new HttpError(503, "APP_URL must be https."); return u.origin + "/account.html";   // fixed path: the client cannot choose a redirect target
}
async function ensureCustomer(raw: Store, p: Principal, env: Record<string, string | undefined>) {
  const b = await getRow(raw, p.orgId); if (b?.customerId) return b;
  const c = await stripePost("/v1/customers", { ...(p.email ? { email: p.email } : {}), name: p.orgName ?? p.orgId, "metadata[org_id]": p.orgId }, "cust-" + p.orgId, env);
  const row: BillingRow = { ...(b ?? { plan: "free", status: "none" }), orgId: p.orgId, customerId: String(c.id) }; await saveRow(raw, row); return row;
}
export async function createCheckout(raw: Store, p: Principal, body: any, env: Env = process.env) {
  ownerOnly(p); assertConfigured(env); const plan = body?.plan as PlanId, interval: Interval = body?.interval === "year" ? "year" : "month"; const price = priceFor(plan, interval, env);
  if (!price) throw new HttpError(400, "Unknown or unconfigured plan or billing interval.");
  const cur = await getRow(raw, p.orgId); if (cur && effectivePlan(cur) !== "free" && cur.status !== "canceled") throw new HttpError(409, "This organization already has an active subscription. Use the billing portal to change it.");
  const row = await ensureCustomer(raw, p, env), url = returnUrl(body, env);
  const s = await stripePost("/v1/checkout/sessions", { mode: "subscription", customer: row.customerId!, client_reference_id: p.orgId, "line_items[0][price]": price, "line_items[0][quantity]": "1", "subscription_data[metadata][org_id]": p.orgId, "metadata[org_id]": p.orgId, success_url: url + "?billing=success", cancel_url: url + "?billing=cancelled" }, undefined, env);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "billing.checkout.start", String(s.id ?? ""), { plan, interval });
  return { url: String(s.url) };
}
export async function createPortal(raw: Store, p: Principal, env: Record<string, string | undefined> = process.env) {
  ownerOnly(p); assertConfigured(env); const b = await getRow(raw, p.orgId); if (!b?.customerId) throw new HttpError(404, "No billing account exists yet. Start a subscription first.");
  const s = await stripePost("/v1/billing_portal/sessions", { customer: b.customerId, return_url: returnUrl({}, env) }, undefined, env);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "billing.portal.open", p.orgId, {}); return { url: String(s.url) };
}

/** Verified Stripe event -> stored subscription state. Idempotent by event id; stale (out-of-order) subscription events are ignored. */
export async function handleWebhook(raw: Store, rawBody: string, sigHeader: string | null, env: Record<string, string | undefined> = process.env, now = Date.now()) {
  if (!env.STRIPE_WEBHOOK_SECRET) throw new HttpError(503, "Billing webhooks are not configured.");
  if (!verifyWebhook(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET, now)) throw new HttpError(400, "Invalid signature.");
  let ev: any; try { ev = JSON.parse(rawBody); } catch { throw new HttpError(400, "Invalid payload."); }
  if (typeof ev?.id !== "string" || typeof ev?.type !== "string" || typeof ev?.created !== "number") throw new HttpError(400, "Invalid event.");
  const mode = stripeMode(env); if (mode && ev.livemode !== (mode === "live")) throw new HttpError(400, "Event mode does not match this server's Stripe mode.");
  if (await raw.get(TE, ev.id)) return { received: true, duplicate: true };
  const obj = ev.data?.object ?? {}; let orgId: string | null = null, handled = true;
  const orgFrom = async (): Promise<string | null> => {
    const m = obj.metadata?.org_id ?? obj.client_reference_id ?? obj.subscription_details?.metadata?.org_id;
    if (typeof m === "string" && UUID_RE.test(m)) { const b = await getRow(raw, m); if (b || (await raw.select("organizations", { where: { id: m }, limit: 1 })).length) { if (typeof obj.customer === "string") { const [owner] = await raw.select<BillingRow>(TB, { where: { customerId: obj.customer }, limit: 1 }); if (owner && owner.orgId !== m) return null; } if (obj.customer && b?.customerId && b.customerId !== obj.customer) return null; return m; } }
    if (typeof obj.customer === "string") { const [b] = await raw.select<BillingRow>(TB, { where: { customerId: obj.customer }, limit: 1 }); return b?.orgId ?? null; } return null;
  };
  switch (ev.type) {
    case "checkout.session.completed": {
      orgId = await orgFrom(); if (!orgId) break; const b = (await getRow(raw, orgId)) ?? { orgId, plan: "free", status: "none" } as BillingRow;
      await saveRow(raw, { ...b, customerId: String(obj.customer ?? b.customerId ?? "") || null, subscriptionId: String(obj.subscription ?? b.subscriptionId ?? "") || null }); break; }
    case "customer.subscription.created": case "customer.subscription.updated": case "customer.subscription.deleted": {
      orgId = await orgFrom(); if (!orgId) break; const b = (await getRow(raw, orgId)) ?? { orgId, plan: "free", status: "none" } as BillingRow;
      if ((b.lastEventAt ?? 0) > ev.created) { handled = false; break; }                      // older than what we already applied
      const item = obj.items?.data?.[0], price = item?.price?.id, pinfo = priceInfo(price, env), paid = pinfo?.plan ?? null, deleted = ev.type.endsWith("deleted");
      const end = obj.current_period_end ?? item?.current_period_end;
      const row: BillingRow = { ...b, orgId, customerId: String(obj.customer ?? b.customerId ?? "") || null, subscriptionId: String(obj.id ?? "") || null,
        plan: deleted ? "free" : paid ?? "free", status: deleted ? "canceled" : String(obj.status ?? "none"), currentPeriodEnd: typeof end === "number" ? new Date(end * 1000).toISOString() : null, cancelAtPeriodEnd: !!obj.cancel_at_period_end, lastEventAt: ev.created, billingInterval: deleted ? null : pinfo?.interval ?? b.billingInterval ?? null };
      await saveRow(raw, row); await raw.upsert("organizations", [{ id: orgId, plan: effectivePlan(row, now) } as any]); break; }
    case "invoice.created": case "invoice.finalized": case "invoice.updated": case "invoice.paid": case "invoice.payment_succeeded": case "invoice.payment_failed": case "invoice.voided": {
      orgId = await orgFrom(); if (!orgId) break; const at = (t: any) => (typeof t === "number" ? new Date(t * 1000).toISOString() : null), iso = new Date(now).toISOString();
      await raw.upsert(TI, [{ id: String(obj.id), orgId, number: obj.number ?? null, status: String(obj.status ?? "open"), amountDue: Number(obj.amount_due ?? 0), amountPaid: Number(obj.amount_paid ?? 0), currency: String(obj.currency ?? "usd"), hostedUrl: obj.hosted_invoice_url ?? null, pdfUrl: obj.invoice_pdf ?? null, periodStart: at(obj.period_start), periodEnd: at(obj.period_end), createdAt: at(obj.created) ?? iso, updatedAt: iso } as any]);
      if (ev.type === "invoice.paid" || ev.type === "invoice.payment_succeeded" || ev.type === "invoice.payment_failed") {
        const ok = ev.type !== "invoice.payment_failed", pid = String(obj.payment_intent ?? "inv_" + obj.id); const prev = (await raw.select<any>(TY, { where: { id: pid }, limit: 1 }))[0];
        if (!(ok === false && prev?.status === "succeeded")) await raw.upsert(TY, [{ id: pid, orgId, invoiceId: String(obj.id), status: ok ? "succeeded" : "failed", amount: Number(ok ? obj.amount_paid : obj.amount_due ?? 0), refunded: Number(prev?.refunded ?? 0), currency: String(obj.currency ?? "usd"), createdAt: prev?.createdAt ?? iso, updatedAt: iso } as any]);
        if (!ok) { const b = (await getRow(raw, orgId)) ?? { orgId, plan: "free", status: "none" } as BillingRow; await saveRow(raw, { ...b, lastPaymentFailedAt: iso }); }
        else { const b = await getRow(raw, orgId); if (b?.lastPaymentFailedAt) await saveRow(raw, { ...b, lastPaymentFailedAt: null }); }
      } break; }
    case "charge.refunded": {                                                                  // refund issued (by an admin or in the Stripe dashboard): record it against the payment
      orgId = await orgFrom(); if (!orgId) break; const pid = String(obj.payment_intent ?? ""); if (!pid) { handled = false; break; }
      const prev = (await raw.select<any>(TY, { where: { id: pid }, limit: 1 }))[0]; if (prev && prev.orgId !== orgId) { orgId = null; handled = false; break; }
      const iso = new Date(now).toISOString(); await raw.upsert(TY, [{ id: pid, orgId, invoiceId: prev?.invoiceId ?? (obj.invoice ? String(obj.invoice) : null), status: prev?.status ?? "succeeded", amount: Number(prev?.amount ?? obj.amount ?? 0), refunded: Number(obj.amount_refunded ?? 0), currency: String(obj.currency ?? "usd"), createdAt: prev?.createdAt ?? iso, updatedAt: iso } as any]); break; }
    default: handled = false;
  }
  if (orgId && handled) await audit(new ScopedStore(raw, orgId), SYSTEM, "billing." + ev.type.replace(/^customer\./, ""), ev.id, { type: ev.type });
  await raw.upsert(TE, [{ id: ev.id, type: ev.type, orgId, processedAt: new Date(now).toISOString() } as any]);
  return { received: true, duplicate: false };
}

/* ---------------- subscription management (owner) ---------------- */
const enc = encodeURIComponent;
async function liveSub(raw: Store, p: Principal, env: Env) {
  ownerOnly(p); assertConfigured(env); const b = await getRow(raw, p.orgId);
  if (!b?.subscriptionId || effectivePlan(b, Date.now(), await graceDays(raw)) === "free") throw new HttpError(409, "This organization has no active subscription. Start one with checkout.");
  return b;
}
/** Upgrade, downgrade or switch monthly/annual. The new plan only takes effect when Stripe confirms it through the signed webhook; lowering a plan never deletes anything. */
export async function changePlan(raw: Store, p: Principal, body: any, env: Env = process.env) {
  const b = await liveSub(raw, p, env), plan = body?.plan as PlanId, interval: Interval = body?.interval === "year" ? "year" : "month", price = priceFor(plan, interval, env);
  if (!price) throw new HttpError(400, "Unknown or unconfigured plan or billing interval.");
  const sub = await stripeGet(`/v1/subscriptions/${enc(b.subscriptionId!)}`, env), item = sub?.items?.data?.[0]?.id; if (!item) throw new HttpError(502, "The subscription could not be read from the payment provider.");
  await stripePost(`/v1/subscriptions/${enc(b.subscriptionId!)}`, { "items[0][id]": String(item), "items[0][price]": price, proration_behavior: "create_prorations", cancel_at_period_end: "false" }, undefined, env);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "billing.plan.change", b.subscriptionId!, { plan, interval });
  return { ok: true, message: "Change requested. It applies as soon as the payment provider confirms it." };
}
export async function setCancel(raw: Store, p: Principal, cancel: boolean, env: Env = process.env) {
  const b = await liveSub(raw, p, env); await stripePost(`/v1/subscriptions/${enc(b.subscriptionId!)}`, { cancel_at_period_end: cancel ? "true" : "false" }, undefined, env);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, cancel ? "billing.cancel" : "billing.resume", b.subscriptionId!, {});
  return { ok: true, message: cancel ? "The subscription will end at the end of the paid period. Nothing is deleted." : "Renewal restored." };
}
export async function listInvoices(raw: Store, p: Principal) { ownerOnly(p); return { invoices: await raw.select<any>(TI, { where: { orgId: p.orgId }, order: ["createdAt", "desc"], limit: 100 }) }; }
export async function listPayments(raw: Store, p: Principal) { ownerOnly(p); return { payments: await raw.select<any>(TY, { where: { orgId: p.orgId }, order: ["createdAt", "desc"], limit: 100 }) }; }

/* ---------------- platform administrator ---------------- */
function adminOnly(p: Principal) { if (!p.platformAdmin) throw new HttpError(403, "Platform administrator only."); }
const adminLog = async (raw: Store, p: Principal, type: string, orgId: string | null, detail: Record<string, unknown>) => {
  await raw.upsert(TE, [{ id: "adm_" + crypto.randomUUID(), type: "admin." + type, orgId, processedAt: new Date().toISOString() } as any]);
  if (orgId) await audit(new ScopedStore(raw, orgId), { name: p.name, role: "platform-admin" }, "billing.admin." + type, orgId, detail);
};
const orgIdOf = (v: string) => { if (!UUID_RE.test(v)) throw new HttpError(400, "Invalid organization id."); return v; };
const intIn = (v: any, lo: number, hi: number, what: string) => { const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) throw new HttpError(400, `${what} must be a whole number from ${lo} to ${hi}.`); return n; };
export async function adminPlans(raw: Store, p: Principal) { adminOnly(p); return { plans: await listPlans(raw), graceDays: await graceDays(raw) }; }
export async function adminUpdatePlan(raw: Store, p: Principal, id: string, b: any) {
  adminOnly(p); if (!PLAN_IDS.includes(id as PlanId)) throw new HttpError(404, "Unknown plan."); const cur = await loadPlan(raw, id as PlanId);
  const n: PlanDef = { ...cur, name: b?.name !== undefined ? String(b.name).trim().slice(0, 60) || cur.name : cur.name,
    maxDevices: b?.maxDevices !== undefined ? intIn(b.maxDevices, 0, 10_000_000, "maxDevices") : cur.maxDevices, maxApiKeys: b?.maxApiKeys !== undefined ? intIn(b.maxApiKeys, 0, 100_000, "maxApiKeys") : cur.maxApiKeys,
    maxExecutors: b?.maxExecutors !== undefined ? intIn(b.maxExecutors, 0, 100_000, "maxExecutors") : cur.maxExecutors, retentionDays: b?.retentionDays !== undefined ? intIn(b.retentionDays, 1, 3650, "retentionDays") : cur.retentionDays,
    trialDays: b?.trialDays !== undefined ? intIn(b.trialDays, 0, 365, "trialDays") : cur.trialDays, priceMonthlyCents: b?.priceMonthlyCents !== undefined ? (b.priceMonthlyCents === null ? null : intIn(b.priceMonthlyCents, 0, 100_000_000, "priceMonthlyCents")) : cur.priceMonthlyCents,
    priceAnnualCents: b?.priceAnnualCents !== undefined ? (b.priceAnnualCents === null ? null : intIn(b.priceAnnualCents, 0, 1_000_000_000, "priceAnnualCents")) : cur.priceAnnualCents,
    features: Array.isArray(b?.features) ? b.features.slice(0, 20).map((f: any) => String(f).slice(0, 80)) : cur.features, active: b?.active !== undefined ? !!b.active : cur.active };
  await raw.upsert(TP, [{ ...n, updatedAt: new Date().toISOString() } as any], "id"); await adminLog(raw, p, "plan.update", null, { id }); return { plan: n };
}
export async function adminSettings(raw: Store, p: Principal, b: any) {
  adminOnly(p); const g = intIn(b?.graceDays, 0, 90, "graceDays"); await raw.upsert(TS, [{ key: "graceDays", value: String(g), updatedAt: new Date().toISOString() } as any], "key"); await adminLog(raw, p, "settings", null, { graceDays: g }); return { graceDays: g };
}
export async function adminOrgs(raw: Store, p: Principal, env: Env = process.env) {
  adminOnly(p); const orgs = await raw.select<{ id: string; name: string; slug?: string }>("organizations", { limit: 5000 }), rows = await raw.select<BillingRow>(TB, { limit: 5000 }), gd = await graceDays(raw), now = Date.now();
  return { enforced: billingEnforced(env), organizations: orgs.map((o) => { const b = rows.find((r) => r.orgId === o.id) ?? null, plan = effectivePlan(b, now, gd);
    return { id: o.id, name: o.name, plan, status: b?.status ?? "none", interval: b?.billingInterval ?? null, trial: trialState(b, plan, now), trialEndsAt: b?.trialEndsAt ?? null, currentPeriodEnd: b?.currentPeriodEnd ?? null, cancelAtPeriodEnd: !!b?.cancelAtPeriodEnd, paymentFailedAt: b?.lastPaymentFailedAt ?? null, overrides: b?.overrides ?? {} }; }) };
}
export async function adminSetOverrides(raw: Store, p: Principal, orgId: string, b: any) {
  adminOnly(p); orgIdOf(orgId); if (!(await raw.select("organizations", { where: { id: orgId }, limit: 1 })).length) throw new HttpError(404, "Organization not found.");
  let ov: Overrides; try { ov = validLimits(b); } catch { throw new HttpError(400, "A limit is out of range."); } const clean = Object.fromEntries(Object.entries(ov).filter(([, v]) => v !== undefined)) as Overrides;
  const cur = (await getRow(raw, orgId)) ?? { orgId, plan: "free", status: "none" } as BillingRow; const merged: Overrides = b?.reset === true ? {} : { ...(cur.overrides ?? {}), ...clean };   // null = unlimited for this organization; reset:true removes all overrides
  await saveRow(raw, { ...cur, overrides: merged }); await adminLog(raw, p, "overrides", orgId, { overrides: merged }); return { orgId, overrides: merged };
}
export async function adminGrantTrial(raw: Store, p: Principal, orgId: string, b: any, now = Date.now()) {
  adminOnly(p); orgIdOf(orgId); const days = intIn(b?.days, 1, 365, "days"); if (!(await raw.select("organizations", { where: { id: orgId }, limit: 1 })).length) throw new HttpError(404, "Organization not found.");
  const cur = (await getRow(raw, orgId)) ?? { orgId, plan: "free", status: "none" } as BillingRow, end = new Date(now + days * DAY).toISOString();
  await saveRow(raw, { ...cur, trialStartedAt: cur.trialStartedAt ?? new Date(now).toISOString(), trialEndsAt: end }); await adminLog(raw, p, "trial.grant", orgId, { days }); return { orgId, trialEndsAt: end };
}
export async function adminCreateCoupon(raw: Store, p: Principal, b: any, env: Env = process.env) {
  adminOnly(p); assertConfigured(env); const pct = intIn(b?.percentOff, 1, 100, "percentOff"), dur = ["once", "repeating", "forever"].includes(b?.duration) ? b.duration : "once";
  const body: Record<string, string> = { percent_off: String(pct), duration: dur, ...(dur === "repeating" ? { duration_in_months: String(intIn(b?.months, 1, 36, "months")) } : {}) };
  const c = await stripePost("/v1/coupons", body, undefined, env); await adminLog(raw, p, "coupon.create", null, { id: String(c.id), pct }); return { couponId: String(c.id) };
}
export async function adminApplyDiscount(raw: Store, p: Principal, orgId: string, b: any, env: Env = process.env) {
  adminOnly(p); assertConfigured(env); orgIdOf(orgId); const coupon = String(b?.couponId ?? ""); if (!/^[A-Za-z0-9_-]{1,64}$/.test(coupon)) throw new HttpError(400, "Invalid coupon id.");
  const row = await getRow(raw, orgId); if (!row?.subscriptionId) throw new HttpError(409, "This organization has no subscription to discount.");
  await stripePost(`/v1/subscriptions/${enc(row.subscriptionId)}`, { "discounts[0][coupon]": coupon }, undefined, env); await adminLog(raw, p, "discount.apply", orgId, { coupon }); return { ok: true };
}
export async function adminRefund(raw: Store, p: Principal, orgId: string, b: any, env: Env = process.env) {
  adminOnly(p); assertConfigured(env); orgIdOf(orgId); const pay = (await raw.select<any>(TY, { where: { id: String(b?.paymentId ?? ""), orgId }, limit: 1 }))[0];
  if (!pay || pay.status !== "succeeded" || String(pay.id).startsWith("inv_")) throw new HttpError(404, "No refundable payment with that id in this organization.");
  const left = Number(pay.amount) - Number(pay.refunded ?? 0), amt = b?.amountCents === undefined ? left : intIn(b.amountCents, 1, left, "amountCents"); if (left <= 0) throw new HttpError(409, "This payment is already fully refunded.");
  await stripePost("/v1/refunds", { payment_intent: String(pay.id), amount: String(amt) }, `refund-${pay.id}-${pay.refunded ?? 0}-${amt}`, env); await adminLog(raw, p, "refund", orgId, { paymentId: pay.id, amountCents: amt });
  return { ok: true, message: "Refund requested. The payment record updates when Stripe confirms it." };   // recorded by the signed charge.refunded webhook
}
export async function adminStats(raw: Store, p: Principal, now = Date.now()) {
  adminOnly(p); const gd = await graceDays(raw), rows = await raw.select<BillingRow>(TB, { limit: 10000 }), plans = await listPlans(raw), orgCount = (await raw.select("organizations", { limit: 100000 })).length;
  const byPlan: Record<string, number> = { free: 0, pro: 0, enterprise: 0 }, by = { trialing: 0, trialExpired: 0, pastDue: 0, canceling: 0 }; let mrr = 0, paid = 0;
  for (const b of rows) { const pl = effectivePlan(b, now, gd); byPlan[pl]++; const t = trialState(b, pl, now); if (t === "active") by.trialing++; if (t === "expired" && !b.subscriptionId) by.trialExpired++; if (b.status === "past_due") by.pastDue++; if (b.cancelAtPeriodEnd) by.canceling++;
    if (pl !== "free" && b.status === "active") { paid++; const d = plans.find((x) => x.id === pl); const c = b.billingInterval === "year" ? (d?.priceAnnualCents ?? 0) / 12 : d?.priceMonthlyCents ?? 0; mrr += c; } }
  byPlan.free += Math.max(0, orgCount - rows.length);
  const inv = await raw.select<any>(TI, { limit: 100000 }), pay = await raw.select<any>(TY, { limit: 100000 }), since = now - 30 * DAY;
  const paidInv = inv.filter((i) => i.status === "paid"), sum = (a: any[], f: (x: any) => number) => a.reduce((t, x) => t + f(x), 0);
  return { organizations: orgCount, byPlan, ...by, paidSubscriptions: paid, estimatedMrrCents: Math.round(mrr), revenueTotalCents: sum(paidInv, (i) => Number(i.amountPaid)), revenueLast30dCents: sum(paidInv.filter((i) => Date.parse(i.createdAt) >= since), (i) => Number(i.amountPaid)),
    refundedTotalCents: sum(pay, (x) => Number(x.refunded ?? 0)), failedPayments: pay.filter((x) => x.status === "failed").length, note: "Revenue figures come from invoices Stripe has told us about (test mode in development)." };
}
