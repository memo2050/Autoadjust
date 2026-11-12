// Subscriptions: checkout, billing portal, webhook processing, entitlements. Uses the RAW (service-role) store because Stripe's webhook has no organization login;
// the organization is established ONLY from data we put into Stripe ourselves (client_reference_id / metadata.org_id) and from the stored customer id.
import type { Store } from "../soc/store";
import { audit, HttpError } from "../soc/pipeline";
import { ScopedStore, UUID_RE } from "../tenant/scoped-store";
import type { Principal } from "../tenant/auth";
import { assertConfigured, stripeMode, stripePost, verifyWebhook } from "./stripe";
import { billingEnforced, effectivePlan, PLAN_LIMITS, planForPrice, type Entitlements, type PlanId } from "./plans";

export interface BillingRow { orgId: string; customerId?: string | null; subscriptionId?: string | null; plan: string; status: string; currentPeriodEnd?: string | null; cancelAtPeriodEnd?: boolean; lastEventAt?: number; updatedAt?: string }
const TB = "org_billing", TE = "billing_events";
const SYSTEM = { name: "stripe-webhook", role: "system" };
// If the billing table does not exist yet (migration 0109 not applied) or cannot be read, the organization is treated as FREE: the most restrictive plan, never a paid one.
const getRow = async (raw: Store, orgId: string) => { try { return (await raw.select<BillingRow>(TB, { where: { orgId }, limit: 1 }))[0] ?? null; } catch { return null; } };
const saveRow = (raw: Store, r: BillingRow) => raw.upsert(TB, [{ ...r, updatedAt: new Date().toISOString() } as any], "org_id");

export async function getEntitlements(raw: Store, orgId: string, now = Date.now(), env: Record<string, string | undefined> = process.env): Promise<Entitlements> {
  const plan = effectivePlan(await getRow(raw, orgId), now);
  if (!billingEnforced(env)) return { plan, enforced: false, maxExecutors: null, maxApiKeys: null, maxDevices: null, retentionDays: null, aiAnalyst: true };
  return { plan, enforced: true, ...PLAN_LIMITS[plan] };
}
export async function requireRoom(raw: Store, orgId: string, what: "executors" | "keys", current: number, env: Record<string, string | undefined> = process.env) {
  const e = await getEntitlements(raw, orgId, Date.now(), env), max = what === "executors" ? e.maxExecutors : e.maxApiKeys;
  if (max !== null && current >= max) throw new HttpError(402, `Your ${e.plan} plan allows ${max} ${what === "executors" ? "executors" : "API keys"}. Upgrade the subscription to add more.`);
}
/** Monitored-device limit for the organization, or null (unlimited / not enforced). Only NEW devices are ever refused; existing ones are never touched. */
export const deviceLimit = async (raw: Store, orgId: string, env: Record<string, string | undefined> = process.env) => (await getEntitlements(raw, orgId, Date.now(), env)).maxDevices;
export async function status(raw: Store, orgId: string, env: Record<string, string | undefined> = process.env) {
  const b = await getRow(raw, orgId), e = await getEntitlements(raw, orgId, Date.now(), env);
  return { configured: !!stripeMode(env), mode: stripeMode(env), plan: e.plan, enforced: e.enforced, entitlements: e, planLimits: PLAN_LIMITS[e.plan], subscription: b ? { status: b.status, currentPeriodEnd: b.currentPeriodEnd ?? null, cancelAtPeriodEnd: !!b.cancelAtPeriodEnd } : null };
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
export async function createCheckout(raw: Store, p: Principal, body: any, env: Record<string, string | undefined> = process.env) {
  ownerOnly(p); assertConfigured(env); const plan = body?.plan as PlanId; const price = plan === "pro" ? env.STRIPE_PRICE_PRO : plan === "enterprise" ? env.STRIPE_PRICE_ENTERPRISE : undefined;
  if (!price) throw new HttpError(400, "Unknown or unconfigured plan.");
  const cur = await getRow(raw, p.orgId); if (cur && effectivePlan(cur) !== "free" && cur.status !== "canceled") throw new HttpError(409, "This organization already has an active subscription. Use the billing portal to change it.");
  const row = await ensureCustomer(raw, p, env), url = returnUrl(body, env);
  const s = await stripePost("/v1/checkout/sessions", { mode: "subscription", customer: row.customerId!, client_reference_id: p.orgId, "line_items[0][price]": price, "line_items[0][quantity]": "1", "subscription_data[metadata][org_id]": p.orgId, "metadata[org_id]": p.orgId, success_url: url + "?billing=success", cancel_url: url + "?billing=cancelled" }, undefined, env);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "billing.checkout.start", String(s.id ?? ""), { plan });
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
      const item = obj.items?.data?.[0], price = item?.price?.id, paid = planForPrice(price, env), deleted = ev.type.endsWith("deleted");
      const end = obj.current_period_end ?? item?.current_period_end;
      const row: BillingRow = { ...b, orgId, customerId: String(obj.customer ?? b.customerId ?? "") || null, subscriptionId: String(obj.id ?? "") || null,
        plan: deleted ? "free" : paid ?? "free", status: deleted ? "canceled" : String(obj.status ?? "none"), currentPeriodEnd: typeof end === "number" ? new Date(end * 1000).toISOString() : null, cancelAtPeriodEnd: !!obj.cancel_at_period_end, lastEventAt: ev.created };
      await saveRow(raw, row); await raw.upsert("organizations", [{ id: orgId, plan: effectivePlan(row, now) } as any]); break; }
    case "invoice.payment_failed": orgId = await orgFrom(); break;                            // status itself arrives through the subscription event
    default: handled = false;
  }
  if (orgId && handled) await audit(new ScopedStore(raw, orgId), SYSTEM, "billing." + ev.type.replace(/^customer\./, ""), ev.id, { type: ev.type });
  await raw.upsert(TE, [{ id: ev.id, type: ev.type, orgId, processedAt: new Date(now).toISOString() } as any]);
  return { received: true, duplicate: false };
}
