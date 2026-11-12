// Plans and entitlements. Code holds the DEFAULTS; the platform administrator can change them in the billing_plans table (no deploy needed). Prices charged live in Stripe (price ids come from env).
export type PlanId = "free" | "pro" | "enterprise";
export type Interval = "month" | "year";
export const PLAN_IDS: PlanId[] = ["free", "pro", "enterprise"];
/** null = unlimited. `enforced` = whether limits are actually applied (BILLING_ENFORCE=1). `restricted` = trial over and never subscribed: existing data/monitoring continue, nothing NEW can be added. */
export interface Entitlements { plan: PlanId; enforced: boolean; restricted: boolean; maxExecutors: number | null; maxApiKeys: number | null; maxDevices: number | null; retentionDays: number | null; aiAnalyst: boolean }
export interface PlanDef { id: PlanId; name: string; maxDevices: number; maxApiKeys: number; maxExecutors: number; retentionDays: number; trialDays: number; priceMonthlyCents: number | null; priceAnnualCents: number | null; features: string[]; active: boolean }
export const DEFAULT_PLANS: Record<PlanId, PlanDef> = {
  free: { id: "free", name: "Free / Trial", maxDevices: 25, maxApiKeys: 25, maxExecutors: 3, retentionDays: 7, trialDays: 14, priceMonthlyCents: 0, priceAnnualCents: 0, features: ["SOK Monitoring", "NOK Monitoring"], active: true },
  pro: { id: "pro", name: "Professional", maxDevices: 100, maxApiKeys: 100, maxExecutors: 10, retentionDays: 30, trialDays: 0, priceMonthlyCents: 4900, priceAnnualCents: 49000, features: ["SOK Monitoring", "NOK Monitoring", "Advanced reports and alerts"], active: true },
  enterprise: { id: "enterprise", name: "Business / Enterprise", maxDevices: 100000, maxApiKeys: 1000, maxExecutors: 1000, retentionDays: 365, trialDays: 0, priceMonthlyCents: null, priceAnnualCents: null, features: ["Configurable limits", "Custom retention", "Advanced reporting", "Priority support"], active: true },   // custom pricing/limits per organization
};
export const PLAN_LIMITS = DEFAULT_PLANS;   // back-compat alias for code defaults
export interface Overrides { maxDevices?: number | null; maxApiKeys?: number | null; maxExecutors?: number | null; retentionDays?: number | null }
/** Plan limits are applied ONLY when billing is deliberately switched on. Default off: existing organizations keep working exactly as before. */
export const billingEnforced = (env: Record<string, string | undefined> = process.env) => env.BILLING_ENFORCE === "1";
/** Stripe price id -> { plan, interval }. Unknown price ids NEVER grant a paid plan. */
export function planForPrice(priceId: string | undefined, env: Record<string, string | undefined> = process.env): PlanId | null { return priceInfo(priceId, env)?.plan ?? null; }
export function priceInfo(priceId: string | undefined, env: Record<string, string | undefined> = process.env): { plan: PlanId; interval: Interval } | null {
  if (!priceId) return null; const m: [string | undefined, PlanId, Interval][] = [[env.STRIPE_PRICE_PRO, "pro", "month"], [env.STRIPE_PRICE_PRO_ANNUAL, "pro", "year"], [env.STRIPE_PRICE_ENTERPRISE, "enterprise", "month"], [env.STRIPE_PRICE_ENTERPRISE_ANNUAL, "enterprise", "year"]];
  for (const [id, plan, interval] of m) if (id && id === priceId) return { plan, interval }; return null;
}
export const priceFor = (plan: PlanId, interval: Interval, env: Record<string, string | undefined> = process.env) =>
  plan === "pro" ? (interval === "year" ? env.STRIPE_PRICE_PRO_ANNUAL : env.STRIPE_PRICE_PRO) : plan === "enterprise" ? (interval === "year" ? env.STRIPE_PRICE_ENTERPRISE_ANNUAL : env.STRIPE_PRICE_ENTERPRISE) : undefined;
export const PAID_ACTIVE = new Set(["active", "trialing"]);
/** Effective plan from a stored subscription record. past_due keeps access until the paid period ends PLUS the configurable grace days (no free ride after that). */
export function effectivePlan(b: { plan?: string; status?: string; currentPeriodEnd?: string | null } | null | undefined, now = Date.now(), graceDays = 0): PlanId {
  if (!b || (b.plan !== "pro" && b.plan !== "enterprise")) return "free";
  if (b.status && PAID_ACTIVE.has(b.status)) return b.plan;
  if (b.status === "past_due" && b.currentPeriodEnd && Date.parse(b.currentPeriodEnd) + graceDays * 86400000 > now) return b.plan;
  return "free";
}
const nn = (v: unknown, lo: number, hi: number): number | null | undefined => { if (v === undefined) return undefined; if (v === null) return null; const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) throw new RangeError("out of range"); return n; };
export const validLimits = (o: any): Overrides => ({ maxDevices: nn(o?.maxDevices, 0, 10_000_000), maxApiKeys: nn(o?.maxApiKeys, 0, 100_000), maxExecutors: nn(o?.maxExecutors, 0, 100_000), retentionDays: nn(o?.retentionDays, 1, 3650) });
