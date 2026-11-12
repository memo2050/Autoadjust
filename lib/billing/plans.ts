// Plans and entitlements. The ONLY place that decides what a plan allows. Prices live in Stripe (price ids come from env), never here.
export type PlanId = "free" | "pro" | "enterprise";
/** null = unlimited. `enforced` tells whether these limits are actually applied (BILLING_ENFORCE=1); when false every limit is null and nothing is restricted or pruned. */
export interface Entitlements { plan: PlanId; enforced: boolean; maxExecutors: number | null; maxApiKeys: number | null; maxDevices: number | null; retentionDays: number | null; aiAnalyst: boolean }
export const PLAN_LIMITS: Record<PlanId, Omit<Entitlements, "plan" | "enforced">> = {
  free: { maxApiKeys: 25, maxExecutors: 3, maxDevices: 25, retentionDays: 7, aiAnalyst: true },
  pro: { maxApiKeys: 100, maxExecutors: 50, maxDevices: 500, retentionDays: 30, aiAnalyst: true },
  enterprise: { maxApiKeys: 1000, maxExecutors: 1000, maxDevices: 100000, retentionDays: 365, aiAnalyst: true },   // "custom": large defaults, raised per contract
};
/** Plan limits are applied ONLY when billing is deliberately switched on. Default off: existing organizations keep working exactly as before. */
export const billingEnforced = (env: Record<string, string | undefined> = process.env) => env.BILLING_ENFORCE === "1";
/** Stripe price id -> plan. Unknown price ids NEVER grant a paid plan. */
export function planForPrice(priceId: string | undefined, env: Record<string, string | undefined> = process.env): PlanId | null {
  if (!priceId) return null; if (env.STRIPE_PRICE_PRO && priceId === env.STRIPE_PRICE_PRO) return "pro"; if (env.STRIPE_PRICE_ENTERPRISE && priceId === env.STRIPE_PRICE_ENTERPRISE) return "enterprise"; return null;
}
export const PAID_ACTIVE = new Set(["active", "trialing"]);
/** Effective plan from a stored subscription record. past_due keeps access only until the paid period ends (no free ride after that). */
export function effectivePlan(b: { plan?: string; status?: string; currentPeriodEnd?: string | null } | null | undefined, now = Date.now()): PlanId {
  if (!b || (b.plan !== "pro" && b.plan !== "enterprise")) return "free";
  if (b.status && PAID_ACTIVE.has(b.status)) return b.plan;
  if (b.status === "past_due" && b.currentPeriodEnd && Date.parse(b.currentPeriodEnd) > now) return b.plan;
  return "free";
}
