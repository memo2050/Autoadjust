// Plans and entitlements. The ONLY place that decides what a plan allows. Prices live in Stripe (price ids come from env), never here.
export type PlanId = "free" | "pro" | "enterprise";
export interface Entitlements { plan: PlanId; maxExecutors: number; maxApiKeys: number; aiAnalyst: boolean }
export const PLAN_LIMITS: Record<PlanId, Omit<Entitlements, "plan">> = {
  free: { maxExecutors: 3, maxApiKeys: 5, aiAnalyst: true },
  pro: { maxExecutors: 25, maxApiKeys: 25, aiAnalyst: true },
  enterprise: { maxExecutors: 500, maxApiKeys: 200, aiAnalyst: true },
};
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
