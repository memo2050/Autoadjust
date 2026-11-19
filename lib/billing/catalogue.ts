// Single source of truth for plan NAMES/IDs: free account state + the five public tiers.
// Read-only view over pricing.ts (prices, limits) and plans.ts (engine). It changes NO price, limit or billing setting.
import { TIERS, type TierId } from "./pricing";
import { PLAN_IDS, type PlanId } from "./plans";
export type CatalogueId = "free" | TierId;
export const CATALOGUE_IDS: CatalogueId[] = ["free", ...TIERS.map(t => t.id)];
/** Legacy engine plan ids kept as aliases. "pro" is grandfathered: it keeps its existing engine limits and is shown as Basic (same $49 price point). */
export const LEGACY_ALIASES: Record<PlanId, { id: CatalogueId; grandfathered: boolean }> = {
  free: { id: "free", grandfathered: false },
  pro: { id: "basic", grandfathered: true },
  enterprise: { id: "enterprise", grandfathered: false },
};
export const resolveCatalogueId = (x: string | null | undefined): CatalogueId | null => {
  if (!x) return null; const k = x.toLowerCase();
  if ((CATALOGUE_IDS as string[]).includes(k)) return k as CatalogueId;
  return (PLAN_IDS as string[]).includes(k) ? LEGACY_ALIASES[k as PlanId].id : null;
};
export const catalogueName = (id: CatalogueId) => id === "free" ? "Free account" : TIERS.find(t => t.id === id)!.name;
