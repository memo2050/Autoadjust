// Public pricing catalogue (display only). Payments are DISABLED: nothing here creates a charge, a checkout or a subscription.
// Source of truth for the /pricing page (public/pricing.html is generated from this file by scripts/gen-pricing.ts).
export type TierId = "basic" | "standard" | "professional" | "business" | "enterprise";
export interface Tier { id: TierId; name: string; monthlyUsd: number | null; endpoints: number | null; devices: number | null; users: number | null; retentionDays: number | null; support: string; trial: string; blurb: string }
export const ANNUAL_DISCOUNT = 0.15;
export const PAYMENTS_ENABLED = false as const;
export const TIERS: Tier[] = [
  { id: "basic", name: "Basic", monthlyUsd: 49, endpoints: 25, devices: 10, users: 3, retentionDays: 7, support: "Email", trial: "14 days", blurb: "Small teams starting with security and network monitoring." },
  { id: "standard", name: "Standard", monthlyUsd: 99, endpoints: 75, devices: 30, users: 5, retentionDays: 15, support: "Standard", trial: "14 days", blurb: "Growing teams that want AI-assisted triage." },
  { id: "professional", name: "Professional", monthlyUsd: 199, endpoints: 200, devices: 75, users: 10, retentionDays: 30, support: "Priority", trial: "14 days", blurb: "Operations teams running SOC and NOC together." },
  { id: "business", name: "Business", monthlyUsd: 399, endpoints: 500, devices: 200, users: 25, retentionDays: 60, support: "Priority technical", trial: "14 days", blurb: "Larger environments with heavier log volume." },
  { id: "enterprise", name: "Enterprise", monthlyUsd: null, endpoints: null, devices: null, users: null, retentionDays: null, support: "Custom SLA", trial: "Pilot", blurb: "Custom limits, extended retention and a negotiated SLA." },
];
export const ADDONS = [
  { name: "+25 endpoints", monthlyUsd: 15 }, { name: "+10 network devices", monthlyUsd: 10 },
  { name: "+30 days log retention (per 100 endpoints)", monthlyUsd: 10 }, { name: "+10 GB extra storage", monthlyUsd: 5 },
];
/** status: "available" = sellable; "soon" = built but not yet validated against real systems; "planned" = not built. Only "available" features may carry a tier price claim. */
export interface Feature { name: string; status: "available" | "soon" | "planned"; from: TierId; note?: string }
export const FEATURES: Feature[] = [
  { name: "Role-based access and multiple organizations", status: "available", from: "basic" },
  { name: "SOC dashboards, incidents and vulnerability views", status: "available", from: "basic", note: "Staging tests in progress" },
  { name: "AI assistance and AI agents", status: "soon", from: "standard", note: "Live-model test pending" },
  { name: "Windows monitoring and collector", status: "soon", from: "basic" },
  { name: "Wazuh integration", status: "soon", from: "standard" },
  { name: "Zabbix integration (SNMP via Zabbix)", status: "soon", from: "professional" },
  { name: "Prometheus / Grafana alert webhooks", status: "available", from: "professional" },
  { name: "Alert correlation and root-cause analysis", status: "soon", from: "professional" },
  { name: "Syslog collector", status: "planned", from: "standard" },
  { name: "PRTG and Nagios connectors", status: "planned", from: "business" },
];
const ORDER: TierId[] = ["basic", "standard", "professional", "business", "enterprise"];
export const includes = (tier: TierId, f: Feature) => ORDER.indexOf(tier) >= ORDER.indexOf(f.from);
const r2 = (n: number) => Math.round(n * 100) / 100;
export const annualUsd = (m: number) => r2(m * 12 * (1 - ANNUAL_DISCOUNT));
export const annualPerMonthUsd = (m: number) => r2(annualUsd(m) / 12);
export const perEndpointUsd = (t: Tier) => (t.monthlyUsd && t.endpoints ? r2(t.monthlyUsd / t.endpoints) : null);
export const PRICING_NOTES = [
  "Prices are in USD and are a launch proposal. Online payment is not enabled; no card is taken and no subscription can be started.",
  "The 14-day trial (no card, capped at 10 endpoints and 5 network devices, 20 AI calls) is coming soon and subject to cost validation.",
  "Features marked Coming soon or Planned are not sold and carry no price today.",
];
