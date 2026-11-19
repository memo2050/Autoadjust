import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "fs";
import { TIERS, ADDONS, FEATURES, annualUsd, annualPerMonthUsd, PAYMENTS_ENABLED, includes } from "../lib/billing/pricing";
const html = readFileSync("public/pricing.html", "utf8");
const it = test; const expect = (v: any) => ({ toBe: (x: any) => assert.equal(v, x), toEqual: (x: any) => assert.deepEqual(v, x), toContain: (x: string) => assert.ok(v.includes(x), "missing " + x), toMatch: (r: RegExp) => assert.match(v, r), not: { toMatch: (r: RegExp) => assert.doesNotMatch(v, r) } });
{
  it("payments are disabled and the page has no checkout/payment wiring", () => {
    expect(PAYMENTS_ENABLED).toBe(false);
    expect(html).not.toMatch(/checkout|stripe|js\.stripe|api\/billing|<form|type="card"/i);
    expect(html).toContain("Payments are not enabled");
  });
  it("prices match the approved proposal", () => {
    expect(TIERS.map(t => t.monthlyUsd)).toEqual([49, 99, 199, 399, null]);
    expect(TIERS.map(t => t.endpoints)).toEqual([25, 75, 200, 500, null]);
  });
  it("annual is 15% off twelve months", () => {
    expect(annualUsd(49)).toBe(499.8); expect(annualUsd(399)).toBe(4069.8);
    expect(annualPerMonthUsd(99)).toBe(84.15); expect(annualPerMonthUsd(199)).toBe(169.15);
  });
  it("generated page contains every price, annual figure and add-on", () => {
    for (const t of TIERS) if (t.monthlyUsd) { expect(html).toContain(`data-m="${t.monthlyUsd}"`); expect(html).toContain(`data-y="${annualUsd(t.monthlyUsd)}"`); }
    for (const a of ADDONS) expect(html).toContain(a.name);
  });
  it("unbuilt/unvalidated features are never presented as plain available", () => {
    for (const f of FEATURES.filter(f => f.status !== "available")) expect(html).toMatch(new RegExp(f.name.replace(/[()/]/g, ".") + ".{0,10}(Coming soon|Planned)"));
    expect(includes("basic", FEATURES.find(f => f.name.startsWith("PRTG"))!)).toBe(false);
  });
  it("is responsive and routed", () => {
    expect(html).toContain("width=device-width"); expect(readFileSync("next.config.js", "utf8")).toContain('"/pricing"');
  });
  it("migration is additive-only to the id check", () => {
    const m = readFileSync("supabase/migrations/0115_billing_tiers.sql", "utf8"); expect(m).not.toMatch(/drop table|delete from public/i);
  });
}
