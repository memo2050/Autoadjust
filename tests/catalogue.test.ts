import test from "node:test"; import assert from "node:assert/strict";
import { CATALOGUE_IDS, LEGACY_ALIASES, resolveCatalogueId, catalogueName } from "../lib/billing/catalogue";
import { TIERS } from "../lib/billing/pricing"; import { PLAN_IDS } from "../lib/billing/plans";
test("catalogue = free + five tiers", () => assert.deepEqual(CATALOGUE_IDS, ["free","basic","standard","professional","business","enterprise"]));
test("every legacy plan id aliases into the catalogue", () => { for (const p of PLAN_IDS) assert.ok(CATALOGUE_IDS.includes(LEGACY_ALIASES[p].id)); assert.equal(resolveCatalogueId("pro"), "basic"); assert.equal(resolveCatalogueId("Enterprise"), "enterprise"); assert.equal(resolveCatalogueId("nope"), null); });
test("prices untouched", () => assert.deepEqual(TIERS.map(t => t.monthlyUsd), [49,99,199,399,null]));
test("names", () => { assert.equal(catalogueName("free"), "Free account"); assert.equal(catalogueName("business"), "Business"); });
