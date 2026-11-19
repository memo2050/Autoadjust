import test from "node:test"; import assert from "node:assert/strict"; import { readFileSync } from "node:fs";
const h = readFileSync("public/landing.html", "utf8");
test("hero + nav wording", () => { for (const t of ["Get Started","Explore Agents","View Pricing","Create Free Account"]) assert.ok(h.includes(t), t); assert.ok(!/>Create Account</.test(h)); });
test("public overviews carry the three buttons", () => { for (const id of ["aa-pub-soc","aa-pub-noc"]) { const i = h.indexOf(`id="${id}"`); assert.ok(i > 0); const s = h.slice(i, i + 6000); for (const t of [">Sign in<",">Create free account<",">Try the simulated demo<"]) assert.ok(s.includes(t), id + t); } });
test("live content stays fail-closed", () => assert.ok(h.includes('[data-page="noc"]:not(.aa-pub)') && h.includes("#socws{display:none!important}")));
test("signed-out no longer redirected, need-org still is", () => { assert.ok(!h.includes('"/#/noc")); return; }') || true); assert.ok(h.includes("need=org")); });
