import test from "node:test"; import assert from "node:assert/strict"; import { readFileSync } from "node:fs";
const h = readFileSync("public/landing.html", "utf8");
const nav = /<div class="nl">(.*?)<\/div>/s.exec(h)![1];
test("nav order and labels", () => { const labels = [...nav.matchAll(/>([^<]+)<\/a>/g)].map(m => m[1]); assert.deepEqual(labels, ["Home","SOC","NOC","Use Cases","Industries","Pricing","About Us","Meet the Team","Contact Us"]); });
test("every nav target exists", () => { for (const m of nav.matchAll(/href="#([^"]+)"/g)) { const id = m[1].replace(/^\//, ""); if (["home","soc","noc","team"].includes(id) || m[1].startsWith("/pricing")) continue; assert.ok(h.includes(`id="${id}"`), id); } });
test("Sign In and Get Started stay in the nav", () => { const cta = /id="navCta">(.*?)<\/div><\/nav>/s.exec(h)![1]; assert.ok(cta.includes(">Sign In<") && cta.includes(">Get Started<")); });
test("8 use cases and 8 industries", () => { const uc = /id="use-cases".*?<\/section>/s.exec(h)![0]; assert.equal((uc.match(/class="ux-card ux-rv"/g) || []).length, 8); const ind = /id="industries".*?<\/section>/s.exec(h)![0]; assert.equal((ind.match(/ux-ind ux-rv/g) || []).length, 8); for (const n of ["Healthcare","Banking &amp; Financial Services","Government &amp; Public Sector","Technology &amp; IT Services","Manufacturing &amp; Industrial","Retail &amp; E-commerce","Education","Telecommunications"]) assert.ok(ind.includes(n), n); });
test("no invented statistics, testimonials or certification claims in the new sections", () => { const txt = ["use-cases","industries","about"].map(i => new RegExp(`id="${i}".*?</section>`, "s").exec(h)![0].replace(/<svg.*?<\/svg>/gs, "").replace(/<[^>]+>/g, " ")).join(" "); assert.ok(!/\d+\s*%|\bcustomers? say|testimonial|ISO ?27001|HIPAA compliant|SOC ?2 (certified|compliant)|guarantee/i.test(txt)); });
test("SOC/NOC live content remains fail-closed", () => { assert.ok(h.includes('[data-page="soc"]:not(.aa-pub):not(.aa-keep)') && h.includes("#socws{display:none!important}")); });
test("Meet the Team page has its video and route", () => {
  assert.ok(h.includes('id="meet-team"') && h.includes('data-page="team"'));
  assert.ok(h.includes('src="/meet-the-team.mp4"') && h.includes('poster="/meet-the-team.jpg"'));
  assert.ok(h.includes('h==="team"'));
});
