import test from "node:test"; import assert from "node:assert/strict"; import { spawnSync } from "node:child_process"; import { readFileSync } from "node:fs";
// @ts-ignore plain ESM helper shared by the smoke test and the load test
import { checkStagingUrl, APPROVED_STAGING_HOSTS } from "../scripts/lib/staging-target.mjs";
const H = "stellar-purple-horse-66.hostingersite.com";
test("the approved list is exactly the confirmed staging host", () => assert.deepEqual([...APPROVED_STAGING_HOSTS], [H]));
test("accepts the confirmed staging host over HTTPS (with or without trailing slash, any case)", () => { for (const u of [`https://${H}`, `https://${H}/`, `https://${H.toUpperCase()}`]) { const r = checkStagingUrl(u); assert.equal(r.ok, true, u); assert.equal((r as any).base, `https://${H}`); } });
test("accepts localhost and 127.0.0.1 (self-tests)", () => { for (const u of ["http://127.0.0.1:4000", "http://localhost:3000", "https://localhost"]) assert.equal(checkStagingUrl(u).ok, true, u); });
test("rejects production, look-alikes and every unapproved host", () => {
  for (const u of ["https://autoadjust.net", "https://www.autoadjust.net", "https://staging.autoadjust.net", "https://prod-staging.example.com",
    `http://${H}`, `https://${H}:8443`, `https://${H}.evil.com`, `https://evil-${H}`, `https://x.${H}`, "https://other-app.hostingersite.com", "https://hostingersite.com",
    `https://${H}@evil.com`, `https://user:pw@${H}`, `https://${H}/path`, `https://${H}/?a=1`, "ftp://127.0.0.1", "not a url", "", undefined as any, null as any]) assert.equal(checkStagingUrl(u).ok, false, String(u));
});
test("no broad Hostinger rule: another hostingersite.com app is refused", () => assert.equal(checkStagingUrl("https://another-random-app-12.hostingersite.com").ok, false));
for (const script of ["scripts/staging-smoke.mjs", "scripts/load-test.mjs"]) {
  test(`${script} uses the shared check and refuses unapproved targets with exit code 2`, () => {
    assert.match(readFileSync(script, "utf8"), /from "\.\/lib\/staging-target\.mjs"/);
    for (const u of ["https://autoadjust.net", "https://www.autoadjust.net", "https://other-app.hostingersite.com", `http://${H}`, `https://${H}.evil.com`, ""]) { const r = spawnSync("node", [script], { env: { PATH: process.env.PATH, STAGING_URL: u }, encoding: "utf8" }); assert.equal(r.status, 2, `${script} ${u}`); assert.match(r.stderr, /Refusing/); }
  });
}
