// Guards against the stale ALL.sql problem: ALL.sql must equal the concatenation made by scripts/build-migrations-all.sh.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
test("supabase/migrations/ALL.sql is up to date with the numbered migrations", () => {
  const before = readFileSync("supabase/migrations/ALL.sql", "utf8"); execFileSync("bash", ["scripts/build-migrations-all.sh"]);
  const after = readFileSync("supabase/migrations/ALL.sql", "utf8");
  assert.equal(before, after, "ALL.sql was stale: run scripts/build-migrations-all.sh and commit");
  for (const f of readdirSync("supabase/migrations").filter((x) => /^0\d{3}_.*\.sql$/.test(x))) assert.ok(after.includes(`===== ${f} =====`), f + " missing from ALL.sql");
});
test("migration numbers are unique and consecutive", () => {
  const n = readdirSync("supabase/migrations").filter((x) => /^0\d{3}_.*\.sql$/.test(x)).map((x) => Number(x.slice(0, 4))).sort((a, b) => a - b);
  n.forEach((v, i) => assert.equal(v, 100 + i, "gap or duplicate near " + v));
});
