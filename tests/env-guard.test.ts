import test from "node:test"; import assert from "node:assert/strict";
// @ts-ignore plain .mjs module
import { checkTarget, projectRef } from "../scripts/env-guard.mjs";
const STG = "abcdefghijklmnopqrst", PRD = "zyxwvutsrqponmlkjihg";
const url = (ref: string) => `postgresql://postgres:pw@db.${ref}.supabase.co:5432/postgres`;
const base = { TARGET: "staging", DATABASE_URL: url(STG), EXPECTED_PROJECT_REF: STG, CONFIRM_PROJECT_REF: STG, PRODUCTION_PROJECT_REF: PRD };
test("guard: correct staging run passes; pooler URLs parse", () => { assert.equal(checkTarget(base).ok, true); assert.equal(projectRef(`postgresql://postgres.${STG}:pw@aws-0-us-west-1.pooler.supabase.com:6543/postgres`), STG); });
test("guard: fails closed", () => {
  const bad = (o: object) => assert.equal(checkTarget({ ...base, ...o } as any).ok, false, JSON.stringify(Object.keys(o)));
  bad({ DATABASE_URL: url(PRD) });                               // staging target pointing at production: refused (also expected/confirm mismatch)
  bad({ DATABASE_URL: url(PRD), EXPECTED_PROJECT_REF: PRD, CONFIRM_PROJECT_REF: PRD });   // all three agree but it is the production project and target says staging
  bad({ PRODUCTION_PROJECT_REF: "" }); bad({ EXPECTED_PROJECT_REF: "" }); bad({ CONFIRM_PROJECT_REF: "other" }); bad({ TARGET: "prod" }); bad({ TARGET: "" }); bad({ DATABASE_URL: "postgresql://x" }); bad({ DATABASE_URL: "" });
});
test("guard: production needs owner approval string and a production database", () => {
  const p = { ...base, TARGET: "production", DATABASE_URL: url(PRD), EXPECTED_PROJECT_REF: PRD, CONFIRM_PROJECT_REF: PRD };
  assert.equal(checkTarget(p as any).ok, false, "no approval"); assert.equal(checkTarget({ ...p, RELEASE_APPROVAL: "yes" } as any).ok, false); assert.equal(checkTarget({ ...p, RELEASE_APPROVAL: "APPROVED-BY-OWNER" } as any).ok, true);
  assert.equal(checkTarget({ ...p, DATABASE_URL: url(STG), EXPECTED_PROJECT_REF: STG, CONFIRM_PROJECT_REF: STG, RELEASE_APPROVAL: "APPROVED-BY-OWNER" } as any).ok, false, "production target on a non-production database");
});
test("guard: never prints the connection string", () => { const r = checkTarget({ ...base, DATABASE_URL: "postgresql://postgres:SuperSecret1@db.bad.supabase.co/postgres" } as any); assert.ok(!JSON.stringify(r).includes("SuperSecret1")); });
