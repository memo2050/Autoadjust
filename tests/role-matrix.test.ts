// Keeps the live role-matrix probe (scripts/live/role-matrix.js) in sync with the real authorization code.
import test from "node:test"; import assert from "node:assert/strict"; import { readFileSync } from "node:fs";
import { allowed, ROLE_MAP, ORG_ROLES, type Principal, type OrgRole } from "../lib/tenant/auth";
const src = readFileSync(new URL("../scripts/live/role-matrix.js", import.meta.url), "utf8");
const table: Record<string, Record<string, number>> = {};
for (const m of src.matchAll(/"((?:GET|POST) [^"]+)": \{ ([^}]*) \}/g)) { table[m[1]] = Object.fromEntries([...m[2].matchAll(/(\w+): (\d)/g)].map((x) => [x[1], Number(x[2])])); }
const pr = (r: OrgRole): Principal => ({ kind: "user", name: "t", orgId: "o", orgRole: r, role: ROLE_MAP[r], platformAdmin: false });
const rule: Record<string, (r: OrgRole) => boolean> = {
  "GET me": (r) => allowed(pr(r), "read", "soc"), "GET overview": (r) => allowed(pr(r), "read", "soc"), "GET noc/devices": (r) => allowed(pr(r), "read", "noc"), "GET org/members": (r) => allowed(pr(r), "read", "org"),
  "GET audit": (r) => allowed(pr(r), "audit", "soc"), "GET wazuh/cursor": (r) => allowed(pr(r), "ingest", "soc"), "POST noc/maps": (r) => allowed(pr(r), "write", "noc"), "POST noc/sources": (r) => allowed(pr(r), "approve", "noc"),
};
test("live role-matrix expectations equal what the authorization code actually allows, for all five roles", () => {
  assert.deepEqual(Object.keys(table).sort(), Object.keys(rule).sort());
  for (const [k, row] of Object.entries(table)) for (const r of ORG_ROLES) assert.equal(!!row[r], rule[k](r), `${k} as ${r}`);
});
