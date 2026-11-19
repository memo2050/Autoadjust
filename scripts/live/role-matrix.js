/* Live role-matrix probe for STAGING. Paste into the browser console (or run with the Chrome javascript tool) on a tab that is signed in as the test user.
   It sends only harmless requests: GETs, and POSTs with an empty body that are rejected by validation (400/404/422) if the role IS allowed, or by authorization (403) if it is NOT.
   Nothing is created, changed or deleted. Usage: await AA_ROLE_MATRIX("noc_operator")   (the role the owner has just assigned to this user) */
async function AA_ROLE_MATRIX(role) {
  const T = sessionStorage.getItem("socToken"); if (!T) return { error: "not signed in in this tab" };
  // expectation: true = the role may do it (request passes authorization), false = must get 403.  Derived from lib/tenant/auth.ts (ROLE_MAP, DOMAIN, PERMS); tests/role-matrix.test.ts keeps this table in sync with the code.
  const EXPECT = {
    "GET me": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 1, executive_readonly: 1 },
    "GET overview": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 1, executive_readonly: 1 },
    "GET noc/devices": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 1, executive_readonly: 1 },
    "GET org/members": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 1, executive_readonly: 1 },
    "GET audit": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 1, executive_readonly: 0 },
    "GET wazuh/cursor": { owner: 1, it_admin: 1, noc_operator: 0, security_analyst: 0, executive_readonly: 0 },
    "POST noc/maps": { owner: 1, it_admin: 1, noc_operator: 1, security_analyst: 0, executive_readonly: 0 },
    "POST noc/sources": { owner: 1, it_admin: 1, noc_operator: 0, security_analyst: 0, executive_readonly: 0 },
  };
  const out = { role, results: {}, pass: 0, fail: 0 };
  for (const [k, exp] of Object.entries(EXPECT)) {
    const [m, p] = k.split(" "); const r = await fetch("/api/soc/" + p, { method: m, headers: { Authorization: "Bearer " + T, ...(m === "POST" ? { "content-type": "application/json" } : {}) }, body: m === "POST" ? "{}" : undefined, cache: "no-store" });
    const allowed = r.status !== 403 && r.status !== 401, want = !!exp[role];
    const ok = allowed === want; out.results[k] = { status: r.status, expected: want ? "allowed" : "403", ok }; ok ? out.pass++ : out.fail++;
  }
  return out;
}
if (typeof module !== "undefined") module.exports = { AA_ROLE_MATRIX };
