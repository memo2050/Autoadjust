# Staging smoke-test checklist
Automated part: `node scripts/staging-smoke.mjs` (refuses non-staging addresses; self-tested against an in-memory harness; NOT yet run against real staging). Manual part = items marked M.
Config for the script (env, on your machine or as GitHub `staging` environment secrets): `STAGING_URL`, `STAGING_SUPABASE_URL`, `STAGING_SUPABASE_ANON_KEY`, `SMOKE_EMAIL_A/B`, `SMOKE_PASSWORD_A/B`.
| Area | Check | How | Evidence |
|---|---|---|---|
| Authentication | no/forged/shared-admin token refused | script | PASS lines |
| Authentication | sign-up, sign-in, sign-out in the real UI | M (you, 2 min) | screenshots |
| Authentication | token verification path works (fallback when JWT secret unset) | script signs in via Supabase and calls the API | PASS lines |
| MFA | enrol TOTP on the account page (existing card), re-login, status shows verified | M | screenshots |
| MFA | with `MFA_ENFORCE=on`: privileged change without aal2 -> 403 `mfa_required`; with aal2 -> allowed | script (aal1) + M (aal2) | script output + screenshot |
| Tenant isolation | user A cannot read/modify org B (keys, members, data) both directions | script | PASS lines |
| Tenant isolation | RLS enabled on org tables (migration checklist step 5) | SQL result | table |
| Billing | Free plan shown, enforcement off, limits listed | script + M page `/billing.html` | output + screenshot |
| Billing | checkout creates a Stripe **test** session only (later, needs test keys) | M with test card 4242... | Stripe test dashboard |
| Agent execution | enroll executor with `executor`-scoped key; allowlisted read-only diagnostic runs; replay refused | needs a Linux executor VM (your lab); I give commands | job/result rows |
| Agent execution | disruptive actions remain disabled | script/UI | |
| Security | rate limit 429 + Retry-After (needs an aal2 test user) | script | PASS or SKIP (stated) |
| Security | scoped key: noc key refused on SOC ingest; revoked key refused | script | PASS lines |
| Security | export link single-use; deletion needs exact name and a second approver | script + M | |
| Security | HTTPS only, security headers, no secrets in responses | script (informational) | output |
| Production check | production URL/DB/migration list unchanged before vs after | you send the 3 read-only results | |
