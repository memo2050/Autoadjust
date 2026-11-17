# Execution report (single, updated in place) — 2026-11-17 (round 2)
Production: **unchanged** (no merge, deploy, production SQL, spend). PR #3: open draft. Evidence class: LOCAL = my sandbox, CI = GitHub Actions, STAGING = none yet, PRODUCTION = none.

## Completed this round
| Item | Evidence |
|---|---|
| JWT verification for Supabase **asymmetric** keys (ES256/RS256 via the project JWKS, cached, rotation-safe, forged-kid refetch limited to 1 per 30 s, fail closed if JWKS is down); issuer, audience, role, expiry, nbf, sub checks on every path; HS256 only for legacy secret, `alg:none`/algorithm-confusion refused | commit 9c04d71..ea9fde6, tests/jwt-asym.test.ts, LOCAL 205/205 tests + tsc |
| Production guard for migrations: `scripts/env-guard.mjs` fails closed unless target, DB project ref, environment variable, typed confirmation and (production) `RELEASE_APPROVAL` string all agree; never prints the URL | tests/env-guard.test.ts, LOCAL |
| Protected workflows: `db-migrate.yml` (manual; GitHub environments staging/production; guard first; baseline refuses non-empty DB), `security.yml` (secrets scan, `npm audit --audit-level=high`, guard tests) | CI run 44144083382 **PASS**; verify-build 44144083009 **PASS** (commit ea9fde6) |
| Dependency audit (production deps, high+critical) | CI **PASS** (no high/critical). 1 moderate previously reported by npm (not blocking) |
| Secrets scan of tracked files | CI + LOCAL **PASS** |
| Inspection of baseline.sql / ALL.sql | No DROP TABLE/TRUNCATE; only `drop trigger/policy if exists` on objects the same script recreates; the 7 UPDATE/DELETE statements are inside function bodies (run only when called; hard_delete_org needs an approved deletion). Repeatable. Safe for an empty staging project; baseline is refused on a non-empty DB by the workflow |

## Findings
Critical/High open: none known in code. **Medium:** staging unproven on real Supabase (RLS, real JWKS, MFA); sync export size caps; legacy tokens still on (by design). **Low:** moderate npm advisory; Node 20 action deprecation notices in CI.

## Blockers needing you (smallest actions)
1. **Staging Supabase project** (I cannot create accounts): create free project + 2 test users (docs/phase7/SUPABASE_STAGING_SETUP.md). Then in GitHub: environments `staging` and `production` (production: required reviewer = you), repo variable `PRODUCTION_PROJECT_REF`, per-environment variable `EXPECTED_PROJECT_REF` and secret `DATABASE_URL`. No secret goes in chat.
2. **Hostinger staging:** which plan do you have (name from hPanel)? Node.js app support depends on the plan; I cannot read your hPanel.
3. Anthropic spend-capped key (GitHub env `ai-live-test`), Stripe test keys (staging env only), lab VMs for Wazuh/Zabbix/Windows.

## Not done (blocked or not testable here) — status NOT TESTED/BLOCKED
Real staging deploy and smoke run, real MFA/RLS/two-user isolation on Supabase, live AI with spend limit, Stripe test checkout/webhook, Windows executor isolation, Wazuh, Zabbix, load test, backup/restore drill, session/cookie review on live host.
## Exact next action
You: do blocker 1 and tell me the Hostinger plan name. Me (meanwhile): staging deploy workflow, load-test script, backup/restore procedure, headers/cookie review.

## Round 2 (commit 4736bda)
| Item | Status / evidence |
|---|---|
| Hostinger Business Web Hosting + Next.js | **Supported** per Hostinger docs: Node.js web apps on Business plan, Node 20/22, Next.js server mode, each subdomain = its own site, GitHub auto-deploy (one GitHub account per plan, shared by all Node sites). **Not published:** Node app count/RAM for your plan (shared-hosting table shows 1 GB RAM, 150% CPU, 50 processes) -> real-build memory is **UNVERIFIED** until the first staging deploy. Risk: GitHub auto-deploy must watch branch `staging` only |
| Runtime isolation guard (`APP_ENV`, staging refuses production Supabase ref / live Stripe key; service returns 503) | LOCAL tests, 212/212 |
| Load test script (staging-only, capped 50 concurrency / 200 rps; p50/p95/p99, error %, thresholds) | Self-test PASS (LOCAL, refuses prod URLs). **Real staging load test: NOT RUN** |
| Backup/restore drill script + doc | LOCAL **PASS** on scratch Postgres (69 tables, 14 migrations, 0 count mismatches); first two runs correctly failed and exposed the auth.users dependency (documented). **STAGING drill NOT RUN**; no downloadable backups on Free plan (unconfirmed) |
| `staging-verify` workflow (build verify + smoke + load, environment `staging`) | YAML valid, `verify` job PASS on the new `staging` branch; smoke job NOT RUN (needs your staging settings; run cancelled) |
| CI on 4736bda | verify PASS, scan PASS (secrets scan, npm audit high) |
| Owner checklist | docs/phase7/OWNER_CHECKLIST.md (sections A-E, step by step) |
Still NOT DONE: everything needing the staging Supabase/host (real JWKS, MFA, RLS two-user proof, smoke/load on staging, Stripe, AI, Windows, Wazuh, Zabbix, session/cookie/headers review on live host). Production-ready: **No**.

## Production-ready? **No.** Criteria 2-6, 8-14 lack staging evidence.
