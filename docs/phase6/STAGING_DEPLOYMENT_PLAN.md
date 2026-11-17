# Staging deployment plan (separate Supabase project)
Nothing below is executed yet. Every step marked **YOU** needs your account; every step marked **APPROVAL** waits for your explicit yes. Production is never touched.

## 0. Principle
Staging shares **nothing** with production: its own Supabase project, its own keys, its own hostname, its own Stripe *test* keys, its own collector keys. A staging key must never be valid in production and vice versa.

## 1. Resources and cost
| Resource | Who creates | Cost/month |
|---|---|---|
| New Supabase project "autoadjust-staging" (Free plan) | YOU | $0 (Free plan limits: small DB, paused after inactivity; check current limits when creating) |
| Staging site: a subdomain `staging.autoadjust.net` on the existing Hostinger plan **if** it supports a second Node app; else a free hobby host | YOU (+ DNS record for the *new* subdomain only, APPROVAL) | $0, or ~$5-6 VPS only if neither works (APPROVAL with exact price first) |
| GitHub "staging" environment (secrets) | YOU | $0 |
| Stripe: test-mode keys (account already in test mode) | YOU | $0 |
| Anthropic key with a hard monthly cap | YOU | spend-capped; see AI plan (<= ~$2 per full live run at the built-in budget; cap $5) |
| Lab VMs (Wazuh, Zabbix, Windows eval) | YOU | $0 (your hardware; Windows 11 Enterprise 90-day evaluation is free) |
Total committed: **$0** unless you later approve the optional VPS or AI spend.

## 2. Steps
1. **YOU** Create the Supabase project (name it staging; region near you; choose a strong DB password in your password manager). Do not paste any key in chat.
2. **YOU** In Supabase -> Project Settings -> API: note the project URL (not secret) and keep the `anon` key, `service_role` key and JWT secret for step 5. Settings -> Auth: enable email sign-in; set Site URL = the staging URL; **enable MFA (TOTP)**.
3. I give you one SQL file to paste in the **staging** SQL Editor: `baseline.sql` (= supabase/schema.sql, 002, app_records, 003-008 concatenated) followed by `ALL.sql` (0100-0113, regenerated and drift-tested). Verified today on a fresh scratch Postgres (baseline + 0100-0113 applied, re-applied, no errors).
4. **YOU** Run it in the staging SQL Editor; paste back only the result of `select version from private.app_migrations order by 1;` (expect 0100-0113).
5. **YOU** Create the staging site and set its environment variables (names only below; values typed by you into the host's settings, never into chat or git):
   `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_JWT_SECRET`, `NOC_SECRET_KEY` (random 32+ chars, different from production), `EXPORT_SIGNING_SECRET` (random 32+, different), `PLATFORM_ADMIN_USER_IDS` (your staging user id), `MFA_ENFORCE=on`, `SOC_LEGACY_TOKENS` unset/off, `BILLING_ENFORCE` unset (off), `STRIPE_*` = **test** keys only, `APP_HOST`/`SITES_DOMAIN` **not both set**.
6. **APPROVAL** I prepare the deploy of the branch `claude/phase6-staging-prep` (PR #1 + PR #2 + fixes) to the staging site only. You trigger or approve the deploy; production auto-deploy stays off.
7. Smoke test (me, or you if I cannot reach the host): sign up, create org, enrol MFA, create collector key, push test telemetry, export, confirm rate limiting, confirm billing shows Free and enforcement off. Evidence: screenshots + status output.
8. Lab integrations (see INTEGRATION_TEST_PLAN.md).

## 3. Safety checks before and after
- Before: compare staging env var *names* against production names (you tell me names only); confirm no production URL/key appears in staging settings.
- After: confirm production unchanged: production migration list identical to before; production site unchanged.
## 4. Rollback
Staging is disposable: delete the staging project/site. Migration rollbacks exist for 0106-0113 (`rollback_*.sql`).
