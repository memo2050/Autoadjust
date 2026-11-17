# Your consolidated checklist (everything that needs YOU; nothing here asks for a secret in chat)
Do the parts in order. Each box = about 2-10 minutes. Tell me "done A", "done B"... and I continue.
## A. Staging Supabase (free) — see SUPABASE_STAGING_SETUP.md sections A-D
- [ ] A1 New project `autoadjust-staging` (Free). A2 Authentication -> create 2 users (email + strong password in your password manager). A3 TOTP MFA enabled.
- [ ] A4 SQL Editor (staging project only!) -> run `supabase/baseline.sql`, then `supabase/migrations/ALL.sql` (MIGRATION_CHECKLIST.md). Send me ONLY the output of the verification queries.
## B. GitHub (github.com/memo2050/Autoadjust -> Settings)
- [ ] B1 Environments -> New: `staging` (no reviewers). `production` -> Required reviewers: yourself.
- [ ] B2 Settings -> Secrets and variables -> Actions -> **Variables** (repository): `PRODUCTION_PROJECT_REF` = your production Supabase project ref (the part before `.supabase.co`; not secret).
- [ ] B3 Environment `staging`: Variables `STAGING_URL` (https://staging.autoadjust.net), `STAGING_SUPABASE_URL`, `EXPECTED_PROJECT_REF` (staging ref). Secrets: `DATABASE_URL` (staging connection string), `STAGING_SUPABASE_ANON_KEY`, `SMOKE_EMAIL_A/B`, `SMOKE_PASSWORD_A/B`. You type them in the GitHub page; I never see them.
- [ ] B4 Branch protection for `main`: require checks `verify` and `scan`; no direct pushes.
## C. Hostinger staging site (Business Web Hosting supports Node.js web apps; Next.js runs in server mode)
- [ ] C1 hPanel -> Websites -> Add website -> Node.js Apps -> subdomain `staging.autoadjust.net` (own site, not a folder).
- [ ] C2 Import from GitHub: repository `memo2050/Autoadjust`, branch **`staging`** (I create this branch; never `main`). Framework: Next.js, Node 20 or 22. **Do not touch the production site's settings.**
- [ ] C3 Environment variables of the staging site (type them in hPanel): `APP_ENV=staging`, `PRODUCTION_PROJECT_REF`, `SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `NOC_SECRET_KEY`, `EXPORT_SIGNING_SECRET` (both new random 32+ chars), leave `SUPABASE_JWT_SECRET` unset, `SOC_LEGACY_TOKENS=off`, `BILLING_ENFORCE` unset. Values come from the staging Supabase dashboard; never reuse production values.
- [ ] C4 Deploy. If the build fails with out-of-memory (Business plan: about 1 GB), send me the build log: I have a fallback.
- [ ] C5 Check production site settings still show their original branch (screenshot, secrets hidden).
## D. Later (not now)
Anthropic spend-capped key (GitHub environment `ai-live-test`), Stripe test keys (hPanel staging env only), lab VMs for Wazuh/Zabbix/Windows.
## E. Still pending from before
The three read-only production checks (docs/phase6/PRODUCTION_READONLY_CHECKS_GUIDE.md).
