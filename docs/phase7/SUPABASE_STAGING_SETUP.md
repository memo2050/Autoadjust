# Supabase STAGING setup — exact instructions (you do these; no production resource is involved)
Menu names in Supabase change from time to time. If a screen differs, send me a screenshot (hide keys) and I will adapt. **Never paste keys, passwords or JWT secrets into chat or git.**

## A. Create the project (free plan)
1. supabase.com -> Dashboard -> **New project**. Organization: your existing one (or a new free one).
2. Name: `autoadjust-staging`. Database password: generate in your password manager and store it there. Region: closest to you. Plan: **Free ($0)**. If the screen shows any paid add-on, leave it off.
3. Wait until the project says "healthy". Confirm the project name at the top-left says *staging* before every later step.

## B. Authentication settings (Authentication menu)
1. **Sign In / Providers**: Email = enabled. For staging you may turn off "Confirm email" so test users can sign in at once (staging only).
2. **URL Configuration**: Site URL = your staging URL (set later when it exists); add the same URL under Redirect URLs.
3. **Multi-Factor**: make sure **TOTP** enrolment is enabled (default on for new projects; the label may be under Sign In / Providers or Auth settings).
4. Rate limits: leave defaults.

## C. Create two throwaway test users (Authentication -> Users -> Add user)
`smoke-a-staging@<a mailbox you own>` and `smoke-b-staging@...`, each with a strong password kept in your password manager. They are used only by the smoke test (they never exist in production).

## D. Collect the values (Project Settings -> API, and -> Database)
Write down in your password manager (do not paste to me): Project URL, `anon` key, `service_role` key. 
**JWT secret note:** newer Supabase projects sign tokens with asymmetric keys. This app verifies HS256 tokens with `SUPABASE_JWT_SECRET`; if that secret is unset the app verifies tokens by asking Supabase (works with any key type, one extra call per request). For staging: leave `SUPABASE_JWT_SECRET` **unset** unless Settings shows a legacy HS256 secret you choose to use. I will test the fallback path on staging.

## E. Run the database setup (SQL Editor, in the STAGING project only)
Use the migration checklist (MIGRATION_CHECKLIST.md). 

## F. Environment variables for the staging site (typed by you into the staging host's settings)
| Name | Value | Notes |
|---|---|---|
| `SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_URL` | staging project URL | not secret |
| `SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` | staging anon key | public by design |
| `SUPABASE_SERVICE_ROLE_KEY` | staging service_role key | **secret**, server only |
| `NOC_SECRET_KEY` | new random 32+ chars | secret; different from production |
| `EXPORT_SIGNING_SECRET` | new random 32+ chars | secret; different from production |
| `PLATFORM_ADMIN_USER_IDS` | your staging user's id | after you create your own staging user |
| `MFA_ENFORCE` | `on` | turn on after your staging admin has enrolled TOTP |
| `BILLING_ENFORCE` | unset | stays off |
| `SOC_LEGACY_TOKENS` | unset/off | |
| `STRIPE_SECRET_KEY` etc. | Stripe **test** keys (`sk_test_...`) only, later | never live keys |
| `APP_HOST`, `SITES_DOMAIN` | **do not set both** | |
Generate random secrets e.g. with `openssl rand -base64 36` on your lab VM.

## G. Hard rules
Staging values must differ from production values. Never copy a production variable into staging. Never connect the staging site to the production Supabase URL.
