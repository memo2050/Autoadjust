# Production application order (NOT executed; waiting for approval)
1. `tests/db/hardening/capture_rollback.sql` — run first on production; save the generated restore script.
2. `hardening.sql` — closes the anonymous `increment_usage` hole and other grants.
3. `supabase/migrations/0106_org_api_keys.sql`
4. `supabase/migrations/0107_audit_seq_per_org.sql`
5. Hostinger variables (names): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_JWT_SECRET, NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY. Optional: SOC_LEGACY_TOKENS=off after collectors use org keys, PLATFORM_ADMIN_USER_IDS.
6. Supabase Auth settings to review: email confirmation on, password length 10+, leaked-password protection, site URL.
7. Deploy the dev copy after `next build` succeeds.
Rollback: `rollback_0107.sql`, `rollback_0106.sql`, the generated restore script / `hardening_revert.sql`.
