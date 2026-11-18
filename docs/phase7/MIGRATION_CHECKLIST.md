# Staging database migration checklist (STAGING project only; fresh, empty database)
Files come from branch `claude/phase6-staging-prep` (PR #3): `supabase/baseline.sql` then `supabase/migrations/ALL.sql` (regenerated 0100-0113). Verified on scratch Postgres: empty DB -> baseline -> ALL.sql -> ALL.sql again, no errors; CI drift test green.
| # | Step | Who | Expected result |
|---|---|---|---|
| 1 | Confirm the SQL Editor shows the **staging** project name | you | |
| 2 | Open `supabase/baseline.sql` from the branch (I will also send it as a file), paste, **Run** | you | "Success. No rows returned" |
| 3 | Paste `supabase/migrations/ALL.sql`, **Run** | you | Success (the file is repeatable; each migration is its own transaction) |
| 4 | `select version, name from private.app_migrations order by version;` | you -> send me result | 14 rows, 0100...0113 |
| 5 | `select tablename, rowsecurity from pg_tables where schemaname='public' order by 1;` | you -> send me | the org_*/soc_*/noc_*/billing_*/rate_limits tables listed; org tables with rowsecurity = true |
| 6 | `select proname from pg_proc where proname in ('rate_limit_hit','hard_delete_org');` | you | both rows |
| 7 | `select grantee from information_schema.routine_privileges where routine_name in ('rate_limit_hit','hard_delete_org') and grantee in ('anon','authenticated');` | you | **0 rows** (only service_role may call them) |
If any step errors: stop, send me the exact error text. Nothing is applied to production. Rollbacks (`rollback_0106..0113.sql`) exist; staging can also simply be deleted and recreated.
Order dependencies (tested): baseline -> 0100..0113 consecutively; 0111 needs 0106; 0113 refuses to apply without 0100, 0101, 0107, 0109; 0112 must exist before the PR #2 code runs.
