# Backup and restore (staging first; same procedure for production later)
**What is backed up:** application data in schemas `public` and `private` (organizations, members, keys (hashes), events, alerts, billing, audit). **Not in the logical backup:** Supabase-managed `auth` users and `storage` files; those come back only by restoring into the *same* Supabase project (Supabase backups / point-in-time recovery) or by re-inviting users. Free-plan projects, as far as I know, include no daily backups (confirm in Dashboard -> Database -> Backups), so for staging use the script below; for production use a paid plan with daily backups or PITR (spend: needs your approval).
## Procedure
1. `SOURCE_URL` = the staging database connection string (Supabase -> Project Settings -> Database -> Connection string). Keep it in your shell only, never in chat/git.
2. `bash scripts/backup-restore-drill.sh` (needs `pg_dump`, `pg_restore`, `psql` 16+, a scratch Postgres in `DRILL_URL`). It dumps (read-only), restores into a throw-away `drill_*` database, compares the row count of **every** public table and the migration list, drops the scratch database, and prints `DRILL PASS`/`DRILL FAIL`. It refuses a source that contains `PRODUCTION_PROJECT_REF`.
3. Backup files contain data: stored with mode 0600 in a 0700 folder; never commit them (`backups/` is git-ignored).
## Evidence so far
LOCAL (scratch Postgres 16, 69 tables, 14 migrations, test data): **DRILL PASS**, 0 mismatches. First runs correctly FAILED twice (restore error; foreign keys to `auth.users`), which is why the script treats any restore error as failure. STAGING drill: **NOT RUN** (needs the staging project).
## Real disaster restore (outline)
New/clean project -> run baseline.sql + ALL.sql -> `pg_restore --data-only` of the dump (users must exist in `auth.users` with the same ids; same project restore keeps them) -> run smoke test. RTO/RPO to be measured in the staging drill.
