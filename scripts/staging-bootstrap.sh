#!/usr/bin/env bash
# ONE-COMMAND STAGING BOOTSTRAP. Run on YOUR computer (needs: gh logged in as the repo owner, psql, node, curl, openssl). Nothing is sent to anyone but GitHub, your staging Supabase project and the database you name.
# It asks for each value with hidden input (never echoed, never written to disk, never in command-line arguments), checks the guard, then:
#   1. creates GitHub environments staging + production (production = required reviewer: you)  2. stores the values as environment secrets/variables
#   3. applies baseline.sql + ALL.sql to the STAGING database only (baseline only if the public schema is empty)  4. creates two test users with random passwords stored ONLY as GitHub secrets
#   5. prints the migration list. Use --dry-run to stop after the guard (nothing is changed).
set -euo pipefail; cd "$(dirname "$0")/.."
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
for c in gh psql node curl openssl; do command -v $c >/dev/null || { echo "missing tool: $c"; exit 2; }; done
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"; echo "Repository: $REPO"
ask()  { local v; read -r -p "$1: " v; printf '%s' "$v"; }
asks() { local v; read -r -s -p "$1 (hidden): " v; echo >&2; printf '%s' "$v"; }
STG_REF="$(ask 'STAGING Supabase project ref (the part before .supabase.co)')"; PRD_REF="$(ask 'PRODUCTION Supabase project ref')"
DATABASE_URL="$(asks 'STAGING database connection string (Supabase -> Connect)')"
export TARGET=staging DATABASE_URL EXPECTED_PROJECT_REF="$STG_REF" CONFIRM_PROJECT_REF="$STG_REF" PRODUCTION_PROJECT_REF="$PRD_REF"
node scripts/env-guard.mjs || { echo "Guard refused. Nothing was changed."; exit 1; }
[ "$DRY" = 1 ] && { echo "dry run: stopping after the guard."; exit 0; }
SB_URL="https://$STG_REF.supabase.co"; ANON="$(asks 'STAGING anon (public) key')"; SERVICE="$(asks 'STAGING service_role key')"
STAGING_URL="$(ask 'Staging site URL (e.g. https://staging.autoadjust.net)')"; case "$STAGING_URL" in https://*staging*) ;; *) echo "STAGING_URL must be https and contain 'staging'"; exit 1;; esac
ME="$(gh api user -q .login)"; UID_="$(gh api user -q .id)"
gh api -X PUT "repos/$REPO/environments/staging" --silent
gh api -X PUT "repos/$REPO/environments/production" --input - --silent <<<"{\"reviewers\":[{\"type\":\"User\",\"id\":$UID_}]}"
gh variable set PRODUCTION_PROJECT_REF --body "$PRD_REF"
for kv in "STAGING_URL=$STAGING_URL" "STAGING_SUPABASE_URL=$SB_URL" "EXPECTED_PROJECT_REF=$STG_REF"; do gh variable set "${kv%%=*}" --env staging --body "${kv#*=}"; done
printf '%s' "$DATABASE_URL" | gh secret set DATABASE_URL --env staging; printf '%s' "$ANON" | gh secret set STAGING_SUPABASE_ANON_KEY --env staging
n=$(psql "$DATABASE_URL" -tAc "select count(*) from information_schema.tables where table_schema='public'")
if [ "$n" = 0 ]; then echo "empty database: applying baseline.sql"; psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f supabase/baseline.sql; else echo "public schema has $n tables: baseline.sql skipped"; fi
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f supabase/migrations/ALL.sql
for who in A B; do
  em="smoke-$(echo $who | tr A-Z a-z)-$(openssl rand -hex 3)@staging-test.invalid"; pw="$(openssl rand -base64 24)Aa1!"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SB_URL/auth/v1/admin/users" -H "apikey: $SERVICE" -H "Authorization: Bearer $SERVICE" -H 'content-type: application/json' --data "{\"email\":\"$em\",\"password\":\"$pw\",\"email_confirm\":true}")
  [ "$code" = 200 ] || { echo "user $who creation failed (HTTP $code)"; exit 1; }
  printf '%s' "$em" | gh secret set "SMOKE_EMAIL_$who" --env staging; printf '%s' "$pw" | gh secret set "SMOKE_PASSWORD_$who" --env staging; echo "test user $who created (credentials stored only as GitHub secrets)"
done
echo "Applied migrations:"; psql "$DATABASE_URL" -tAc "select string_agg(version,',' order by version) from private.app_migrations"
echo "Done. Tell Claude 'bootstrap done'. (Service-role key was used once, not stored anywhere.)"
