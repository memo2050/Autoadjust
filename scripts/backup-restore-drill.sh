#!/usr/bin/env bash
# Backup + restore drill. READ-ONLY on the source (pg_dump). Restores into a DIFFERENT, throw-away database whose name must start with "drill_".
# Env: SOURCE_URL (staging database connection string; never production), DRILL_URL (admin connection to a scratch Postgres where drill_* databases may be created), DRILL_DB (default drill_$(date +%s)),
#      BACKUP_DIR (default ./backups, created 0700; contains DATA: do not commit). Prints PASS/FAIL; compares row counts of every public table. Never prints the connection strings.
set -euo pipefail
: "${SOURCE_URL:?SOURCE_URL required}"; : "${DRILL_URL:?DRILL_URL required}"
DRILL_DB="${DRILL_DB:-drill_$(date +%s)}"; BACKUP_DIR="${BACKUP_DIR:-./backups}"
[[ "$DRILL_DB" =~ ^drill_[a-z0-9_]+$ ]] || { echo "FAIL: DRILL_DB must match drill_[a-z0-9_]+"; exit 2; }
[ -z "${PRODUCTION_PROJECT_REF:-}" ] || ! grep -qi -- "$PRODUCTION_PROJECT_REF" <<<"$SOURCE_URL" || { echo "FAIL: SOURCE_URL is the production project; drills run on staging only"; exit 2; }
umask 077; mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"; F="$BACKUP_DIR/backup-$(date -u +%Y%m%dT%H%M%SZ).dump"
echo "1/4 dump (custom format, public+private schemas, no owners/privileges)"; pg_dump "$SOURCE_URL" -Fc --no-owner --no-privileges -n public -n private -f "$F"; echo "   size: $(stat -c %s "$F") bytes, sha256 $(sha256sum "$F" | cut -c1-16)"
echo "2/4 create scratch database $DRILL_DB"; psql "$DRILL_URL" -v ON_ERROR_STOP=1 -qc "create database $DRILL_DB"
DST="$(python3 - "$DRILL_URL" "$DRILL_DB" <<'PY'
import sys,urllib.parse as u
p=u.urlparse(sys.argv[1]); print(u.urlunparse(p._replace(path="/"+sys.argv[2])))
PY
)"
echo "3/4 restore"
# A real Supabase restore target already has the auth schema and roles. On a plain scratch Postgres, DRILL_PRELUDE (a .sql file) may create minimal stand-ins (auth.uid(), roles).
[ -z "${DRILL_PRELUDE:-}" ] || psql "$DST" -v ON_ERROR_STOP=1 -q -f "$DRILL_PRELUDE"
# Application tables reference auth.users. A real restore target keeps its own auth users (Supabase manages them; they are NOT in this backup). On the scratch database only ids and emails are copied so the foreign keys can be satisfied (no password hashes).
[ -z "${DRILL_PRELUDE:-}" ] || psql "$SOURCE_URL" -qc "copy (select id, email from auth.users) to stdout" | psql "$DST" -qc "copy auth.users(id, email) from stdin"
psql "$DST" -qc "drop schema if exists public cascade"
set +e; pg_restore --no-owner --no-privileges --exit-on-error -d "$DST" "$F" > "$BACKUP_DIR/restore.log" 2>&1; rc=$?; set -e
[ "$rc" = 0 ] && echo "   restore finished without errors" || { echo "   restore reported errors (first lines):"; head -5 "$BACKUP_DIR/restore.log"; }
echo "4/4 compare row counts (every public table)"
Q="select format('%I', c.relname) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' order by 1"
bad=0; n=0
for t in $(psql "$SOURCE_URL" -tAc "$Q"); do a=$(psql "$SOURCE_URL" -tAc "select count(*) from public.$t"); b=$(psql "$DST" -tAc "select count(*) from public.$t" 2>/dev/null || echo MISSING); n=$((n+1)); [ "$a" = "$b" ] || { echo "   MISMATCH $t: source=$a restored=$b"; bad=$((bad+1)); }; done
mig=$(psql "$DST" -tAc "select count(*) from private.app_migrations" 2>/dev/null || echo 0); echo "   tables compared: $n, mismatches: $bad, migrations restored: $mig"
psql "$DRILL_URL" -qc "drop database $DRILL_DB" && echo "   scratch database dropped (backup file kept: $F)"
[ "$rc" = 0 ] && [ "$bad" = 0 ] && [ "$n" -gt 0 ] && echo "DRILL PASS" || { echo "DRILL FAIL"; exit 1; }
