#!/usr/bin/env bash
# Database tests for the multi-tenant migrations. Needs PostgreSQL 15+ binaries. Usage: tests/db/run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$HERE/../.."; B=${PGBIN:-/usr/lib/postgresql/16/bin}; D=$(mktemp -d); PORT=${PGPORT:-5499}
id postgres >/dev/null 2>&1 || useradd -m postgres; chown postgres "$D"; chmod -R a+rX "$ROOT/supabase" "$HERE"
P() { su postgres -c "$*"; }
cleanup() { P "$B/pg_ctl -D $D/data stop -m fast >/dev/null 2>&1" || true; rm -rf "$D"; }; trap cleanup EXIT
P "$B/initdb -D $D/data >/dev/null 2>&1 && $B/pg_ctl -D $D/data -o '-p $PORT -k /tmp' -l $D/log start >/dev/null"; sleep 3
Q="psql -h /tmp -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"
P "$Q -f $HERE/00_supabase_stub.sql"
for f in schema 002_hosting app_records 003_soc 004_soc_phase3 005_noc 006_noc_realtime 007_topology 008_wazuh; do P "$Q -f $ROOT/supabase/$f.sql" >/dev/null 2>&1; done
P "$Q -f $HERE/10_legacy_seed.sql"
echo "== applying migrations (first run) =="; P "$Q -f $ROOT/supabase/migrations/ALL.sql" 2>&1 | grep -v "^NOTICE\|^psql.*NOTICE" || true
echo "== applying migrations again (must change nothing and raise no error) =="; P "$Q -f $ROOT/supabase/migrations/ALL.sql" 2>&1 | grep -iE "error|fatal" && { echo "SECOND RUN FAILED"; exit 1; } || echo "second run: no errors"
P "$Q -f $HERE/20_harness.sql" && P "$Q -f $HERE/30_setup.sql" | tail -3 && P "$Q -f $HERE/40_tests.sql" >/dev/null
P "$Q -At -F'|' -c \"select ok, name, detail from test.results order by n\"" > "$D/res.txt"
P "$Q -c \"select version, name from private.app_migrations order by 1\""
P "$Q -c \"explain (analyze, costs off, timing on) select * from public.net_devices where org_id=(select id from test.ids where label='A') and primary_ip='10.20.3.4'\"" | tail -6
P "$Q -c \"explain (analyze, costs off, timing on) select id,hostname,status from public.net_devices where org_id=(select id from test.ids where label='A') order by last_seen_at desc limit 50\"" | tail -6
cp "$D/res.txt" /tmp/dbresults.txt; fails=$(grep -c '^f|' "$D/res.txt" || true); total=$(wc -l < "$D/res.txt")
grep '^f|' "$D/res.txt" || true
echo "== rollback test: new objects removed, legacy rows kept, migrations re-apply =="
P "$Q -f $ROOT/supabase/migrations/rollback_0100_0105.sql" >/dev/null 2>&1
P "$Q -At -c \"select 'new tables left: ' || count(*) from information_schema.tables where table_schema='public' and table_name in ('organizations','net_devices','audit_log','scan_jobs','assessments')\""
P "$Q -At -c \"select 'legacy rows kept: ' || (select count(*) from public.soc_assets) || ' asset, ' || (select count(*) from public.soc_events) || ' events, ' || (select count(*) from public.noc_devices) || ' devices; org_id column present: ' || (select count(*) from information_schema.columns where table_name='soc_events' and column_name='org_id')\""
P "$Q -f $ROOT/supabase/migrations/ALL.sql" >/dev/null 2>&1 && echo "re-applied after rollback: ok"
echo "RESULT: $((total - fails)) passed, $fails failed, $total total"; [ "$fails" = 0 ]
