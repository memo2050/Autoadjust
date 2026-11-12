#!/usr/bin/env bash
# Rebuilds a Supabase-like local database (migrations 0100-0108 + hardening), starts PostgREST and runs the real-database dashboard test.
set -u; D="$(cd "$(dirname "$0")/../.." && pwd)"; H=/home/claude/work/spark/tests/db/hardening
pkill -f "postgrest /tmp/persist"; sleep 1
"$H/build_baseline.sh" t4 >/dev/null 2>&1
Q() { su postgres -c "psql -h /tmp -p 5498 -X -q -v ON_ERROR_STOP=1 -d t4 $*"; }
Q "-f $D/supabase/migrations/0106_org_api_keys.sql -f $D/supabase/migrations/0107_audit_seq_per_org.sql -f $D/supabase/migrations/0108_diagnostic_execution.sql -f $H/hardening.sql" >/dev/null
Q "-c \"insert into auth.users(id,email) select ('00000000-0000-4000-8000-'||lpad(g::text,12,'0'))::uuid,'u'||g||'@example.com' from generate_series(1,9) g\"" >/dev/null
pkill -f "postgrest /tmp/persist" ; pkill -f "node proxy.js"; sleep 1
sed 's#/h1?#/t4?#' /tmp/persist/pg.conf > /tmp/persist/pg4.conf
(cd /tmp/persist && setsid su postgres -c "/tmp/pgrst/postgrest /tmp/persist/pg4.conf" >/tmp/persist/pg4.log 2>&1 &); (cd /tmp/persist && setsid node proxy.js >/dev/null 2>&1 &); sleep 3
cd "$D" && tsx tests/db/dashboard_e2e.ts; rc=$?
pkill -f "postgrest /tmp/persist"; pkill -f "node proxy.js"; exit $rc
