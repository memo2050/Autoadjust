#!/usr/bin/env bash
# usage: run_http.sh baseline|hardened   -> fresh DB, seed, (apply hardening), local PostgREST, 47 HTTP tests
set -u; H="$(cd "$(dirname "$0")" && pwd)"; MODE=$1
"$H/build_baseline.sh" dp >/dev/null 2>&1
su postgres -c "psql -h /tmp -p 5498 -d dp -X -q -v ON_ERROR_STOP=1 -f /tmp/seed.sql"
[ "$MODE" = hardened ] && su postgres -c "psql -h /tmp -p 5498 -d dp -X -q -v ON_ERROR_STOP=1 -f $H/hardening.sql"
(su postgres -c "/tmp/pgrst/postgrest $H/http_pgrst.conf" > /tmp/pgrst/log_$MODE.txt 2>&1 &); sleep 3
python3 "$H/http_tests.py"
pkill -f "postgrest $H/http_pgrst.conf"; sleep 1
