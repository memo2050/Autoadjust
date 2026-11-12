#!/usr/bin/env bash
# Builds a local database in the same state as the live Autoadjust project BEFORE hardening:
# Supabase-style roles and default grants + the legacy tables script + migrations 0100-0105 applied one file at a time.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$H/../../.."; PORT=${PGPORT:-5498}; DB=${1:-baseline}
Q() { su postgres -c "psql -h /tmp -p $PORT -X -q -v ON_ERROR_STOP=1 $*"; }
su postgres -c "psql -h /tmp -p $PORT -X -q -d postgres -c 'drop database if exists $DB' -c 'create database $DB'"
# stub creates cluster-wide roles: they already exist on later builds, so run it WITHOUT ON_ERROR_STOP (role errors are harmless)
su postgres -c "psql -h /tmp -p $PORT -X -q -d $DB -f $H/../00_supabase_stub.sql" >/dev/null 2>&1 || true
Q "-d $DB -f $H/01_stub_extra.sql"
Q "-d $DB -f /mnt/user-data/outputs/supabase-all-in-one.sql" >/dev/null
for f in 0100_tenancy 0101_audit_approvals 0102_agents 0103_discovery_topology 0104_assessments_findings 0105_legacy_tables_org; do Q "-d $DB -f $R/supabase/migrations/$f.sql" >/dev/null; done
echo "built $DB"
