-- Spark NOC topology and discovery (phase 6). Run once in the Supabase SQL editor AFTER 006. Safe to run twice.
alter table noc_devices add column if not exists mac text, add column if not exists vendor text, add column if not exists sys_descr text,
  add column if not exists discovered jsonb, add column if not exists approved boolean, add column if not exists approved_by text;
create table if not exists noc_scopes (id text primary key, name text, targets jsonb, size int, authorized boolean, authorized_by text, authorized_at text, note text, created_at text);
create table if not exists noc_scans (id text primary key, scope_id text, scope_name text, status text, options jsonb, total int, done int, found int, rejected int,
  message text, error text, agent_id text, started_by text, created_at text, started_at text, last_beat_at text, ended_at text);
create table if not exists noc_agents (id text primary key, name text, role text, last_seen_at text);
create table if not exists noc_links (id text primary key, a text, b text, a_port text, b_port text, proto text, source text, first_seen text, last_seen text, speed_mbps double precision);
create table if not exists noc_maps (id text primary key, name text, env text, description text, version int, doc jsonb, updated_by text, updated_at text, created_at text);
create table if not exists noc_map_versions (id text primary key, map_id text, version int, doc jsonb, by text, at text, note text);
create index if not exists noc_map_versions_map on noc_map_versions (map_id, version);
create table if not exists noc_changes (id text primary key, device_id text, device_name text, title text, description text, proposed text, proposed_raw text, baseline text, diff jsonb,
  risk text, status text, rollback_of text, backup_id text, requested_by text, decided_by text, decided_at text, note text, result jsonb, created_at text, updated_at text);
create table if not exists noc_backups (id text primary key, device_id text, at text, by text, config text, raw text, sha text, change_id text);
create index if not exists noc_backups_dev on noc_backups (device_id, at);
-- Row level security on, no policies: only the backend's service role key can read or write.
-- noc_changes.proposed_raw and noc_backups.raw are AES-256-GCM encrypted with NOC_SECRET_KEY before storage; the displayed copies have secret lines redacted.
do $$ declare t text; begin foreach t in array array['noc_scopes','noc_scans','noc_agents','noc_links','noc_maps','noc_map_versions','noc_changes','noc_backups'] loop
  execute format('alter table %I enable row level security', t); end loop; end $$;
