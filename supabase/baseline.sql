-- baseline.sql: the base schema that migrations 0100+ build on (for a NEW, EMPTY staging project only). Concatenation of schema.sql, 002_hosting.sql, app_records.sql, 003..008.

-- ===== schema.sql =====
-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
create table projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  name text not null,
  site_url text,
  created_at timestamptz default now()
);
create table versions (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references projects on delete cascade not null,
  prompt text not null,
  html text not null,
  created_at timestamptz default now()
);
create table usage (
  user_id uuid references auth.users not null,
  day date default current_date,
  generations int default 0,
  primary key (user_id, day)
);
alter table projects enable row level security;
alter table versions enable row level security;
alter table usage enable row level security;
create policy own_projects on projects for all using (user_id = auth.uid());
create policy own_versions on versions for all using (
  project_id in (select id from projects where user_id = auth.uid()));
create policy own_usage on usage for select using (user_id = auth.uid());
create function increment_usage(uid uuid) returns void language sql security definer as $$
  insert into usage (user_id, day, generations) values (uid, current_date, 1)
  on conflict (user_id, day) do update set generations = usage.generations + 1;
$$;

-- ===== 002_hosting.sql =====
-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
-- Hosting: published sites served by this app (subdomains + custom domains)
create table sites (
  slug text primary key check (slug ~ '^[a-z0-9-]{3,40}$'),
  project_id uuid references projects on delete cascade not null unique,
  html text not null,
  custom_domain text unique,
  published_at timestamptz default now()
);
alter table sites enable row level security;
create policy sites_public_read on sites for select using (true);
create policy sites_owner_write on sites for all using (
  project_id in (select id from projects where user_id = auth.uid()))
  with check (project_id in (select id from projects where user_id = auth.uid()));

-- ===== app_records.sql =====
-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
-- Built-in database for generated apps (run once in the Supabase SQL editor)
create table if not exists app_records (
  id uuid primary key default gen_random_uuid(),
  app_id text not null,
  collection text not null,
  data jsonb not null,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index if not exists app_records_lookup on app_records (app_id, collection, created_at desc);
alter table app_records enable row level security; -- no policies: only the server (service role) can read/write

-- ===== 003_soc.sql =====
-- Spark SOC module schema. Run once in the Supabase SQL editor.
-- All access goes through the server (service role key). RLS is enabled with NO policies, so the public anon key can read nothing.
-- Timestamps are ISO-8601 text (UTC) on purpose: they sort and compare correctly and round-trip exactly with the app.

create table if not exists soc_assets (
  id text primary key, hostname text not null, ips jsonb default '[]', os text, criticality int default 3,
  authorized boolean default false, authorized_by text, authorized_at text, authorization_note text,
  source text not null, first_seen text, last_seen text, last_event_at text
);
create table if not exists soc_events (
  id text primary key, source text not null, collector text, asset_id text not null, host text, "time" text not null,
  channel text, provider text, event_id int not null, record_id bigint, level text, "user" text, target_user text, domain text,
  src_ip text, src_host text, logon_type int, process text, parent_process text, command_line text, summary text,
  data jsonb default '{}', fingerprint text, ingested_at text
);
create index if not exists soc_events_asset_time on soc_events (asset_id, "time");
create index if not exists soc_events_time on soc_events ("time" desc);
create table if not exists soc_alerts (
  id text primary key, source text not null, rule_id text not null, key text not null, title text, severity text, confidence float8,
  mitre jsonb default '[]', asset_id text not null, host text, event_ids jsonb default '[]', first_seen text, last_seen text,
  reasoning text, entities jsonb default '{}', incident_id text, created_at text
);
create index if not exists soc_alerts_asset on soc_alerts (asset_id, last_seen desc);
create table if not exists soc_incidents (
  id text primary key, source text not null, title text, severity text, confidence float8, status text not null, asset_id text not null, host text,
  alert_ids jsonb default '[]', tactics jsonb default '[]', first_seen text, last_seen text, reasoning text, status_changed_at text, remediated_at text,
  verification jsonb, closed_without_verification boolean, recurrence_of text, created_at text, updated_at text
);
create index if not exists soc_incidents_asset on soc_incidents (asset_id, last_seen desc);
create table if not exists soc_vulns (
  id text primary key, source text not null, asset_id text not null, host text, port text, oid text, name text, cvss float8, severity text,
  cves jsonb default '[]', qod float8, summary text, solution text, solution_type text, status text not null, first_seen text, last_seen text,
  scan_id text, priority int, priority_reasons jsonb default '[]', kev boolean default false, note text, fixed_at text, updated_at text
);
create index if not exists soc_vulns_asset on soc_vulns (asset_id);
create table if not exists soc_scans (
  id text primary key, source text not null, format text, filename text, scan_time text, imported_at text, imported_by text, hosts jsonb default '[]',
  findings int, log_results_skipped int, new_findings int, fixed_verified int, reappeared int
);
create table if not exists soc_agent_runs (
  id text primary key, agent text not null, target text, actor text, model text, prompt_hash text, evidence_ids jsonb default '[]', status text not null,
  summary text, output jsonb, invalid_evidence_ids jsonb default '[]', error text, usage jsonb, created_at text, source text
);
create table if not exists soc_actions (
  id text primary key, source text, incident_id text, type text not null, target text, description text, rationale text, proposed_by text,
  status text not null, requires_approval boolean default true, decided_by text, decided_at text, decision_note text, created_at text
);
create table if not exists soc_audit (
  id text primary key, "time" text not null, actor text, role text, action text not null, target text, detail jsonb default '{}'
);
create index if not exists soc_audit_target on soc_audit (target);
create index if not exists soc_audit_time on soc_audit ("time" desc);
create table if not exists soc_kev (id text primary key);
create table if not exists soc_meta (id text primary key, imported_at text, count int, catalog_version text);

alter table soc_assets enable row level security;  alter table soc_events enable row level security;
alter table soc_alerts enable row level security;  alter table soc_incidents enable row level security;
alter table soc_vulns enable row level security;   alter table soc_scans enable row level security;
alter table soc_agent_runs enable row level security; alter table soc_actions enable row level security;
alter table soc_audit enable row level security;   alter table soc_kev enable row level security;
alter table soc_meta enable row level security;

-- ===== 004_soc_phase3.sql =====
-- Spark SOC phase 3. Run once in the Supabase SQL editor AFTER 003_soc.sql. Safe to run twice.
alter table soc_assets   add column if not exists last_contact_at text, add column if not exists collector text, add column if not exists collector_version text, add column if not exists last_batch int;
alter table soc_events   add column if not exists severity text;
alter table soc_incidents add column if not exists owner text;
alter table soc_audit    add column if not exists seq int, add column if not exists prev_hash text, add column if not exists hash text;
create index if not exists soc_events_ingested on soc_events (ingested_at);
-- Audit hash chain: each record has the next position in the chain; two writers cannot take the same position.
create unique index if not exists soc_audit_seq on soc_audit (seq) where seq is not null;
-- Immutable audit records: even the service role cannot change or delete them (drop these triggers deliberately to purge).
create or replace function soc_audit_immutable() returns trigger language plpgsql as $$ begin raise exception 'soc_audit is append-only'; end $$;
drop trigger if exists soc_audit_no_update on soc_audit; create trigger soc_audit_no_update before update on soc_audit for each row execute function soc_audit_immutable();
drop trigger if exists soc_audit_no_delete on soc_audit; create trigger soc_audit_no_delete before delete on soc_audit for each row execute function soc_audit_immutable();
-- Agent task runs with measured steps.
create table if not exists soc_tasks (
  id text primary key, role text not null, task text, actor text, status text not null, steps jsonb default '[]', steps_done int default 0, steps_total int default 0,
  progress int default 0, state jsonb default '{}', result jsonb, error text, context jsonb, retry_of text, investigation_id text, source text,
  created_at text, started_at text, ended_at text
);
create index if not exists soc_tasks_created on soc_tasks (created_at desc);
alter table soc_tasks enable row level security;

-- ===== 005_noc.sql =====
-- Spark NOC telemetry (phase 4). Run once in the Supabase SQL editor after 004. Safe to run twice.
create table if not exists noc_devices (
  id text primary key, name text, type text not null, ip text, source text default 'live', up boolean default true,
  metrics jsonb default '{}', links jsonb default '[]', config jsonb, history jsonb default '[]', received_at text, collector text
);
alter table noc_devices enable row level security;

-- ===== 006_noc_realtime.sql =====
-- Spark NOC real-time (phase 5). Run once in the Supabase SQL editor AFTER 005. Safe to run twice.
alter table noc_devices add column if not exists source_id text, add column if not exists host_id text, add column if not exists hostname text,
  add column if not exists uptime_sec double precision, add column if not exists known boolean, add column if not exists unsupported jsonb, add column if not exists item_errors jsonb, add column if not exists groups jsonb;

create table if not exists noc_sources (id text primary key, name text, type text, url text, mode text, enabled boolean, status text, detail text, version text,
  secret text, has_secret boolean, verify_tls boolean, stale_after_sec int, last_sync_at text, last_event_at text, last_test_at text, last_error_at text,
  device_count int, interface_count int, disconnected_at text, created_by text, created_at text, updated_at text);
create table if not exists noc_interfaces (id text primary key, device_id text, source_id text, name text, description text, up boolean, in_bps double precision, out_bps double precision,
  speed_bps double precision, util_pct double precision, errors_in double precision, errors_out double precision, drops_in double precision, drops_out double precision, updated_at text);
create table if not exists noc_metrics (id text primary key, device_id text, source_id text, key text, value double precision, t text);
create index if not exists noc_metrics_dev_t on noc_metrics (device_id, t);
create table if not exists noc_events (id text primary key, source_id text, external_id text, device_id text, host text, severity text, title text, detail text, status text,
  time text, received_at text, resolved_at text, incident_id text, origin text);
create table if not exists noc_incidents (id text primary key, title text, severity text, status text, device_id text, host text, source_id text, event_ids jsonb, external_id text,
  assigned_agent text, category text, analysis jsonb, root_cause jsonb, recommendations jsonb, approval_ids jsonb, execution_ids jsonb, verification jsonb, workflow_id text,
  owner text, created_at text, updated_at text, resolved_at text, source text);
create table if not exists noc_activities (id text primary key, agent text, task text, incident_id text, status text, steps jsonb, result jsonb, error text, actor text, started_at text, ended_at text, created_at text);
create table if not exists noc_workflows (id text primary key, incident_id text, status text, steps jsonb, created_at text, updated_at text);
create table if not exists noc_approvals (id text primary key, incident_id text, action_id text, type text, target text, host_id text, description text, risk jsonb, evidence jsonb,
  status text, proposed_by text, decided_by text, decided_at text, note text, execution_id text, created_at text);
create table if not exists noc_executions (id text primary key, approval_id text, incident_id text, action_id text, kind text, source_id text, script_id text, host_id text, target text,
  mode text, status text, response text, error text, requested_by text, started_at text, ended_at text, verification jsonb, created_at text);
create table if not exists noc_actions (id text primary key, name text, description text, kind text, source_id text, script_id text, webhook_url text, applies_to_types jsonb,
  match text, risk text, enabled boolean, created_by text, created_at text);
-- Row level security on, no policies: only the backend's service role key can read or write. Secrets are encrypted before they reach the database.
do $$ declare t text; begin foreach t in array array['noc_sources','noc_interfaces','noc_metrics','noc_events','noc_incidents','noc_activities','noc_workflows','noc_approvals','noc_executions','noc_actions'] loop
  execute format('alter table %I enable row level security', t); end loop; end $$;

-- ===== 007_topology.sql =====
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

-- ===== 008_wazuh.sql =====
-- Spark Wazuh integration. Run once in the Supabase SQL editor AFTER 007. Safe to run twice.
alter table soc_assets add column if not exists agent_id text, add column if not exists agent_status text, add column if not exists agent_version text,
  add column if not exists agent_synced_at text, add column if not exists wazuh_groups jsonb, add column if not exists last_contact_at text,
  add column if not exists collector text, add column if not exists collector_version text, add column if not exists last_batch int;
-- Sync state (cursor, last success/error, last connection test) is stored as JSON in soc_meta.
alter table soc_meta add column if not exists data jsonb;
