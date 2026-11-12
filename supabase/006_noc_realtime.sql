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
