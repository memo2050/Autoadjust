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
