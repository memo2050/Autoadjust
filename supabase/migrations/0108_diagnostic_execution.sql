-- 0108_diagnostic_execution.sql | Phase 5: controlled read-only diagnostics. DEVELOPMENT/STAGING ONLY until the owner authorizes production.
-- Two new tables, both organization-keyed, row security ON, no client access (the service role / application tier is the only writer, like the other noc_* tables).
-- Additive: touches no existing table. Rollback: rollback_0108.sql (drops only these two tables; they hold diagnostic history, so export first if needed).
begin;
create table if not exists public.noc_executors (
  id text primary key, org_id uuid not null references public.organizations(id) on delete restrict,
  host_id text not null, key_id text not null, name text, os text not null check (os in ('linux','windows')), enabled boolean not null default true,
  registered_by text, created_at text, last_poll_at text, last_result_at text);
create unique index if not exists noc_executors_one_enabled_per_host on public.noc_executors (org_id, host_id) where enabled;
create table if not exists public.noc_diag_jobs (
  id text primary key, org_id uuid not null references public.organizations(id) on delete restrict,
  host_id text not null, executor_id text, os text not null, template text not null, tier text not null default 'R0', params jsonb not null default '{}'::jsonb,
  status text not null, dry_run boolean not null default false, requested_by text not null, requested_by_kind text not null, requested_at text not null,
  reason text, incident_id text, evidence_ids jsonb, approved_by text, approved_at text, queued_at text, expires_at text, nonce text not null,
  lease_id text, leased_at text, lease_until text, started_at text, ended_at text, exit_code integer, timed_out boolean, output text, output_sha text,
  truncated boolean, error text, argv_preview text, policy jsonb, note text);
create index if not exists noc_diag_jobs_org_host on public.noc_diag_jobs (org_id, host_id, status);
create index if not exists noc_diag_jobs_org_time on public.noc_diag_jobs (org_id, requested_at);
alter table public.noc_executors enable row level security; alter table public.noc_diag_jobs enable row level security;
revoke all on public.noc_executors, public.noc_diag_jobs from anon, authenticated;
insert into private.app_migrations (version, name) values ('0108', 'diagnostic_execution') on conflict do nothing;
commit;
