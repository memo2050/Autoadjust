-- 0105_legacy_tables_org.sql  |  Give the existing soc_* / noc_* tables an organization key WITHOUT changing them or their data.
-- Non-destructive: adds one nullable-safe column with a default. Every existing row (and every row the current application still inserts
-- without knowing about organizations) belongs to the Default organization. Skips any table that does not exist yet.
-- Direct client access is also removed: these tables were already unreachable (row security on, no policies); this makes it explicit.
-- NOT done here (on purpose): NOT NULL, policies, soc_kev (global reference data), soc_meta (per-integration state, its primary key needs an org-aware redesign).
begin;
do $$
declare t text; d constant uuid := '00000000-0000-0000-0000-000000000001';
begin
  foreach t in array array[
    'soc_assets','soc_events','soc_alerts','soc_incidents','soc_vulns','soc_scans','soc_agent_runs','soc_actions','soc_audit','soc_tasks',
    'noc_devices','noc_sources','noc_interfaces','noc_metrics','noc_events','noc_incidents','noc_activities','noc_workflows','noc_approvals',
    'noc_executions','noc_actions','noc_scopes','noc_scans','noc_agents','noc_links','noc_maps','noc_map_versions','noc_changes','noc_backups'] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I add column if not exists org_id uuid default %L references public.organizations(id) on delete restrict', t, d);
      execute format('create index if not exists %I on public.%I (org_id)', t || '_org_idx', t);
      execute format('alter table public.%I enable row level security', t);
      execute format('revoke all on public.%I from anon, authenticated', t);
    end if;
  end loop;
end $$;
insert into private.app_migrations (version, name) values ('0105', 'legacy_tables_org') on conflict do nothing;
commit;
