-- rollback_0100_0105.sql  |  Removes everything migrations 0100-0105 added. Existing tables and their rows are kept.
-- DESTRUCTIVE for the NEW tables only (organizations, members, agents, devices, scans, findings, audit_log, approvals ...): their data is deleted.
-- audit_log is append-only by design, so the rollback lifts that protection for the duration of the drop (it drops the tables themselves).
-- Run it only if you have not yet stored real organization data you want to keep.
begin;
do $$
declare t text;
begin
  foreach t in array array['soc_assets','soc_events','soc_alerts','soc_incidents','soc_vulns','soc_scans','soc_agent_runs','soc_actions','soc_audit','soc_tasks',
    'noc_devices','noc_sources','noc_interfaces','noc_metrics','noc_events','noc_incidents','noc_activities','noc_workflows','noc_approvals','noc_executions',
    'noc_actions','noc_scopes','noc_scans','noc_agents','noc_links','noc_maps','noc_map_versions','noc_changes','noc_backups'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop index if exists public.%I', t || '_org_idx');
      execute format('alter table public.%I drop column if exists org_id', t);
    end if;
  end loop;
end $$;
drop table if exists public.assessment_reports, public.vulnerability_findings, public.assessments,
  public.topology_changes, public.topology_snapshots, public.scan_results, public.net_segments, public.net_links, public.net_device_services,
  public.net_device_interfaces, public.net_devices, public.scan_schedules, public.scan_jobs, public.scan_scopes,
  public.agent_enrollment_tokens, public.network_agents, public.approvals, public.audit_log,
  public.org_invitations, public.org_members, public.organizations cascade;
drop function if exists public.create_organization(text, text);
drop schema if exists private cascade;
commit;
