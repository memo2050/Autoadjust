-- READ-ONLY inspection of the current Supabase database. Changes nothing. Run it in the SQL Editor and send the result of each block.
-- 1. Version and extensions
select version() as postgres, (select string_agg(extname, ', ' order by extname) from pg_extension) as extensions;

-- 2. Tables in public: row security, policies, estimated rows, size
select c.relname as table_name, c.relrowsecurity as rls_on,
       (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname) as policies,
       c.reltuples::bigint as est_rows, pg_size_pretty(pg_total_relation_size(c.oid)) as size
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r','p') order by c.relname;

-- 3. Names the new migrations will create: any that already exist (a clash would show here)
select n.nspname as schema, c.relname as name, c.relkind
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname in ('public','private') and c.relname in (
  'organizations','org_members','org_invitations','audit_log','approvals','network_agents','agent_enrollment_tokens','scan_scopes','scan_jobs',
  'scan_schedules','net_devices','net_device_interfaces','net_device_services','net_links','net_segments','scan_results','topology_snapshots',
  'topology_changes','assessments','vulnerability_findings','assessment_reports','app_migrations');

-- 4. Functions that exist in public (create_organization must not clash)
select p.proname, pg_get_function_identity_arguments(p.oid) as args from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('public','private') order by 1;

-- 5. Roles the migration needs
select rolname, rolbypassrls from pg_roles where rolname in ('anon','authenticated','service_role') order by 1;

-- 6. Existing policies
select tablename, policyname, cmd, roles from pg_policies where schemaname = 'public' order by 1, 2;
