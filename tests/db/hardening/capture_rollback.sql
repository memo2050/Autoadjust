-- READ-ONLY. Run this BEFORE hardening.sql. It prints the exact statements that restore the current permissions and the sites policy.
-- Copy every row of the result column into a safe place (a text file). Nothing is changed by running it.
select stmt as rollback_statements from (
  select 0 ord, 'begin;' stmt
  union all
  select 1, format('revoke all on table %s from public, anon, authenticated, service_role;', 'public.' || quote_ident(c.relname))
    from pg_class c where c.oid = any (array['public.app_records','public.soc_kev','public.soc_meta','public.projects','public.versions','public.usage','public.sites']::regclass[])
  union all
  select 2, format('grant %s on table %s to %s;', string_agg(x.privilege_type, ', ' order by x.privilege_type), 'public.' || quote_ident(c.relname),
                   case when x.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(x.grantee)) end)
    from pg_class c, lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x
   where c.oid = any (array['public.app_records','public.soc_kev','public.soc_meta','public.projects','public.versions','public.usage','public.sites']::regclass[]) and x.grantee <> c.relowner
   group by c.relname, x.grantee
  union all
  select 3, format('revoke all (%s) on table public.sites from public, anon, authenticated, service_role;', string_agg(quote_ident(a.attname), ', '))
    from pg_attribute a where a.attrelid = 'public.sites'::regclass and a.attnum > 0 and not a.attisdropped
  union all
  select 4, format('grant %s (%s) on table public.sites to %s;', x.privilege_type, quote_ident(a.attname), case when x.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(x.grantee)) end)
    from pg_attribute a, lateral aclexplode(a.attacl) x where a.attrelid = 'public.sites'::regclass and a.attacl is not null
  union all
  select 5, format('revoke all on function public.%s from public, anon, authenticated, service_role;', p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')')
    from pg_proc p where p.oid = 'public.increment_usage(uuid)'::regprocedure
  union all
  select 6, format('grant %s on function public.%s to %s;', string_agg(x.privilege_type, ', '), p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', case when x.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(x.grantee)) end)
    from pg_proc p, lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x
   where p.oid = 'public.increment_usage(uuid)'::regprocedure and x.grantee <> p.proowner
   group by p.oid, p.proname, x.grantee
  union all
  select 7, format('drop policy if exists %I on public.sites;', policyname) from pg_policies where schemaname = 'public' and tablename = 'sites'
  union all
  select 8, format('create policy %I on public.sites as %s for %s to %s%s%s;', policyname, lower(permissive), lower(cmd), array_to_string(roles, ', '),
                   case when qual is not null then ' using (' || qual || ')' else '' end, case when with_check is not null then ' with check (' || with_check || ')' else '' end)
    from pg_policies where schemaname = 'public' and tablename = 'sites'
  union all
  select 9, 'commit;'
) s order by ord, stmt;
