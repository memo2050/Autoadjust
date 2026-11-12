-- Permission snapshot of everything the hardening touches (read-only). Sorted so two snapshots can be diffed.
select 'table|' || c.relname || '|' || coalesce((select string_agg(x, ',' order by x) from unnest(c.relacl::text[]) x), 'NULL') from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r'
union all
select 'column|' || c.relname || '.' || a.attname || '|' || (select string_agg(x, ',' order by x) from unnest(a.attacl::text[]) x) from pg_attribute a join pg_class c on c.oid=a.attrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' and a.attacl is not null
union all
select 'function|' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')|' || coalesce((select string_agg(x, ',' order by x) from unnest(p.proacl::text[]) x), 'NULL(default)') from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','private')
union all
select 'policy|' || tablename || '.' || policyname || '|' || cmd || '|' || roles::text || '|' || coalesce(qual,'') || '|' || coalesce(with_check,'') from pg_policies where schemaname='public'
order by 1;
