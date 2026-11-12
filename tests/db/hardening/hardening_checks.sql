-- Hardening checks. Run with:  set test.hardened = 'on';  (expects the hardened state)  -- before hardening, the items hardening fixes FAIL.
-- Everything is created inside one transaction and rolled back by a deliberate exception at the end.
do $outer$
declare
  h boolean := coalesce(nullif(current_setting('test.hardened', true), ''), 'off') = 'on';
  ua uuid := 'aaaaaaaa-0000-4000-8000-00000000000a'; ub uuid := 'bbbbbbbb-0000-4000-8000-00000000000b';
  pa uuid; pb uuid; summary text; e_priv text; e_zero_or_priv text := 'blocked';
begin
  create temp table res(n serial, name text, outcome text, expect text, pass boolean) on commit drop;
  create function pg_temp.run(p_uid uuid, p_role text, p_sql text) returns text language plpgsql as $f$
  declare v text; k bigint;
  begin
    begin
      perform set_config('request.jwt.claim.sub', coalesce(p_uid::text,''), true);
      perform set_config('request.jwt.claims', case when p_uid is null then '' else json_build_object('sub',p_uid,'role',p_role)::text end, true);
      execute format('set local role %I', p_role);
      if lower(left(ltrim(p_sql),6)) = 'select' then execute p_sql into v; v := coalesce(v,'null');
      else execute p_sql; get diagnostics k = row_count; v := 'rows='||k; end if;
      reset role; return v;
    exception when others then reset role; return 'ERR:'||sqlstate; end;
  end $f$;
  create function pg_temp.chk(p_name text, p_uid uuid, p_role text, p_sql text, p_expect text) returns void language plpgsql as $f$
  declare o text := pg_temp.run(p_uid, p_role, p_sql); ok boolean;
  begin
    ok := case p_expect
      when 'blocked' then (o like 'ERR:%' or o in ('0','rows=0')) when 'err' then o like 'ERR:%' when 'zero' then o in ('0','rows=0')
      when 'pos' then (case when o ~ '^[0-9]+$' then o::bigint > 0 else false end) when 'ok' then o not like 'ERR:%' else o = p_expect end;
    insert into res(name, outcome, expect, pass) values (p_name, o, p_expect, coalesce(ok,false));
  end $f$;

  insert into auth.users (id, instance_id, aud, role, email) values
    (ua,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-a@example.invalid'),
    (ub,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-b@example.invalid');
  insert into public.projects (user_id, name) values (ua, 'A project') returning id into pa;
  insert into public.projects (user_id, name) values (ub, 'B project') returning id into pb;
  insert into public.versions (project_id, prompt, html) values (pa, 'p', '<a>'), (pb, 'p', '<b>');
  insert into public.sites (slug, project_id, html, custom_domain) values ('iso-site-a', pa, '<p>A</p>', 'a.example.test'), ('iso-site-b', pb, '<p>B</p>', 'b.example.test');
  insert into public.usage (user_id, generations) values (ua, 1), (ub, 1);

  -- 1. increment_usage
  e_priv := case when h then 'ERR:42501' else 'ok' end;
  perform pg_temp.chk('1 anon calls increment_usage', null,'anon', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ua), case when h then 'ERR:42501' else '1' end);
  perform pg_temp.chk('1 signed-in A calls increment_usage on itself', ua,'authenticated', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ua), case when h then 'ERR:42501' else '1' end);
  perform pg_temp.chk('1 signed-in A calls increment_usage on user B', ua,'authenticated', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ub), case when h then 'ERR:42501' else '1' end);
  perform pg_temp.chk('1 service_role calls increment_usage (backend keeps access)', null,'service_role', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ua), '1');

  -- 2. backend-only tables
  perform pg_temp.chk('2 anon reads app_records', null,'anon', 'select count(*) from public.app_records', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('2 signed-in A reads app_records', ua,'authenticated', 'select count(*) from public.app_records', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('2 anon writes app_records', null,'anon', $q$insert into public.app_records(app_id,collection,data) values ('x','y','{}')$q$, 'ERR:42501');
  perform pg_temp.chk('2 signed-in A writes app_records', ua,'authenticated', $q$insert into public.app_records(app_id,collection,data) values ('x','y','{}')$q$, 'ERR:42501');
  perform pg_temp.chk('2 anon reads soc_kev', null,'anon', 'select count(*) from public.soc_kev', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('2 signed-in A reads soc_meta', ua,'authenticated', 'select count(*) from public.soc_meta', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('2 service_role inserts app_records (data API of generated apps)', null,'service_role', $q$insert into public.app_records(app_id,collection,data) values ('x','y','{}')$q$, 'rows=1');
  perform pg_temp.chk('2 service_role reads app_records', null,'service_role', 'select count(*) from public.app_records', '1');
  perform pg_temp.chk('2 service_role writes soc_kev', null,'service_role', $q$insert into public.soc_kev(id) values ('CVE-0000-0000')$q$, 'rows=1');
  perform pg_temp.chk('2 service_role writes soc_meta', null,'service_role', $q$insert into public.soc_meta(id) values ('kev')$q$, 'rows=1');

  -- 3. builder tables
  perform pg_temp.chk('3 anon reads projects', null,'anon', 'select count(*) from public.projects', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('3 anon reads versions', null,'anon', 'select count(*) from public.versions', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('3 anon reads usage', null,'anon', 'select count(*) from public.usage', case when h then 'ERR:42501' else '0' end);
  perform pg_temp.chk('3 anon creates a project', null,'anon', format($q$insert into public.projects(user_id,name) values (%L,'evil')$q$, ua), 'ERR:42501');
  perform pg_temp.chk('3 A reads own projects', ua,'authenticated', 'select count(*) from public.projects', '1');
  perform pg_temp.chk('3 A reads projects of B', ua,'authenticated', format('select count(*) from public.projects where user_id=%L', ub), 'zero');
  perform pg_temp.chk('3 A renames own project', ua,'authenticated', format($q$update public.projects set name='renamed' where id=%L$q$, pa), 'rows=1');
  perform pg_temp.chk('3 A renames project of B', ua,'authenticated', format($q$update public.projects set name='evil' where id=%L$q$, pb), 'zero');
  perform pg_temp.chk('3 A creates a project for itself', ua,'authenticated', format($q$insert into public.projects(user_id,name) values (%L,'second')$q$, ua), 'rows=1');
  perform pg_temp.chk('3 A creates a project as user B', ua,'authenticated', format($q$insert into public.projects(user_id,name) values (%L,'evil')$q$, ub), 'err');
  perform pg_temp.chk('3 A reads own versions', ua,'authenticated', 'select count(*) from public.versions', '1');
  perform pg_temp.chk('3 A adds a version to own project (generate flow)', ua,'authenticated', format($q$insert into public.versions(project_id,prompt,html) values (%L,'p2','<x>')$q$, pa), 'rows=1');
  perform pg_temp.chk('3 A adds a version to project of B', ua,'authenticated', format($q$insert into public.versions(project_id,prompt,html) values (%L,'p2','<x>')$q$, pb), 'err');
  perform pg_temp.chk('3 A reads own usage', ua,'authenticated', 'select count(*) from public.usage', '1');
  perform pg_temp.chk('3 A reads usage of B', ua,'authenticated', format('select count(*) from public.usage where user_id=%L', ub), 'zero');
  perform pg_temp.chk('3 A writes own usage directly', ua,'authenticated', format('insert into public.usage(user_id,day) values (%L, current_date + 1)', ua), 'err');
  perform pg_temp.chk('3 A deletes project of B', ua,'authenticated', format('delete from public.projects where id=%L', pb), 'zero');

  -- 4. published sites
  perform pg_temp.chk('4 anon serves site by slug (the /serve query)', null,'anon', $q$select html from public.sites where slug='iso-site-a'$q$, '<p>A</p>');
  perform pg_temp.chk('4 anon serves site by custom domain (the /serve query)', null,'anon', $q$select html from public.sites where custom_domain='b.example.test'$q$, '<p>B</p>');
  perform pg_temp.chk('4 anon reads project_id of a site', null,'anon', 'select project_id::text from public.sites limit 1', case when h then 'ERR:42501' else 'ok' end);
  perform pg_temp.chk('4 anon select * on sites', null,'anon', 'select count(*) from (select * from public.sites) s', case when h then 'ERR:42501' else 'ok' end);
  perform pg_temp.chk('4 anon filters sites by project_id', null,'anon', format('select count(*) from public.sites where project_id=%L', pa), case when h then 'ERR:42501' else 'ok' end);
  perform pg_temp.chk('4 anon edits a site', null,'anon', $q$update public.sites set html='defaced'$q$, 'ERR:42501');
  perform pg_temp.chk('4 anon inserts a site', null,'anon', format($q$insert into public.sites(slug,project_id,html) values ('iso-evil',%L,'x')$q$, pa), 'ERR:42501');
  perform pg_temp.chk('4 anon deletes a site', null,'anon', 'delete from public.sites', 'ERR:42501');
  perform pg_temp.chk('4 A sees only its own sites', ua,'authenticated', 'select count(*) from public.sites', case when h then '1' else '2' end);
  perform pg_temp.chk('4 A reads project_id of B''s site', ua,'authenticated', format('select count(*) from public.sites where project_id=%L', pb), case when h then 'zero' else 'ok' end);
  perform pg_temp.chk('4 A publishes own project (the /api/publish upsert)', ua,'authenticated', format($q$insert into public.sites(project_id,slug,html,custom_domain,published_at) values (%L,'iso-site-a2','<p>A2</p>',null,now()) on conflict (project_id) do update set slug=excluded.slug, html=excluded.html, custom_domain=excluded.custom_domain, published_at=excluded.published_at$q$, pa), 'rows=1');
  perform pg_temp.chk('4 A publishes with a name already taken by B', ua,'authenticated', format($q$insert into public.sites(project_id,slug,html) values (%L,'iso-site-b','x') on conflict (project_id) do update set slug=excluded.slug$q$, pa), 'ERR:23505');
  perform pg_temp.chk('4 A publishes B''s project', ua,'authenticated', format($q$insert into public.sites(project_id,slug,html) values (%L,'iso-site-evil','x') on conflict (project_id) do update set html=excluded.html$q$, pb), 'err');
  perform pg_temp.chk('4 A defaces B''s site', ua,'authenticated', $q$update public.sites set html='defaced' where slug='iso-site-b'$q$, 'zero');
  perform pg_temp.chk('4 A deletes B''s site', ua,'authenticated', $q$delete from public.sites where slug='iso-site-b'$q$, 'zero');
  perform pg_temp.chk('4 service_role reads every site', null,'service_role', 'select count(*) from public.sites', '2');
  perform pg_temp.chk('4 data intact: sites keep their project link (owner view)', null,'postgres', 'select count(*) from public.sites where project_id is not null', '2');

  select format('HARDENING_CHECKS mode=%s total=%s pass=%s fail=%s', case when h then 'hardened' else 'baseline' end, count(*), count(*) filter (where pass), count(*) filter (where not pass)) into summary from res;
  raise exception E'%\n%', summary, (select string_agg(format('%s %s | %s | got=%s want=%s', case when pass then 'PASS' else 'FAIL' end, n, name, outcome, expect), E'\n' order by n) from res) using errcode = 'P0001';
end $outer$;
