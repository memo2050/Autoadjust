-- Two-organization isolation test (v2: 'anon reads projects/versions' accepts either 0 rows or a permission error, so it passes before and after hardening).
-- Live two-organization isolation test. Creates test users/orgs/rows INSIDE one transaction and ALWAYS ends with a deliberate
-- exception, so PostgreSQL rolls everything back. Nothing is persisted. The results are returned in the error text.
do $outer$
declare
  ua uuid := 'aaaaaaaa-0000-4000-8000-00000000000a';  -- owner of org A
  ub uuid := 'bbbbbbbb-0000-4000-8000-00000000000b';  -- owner of org B
  uc uuid := 'cccccccc-0000-4000-8000-00000000000c';  -- noc_operator in org A
  ud uuid := 'dddddddd-0000-4000-8000-00000000000d';  -- executive_readonly in org A
  oa uuid; ob uuid; sa uuid; sb uuid; aa uuid; ab uuid; o uuid; sid uuid; aid uuid; t text;
  tenant text[] := array['approvals','audit_log','net_devices','net_device_interfaces','net_device_services','net_links','net_segments','scan_scopes','scan_jobs','scan_schedules','scan_results','topology_snapshots','topology_changes','assessments','vulnerability_findings','assessment_reports','network_agents','agent_enrollment_tokens','org_invitations','org_members'];
  seeded text[] := array['approvals','audit_log','net_devices','net_segments','scan_scopes','scan_jobs','assessments','vulnerability_findings','network_agents','agent_enrollment_tokens','org_invitations','org_members'];
  summary text;
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
      reset role;
      return v;
    exception when others then
      reset role;
      return 'ERR:'||sqlstate;
    end;
  end $f$;

  create function pg_temp.chk(p_name text, p_uid uuid, p_role text, p_sql text, p_expect text) returns void language plpgsql as $f$
  declare o text := pg_temp.run(p_uid, p_role, p_sql); ok boolean;
  begin
    ok := case p_expect
      when 'blocked' then (o like 'ERR:%' or o in ('0','rows=0'))
      when 'err'     then o like 'ERR:%'
      when 'zero'    then o in ('0','rows=0')
      when 'pos'     then (case when o ~ '^[0-9]+$' then o::bigint > 0 else false end)
      when 'ok'      then o not like 'ERR:%'
      else o = p_expect end;
    insert into res(name, outcome, expect, pass) values (p_name, o, p_expect, coalesce(ok,false));
  end $f$;

  -- ---------- test users (rolled back) ----------
  insert into auth.users (id, instance_id, aud, role, email) values
    (ua,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-a@example.invalid'),
    (ub,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-b@example.invalid'),
    (uc,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-c@example.invalid'),
    (ud,'00000000-0000-0000-0000-000000000000','authenticated','authenticated','iso-d@example.invalid');

  -- organizations are created through the real self-service function, as each user
  oa := pg_temp.run(ua,'authenticated',$q$select public.create_organization('Iso Test A','iso-test-aa')::text$q$)::uuid;
  ob := pg_temp.run(ub,'authenticated',$q$select public.create_organization('Iso Test B','iso-test-bb')::text$q$)::uuid;

  -- seed identical test data in both orgs (as the backend would)
  foreach o in array array[oa, ob] loop
    insert into public.scan_scopes (org_id, name, targets) values (o, 'seed scope', array['192.168.77.0/24']::cidr[]) returning id into sid;
    insert into public.net_devices (org_id, identity_key) values (o, 'seed-dev-'||o::text);
    insert into public.net_segments (org_id, name) values (o, 'seed segment');
    insert into public.approvals (org_id, kind, subject_type, subject_id, summary) values (o, 'scan', 'scope', 'x', 'seed approval');
    insert into public.audit_log (org_id, actor_type, action) values (o, 'system', 'test.seed');
    insert into public.network_agents (org_id, name, credential_hash) values (o, 'seed-agent', 'hash-'||o::text);
    insert into public.agent_enrollment_tokens (org_id, token_hash, token_prefix, label, expires_at) values (o, 'th-'||o::text, 'tok', 'seed', now() + interval '1 day');
    insert into public.org_invitations (org_id, email, role, token_hash, expires_at) values (o, 'x@example.invalid', 'it_admin', 'ih-'||o::text, now() + interval '2 days');
    insert into public.assessments (org_id, name, scope_id) values (o, 'seed assessment', sid) returning id into aid;
    insert into public.vulnerability_findings (org_id, assessment_id, fingerprint, source, title, category, severity, provenance) values (o, aid, 'fp1', 'manual', 'seed finding', 'network', 'low', 'analyst_confirmed');
    insert into public.scan_jobs (org_id, scope_id, kind) values (o, sid, 'discovery');
    if o = oa then sa := sid; aa := aid; else sb := sid; ab := aid; end if;
  end loop;
  insert into public.projects (user_id, name) values (ua, 'A project'), (ub, 'B project');
  insert into public.versions (project_id, prompt, html) select id, 'p', 'h' from public.projects;
  insert into public.sites (slug, project_id, html) select 'iso-site-' || lower(substr(name,1,1)), id, '<p>x</p>' from public.projects;

  -- owner A adds two staff members to org A through the policy path
  perform pg_temp.chk('A owner adds noc_operator to A', ua,'authenticated', format($q$insert into public.org_members(org_id,user_id,role) values (%L,%L,'noc_operator')$q$, oa, uc), 'ok');
  perform pg_temp.chk('A owner adds executive_readonly to A', ua,'authenticated', format($q$insert into public.org_members(org_id,user_id,role) values (%L,%L,'executive_readonly')$q$, oa, ud), 'ok');

  -- ---------- 1. organization A reading organization B (and the reverse) ----------
  perform pg_temp.chk('A sees only its own organization', ua,'authenticated', 'select count(*) from public.organizations', '1');
  perform pg_temp.chk('A reads org B record', ua,'authenticated', format('select count(*) from public.organizations where id=%L', ob), 'blocked');
  perform pg_temp.chk('B reads org A record', ub,'authenticated', format('select count(*) from public.organizations where id=%L', oa), 'blocked');
  foreach t in array tenant loop
    perform pg_temp.chk('A reads B rows in '||t, ua,'authenticated', format('select count(*) from public.%I where org_id=%L', t, ob), 'blocked');
    perform pg_temp.chk('B reads A rows in '||t, ub,'authenticated', format('select count(*) from public.%I where org_id=%L', t, oa), 'blocked');
  end loop;
  foreach t in array seeded loop
    perform pg_temp.chk('CONTROL: A reads its own rows in '||t, ua,'authenticated', format('select count(*) from public.%I where org_id=%L', t, oa), 'pos');
  end loop;

  -- ---------- 2. organization A modifying organization B ----------
  perform pg_temp.chk('A renames org B', ua,'authenticated', format($q$update public.organizations set name='hacked' where id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A adds itself to org B members', ua,'authenticated', format($q$insert into public.org_members(org_id,user_id,role) values (%L,%L,'owner')$q$, ob, ua), 'err');
  perform pg_temp.chk('A changes roles in org B', ua,'authenticated', format($q$update public.org_members set role='executive_readonly' where org_id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A removes members of org B', ua,'authenticated', format('delete from public.org_members where org_id=%L', ob), 'zero');
  perform pg_temp.chk('A inserts scope into B', ua,'authenticated', format($q$insert into public.scan_scopes(org_id,name,targets) values (%L,'evil','{10.0.0.0/24}')$q$, ob), 'err');
  perform pg_temp.chk('A edits scope of B', ua,'authenticated', format($q$update public.scan_scopes set name='evil' where org_id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A inserts approval into B', ua,'authenticated', format($q$insert into public.approvals(org_id,kind,subject_type,subject_id,summary) values (%L,'scan','scope','x','evil approval')$q$, ob), 'err');
  perform pg_temp.chk('A approves a request of B', ua,'authenticated', format($q$update public.approvals set status='approved' where org_id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A creates scan job in B', ua,'authenticated', format($q$insert into public.scan_jobs(org_id,scope_id,kind) values (%L,%L,'discovery')$q$, ob, sb), 'err');
  perform pg_temp.chk('A creates scan job in A using scope of B', ua,'authenticated', format($q$insert into public.scan_jobs(org_id,scope_id,kind) values (%L,%L,'discovery')$q$, oa, sb), 'err');
  perform pg_temp.chk('A edits devices of B', ua,'authenticated', format($q$update public.net_devices set label='evil' where org_id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A inserts segment into B', ua,'authenticated', format($q$insert into public.net_segments(org_id,name) values (%L,'evil')$q$, ob), 'err');
  perform pg_temp.chk('A deletes segments of B', ua,'authenticated', format('delete from public.net_segments where org_id=%L', ob), 'zero');
  perform pg_temp.chk('A moves its own segment into B', ua,'authenticated', format('update public.net_segments set org_id=%L where org_id=%L', ob, oa), 'blocked');
  perform pg_temp.chk('A inserts assessment into B', ua,'authenticated', format($q$insert into public.assessments(org_id,name,scope_id) values (%L,'evil',%L)$q$, ob, sb), 'err');
  perform pg_temp.chk('A edits findings of B', ua,'authenticated', format($q$update public.vulnerability_findings set status='remediated' where org_id=%L$q$, ob), 'zero');
  perform pg_temp.chk('A renames agents of B', ua,'authenticated', format($q$update public.network_agents set name='evil' where org_id=%L$q$, ob), 'zero');

  -- ---------- 3. secrets and privileged functions ----------
  perform pg_temp.chk('A reads invitation token_hash of its own org', ua,'authenticated', 'select count(token_hash) from public.org_invitations', 'ERR:42501');
  perform pg_temp.chk('A reads agent credential_hash of its own org', ua,'authenticated', 'select count(credential_hash) from public.network_agents', 'ERR:42501');
  perform pg_temp.chk('A reads enrollment token_hash of its own org', ua,'authenticated', 'select count(token_hash) from public.agent_enrollment_tokens', 'ERR:42501');
  perform pg_temp.chk('A forges an audit_log entry', ua,'authenticated', format($q$insert into public.audit_log(org_id,actor_type,action) values (%L,'user','forged.entry')$q$, oa), 'ERR:42501');
  perform pg_temp.chk('A calls verify_audit_chain', ua,'authenticated', format('select count(*) from private.verify_audit_chain(%L)', oa), 'ERR:42501');
  perform pg_temp.chk('A calls enroll_agent', ua,'authenticated', $q$select private.enroll_agent('a','b','linux','1','h',null,'c')::text$q$, 'ERR:42501');
  perform pg_temp.chk('A calls claim_next_job', ua,'authenticated', $q$select count(*) from (select private.claim_next_job(gen_random_uuid())) s$q$, 'ERR:42501');
  perform pg_temp.chk('Last owner cannot leave org A', ua,'authenticated', format('delete from public.org_members where org_id=%L and user_id=%L', oa, ua), 'ERR:23514');
  perform pg_temp.chk('Audit log cannot be edited (even by the database owner)', null,'postgres', $q$update public.audit_log set action='tamper'$q$, 'ERR:42501');
  perform pg_temp.chk('Audit chain verifies for org B (backend role)', null,'service_role', format('select ok::text from private.verify_audit_chain(%L)', ob), 'true');

  -- ---------- 4. roles inside one organization ----------
  perform pg_temp.chk('noc_operator reads devices of A', uc,'authenticated', format('select count(*) from public.net_devices where org_id=%L', oa), 'pos');
  perform pg_temp.chk('noc_operator cannot read assessments', uc,'authenticated', format('select count(*) from public.assessments where org_id=%L', oa), 'zero');
  perform pg_temp.chk('noc_operator cannot read findings', uc,'authenticated', format('select count(*) from public.vulnerability_findings where org_id=%L', oa), 'zero');
  perform pg_temp.chk('noc_operator cannot read audit log', uc,'authenticated', format('select count(*) from public.audit_log where org_id=%L', oa), 'zero');
  perform pg_temp.chk('noc_operator cannot authorize a scope', uc,'authenticated', format($q$update public.scan_scopes set authorized=true, attestation='I confirm this is my network and authorized' where org_id=%L$q$, oa), 'zero');
  perform pg_temp.chk('noc_operator can document segments', uc,'authenticated', format($q$insert into public.net_segments(org_id,name) values (%L,'noc segment')$q$, oa), 'ok');
  perform pg_temp.chk('executive_readonly reads assessments', ud,'authenticated', format('select count(*) from public.assessments where org_id=%L', oa), 'pos');
  perform pg_temp.chk('executive_readonly cannot write segments', ud,'authenticated', format($q$insert into public.net_segments(org_id,name) values (%L,'exec segment')$q$, oa), 'err');
  perform pg_temp.chk('executive_readonly cannot edit devices', ud,'authenticated', format($q$update public.net_devices set label='x' where org_id=%L$q$, oa), 'zero');
  perform pg_temp.chk('executive_readonly cannot create approvals', ud,'authenticated', format($q$insert into public.approvals(org_id,kind,subject_type,subject_id,summary) values (%L,'scan','scope','x','exec approval')$q$, oa), 'err');
  perform pg_temp.chk('executive_readonly cannot read audit log', ud,'authenticated', format('select count(*) from public.audit_log where org_id=%L', oa), 'zero');

  -- ---------- 5. anonymous (public API key) ----------
  foreach t in array tenant || array['organizations'] loop
    perform pg_temp.chk('anon reads '||t, null,'anon', format('select count(*) from public.%I', t), 'ERR:42501');
  end loop;
  perform pg_temp.chk('anon creates an organization', null,'anon', $q$select public.create_organization('x','xx-anon')::text$q$, 'ERR:42501');
  perform pg_temp.chk('anon calls increment_usage (inflate a user''s counter)', null,'anon', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ua), 'ERR:42501');
  perform pg_temp.chk('authenticated A calls increment_usage for user B', ua,'authenticated', format('select count(*) from (select public.increment_usage(%L::uuid)) s', ub), 'ERR:42501');

  -- ---------- 6. legacy SOC / NOC / builder tables ----------
  perform pg_temp.chk('A reads soc_events', ua,'authenticated', 'select count(*) from public.soc_events', 'ERR:42501');
  perform pg_temp.chk('anon reads soc_events', null,'anon', 'select count(*) from public.soc_events', 'ERR:42501');
  perform pg_temp.chk('A reads noc_devices', ua,'authenticated', 'select count(*) from public.noc_devices', 'ERR:42501');
  perform pg_temp.chk('anon reads noc_devices', null,'anon', 'select count(*) from public.noc_devices', 'ERR:42501');
  perform pg_temp.chk('anon writes app_records (RLS, no policy)', null,'anon', $q$insert into public.app_records(app_id,collection,data) values ('x','y','{}')$q$, 'ERR:42501');
  perform pg_temp.chk('A writes app_records (RLS, no policy)', ua,'authenticated', $q$insert into public.app_records(app_id,collection,data) values ('x','y','{}')$q$, 'ERR:42501');
  perform pg_temp.chk('anon writes soc_kev (RLS, no policy)', null,'anon', $q$insert into public.soc_kev(id) values ('x')$q$, 'ERR:42501');
  perform pg_temp.chk('A writes soc_meta (RLS, no policy)', ua,'authenticated', $q$insert into public.soc_meta(id) values ('x')$q$, 'ERR:42501');
  perform pg_temp.chk('A reads projects of B', ua,'authenticated', format('select count(*) from public.projects where user_id=%L', ub), 'zero');
  perform pg_temp.chk('CONTROL: A reads own projects', ua,'authenticated', format('select count(*) from public.projects where user_id=%L', ua), 'pos');
  perform pg_temp.chk('A edits project of B', ua,'authenticated', format($q$update public.projects set name='evil' where user_id=%L$q$, ub), 'zero');
  perform pg_temp.chk('A sees only its own versions', ua,'authenticated', 'select count(*) from public.versions', '1');
  perform pg_temp.chk('anon reads projects', null,'anon', 'select count(*) from public.projects', 'blocked');
  perform pg_temp.chk('anon reads versions', null,'anon', 'select count(*) from public.versions', 'blocked');
  perform pg_temp.chk('anon reads published sites (public by design)', null,'anon', 'select count(*) from public.sites', 'pos');
  perform pg_temp.chk('anon edits published sites', null,'anon', $q$update public.sites set html='defaced'$q$, 'blocked');
  perform pg_temp.chk('A edits published site of B', ua,'authenticated', format($q$update public.sites set html='defaced' where project_id in (select id from public.projects where user_id=%L)$q$, ub), 'zero');

  -- ---------- 7. backend (service role) still works ----------
  perform pg_temp.chk('service_role reads all orgs'' approvals', null,'service_role', 'select count(*) from public.approvals', 'pos');
  perform pg_temp.chk('service_role reads soc_events', null,'service_role', 'select count(*) from public.soc_events', '0');
  perform pg_temp.chk('service_role reads app_records', null,'service_role', 'select count(*) from public.app_records', '0');

  select format('ISOLATION_TEST total=%s pass=%s fail=%s', count(*), count(*) filter (where pass), count(*) filter (where not pass)) into summary from res;
  raise exception E'%\n%', summary, (select string_agg(format('%s %s | %s | got=%s want=%s', case when pass then 'PASS' else 'FAIL' end, n, name, outcome, expect), E'\n' order by n) from res)
    using errcode = 'P0001';
end $outer$;
