\set ON_ERROR_STOP on
\set oa '''11111111-1111-1111-1111-111111111111'''
\set ad '''11111111-1111-1111-1111-111111111112'''
\set noc '''11111111-1111-1111-1111-111111111113'''
\set sec '''11111111-1111-1111-1111-111111111114'''
\set exe '''11111111-1111-1111-1111-111111111115'''
\set ob '''22222222-2222-2222-2222-222222222221'''
\set out '''33333333-3333-3333-3333-333333333331'''
\set AUTH '''authenticated'''

-- ===== 1. Tenant isolation: organization B must see nothing of organization A, in every tenant table =====
select test.run('A reads its own '||t, :oa, 'authenticated', format('select 1 from public.%I where org_id = ''{A}'' limit 1', t), 'ok', 1)
from unnest(array['org_members','network_agents','scan_scopes','net_devices','assessments','vulnerability_findings','approvals','audit_log']) t;
select test.run('B cannot read A '||t, :ob, 'authenticated', format('select 1 from public.%I where org_id = ''{A}''', t), 'ok', 0)
from unnest(array['org_members','network_agents','agent_enrollment_tokens','scan_scopes','scan_jobs','net_devices','net_links','assessments','vulnerability_findings','approvals','audit_log','scan_results','topology_changes']) t;
select test.run('B cannot read organization A row', :ob, 'authenticated', $q$select 1 from public.organizations where id = '{A}'$q$, 'ok', 0);
select test.run('B cannot rename organization A', :ob, 'authenticated', $q$update public.organizations set name = 'hacked' where id = '{A}'$q$, 'ok', 0);
select test.run('B cannot add itself to A', :ob, 'authenticated', $q$insert into public.org_members (org_id,user_id,role) values ('{A}', '22222222-2222-2222-2222-222222222221', 'owner')$q$, 'error');
select test.run('B cannot insert a scope into A', :ob, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.1.0.0/24}')$q$, 'error');
select test.run('B cannot edit an A device label', :ob, 'authenticated', $q$update public.net_devices set label='x' where id = '{DEV_A1}'$q$, 'ok', 0);
select test.run('user with no organization sees no organizations', :out, 'authenticated', 'select 1 from public.organizations', 'ok', 0);
select test.run('anonymous role cannot read organizations', null, 'anon', 'select 1 from public.organizations', 'error');
select test.run('anonymous role cannot read devices', null, 'anon', 'select 1 from public.net_devices', 'error');
select test.run('anonymous role cannot create an organization', null, 'anon', $q$select public.create_organization('Anon org','anon-org')$q$, 'error');

-- ===== 2. Roles =====
select test.run('noc_operator cannot read assessments', :noc, 'authenticated', $q$select 1 from public.assessments where org_id='{A}'$q$, 'ok', 0);
select test.run('noc_operator cannot read findings', :noc, 'authenticated', $q$select 1 from public.vulnerability_findings where org_id='{A}'$q$, 'ok', 0);
select test.run('security_analyst reads assessments', :sec, 'authenticated', $q$select 1 from public.assessments where org_id='{A}'$q$, 'ok', 1);
select test.run('executive reads assessments', :exe, 'authenticated', $q$select 1 from public.assessments where org_id='{A}'$q$, 'ok', 1);
select test.run('executive reads devices', :exe, 'authenticated', $q$select 1 from public.net_devices where org_id='{A}'$q$, 'ok', 2);
select test.run('executive cannot read the audit log', :exe, 'authenticated', $q$select 1 from public.audit_log where org_id='{A}'$q$, 'ok', 0);
select test.run('noc_operator cannot read the audit log', :noc, 'authenticated', $q$select 1 from public.audit_log where org_id='{A}'$q$, 'ok', 0);
select test.run('security_analyst reads the audit log', :sec, 'authenticated', $q$select 1 from public.audit_log where org_id='{A}'$q$, 'ok', (select count(*)::int from public.audit_log where org_id=(select id from test.ids where label='A')));
select test.run('noc_operator documents a device', :noc, 'authenticated', $q$update public.net_devices set label='Core switch', criticality='critical' where id='{DEV_A1}'$q$, 'ok', 1);
select test.run('executive cannot document a device', :exe, 'authenticated', $q$update public.net_devices set label='x' where id='{DEV_A1}'$q$, 'ok', 0);
select test.run('nobody can rewrite discovered facts (vendor)', :ad, 'authenticated', $q$update public.net_devices set vendor='Fake', vendor_confidence='confirmed' where id='{DEV_A1}'$q$, 'error');
select test.run('nobody can delete a device through the API', :oa, 'authenticated', $q$delete from public.net_devices where id='{DEV_A1}'$q$, 'error');
select test.run('only owners change members', :ad, 'authenticated', $q$update public.org_members set role='owner' where user_id='11111111-1111-1111-1111-111111111113'$q$, 'ok', 0);
select test.run('owner can change a role', :oa, 'authenticated', $q$update public.org_members set role='it_admin' where user_id='11111111-1111-1111-1111-111111111113'$q$, 'ok', 1);
select test.run('invitation token hash is unreadable', :oa, 'authenticated', 'select token_hash from public.org_invitations', 'error');
select test.run('invitations are listable by administrators (no hash)', :oa, 'authenticated', 'select id, email, role from public.org_invitations', 'ok');

-- ===== 3. Internal-only scan scopes, enforced by the database =====
select test.run('it_admin creates a private scope', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Branch','{10.5.0.0/24,192.168.1.0/24}')$q$, 'ok', 1);
select test.run('public range is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Pub','{8.8.8.0/24}')$q$, 'error');
select test.run('a mix with one public range is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Mix','{10.5.0.0/24,1.1.1.0/24}')$q$, 'error');
select test.run('172.32.0.0/16 (outside 172.16/12) is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{172.32.0.0/16}')$q$, 'error');
select test.run('100.64.0.0/16 (carrier NAT) is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{100.64.0.0/16}')$q$, 'error');
select test.run('10.0.0.0/8 (too broad) is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.0.0.0/8}')$q$, 'error');
select test.run('172.16.0.0/16 is accepted', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{172.16.0.0/16}')$q$, 'ok', 1);
select test.run('single host /32 is accepted', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.0.0.9/32}')$q$, 'ok', 1);
select test.run('private IPv6 /112 is accepted', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{fd00::/112}')$q$, 'ok', 1);
select test.run('public IPv6 is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{2001:db8::/112}')$q$, 'error');
select test.run('empty target list is rejected', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{}')$q$, 'error');
select test.run('external kind does not exist yet', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,kind,targets) values ('{A}','Test scope','external','{10.5.0.0/24}')$q$, 'error');
select test.run('authorizing without an attestation fails', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets,authorized) values ('{A}','Test scope','{10.5.0.0/24}',true)$q$, 'error');
select test.run('authorizing with an attestation works', :ad, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets,authorized,attestation) values ('{A}','Test scope','{10.5.0.0/24}',true,'I am authorized to scan this network')$q$, 'ok', 1);
select test.run('authorized_by is stamped from the signed-in user', :ad, 'authenticated',
  $q$do $d$ declare b uuid; begin insert into public.scan_scopes (org_id,name,targets,authorized,attestation,authorized_by) values ('{A}','Test scope','{10.5.0.0/24}',true,'I am authorized to scan this network','11111111-1111-1111-1111-111111111111') returning authorized_by into b; if b <> '11111111-1111-1111-1111-111111111112' then raise exception 'wrong authorized_by %', b; end if; end $d$$q$, 'ok');
select test.run('noc_operator cannot create scopes', :noc, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.5.0.0/24}')$q$, 'error');
select test.run('security_analyst cannot create scopes', :sec, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.5.0.0/24}')$q$, 'error');
select test.run('executive cannot create scopes', :exe, 'authenticated', $q$insert into public.scan_scopes (org_id,name,targets) values ('{A}','Test scope','{10.5.0.0/24}')$q$, 'error');

-- ===== 4. Scan jobs: no job without an authorized scope; probing jobs need an approved approval =====
select test.run('operator queues discovery on an authorized scope', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','discovery','queued')$q$, 'ok', 1);
select test.run('discovery on an unauthorized scope is refused', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A2}','discovery','queued')$q$, 'error');
select test.run('a job cannot start already running', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','discovery','running')$q$, 'error');
select test.run('operator cannot request a vulnerability assessment job', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','vuln_assessment','pending_approval')$q$, 'error');
select test.run('analyst: vuln job queued without approval is refused', :sec, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','vuln_assessment','queued')$q$, 'error');
select test.run('analyst: vuln job waits as pending_approval', :sec, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','vuln_assessment','pending_approval')$q$, 'ok', 1);
select test.run('analyst: vuln job queued with an approved approval', :sec, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status,approval_id) values ('{A}','{SCOPE_A}','vuln_assessment','queued','{APPR_OK}')$q$, 'ok', 1);
select test.run('pending (not approved) approval does not unlock a job', :sec, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status,approval_id) values ('{A}','{SCOPE_A}','vuln_assessment','queued','{APPR_PEND}')$q$, 'error');
select test.run('approval of another organization does not unlock a job', :sec, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status,approval_id) select '{A}','{SCOPE_A}','vuln_assessment','queued',id from public.approvals where org_id = '{B}'$q$, 'ok', 0);
select test.run('job pointing at another organization''s scope is refused', null, 'service_role', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_B}','discovery','queued')$q$, 'error');
select test.run('job with another organization''s agent is refused', null, 'service_role', $q$insert into public.scan_jobs (org_id,scope_id,agent_id,kind,status) values ('{A}','{SCOPE_A}','{AG_B}','discovery','queued')$q$, 'error');
select test.run('executive cannot queue jobs', :exe, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status) values ('{A}','{SCOPE_A}','discovery','queued')$q$, 'error');
select test.run('methods outside the safe list are refused', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status,methods) values ('{A}','{SCOPE_A}','discovery','queued','{exploit}')$q$, 'error');
select test.run('profile "destructive" does not exist', :noc, 'authenticated', $q$insert into public.scan_jobs (org_id,scope_id,kind,status,profile) values ('{A}','{SCOPE_A}','discovery','queued','destructive')$q$, 'error');

-- withdrawing authorization stops queued jobs (persisted: checked below)
do $$ declare a uuid := (select id from test.ids where label='A'); s uuid; j1 uuid; j2 uuid; st1 text; cr2 boolean; begin
  insert into public.scan_scopes (org_id,name,targets,authorized,authorized_at,attestation) values (a,'Temp','{10.77.0.0/24}',true,now(),'I am authorized to scan the temp network') returning id into s;
  insert into public.scan_jobs (org_id,scope_id,kind,status) values (a,s,'discovery','queued') returning id into j1;
  insert into public.scan_jobs (org_id,scope_id,kind,status) values (a,s,'discovery','queued') returning id into j2;
  update public.scan_jobs set status='running', started_at=now() where id=j2;
  update public.scan_scopes set authorized=false where id=s;
  select status into st1 from public.scan_jobs where id=j1; select cancel_requested into cr2 from public.scan_jobs where id=j2;
  perform test.check('withdrawing authorization cancels queued jobs', st1 = 'cancelled', st1);
  perform test.check('withdrawing authorization asks running jobs to stop', cr2, cr2::text);
  begin update public.scan_jobs set status='queued' where id=j1; perform test.check('a cancelled job cannot be requeued onto a de-authorized scope', false, 'it was requeued');
  exception when others then perform test.check('a cancelled job cannot be requeued onto a de-authorized scope', true, left(sqlerrm,90)); end;
end $$;

-- ===== 5. Approvals =====
select test.run('operator requests an approval', :noc, 'authenticated', $q$insert into public.approvals (org_id,kind,subject_type,subject_id,summary) values ('{A}','config_change','device','d','Reboot core-sw')$q$, 'ok', 1);
select test.run('operator cannot create an already-approved approval', :noc, 'authenticated', $q$insert into public.approvals (org_id,kind,subject_type,subject_id,summary,status) values ('{A}','config_change','device','d','Reboot core-sw','approved')$q$, 'error');
select test.run('executive cannot request an approval', :exe, 'authenticated', $q$insert into public.approvals (org_id,kind,subject_type,subject_id,summary) values ('{A}','config_change','device','d','x')$q$, 'error');
select test.run('admin approves someone else''s request', :ad, 'authenticated', $q$update public.approvals set status='approved' where id='{APPR_PEND}'$q$, 'ok', 1);
select test.run('requester cannot approve their own request', :sec, 'authenticated', $q$update public.approvals set status='approved' where id='{APPR_PEND}'$q$, 'ok', 0);
select test.run('security_analyst cannot decide approvals (role)', :sec, 'authenticated', $q$update public.approvals set status='rejected' where id='{APPR_PEND}'$q$, 'ok', 0);
select test.run('noc_operator cannot decide approvals', :noc, 'authenticated', $q$update public.approvals set status='approved' where id='{APPR_PEND}'$q$, 'ok', 0);
select test.run('B admin cannot decide A approvals', :ob, 'authenticated', $q$update public.approvals set status='approved' where id='{APPR_PEND}'$q$, 'ok', 0);
select test.run('the approved request cannot be edited while deciding (column privileges)', :ad, 'authenticated', $q$update public.approvals set status='approved', summary='something else entirely' where id='{APPR_PEND}'$q$, 'error');
select test.run('an approved approval cannot be flipped to rejected', :ad, 'authenticated', $q$update public.approvals set status='rejected' where id='{APPR_OK}'$q$, 'error');
select test.run('nobody can choose decided_by directly', :ad, 'authenticated', $q$update public.approvals set status='approved', decided_by='11111111-1111-1111-1111-111111111115' where id='{APPR_PEND}'$q$, 'error');
select test.run('decision stamps decided_by from the signed-in user', :ad, 'authenticated',
  $q$do $d$ declare b uuid; begin update public.approvals set status='approved' where id='{APPR_PEND}' returning decided_by into b; if b <> '11111111-1111-1111-1111-111111111112' then raise exception 'decided_by was %', b; end if; end $d$$q$, 'ok');
update public.organizations set settings = '{"allow_self_approval": true}' where id = (select id from test.ids where label='A');
select test.run('self-approval works when the organization allows it', :sec, 'authenticated', $q$update public.approvals set status='approved' where id='{APPR_PEND}'$q$, 'ok', 0);   -- still 0: security_analyst is not an approver role
update public.organizations set settings = '{}' where id = (select id from test.ids where label='A');

-- ===== 6. Audit log: append-only, hash-chained, tenant-private =====
select test.run('service role appends an audit row', null, 'service_role', $q$insert into public.audit_log (org_id,actor_type,action) values ('{A}','system','test.append')$q$, 'ok', 1);
select test.run('audit row cannot be updated (even by the service role)', null, 'service_role', $q$update public.audit_log set action='edited' where org_id='{A}'$q$, 'error');
select test.run('audit row cannot be deleted', null, 'service_role', $q$delete from public.audit_log where org_id='{A}'$q$, 'error');
select test.run('audit log cannot be truncated', null, 'service_role', 'truncate public.audit_log', 'error');
select test.run('users cannot insert audit rows', :oa, 'authenticated', $q$insert into public.audit_log (org_id,actor_type,action) values ('{A}','user','forged.entry')$q$, 'error');
select test.run('an organization with history cannot be deleted', null, 'service_role', $q$delete from public.organizations where id='{A}'$q$, 'error');
select test.check('audit chain verifies for A', (select ok from private.verify_audit_chain((select id from test.ids where label='A'))), (select checked::text from private.verify_audit_chain((select id from test.ids where label='A'))) || ' rows');
select test.check('audit chains are independent per organization', (select checked from private.verify_audit_chain((select id from test.ids where label='B'))) = 2, 'B has its own chain');
do $$ declare a uuid := (select id from test.ids where label='A'); okk boolean; bk bigint; begin
  begin
    alter table public.audit_log disable trigger audit_log_no_change;
    update public.audit_log set detail = '{"tampered": true}' where id = (select min(id) from public.audit_log where org_id = a);
    select ok, broken_at into okk, bk from private.verify_audit_chain(a);
    raise exception using errcode='P0001', message='__rollback__';
  exception when others then if sqlerrm <> '__rollback__' then raise; end if; end;
  perform test.check('tampering with an audit row is detected', okk = false and bk is not null, 'broken at row ' || coalesce(bk::text,'?'));
end $$;

-- ===== 7. Agents and enrollment =====
select test.run('admin lists agents', :ad, 'authenticated', 'select id, name, status, last_seen_at from public.network_agents', 'ok', 2);
select test.run('credential hash is unreadable', :ad, 'authenticated', 'select credential_hash from public.network_agents', 'error');
select test.run('select * is refused (it includes the hash)', :ad, 'authenticated', 'select * from public.network_agents', 'error');
select test.run('enrollment token hash is unreadable', :ad, 'authenticated', 'select token_hash from public.agent_enrollment_tokens', 'error');
select test.run('enrollment tokens are listable without the hash', :ad, 'authenticated', 'select id, token_prefix, used_count from public.agent_enrollment_tokens', 'ok');
select test.run('noc_operator cannot see enrollment tokens', :noc, 'authenticated', 'select id from public.agent_enrollment_tokens', 'ok', 0);
select test.run('admin renames an agent', :ad, 'authenticated', $q$update public.network_agents set name='edge-1' where id='{AG_A}'$q$, 'ok', 1);
select test.run('nobody can replace an agent credential through the API', :oa, 'authenticated', $q$update public.network_agents set credential_hash='stolen' where id='{AG_A}'$q$, 'error');
select test.run('users cannot call enrollment directly', :oa, 'authenticated', $q$select private.enroll_agent('tok-a1','x','linux','1','h',null,'c')$q$, 'error');
select test.run('a used token cannot enroll again', null, 'service_role', $q$select private.enroll_agent('tok-a1','again','linux','1','h',null,'cred-x')$q$, 'error');
select test.run('an unknown token is refused', null, 'service_role', $q$select private.enroll_agent('nope','x','linux','1','h',null,'cred-y')$q$, 'error');
insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at,created_at) select id,'tok-old','tok-oldx','old',now()-interval '1 minute',now()-interval '2 hours' from test.ids where label='A';
insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at,revoked_at) select id,'tok-rev','tok-revx','rev',now()+interval '1 hour',now() from test.ids where label='A';
select test.run('an expired token is refused', null, 'service_role', $q$select private.enroll_agent('tok-old','x','linux','1','h',null,'cred-z')$q$, 'error');
select test.run('a revoked token is refused', null, 'service_role', $q$select private.enroll_agent('tok-rev','x','linux','1','h',null,'cred-w')$q$, 'error');
select test.run('token lifetime over 7 days is refused', null, 'service_role', $q$insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at) values ('{A}','tok-long','tok-lonx','l', now()+interval '8 days')$q$, 'error');
select test.check('enrollment wrote an audit row', exists (select 1 from public.audit_log where action='agent.enrolled' and actor_agent_id = (select id from test.ids where label='AG_A')), null);
select test.check('token consumed after its single use', (select consumed_at is not null and used_count = 1 from public.agent_enrollment_tokens where token_hash='tok-a1'), null);

-- job hand-out
do $$ declare a uuid := (select id from test.ids where label='A'); sc uuid := (select id from test.ids where label='SCOPE_A'); j uuid; c1 public.scan_jobs; c2 public.scan_jobs; cb public.scan_jobs; cs public.scan_jobs;
begin
  insert into public.scan_jobs (org_id,scope_id,kind,status) values (a,sc,'discovery','queued') returning id into j;
  cb := private.claim_next_job((select id from test.ids where label='AG_B'));
  perform test.check('an agent of another organization cannot claim the job', cb.id is null, coalesce(cb.id::text,'nothing claimed'));
  cs := private.claim_next_job((select id from test.ids where label='AG_A_SCAN'));
  perform test.check('a scanner-only agent does not take a discovery job', cs.id is null, coalesce(cs.id::text,'nothing claimed'));
  c1 := private.claim_next_job((select id from test.ids where label='AG_A'));
  perform test.check('the discovery agent claims the job', c1.id = j and c1.status = 'claimed' and c1.agent_id = (select id from test.ids where label='AG_A'), c1.status);
  c2 := private.claim_next_job((select id from test.ids where label='AG_A'));
  perform test.check('the same job is never handed out twice', c2.id is null or c2.id <> j, coalesce(c2.id::text,'nothing left'));
  update public.network_agents set revoked_at = now(), status = 'revoked' where id = (select id from test.ids where label='AG_A');
  insert into public.scan_jobs (org_id,scope_id,kind,status) values (a,sc,'discovery','queued');
  perform test.check('a revoked agent claims nothing', (private.claim_next_job((select id from test.ids where label='AG_A'))).id is null, null);
  update public.network_agents set revoked_at = null, status = 'online' where id = (select id from test.ids where label='AG_A');
end $$;

-- ===== 8. Assessments and findings =====
select test.run('analyst creates a draft assessment', :sec, 'authenticated', $q$insert into public.assessments (org_id,name,scope_id) values ('{A}','Draft','{SCOPE_A}')$q$, 'ok', 1);
select test.run('cannot start scanning without authorization', :sec, 'authenticated', $q$insert into public.assessments (org_id,name,scope_id,status) values ('{A}','No auth','{SCOPE_A}','scanning')$q$, 'error');
select test.run('analyst cannot confirm authorization', :sec, 'authenticated', $q$update public.assessments set authorization_confirmed_at=now(), authorization_statement='I confirm we own and may assess these systems' where id='{ASM_A}'$q$, 'error');
select test.run('noc_operator cannot create assessments', :noc, 'authenticated', $q$insert into public.assessments (org_id,name,scope_id) values ('{A}','Role test','{SCOPE_A}')$q$, 'error');
select test.run('executive cannot create assessments', :exe, 'authenticated', $q$insert into public.assessments (org_id,name,scope_id) values ('{A}','Role test','{SCOPE_A}')$q$, 'error');
select test.run('assessment on another organization''s scope is refused', :sec, 'authenticated', $q$insert into public.assessments (org_id,name,scope_id) values ('{A}','Cross tenant test','{SCOPE_B}')$q$, 'error');
select test.run('admin confirms authorization', :ad, 'authenticated', $q$update public.assessments set authorization_confirmed_at=now(), authorization_statement='I confirm we own and may assess these systems', status='awaiting_approval' where id='{ASM_A}'$q$, 'ok', 1);
select test.run('a short statement is not accepted', :ad, 'authenticated', $q$update public.assessments set authorization_confirmed_at=now(), authorization_statement='ok', status='scanning' where id='{ASM_A}'$q$, 'error');
update public.assessments set authorization_confirmed_at = now(), authorization_statement = 'I confirm we own and may assess these systems', authorization_confirmed_by = '11111111-1111-1111-1111-111111111112', status='awaiting_approval' where id = (select id from test.ids where label='ASM_A');
select test.run('analyst moves an authorized assessment to scanning', :sec, 'authenticated', $q$update public.assessments set status='scanning' where id='{ASM_A}'$q$, 'ok', 1);
select test.run('the assessment scope cannot be swapped by users (column privileges)', :sec, 'authenticated', $q$update public.assessments set scope_id='{SCOPE_A2}' where id='{ASM_A}'$q$, 'error');
select test.run('scanning is refused if the scope lost authorization', null, 'service_role', $q$do $d$ begin update public.scan_scopes set authorized=false where id='{SCOPE_A}'; update public.assessments set status='scanning' where id='{ASM_A}'; end $d$$q$, 'error');

select test.run('scanner_verified needs a scanner source', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance,evidence) values ('{A}','{ASM_A}','f2','manual','x y z','network','low','scanner_verified','{"a":1}')$q$, 'error');
select test.run('scanner_verified needs evidence', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance) values ('{A}','{ASM_A}','f3','nmap','x y z','network','low','scanner_verified')$q$, 'error');
select test.run('an AI finding cannot claim to be scanner-verified', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance,evidence) values ('{A}','{ASM_A}','f4','ai','x y z','network','low','scanner_verified','{"a":1}')$q$, 'error');
select test.run('an AI hypothesis is stored as such', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance) values ('{A}','{ASM_A}','f5','ai','Possible lateral movement path','network','medium','ai_hypothesis')$q$, 'ok', 1);
select test.run('the same fingerprint cannot repeat in one assessment', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance,evidence) values ('{A}','{ASM_A}','fp-1','nmap','dup dup','network','low','scanner_verified','{"a":1}')$q$, 'error');
select test.run('a finding cannot reference another organization''s device', null, 'service_role', $q$insert into public.vulnerability_findings (org_id,assessment_id,device_id,fingerprint,source,title,category,severity,provenance,evidence) values ('{A}','{ASM_A}','{DEV_B1}','f6','nmap','x y z','network','low','scanner_verified','{"a":1}')$q$, 'error');
select test.run('users cannot create findings', :sec, 'authenticated', $q$insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance) values ('{A}','{ASM_A}','f7','manual','x y z','network','low','analyst_confirmed')$q$, 'error');
select test.run('analyst changes a finding status', :sec, 'authenticated', $q$update public.vulnerability_findings set status='in_progress', status_note='ticket 42' where org_id='{A}' and fingerprint='fp-1'$q$, 'ok', 1);
select test.run('status_by is stamped automatically', :sec, 'authenticated',
  $q$do $d$ declare b uuid; begin update public.vulnerability_findings set status='remediated' where org_id='{A}' and fingerprint='fp-1' returning status_by into b; if b <> '11111111-1111-1111-1111-111111111114' then raise exception 'status_by %', b; end if; end $d$$q$, 'ok');
select test.run('executive cannot change finding status', :exe, 'authenticated', $q$update public.vulnerability_findings set status='false_positive' where org_id='{A}' and fingerprint='fp-1'$q$, 'ok', 0);
select test.run('nobody can rewrite scanner evidence or severity', :sec, 'authenticated', $q$update public.vulnerability_findings set severity='info', evidence='{}' where org_id='{A}' and fingerprint='fp-1'$q$, 'error');

-- ===== 9. Devices, links and cross-tenant references =====
select test.run('same identity key twice in one organization is refused', null, 'service_role', $q$insert into public.net_devices (org_id,identity_key) values ('{A}','mac:aa:01')$q$, 'error');
select test.run('the same identity key in another organization is fine', null, 'service_role', $q$insert into public.net_devices (org_id,identity_key) values ('{B}','mac:aa:01')$q$, 'ok', 1);
select test.run('link between devices of different organizations is refused', null, 'service_role', $q$insert into public.net_links (org_id,a_device_id,b_device_id,protocol,confidence) values ('{A}', least('{DEV_A1}'::uuid,'{DEV_B1}'::uuid), greatest('{DEV_A1}'::uuid,'{DEV_B1}'::uuid), 'lldp','confirmed')$q$, 'error');
select test.run('a confirmed LLDP link is stored', null, 'service_role', $q$insert into public.net_links (org_id,a_device_id,b_device_id,a_port,b_port,protocol,confidence) values ('{A}', least('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), greatest('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), 'Gi0/1','eth0','lldp','confirmed')$q$, 'ok', 1);
select test.run('an ARP-based link cannot be marked confirmed', null, 'service_role', $q$insert into public.net_links (org_id,a_device_id,b_device_id,protocol,confidence) values ('{A}', least('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), greatest('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), 'arp','confirmed')$q$, 'error');
select test.run('an inferred link is stored as inferred', null, 'service_role', $q$insert into public.net_links (org_id,a_device_id,b_device_id,protocol,confidence) values ('{A}', least('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), greatest('{DEV_A1}'::uuid,'{DEV_A2}'::uuid), 'arp','inferred')$q$, 'ok', 1);
select test.run('a link cannot join a device to itself', null, 'service_role', $q$insert into public.net_links (org_id,a_device_id,b_device_id,protocol,confidence) values ('{A}','{DEV_A1}','{DEV_A1}','arp','inferred')$q$, 'error');
select test.run('an interface cannot hang off another organization''s device', null, 'service_role', $q$insert into public.net_device_interfaces (org_id,device_id,name) values ('{A}','{DEV_B1}','eth0')$q$, 'error');
select test.run('a service row is stored', null, 'service_role', $q$insert into public.net_device_services (org_id,device_id,port,proto,service_name) values ('{A}','{DEV_A1}',22,'tcp','ssh')$q$, 'ok', 1);
select test.run('a device type outside the list is refused', null, 'service_role', $q$insert into public.net_devices (org_id,identity_key,device_type) values ('{A}','mac:zz','toaster')$q$, 'error');
select test.run('operators can create network segments', :noc, 'authenticated', $q$insert into public.net_segments (org_id,name,kind,cidr) values ('{A}','Servers','subnet','10.0.1.0/24')$q$, 'ok', 1);
select test.run('executive cannot create network segments', :exe, 'authenticated', $q$insert into public.net_segments (org_id,name) values ('{A}','x')$q$, 'error');

-- ===== 10. Organization rules =====
select test.run('the last owner cannot demote themselves', :ob, 'authenticated', $q$update public.org_members set role='it_admin' where user_id='22222222-2222-2222-2222-222222222221'$q$, 'error');
select test.run('the last owner cannot leave', :ob, 'authenticated', $q$delete from public.org_members where user_id='22222222-2222-2222-2222-222222222221'$q$, 'error');
select test.run('a member can leave', :noc, 'authenticated', $q$delete from public.org_members where user_id='11111111-1111-1111-1111-111111111113'$q$, 'ok', 1);
select test.run('a second owner lets the first one step down', :oa, 'authenticated', $q$do $d$ begin update public.org_members set role='owner' where user_id='11111111-1111-1111-1111-111111111112'; update public.org_members set role='it_admin' where user_id='11111111-1111-1111-1111-111111111111'; end $d$$q$, 'ok');
select test.run('creating an organization needs a signed-in user', null, 'authenticated', $q$select public.create_organization('Ghost','ghost-org')$q$, 'error');
select test.run('bad slug is refused', :out, 'authenticated', $q$select public.create_organization('Bad','Bad Slug!')$q$, 'error');
select test.run('duplicate slug is refused', :out, 'authenticated', $q$select public.create_organization('Again','org-a')$q$, 'error');
select test.run('a user can create an organization and becomes its owner', :out, 'authenticated',
  $q$do $d$ declare o uuid; begin o := public.create_organization('Newco','newco'); if (select role from public.org_members where org_id = o and user_id = '33333333-3333-3333-3333-333333333331') <> 'owner' then raise exception 'not owner'; end if; end $d$$q$, 'ok');
do $$ declare i int; ok boolean := true; msg text; begin
  perform set_config('request.jwt.claim.sub','33333333-3333-3333-3333-333333333331',true);
  set local role authenticated;
  begin for i in 1..6 loop perform public.create_organization('Org '||i, 'lim-org-'||i); end loop; ok := false; msg := 'six organizations were created';
  exception when others then msg := left(sqlerrm,90); end;
  reset role;
  perform test.check('an account is limited to 5 organizations', ok, msg);
end $$;
update public.organizations set disabled_at = now() where id = (select id from test.ids where label='B');
select test.run('members of a disabled organization lose access', :ob, 'authenticated', $q$select 1 from public.net_devices where org_id='{B}'$q$, 'ok', 0);
update public.organizations set disabled_at = null where id = (select id from test.ids where label='B');

-- ===== 11. Existing data and the existing application =====
select test.check('legacy soc_assets row kept and placed in the Default organization', (select org_id = '00000000-0000-0000-0000-000000000001' from public.soc_assets where id='legacy-asset-1'), null);
select test.check('legacy soc_events row kept', (select org_id = '00000000-0000-0000-0000-000000000001' from public.soc_events where id='legacy-event-1'), null);
select test.check('legacy noc_devices row kept', (select org_id = '00000000-0000-0000-0000-000000000001' and ip='10.0.0.2' from public.noc_devices where id='legacy-dev-1'), null);
select test.check('legacy noc_scopes row kept', (select org_id = '00000000-0000-0000-0000-000000000001' from public.noc_scopes where id='legacy-scope'), null);
select test.run('the current app (service role) still inserts without org_id', null, 'service_role', $q$insert into public.soc_events (id,source,asset_id,"time",event_id) values ('new-event','test','legacy-asset-1','2026-11-02T00:00:00Z',4625)$q$, 'ok', 1);
select test.check('rows inserted by the current app land in the Default organization', (select count(*) = 0 from public.soc_events where org_id is null), null);
select test.run('the current app (service role) still reads legacy tables', null, 'service_role', 'select 1 from public.soc_assets', 'ok', 1);
select test.run('signed-in users cannot read legacy tables directly', :oa, 'authenticated', 'select 1 from public.soc_events', 'error');
select test.run('anonymous cannot read legacy tables', null, 'anon', 'select 1 from public.noc_devices', 'error');
select test.check('existing website-builder policies are untouched', (select count(*) from pg_policies where schemaname='public' and tablename in ('projects','versions','usage','sites')) = 5, (select count(*)::text from pg_policies where schemaname='public' and tablename in ('projects','versions','usage','sites')));
select test.run('published sites are still publicly readable (by design)', null, 'anon', 'select 1 from public.sites', 'ok');
select test.check('soc_kev and soc_meta were not modified', (select count(*) = 0 from information_schema.columns where table_name in ('soc_kev') and column_name='org_id'), null);

-- ===== 12. Scale: 20,000 devices per organization =====
insert into public.net_devices (org_id, identity_key, primary_ip, hostname, device_type, status, last_seen_at)
  select (select id from test.ids where label='A'), 'bulk:'||g, ('10.20.'||(g/250)||'.'||(g%250+1))::inet, 'host-'||g, 'workstation', case when g%9=0 then 'offline' else 'online' end, now() - (g||' seconds')::interval from generate_series(1,20000) g;
insert into public.net_devices (org_id, identity_key, primary_ip, hostname, device_type, status, last_seen_at)
  select (select id from test.ids where label='B'), 'bulk:'||g, ('10.30.'||(g/250)||'.'||(g%250+1))::inet, 'bhost-'||g, 'workstation', 'online', now() - (g||' seconds')::interval from generate_series(1,20000) g;
analyze public.net_devices;
select test.run('A sees exactly its own devices at scale', :oa, 'authenticated', $q$select 1 from public.net_devices$q$, 'ok', (select count(*)::int from public.net_devices where org_id=(select id from test.ids where label='A')));
select test.run('B sees exactly its own devices at scale', :ob, 'authenticated', $q$select 1 from public.net_devices$q$, 'ok', (select count(*)::int from public.net_devices where org_id=(select id from test.ids where label='B')));
