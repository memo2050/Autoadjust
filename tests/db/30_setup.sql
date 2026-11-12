\set ON_ERROR_STOP on
grant usage on schema test to public;
create table test.ids (label text primary key, id uuid not null);
create table test.out (label text, id uuid);
grant select on test.ids to public; grant all on test.out to public;

insert into auth.users (id, email) values
 ('11111111-1111-1111-1111-111111111111','owner-a@x.test'), ('11111111-1111-1111-1111-111111111112','admin-a@x.test'),
 ('11111111-1111-1111-1111-111111111113','noc-a@x.test'),   ('11111111-1111-1111-1111-111111111114','sec-a@x.test'),
 ('11111111-1111-1111-1111-111111111115','exec-a@x.test'),  ('22222222-2222-2222-2222-222222222221','owner-b@x.test'),
 ('33333333-3333-3333-3333-333333333331','outsider@x.test');

-- Organizations are created through the public RPC, as a signed-in user would.
begin; select set_config('request.jwt.claim.sub','11111111-1111-1111-1111-111111111111',true); set local role authenticated;
  insert into test.out select 'A', public.create_organization('Org A','org-a'); commit;
begin; select set_config('request.jwt.claim.sub','22222222-2222-2222-2222-222222222221',true); set local role authenticated;
  insert into test.out select 'B', public.create_organization('Org B','org-b'); commit;
insert into test.ids select label, id from test.out;

insert into public.org_members (org_id, user_id, role) select (select id from test.ids where label='A'), u, r from (values
 ('11111111-1111-1111-1111-111111111112'::uuid,'it_admin'), ('11111111-1111-1111-1111-111111111113','noc_operator'),
 ('11111111-1111-1111-1111-111111111114','security_analyst'), ('11111111-1111-1111-1111-111111111115','executive_readonly')) v(u, r);

-- Seed data, one organization each, written by the backend (superuser here = service role).
with s as (insert into public.scan_scopes (org_id,name,targets,authorized,authorized_at,attestation,authorized_by)
  select id,'HQ LAN','{10.0.0.0/24}',true,now(),'I am authorized to scan the HQ network','11111111-1111-1111-1111-111111111111' from test.ids where label='A' returning id) insert into test.ids select 'SCOPE_A', id from s;
with s as (insert into public.scan_scopes (org_id,name,targets) select id,'Lab (not authorized)','{192.168.50.0/24}' from test.ids where label='A' returning id) insert into test.ids select 'SCOPE_A2', id from s;
with s as (insert into public.scan_scopes (org_id,name,targets,authorized,authorized_at,attestation)
  select id,'B LAN','{10.9.0.0/24}',true,now(),'I am authorized to scan the B network' from test.ids where label='B' returning id) insert into test.ids select 'SCOPE_B', id from s;

insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at,capabilities) select id,'tok-a1','tok-a1xx','a1',now()+interval '1 hour','{discovery}' from test.ids where label='A';
insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at,capabilities) select id,'tok-a2','tok-a2xx','a2',now()+interval '1 hour','{scanner}' from test.ids where label='A';
insert into public.agent_enrollment_tokens (org_id,token_hash,token_prefix,label,expires_at,capabilities) select id,'tok-b1','tok-b1xx','b1',now()+interval '1 hour','{discovery,scanner}' from test.ids where label='B';
insert into test.ids values ('AG_A', private.enroll_agent('tok-a1','agent-a','linux','1.0.0','host-a','10.0.0.5','cred-a'));
insert into test.ids values ('AG_A_SCAN', private.enroll_agent('tok-a2','scanner-a','docker','1.0.0','host-s','10.0.0.6','cred-s'));
insert into test.ids values ('AG_B', private.enroll_agent('tok-b1','agent-b','windows','1.0.0','host-b','10.9.0.5','cred-b'));

insert into public.net_devices (org_id, identity_key, primary_ip, hostname, device_type, status, last_seen_at, vendor, vendor_confidence)
  select id,'mac:aa:01','10.0.0.1','core-sw','switch','online',now(),'Cisco','inferred' from test.ids where label='A';
insert into public.net_devices (org_id, identity_key, primary_ip, hostname, device_type, status, last_seen_at) select id,'mac:aa:02','10.0.0.2','fw-1','firewall','online',now() from test.ids where label='A';
insert into public.net_devices (org_id, identity_key, primary_ip, hostname, device_type, status, last_seen_at) select id,'mac:bb:01','10.9.0.1','b-sw','switch','online',now() from test.ids where label='B';
insert into test.ids select 'DEV_A1', id from public.net_devices where identity_key='mac:aa:01';
insert into test.ids select 'DEV_A2', id from public.net_devices where identity_key='mac:aa:02';
insert into test.ids select 'DEV_B1', id from public.net_devices where identity_key='mac:bb:01';

with s as (insert into public.approvals (org_id,kind,subject_type,subject_id,summary,status,decided_at,decided_by,requested_by)
  select id,'assessment','assessment','x','Approved assessment run','approved',now(),'11111111-1111-1111-1111-111111111111','11111111-1111-1111-1111-111111111114' from test.ids where label='A' returning id) insert into test.ids select 'APPR_OK', id from s;
with s as (insert into public.approvals (org_id,kind,subject_type,subject_id,summary,requested_by)
  select id,'config_change','device','d1','Change VLAN 20 on core-sw','11111111-1111-1111-1111-111111111114' from test.ids where label='A' returning id) insert into test.ids select 'APPR_PEND', id from s;
insert into public.approvals (org_id,kind,subject_type,subject_id,summary) select id,'scan','scope','s','B approval' from test.ids where label='B';

with s as (insert into public.assessments (org_id,name,scope_id) select a.id,'Q4 assessment',s.id from test.ids a, test.ids s where a.label='A' and s.label='SCOPE_A' returning id) insert into test.ids select 'ASM_A', id from s;
with s as (insert into public.assessments (org_id,name,scope_id) select a.id,'B assessment',s.id from test.ids a, test.ids s where a.label='B' and s.label='SCOPE_B' returning id) insert into test.ids select 'ASM_B', id from s;
insert into public.vulnerability_findings (org_id,assessment_id,device_id,fingerprint,source,source_ref,title,category,severity,provenance,evidence)
  select a.id, m.id, d.id, 'fp-1','nmap','smb-vuln','SMBv1 enabled','network','high','scanner_verified','{"port":445}' from test.ids a, test.ids m, test.ids d where a.label='A' and m.label='ASM_A' and d.label='DEV_A1';
insert into public.vulnerability_findings (org_id,assessment_id,fingerprint,source,title,category,severity,provenance,evidence)
  select a.id, m.id, 'fp-b','nmap','B finding','network','low','scanner_verified','{"port":22}' from test.ids a, test.ids m where a.label='B' and m.label='ASM_B';
insert into public.audit_log (org_id, actor_type, actor_label, action) select id,'user','seed','test.seed.one' from test.ids where label='A';
insert into public.audit_log (org_id, actor_type, actor_label, action) select id,'user','seed','test.seed.two' from test.ids where label='A';
insert into public.audit_log (org_id, actor_type, actor_label, action) select id,'user','seed','test.seed.b' from test.ids where label='B';
select 'setup ok' as status, (select count(*) from test.ids) as ids;
