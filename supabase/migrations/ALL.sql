-- ALL.sql: migrations 0100 to 0105 in order, for pasting into the Supabase SQL Editor in one go.
-- Repeatable: running it again changes nothing. Review the individual files first.
-- ===== 0100_tenancy.sql =====
-- 0100_tenancy.sql  |  Organizations, members, invitations, role helpers.
-- Additive and repeatable: safe to run more than once. Touches no existing table.
-- Requires Supabase (roles anon / authenticated / service_role and auth.users / auth.uid()).
begin;

create schema if not exists private;                       -- not exposed through the Supabase API
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;

create table if not exists private.app_migrations (
  version text primary key, name text not null, applied_at timestamptz not null default now()
);

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 2 and 120),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$'),
  plan text not null default 'free',
  settings jsonb not null default '{}'::jsonb,   -- e.g. {"allow_self_approval": true}
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  disabled_at timestamptz                          -- organizations are disabled, never deleted (audit history must survive)
);

create table if not exists public.org_members (
  org_id uuid not null references public.organizations on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null check (role in ('owner','it_admin','noc_operator','security_analyst','executive_readonly')),
  invited_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index if not exists org_members_user on public.org_members (user_id);

create table if not exists public.org_invitations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  email text not null check (email = lower(email) and position('@' in email) > 1),
  role text not null check (role in ('it_admin','noc_operator','security_analyst','executive_readonly')),  -- owners are added by an owner directly
  token_hash text not null unique,                 -- sha256 of the invite token; the token itself is never stored
  invited_by uuid references auth.users on delete set null,
  expires_at timestamptz not null,
  accepted_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at > created_at and expires_at <= created_at + interval '30 days')
);
create index if not exists org_invitations_org on public.org_invitations (org_id);

-- The organization that holds all data created before multi-tenancy existed.
insert into public.organizations (id, name, slug)
values ('00000000-0000-0000-0000-000000000001', 'Default organization', 'default')
on conflict (id) do nothing;

-- ---------- helpers (SECURITY DEFINER so they can read org_members without recursing through its own RLS) ----------
create or replace function private.org_role(p_org uuid) returns text
language sql stable security definer set search_path = '' as $$
  select m.role from public.org_members m join public.organizations o on o.id = m.org_id
  where m.org_id = p_org and m.user_id = auth.uid() and o.disabled_at is null
$$;
create or replace function private.is_member(p_org uuid) returns boolean
language sql stable security definer set search_path = '' as $$ select private.org_role(p_org) is not null $$;
create or replace function private.has_role(p_org uuid, p_roles text[]) returns boolean
language sql stable security definer set search_path = '' as $$ select coalesce(private.org_role(p_org) = any(p_roles), false) $$;
create or replace function private.is_human() returns boolean
language sql stable as $$ select current_user in ('authenticated', 'anon') $$;   -- true for API users, false for the backend service role

revoke all on function private.org_role(uuid), private.is_member(uuid), private.has_role(uuid, text[]), private.is_human() from public, anon;
grant execute on function private.org_role(uuid), private.is_member(uuid), private.has_role(uuid, text[]), private.is_human() to authenticated, service_role;

create or replace function private.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
drop trigger if exists organizations_touch on public.organizations;
create trigger organizations_touch before update on public.organizations for each row execute function private.touch_updated_at();

-- An organization can never be left without an owner.
create or replace function private.guard_last_owner() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.role = 'owner' and (tg_op = 'DELETE' or new.role <> 'owner' or new.org_id <> old.org_id) then
    if exists (select 1 from public.organizations where id = old.org_id)
       and not exists (select 1 from public.org_members where org_id = old.org_id and role = 'owner' and user_id <> old.user_id) then
      raise exception 'An organization must keep at least one owner' using errcode = '23514';
    end if;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end $$;
drop trigger if exists org_members_last_owner on public.org_members;
create trigger org_members_last_owner before update or delete on public.org_members for each row execute function private.guard_last_owner();

-- Self-service creation: the caller becomes the owner. Nothing else can insert organizations.
create or replace function public.create_organization(p_name text, p_slug text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid(); oid uuid;
begin
  if uid is null then raise exception 'Sign in first' using errcode = '28000'; end if;
  if (select count(*) from public.organizations where created_by = uid) >= 5 then
    raise exception 'Organization limit reached for this account' using errcode = '54000'; end if;
  insert into public.organizations (name, slug, created_by) values (btrim(p_name), lower(btrim(p_slug)), uid) returning id into oid;
  insert into public.org_members (org_id, user_id, role) values (oid, uid, 'owner');
  return oid;
end $$;
revoke all on function public.create_organization(text, text) from public, anon;
grant execute on function public.create_organization(text, text) to authenticated, service_role;

-- ---------- privileges and row level security ----------
alter table public.organizations enable row level security;
alter table public.org_members enable row level security;
alter table public.org_invitations enable row level security;
revoke all on public.organizations, public.org_members, public.org_invitations from anon, authenticated;
grant select on public.organizations to authenticated;
grant update (name, settings) on public.organizations to authenticated;
grant select, insert, update, delete on public.org_members to authenticated;
grant select (id, org_id, email, role, invited_by, expires_at, accepted_at, created_at) on public.org_invitations to authenticated;  -- token_hash is never readable

drop policy if exists organizations_select on public.organizations;
create policy organizations_select on public.organizations for select to authenticated using (private.is_member(id));
drop policy if exists organizations_update on public.organizations;
create policy organizations_update on public.organizations for update to authenticated using (private.has_role(id, array['owner'])) with check (private.has_role(id, array['owner']));

drop policy if exists org_members_select on public.org_members;
create policy org_members_select on public.org_members for select to authenticated using (private.is_member(org_id));
drop policy if exists org_members_insert on public.org_members;
create policy org_members_insert on public.org_members for insert to authenticated with check (private.has_role(org_id, array['owner']));
drop policy if exists org_members_update on public.org_members;
create policy org_members_update on public.org_members for update to authenticated using (private.has_role(org_id, array['owner'])) with check (private.has_role(org_id, array['owner']));
drop policy if exists org_members_delete on public.org_members;
create policy org_members_delete on public.org_members for delete to authenticated using (private.has_role(org_id, array['owner']) or user_id = auth.uid());

drop policy if exists org_invitations_select on public.org_invitations;
create policy org_invitations_select on public.org_invitations for select to authenticated using (private.has_role(org_id, array['owner','it_admin']));

insert into private.app_migrations (version, name) values ('0100', 'tenancy') on conflict do nothing;
commit;

-- ===== 0101_audit_approvals.sql =====
-- 0101_audit_approvals.sql  |  Immutable hash-chained audit log and approval records (per organization).
begin;

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete restrict,
  at timestamptz not null default now(),
  actor_type text not null check (actor_type in ('user','agent','system')),
  actor_user_id uuid,
  actor_agent_id uuid,
  actor_label text,
  action text not null check (char_length(action) between 3 and 120),
  target_type text, target_id text,
  detail jsonb not null default '{}'::jsonb,
  prev_hash text, hash text
);
create index if not exists audit_log_org_id on public.audit_log (org_id, id desc);
create index if not exists audit_log_org_action on public.audit_log (org_id, action, at desc);

-- Each row stores the hash of the previous row of the same organization, so any edit or removal breaks the chain.
create or replace function private.audit_chain() returns trigger language plpgsql security definer set search_path = '' as $$
declare p text;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.org_id::text, 17));
  select hash into p from public.audit_log where org_id = new.org_id order by id desc limit 1;
  new.prev_hash := p;
  new.hash := encode(sha256(convert_to(coalesce(p,'') || '|' || new.org_id::text || '|' || new.at::text || '|' || new.actor_type || '|' ||
    coalesce(new.actor_user_id::text,'') || coalesce(new.actor_agent_id::text,'') || '|' || new.action || '|' || coalesce(new.target_type,'') || '|' ||
    coalesce(new.target_id,'') || '|' || new.detail::text, 'utf8')), 'hex');
  return new;
end $$;
drop trigger if exists audit_log_chain on public.audit_log;
create trigger audit_log_chain before insert on public.audit_log for each row execute function private.audit_chain();

create or replace function private.audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_log is append-only' using errcode = '42501'; end $$;
drop trigger if exists audit_log_no_change on public.audit_log;
create trigger audit_log_no_change before update or delete on public.audit_log for each row execute function private.audit_immutable();
drop trigger if exists audit_log_no_truncate on public.audit_log;
create trigger audit_log_no_truncate before truncate on public.audit_log for each statement execute function private.audit_immutable();

create or replace function private.verify_audit_chain(p_org uuid) returns table (ok boolean, checked bigint, broken_at bigint)
language plpgsql stable security definer set search_path = '' as $$
declare r record; p text := null; n bigint := 0; h text;
begin
  for r in select * from public.audit_log where org_id = p_org order by id loop
    h := encode(sha256(convert_to(coalesce(p,'') || '|' || r.org_id::text || '|' || r.at::text || '|' || r.actor_type || '|' ||
      coalesce(r.actor_user_id::text,'') || coalesce(r.actor_agent_id::text,'') || '|' || r.action || '|' || coalesce(r.target_type,'') || '|' ||
      coalesce(r.target_id,'') || '|' || r.detail::text, 'utf8')), 'hex');
    n := n + 1;
    if r.prev_hash is distinct from p or r.hash <> h then return query select false, n, r.id; return; end if;
    p := r.hash;
  end loop;
  return query select true, n, null::bigint;
end $$;
revoke all on function private.verify_audit_chain(uuid) from public, anon, authenticated;
grant execute on function private.verify_audit_chain(uuid) to service_role;

create table if not exists public.approvals (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete restrict,
  kind text not null check (kind in ('scan','assessment','config_change','remediation','agent_command','other')),
  subject_type text not null, subject_id text not null,
  summary text not null check (char_length(summary) between 3 and 500),
  impact text,
  risk text not null default 'medium' check (risk in ('low','medium','high','critical')),
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','rejected','expired','cancelled','executed','failed')),
  requested_by uuid references auth.users on delete set null,
  requested_at timestamptz not null default now(),
  decided_by uuid references auth.users on delete set null,
  decided_at timestamptz,
  decision_note text,
  expires_at timestamptz,
  executed_at timestamptz,
  result jsonb,
  unique (org_id, id),
  check (status not in ('approved','rejected','executed','failed') or decided_at is not null)
);
create index if not exists approvals_org_status on public.approvals (org_id, status, requested_at desc);
create index if not exists approvals_subject on public.approvals (org_id, subject_type, subject_id);

-- People may only move a pending approval to approved or rejected, may not edit what is being approved,
-- and (unless the organization allows it) may not approve their own request.
create or replace function private.guard_approval() returns trigger language plpgsql as $$
declare allow_self boolean;
begin
  if tg_op = 'INSERT' then
    if private.is_human() then
      if new.status <> 'pending' then raise exception 'An approval request starts as pending' using errcode = '42501'; end if;
      new.requested_by := auth.uid(); new.requested_at := now();
      new.decided_by := null; new.decided_at := null; new.executed_at := null; new.result := null;
    end if;
    return new;
  end if;
  if private.is_human() then
    if old.status <> 'pending' then raise exception 'This approval is already %', old.status using errcode = '42501'; end if;
    if new.status not in ('approved','rejected') then raise exception 'Only approve or reject is allowed' using errcode = '42501'; end if;
    if (new.org_id, new.kind, new.subject_type, new.subject_id, new.summary, new.impact, new.risk, new.payload, new.requested_by, new.requested_at, new.expires_at)
       is distinct from (old.org_id, old.kind, old.subject_type, old.subject_id, old.summary, old.impact, old.risk, old.payload, old.requested_by, old.requested_at, old.expires_at) then
      raise exception 'The request cannot be edited while deciding' using errcode = '42501'; end if;
    if old.expires_at is not null and old.expires_at < now() then raise exception 'This approval has expired' using errcode = '42501'; end if;
    select coalesce((settings->>'allow_self_approval')::boolean, false) into allow_self from public.organizations where id = old.org_id;
    if new.status = 'approved' and old.requested_by = auth.uid() and not allow_self then
      raise exception 'You cannot approve your own request (organization setting allow_self_approval is off)' using errcode = '42501'; end if;
    new.decided_by := auth.uid(); new.decided_at := now();
  end if;
  return new;
end $$;
drop trigger if exists approvals_guard on public.approvals;
create trigger approvals_guard before insert or update on public.approvals for each row execute function private.guard_approval();

-- privileges and RLS
alter table public.audit_log enable row level security;
alter table public.approvals enable row level security;
revoke all on public.audit_log, public.approvals from anon, authenticated;
grant select on public.audit_log to authenticated;
grant select, insert on public.approvals to authenticated;
grant update (status, decision_note) on public.approvals to authenticated;

drop policy if exists audit_log_select on public.audit_log;
create policy audit_log_select on public.audit_log for select to authenticated using (private.has_role(org_id, array['owner','it_admin','security_analyst']));
drop policy if exists approvals_select on public.approvals;
create policy approvals_select on public.approvals for select to authenticated using (private.is_member(org_id));
drop policy if exists approvals_insert on public.approvals;
create policy approvals_insert on public.approvals for insert to authenticated
  with check (private.has_role(org_id, array['owner','it_admin','noc_operator','security_analyst']) and status = 'pending');
drop policy if exists approvals_decide on public.approvals;
create policy approvals_decide on public.approvals for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));

insert into private.app_migrations (version, name) values ('0101', 'audit_approvals') on conflict do nothing;
commit;

-- ===== 0102_agents.sql =====
-- 0102_agents.sql  |  Local network agents / scanner workers and secure enrollment.
-- Agents never hold a database key. They talk to the Autoadjust API with a per-agent credential whose hash is stored here.
begin;

create table if not exists public.network_agents (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 80),
  capabilities text[] not null default '{discovery}' check (capabilities <@ array['discovery','scanner'] and cardinality(capabilities) > 0),
  platform text not null default 'linux' check (platform in ('linux','windows','docker','other')),
  version text, hostname text, last_ip inet,
  status text not null default 'online' check (status in ('online','offline','revoked','error')),
  health jsonb not null default '{}'::jsonb,       -- tools present, queue depth, clock skew, last error
  last_seen_at timestamptz,
  credential_hash text not null,                   -- sha256 of the agent secret; never readable through the API
  credential_rotated_at timestamptz not null default now(),
  revoked_at timestamptz,
  notes text,
  enrolled_at timestamptz not null default now(),
  unique (org_id, id), unique (org_id, name)
);
create index if not exists network_agents_org_status on public.network_agents (org_id, status);
create unique index if not exists network_agents_credential on public.network_agents (credential_hash);

create table if not exists public.agent_enrollment_tokens (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  token_hash text not null unique,                 -- sha256 of the one-time token shown once to the administrator
  token_prefix text not null,                      -- first characters, for recognising it in a list
  label text not null,
  capabilities text[] not null default '{discovery}' check (capabilities <@ array['discovery','scanner']),
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  max_uses int not null default 1 check (max_uses between 1 and 25),
  used_count int not null default 0,
  consumed_at timestamptz,
  revoked_at timestamptz,
  check (expires_at > created_at and expires_at <= created_at + interval '7 days'),
  check (used_count <= max_uses)
);
create index if not exists agent_enrollment_org on public.agent_enrollment_tokens (org_id, created_at desc);

-- Atomic, single-use enrollment. Called only by the backend (service role).
create or replace function private.enroll_agent(p_token_hash text, p_name text, p_platform text, p_version text, p_hostname text, p_ip inet, p_credential_hash text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare t public.agent_enrollment_tokens; aid uuid;
begin
  select * into t from public.agent_enrollment_tokens where token_hash = p_token_hash for update;
  if not found then raise exception 'Invalid enrollment token' using errcode = '28000'; end if;
  if t.revoked_at is not null then raise exception 'Enrollment token was revoked' using errcode = '28000'; end if;
  if t.expires_at < now() then raise exception 'Enrollment token expired' using errcode = '28000'; end if;
  if t.used_count >= t.max_uses then raise exception 'Enrollment token already used' using errcode = '28000'; end if;
  insert into public.network_agents (org_id, name, capabilities, platform, version, hostname, last_ip, credential_hash, last_seen_at)
  values (t.org_id, p_name, t.capabilities, p_platform, p_version, p_hostname, p_ip, p_credential_hash, now()) returning id into aid;
  update public.agent_enrollment_tokens set used_count = used_count + 1, consumed_at = case when used_count + 1 >= max_uses then now() else consumed_at end where id = t.id;
  insert into public.audit_log (org_id, actor_type, actor_agent_id, actor_label, action, target_type, target_id, detail)
  values (t.org_id, 'agent', aid, p_name, 'agent.enrolled', 'agent', aid::text, jsonb_build_object('platform', p_platform, 'version', p_version, 'token', t.token_prefix));
  return aid;
end $$;
revoke all on function private.enroll_agent(text,text,text,text,text,inet,text) from public, anon, authenticated;
grant execute on function private.enroll_agent(text,text,text,text,text,inet,text) to service_role;

alter table public.network_agents enable row level security;
alter table public.agent_enrollment_tokens enable row level security;
revoke all on public.network_agents, public.agent_enrollment_tokens from anon, authenticated;
grant select (id, org_id, name, capabilities, platform, version, hostname, last_ip, status, health, last_seen_at, credential_rotated_at, revoked_at, notes, enrolled_at) on public.network_agents to authenticated;
grant update (name, notes) on public.network_agents to authenticated;
grant select (id, org_id, token_prefix, label, capabilities, created_by, created_at, expires_at, max_uses, used_count, consumed_at, revoked_at) on public.agent_enrollment_tokens to authenticated;

drop policy if exists network_agents_select on public.network_agents;
create policy network_agents_select on public.network_agents for select to authenticated using (private.is_member(org_id));
drop policy if exists network_agents_update on public.network_agents;
create policy network_agents_update on public.network_agents for update to authenticated using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));
drop policy if exists agent_enrollment_select on public.agent_enrollment_tokens;
create policy agent_enrollment_select on public.agent_enrollment_tokens for select to authenticated using (private.has_role(org_id, array['owner','it_admin']));

insert into private.app_migrations (version, name) values ('0102', 'agents') on conflict do nothing;
commit;

-- ===== 0103_discovery_topology.sql =====
-- 0103_discovery_topology.sql  |  Scan scopes (internal networks only), scan jobs, discovered devices, topology.
-- Tenant isolation is enforced twice: row level security AND composite foreign keys (org_id, id), so a row can never point at another organization's row.
begin;

-- ---------- internal-only scope rule, enforced in the database ----------
create or replace function private.cidr_ok(c cidr) returns boolean language sql immutable as $$
  select case family(c)
    when 4 then masklen(c) >= 16 and (c <<= '10.0.0.0/8'::cidr or c <<= '172.16.0.0/12'::cidr or c <<= '192.168.0.0/16'::cidr or c <<= '169.254.0.0/16'::cidr)
    else masklen(c) >= 112 and (c <<= 'fc00::/7'::cidr or c <<= 'fe80::/10'::cidr) end
$$;
create or replace function private.all_cidr_ok(cs cidr[]) returns boolean language sql immutable as $$
  select coalesce(bool_and(private.cidr_ok(x)), false) from unnest(cs) as x
$$;

create or replace function private.vlans_ok(v int[]) returns boolean language sql immutable as $$
  select coalesce(bool_and(x between 1 and 4094), true) from unnest(v) as x
$$;

create table if not exists public.scan_scopes (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 120),
  description text,
  kind text not null default 'internal' check (kind = 'internal'),   -- 'external' is added by a later migration, together with domain ownership verification
  targets cidr[] not null check (cardinality(targets) between 1 and 256 and private.all_cidr_ok(targets)),
  exclusions cidr[] not null default '{}',
  vlan_ids int[] not null default '{}' check (private.vlans_ok(vlan_ids)),
  agent_id uuid,                                                       -- the local agent / worker that scans this scope
  max_pps int not null default 50 check (max_pps between 1 and 1000),
  testing_window jsonb,                                                -- e.g. {"tz":"America/Los_Angeles","days":[1,2,3,4,5],"from":"20:00","to":"05:00"}
  authorized boolean not null default false,
  authorized_by uuid references auth.users on delete set null,
  authorized_at timestamptz,
  attestation text,                                                    -- the statement the administrator confirmed
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, id), unique (org_id, name),
  foreign key (org_id, agent_id) references public.network_agents (org_id, id) on delete set null (agent_id),
  check (not authorized or (authorized_at is not null and attestation is not null and char_length(attestation) >= 20))
);
create index if not exists scan_scopes_org on public.scan_scopes (org_id);

create or replace function private.guard_scope() returns trigger language plpgsql as $$
begin
  if private.is_human() then
    if new.authorized and (tg_op = 'INSERT' or not old.authorized) then
      if not private.has_role(new.org_id, array['owner','it_admin']) then raise exception 'Only an owner or IT administrator can authorize a scope' using errcode = '42501'; end if;
      new.authorized_by := auth.uid(); new.authorized_at := now();
    end if;
    if tg_op = 'INSERT' then new.created_by := auth.uid(); end if;
  end if;
  if not new.authorized then new.authorized_by := null; new.authorized_at := null; end if;
  return new;
end $$;
drop trigger if exists scan_scopes_guard on public.scan_scopes;
create trigger scan_scopes_guard before insert or update on public.scan_scopes for each row execute function private.guard_scope();
drop trigger if exists scan_scopes_touch on public.scan_scopes;
create trigger scan_scopes_touch before update on public.scan_scopes for each row execute function private.touch_updated_at();

-- Withdrawing authorization stops work that has not finished.
create or replace function private.scope_deauthorized() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.authorized and not new.authorized then
    update public.scan_jobs set status = 'cancelled', finished_at = now(), message = 'Scope authorization was withdrawn'
      where scope_id = new.id and org_id = new.org_id and status in ('pending_approval','queued');
    update public.scan_jobs set cancel_requested = true where scope_id = new.id and org_id = new.org_id and status in ('claimed','running');
  end if;
  return new;
end $$;
drop trigger if exists scan_scopes_deauth on public.scan_scopes;
create trigger scan_scopes_deauth after update on public.scan_scopes for each row execute function private.scope_deauthorized();

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  scope_id uuid not null,
  agent_id uuid,
  kind text not null check (kind in ('discovery','service_discovery','port_scan','vuln_assessment','config_review')),
  profile text not null default 'safe' check (profile in ('safe','standard')),       -- no destructive profile exists
  methods text[] not null default '{icmp,arp,dns,tcp}' check (methods <@ array['icmp','arp','dns','tcp','snmp','lldp','cdp','service']),
  options jsonb not null default '{}'::jsonb,
  status text not null default 'pending_approval' check (status in ('pending_approval','queued','claimed','running','completed','failed','cancelled','expired')),
  approval_id uuid,
  requested_by uuid references auth.users on delete set null,
  scheduled_for timestamptz,
  schedule_id uuid,
  total_targets int, done int not null default 0, found int not null default 0,
  rejected_out_of_scope int not null default 0,       -- hosts the agent reported outside the approved scope; they are dropped and counted
  cancel_requested boolean not null default false,
  message text, error text,
  created_at timestamptz not null default now(),
  claimed_at timestamptz, started_at timestamptz, last_beat_at timestamptz, finished_at timestamptz,
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete restrict,
  foreign key (org_id, agent_id) references public.network_agents (org_id, id) on delete set null (agent_id),
  foreign key (org_id, approval_id) references public.approvals (org_id, id) on delete set null (approval_id)
);
create index if not exists scan_jobs_org_status on public.scan_jobs (org_id, status, created_at desc);
create index if not exists scan_jobs_queue on public.scan_jobs (org_id, created_at) where status = 'queued';
create index if not exists scan_jobs_scope on public.scan_jobs (org_id, scope_id, created_at desc);

-- A job cannot be queued or run unless its scope is authorized, and probing jobs need an approved approval record.
create or replace function private.guard_scan_job() returns trigger language plpgsql as $$
declare s public.scan_scopes; a public.approvals;
begin
  if private.is_human() then
    if tg_op = 'INSERT' then
      if new.status not in ('pending_approval','queued') then raise exception 'A job starts as pending_approval or queued' using errcode = '42501'; end if;
      new.requested_by := auth.uid();
    end if;
  end if;
  if tg_op = 'INSERT' or new.status is distinct from old.status then
    if new.status in ('queued','claimed','running') then
      select * into s from public.scan_scopes where id = new.scope_id and org_id = new.org_id;
      if not found then raise exception 'Scope not found in this organization' using errcode = '23503'; end if;
      if not s.authorized then raise exception 'The scan scope is not authorized' using errcode = '42501'; end if;
      if new.kind in ('vuln_assessment','config_review') then
        select * into a from public.approvals where id = new.approval_id and org_id = new.org_id;
        if not found or a.status not in ('approved','executed') then raise exception '% jobs need an approved approval record', new.kind using errcode = '42501'; end if;
      end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists scan_jobs_guard on public.scan_jobs;
create trigger scan_jobs_guard before insert or update on public.scan_jobs for each row execute function private.guard_scan_job();

create table if not exists public.scan_schedules (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  scope_id uuid not null,
  kind text not null check (kind in ('discovery','service_discovery')),
  methods text[] not null default '{icmp,arp,dns,tcp}' check (methods <@ array['icmp','arp','dns','tcp','snmp','lldp','cdp','service']),
  options jsonb not null default '{}'::jsonb,
  cron text not null check (char_length(cron) between 9 and 60),
  enabled boolean not null default true,
  next_run_at timestamptz, last_run_at timestamptz,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete cascade
);
create index if not exists scan_schedules_due on public.scan_schedules (next_run_at) where enabled;

-- Atomic job hand-out to an agent (the backend calls this after authenticating the agent). No two agents get the same job.
create or replace function private.claim_next_job(p_agent uuid) returns public.scan_jobs
language plpgsql security definer set search_path = '' as $$
declare a public.network_agents; j public.scan_jobs;
begin
  select * into a from public.network_agents where id = p_agent and status <> 'revoked' and revoked_at is null;
  if not found then return null; end if;
  select * into j from public.scan_jobs
   where org_id = a.org_id and status = 'queued' and (agent_id is null or agent_id = a.id) and (scheduled_for is null or scheduled_for <= now())
     and case kind when 'discovery' then 'discovery' = any(a.capabilities)
                   when 'service_discovery' then a.capabilities && array['discovery','scanner']
                   else 'scanner' = any(a.capabilities) end
   order by created_at limit 1 for update skip locked;
  if not found then return null; end if;
  update public.scan_jobs set status = 'claimed', agent_id = a.id, claimed_at = now(), last_beat_at = now() where id = j.id returning * into j;
  update public.network_agents set last_seen_at = now(), status = 'online' where id = a.id;
  return j;
end $$;
revoke all on function private.claim_next_job(uuid) from public, anon, authenticated;
grant execute on function private.claim_next_job(uuid) to service_role;

-- ---------- discovered inventory ----------
create table if not exists public.net_devices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  identity_key text not null,                         -- stable key computed by the backend (MAC when confirmed, otherwise address within the scope)
  primary_ip inet, primary_mac macaddr, hostname text, fqdn text,
  device_type text not null default 'unknown' check (device_type in ('router','switch','firewall','server','vm','hypervisor','workstation','printer','access_point','storage','load_balancer','appliance','unknown')),
  type_confidence text not null default 'unknown' check (type_confidence in ('confirmed','inferred','unknown')),
  vendor text, vendor_confidence text not null default 'unknown' check (vendor_confidence in ('confirmed','inferred','unknown')),
  model text, serial text, sys_descr text, sys_object_id text,
  os_name text, os_version text, os_confidence text not null default 'unknown' check (os_confidence in ('confirmed','inferred','unknown')),
  adapter_key text,                                   -- which fingerprint profile matched (cisco, fortinet, ubiquiti, mikrotik, aruba_hp, juniper, generic_snmp, windows, linux, ...). Vendor modules plug in here later.
  capabilities jsonb not null default '{}'::jsonb,
  status text not null default 'unknown' check (status in ('online','offline','warning','unknown')),
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz, missing_since timestamptz,
  discovery_methods text[] not null default '{}',
  last_scan_job_id uuid,
  label text, description text, location text, owner_label text,
  criticality text not null default 'normal' check (criticality in ('low','normal','high','critical')),
  group_name text, tags text[] not null default '{}',
  attrs jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (org_id, id), unique (org_id, identity_key)
);
create index if not exists net_devices_org_status on public.net_devices (org_id, status);
create index if not exists net_devices_org_type on public.net_devices (org_id, device_type);
create index if not exists net_devices_org_ip on public.net_devices (org_id, primary_ip);
create index if not exists net_devices_org_host on public.net_devices (org_id, lower(hostname));
create index if not exists net_devices_org_seen on public.net_devices (org_id, last_seen_at desc);
drop trigger if exists net_devices_touch on public.net_devices;
create trigger net_devices_touch before update on public.net_devices for each row execute function private.touch_updated_at();

create table if not exists public.net_device_interfaces (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  device_id uuid not null,
  name text not null, if_index int, mac macaddr, ips inet[] not null default '{}',
  speed_mbps bigint, admin_up boolean, oper_up boolean, vlan_id int check (vlan_id between 1 and 4094), description text,
  last_seen_at timestamptz,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete cascade,
  unique (device_id, name)
);
create index if not exists net_if_org_device on public.net_device_interfaces (org_id, device_id);

create table if not exists public.net_device_services (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  device_id uuid not null,
  port int not null check (port between 1 and 65535), proto text not null default 'tcp' check (proto in ('tcp','udp')),
  state text not null default 'open' check (state in ('open','closed','filtered')),
  service_name text, product text, version text,
  confidence text not null default 'confirmed' check (confidence in ('confirmed','inferred')),
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete cascade,
  unique (device_id, proto, port)
);
create index if not exists net_services_org_device on public.net_device_services (org_id, device_id);

create table if not exists public.net_links (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  a_device_id uuid not null, b_device_id uuid not null,
  a_port text, b_port text,
  protocol text not null check (protocol in ('lldp','cdp','arp','fdb','snmp','inferred')),
  confidence text not null check (confidence in ('confirmed','inferred')),     -- never present an inferred link as confirmed
  evidence jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  foreign key (org_id, a_device_id) references public.net_devices (org_id, id) on delete cascade,
  foreign key (org_id, b_device_id) references public.net_devices (org_id, id) on delete cascade,
  check (a_device_id < b_device_id),                  -- one canonical direction, so a link cannot be stored twice
  check (confidence = 'inferred' or protocol in ('lldp','cdp','snmp'))
);
create unique index if not exists net_links_unique on public.net_links (org_id, a_device_id, b_device_id, coalesce(a_port,''), coalesce(b_port,''), protocol);
create index if not exists net_links_a on public.net_links (org_id, a_device_id);
create index if not exists net_links_b on public.net_links (org_id, b_device_id);

create table if not exists public.net_segments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 120),
  kind text not null default 'subnet' check (kind in ('subnet','vlan','site','custom')),
  cidr cidr, vlan_id int check (vlan_id between 1 and 4094), location text, description text,
  created_by uuid references auth.users on delete set null, created_at timestamptz not null default now(),
  unique (org_id, name)
);

-- High-volume, append-only observations (the table to partition by time when an organization reaches millions of rows).
create table if not exists public.scan_results (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid not null,
  device_id uuid,
  ip inet not null, observed_at timestamptz not null default now(),
  up boolean not null, rtt_ms numeric(9,2), methods text[] not null default '{}',
  data jsonb not null default '{}'::jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete cascade,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete set null (device_id)
);
create index if not exists scan_results_job on public.scan_results (org_id, job_id);
create index if not exists scan_results_device on public.scan_results (org_id, device_id, observed_at desc);

create table if not exists public.topology_snapshots (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid, taken_at timestamptz not null default now(),
  device_count int not null, link_count int not null, online_count int not null default 0,
  summary jsonb not null default '{}'::jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete set null (job_id)
);
create index if not exists topology_snapshots_org on public.topology_snapshots (org_id, taken_at desc);

create table if not exists public.topology_changes (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid, at timestamptz not null default now(),
  change_type text not null check (change_type in ('device_added','device_removed','device_changed','device_status','link_added','link_removed')),
  entity_type text not null check (entity_type in ('device','link')), entity_id uuid not null,
  before jsonb, after jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete set null (job_id)
);
create index if not exists topology_changes_org on public.topology_changes (org_id, at desc);
create index if not exists topology_changes_entity on public.topology_changes (org_id, entity_id, at desc);

-- ---------- privileges and RLS ----------
do $$ declare t text; begin
  foreach t in array array['scan_scopes','scan_jobs','scan_schedules','net_devices','net_device_interfaces','net_device_services','net_links','net_segments','scan_results','topology_snapshots','topology_changes'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('drop policy if exists %I on public.%I', t || '_select', t);
    execute format('create policy %I on public.%I for select to authenticated using (private.is_member(org_id))', t || '_select', t);
  end loop; end $$;

-- scopes and schedules: owners and IT administrators manage them
grant insert, update, delete on public.scan_scopes, public.scan_schedules to authenticated;
drop policy if exists scan_scopes_write on public.scan_scopes;
create policy scan_scopes_write on public.scan_scopes for all to authenticated using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));
drop policy if exists scan_schedules_write on public.scan_schedules;
create policy scan_schedules_write on public.scan_schedules for all to authenticated using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));

-- jobs: discovery by operators, assessment jobs by security analysts; everyone with a role may only request cancellation afterwards
grant insert on public.scan_jobs to authenticated;
grant update (cancel_requested) on public.scan_jobs to authenticated;
drop policy if exists scan_jobs_insert on public.scan_jobs;
create policy scan_jobs_insert on public.scan_jobs for insert to authenticated with check (
  case when kind in ('discovery','service_discovery') then private.has_role(org_id, array['owner','it_admin','noc_operator'])
       else private.has_role(org_id, array['owner','it_admin','security_analyst']) end);
drop policy if exists scan_jobs_cancel on public.scan_jobs;
create policy scan_jobs_cancel on public.scan_jobs for update to authenticated
  using (case when kind in ('discovery','service_discovery') then private.has_role(org_id, array['owner','it_admin','noc_operator'])
              else private.has_role(org_id, array['owner','it_admin','security_analyst']) end)
  with check (private.is_member(org_id));

-- devices: discovery data is written only by the backend; people edit documentation fields only
grant update (label, description, location, owner_label, criticality, group_name, tags) on public.net_devices to authenticated;
drop policy if exists net_devices_document on public.net_devices;
create policy net_devices_document on public.net_devices for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','noc_operator'])) with check (private.has_role(org_id, array['owner','it_admin','noc_operator']));

grant insert, update, delete on public.net_segments to authenticated;
drop policy if exists net_segments_write on public.net_segments;
create policy net_segments_write on public.net_segments for all to authenticated using (private.has_role(org_id, array['owner','it_admin','noc_operator'])) with check (private.has_role(org_id, array['owner','it_admin','noc_operator']));

insert into private.app_migrations (version, name) values ('0103', 'discovery_topology') on conflict do nothing;
commit;

-- ===== 0104_assessments_findings.sql =====
-- 0104_assessments_findings.sql  |  Security assessments, vulnerability findings, reports.
-- Security data is visible only to owner, it_admin, security_analyst and executive_readonly. NOC operators do not see it.
begin;

create table if not exists public.assessments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 160),
  scope_id uuid not null,
  status text not null default 'draft' check (status in ('draft','scope_validation','awaiting_authorization','awaiting_approval','scanning','analyzing','awaiting_review','remediation_planning','reporting','completed','cancelled','failed')),
  profile text not null default 'safe' check (profile in ('safe','standard')),
  categories text[] not null default '{network,vulnerability}' check (categories <@ array['network','vulnerability','web_app','infrastructure','configuration'] and cardinality(categories) > 0),
  tools text[] not null default '{}' check (tools <@ array['nmap','greenbone','zap','cis','spark_check']),
  window_start timestamptz, window_end timestamptz,
  authorization_confirmed_by uuid references auth.users on delete set null,
  authorization_confirmed_at timestamptz,
  authorization_statement text,
  approval_id uuid,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  started_at timestamptz, finished_at timestamptz,
  posture_score int check (posture_score between 0 and 100),
  summary jsonb not null default '{}'::jsonb,
  limitations text,
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete restrict,
  foreign key (org_id, approval_id) references public.approvals (org_id, id) on delete set null (approval_id),
  check (window_end is null or window_start is null or window_end > window_start),
  -- No scanning, analysis or reporting stage can exist without an administrator's explicit authorization.
  check (status in ('draft','scope_validation','awaiting_authorization','cancelled')
         or (authorization_confirmed_at is not null and authorization_statement is not null and char_length(authorization_statement) >= 20))
);
create index if not exists assessments_org on public.assessments (org_id, created_at desc);
create index if not exists assessments_scope on public.assessments (org_id, scope_id);

create or replace function private.guard_assessment() returns trigger language plpgsql as $$
begin
  if private.is_human() then
    if tg_op = 'INSERT' then new.created_by := auth.uid(); end if;
    if new.authorization_confirmed_at is not null and (tg_op = 'INSERT' or old.authorization_confirmed_at is null) then
      if not private.has_role(new.org_id, array['owner','it_admin']) then raise exception 'Only an owner or IT administrator can confirm authorization' using errcode = '42501'; end if;
      new.authorization_confirmed_by := auth.uid(); new.authorization_confirmed_at := now();
    end if;
    if tg_op = 'UPDATE' and old.authorization_confirmed_at is not null
       and (new.authorization_confirmed_at, new.authorization_statement, new.scope_id) is distinct from (old.authorization_confirmed_at, old.authorization_statement, old.scope_id) then
      raise exception 'The confirmed authorization and scope cannot be changed; start a new assessment' using errcode = '42501'; end if;
  end if;
  if new.status in ('scanning','analyzing') and not exists (select 1 from public.scan_scopes s where s.id = new.scope_id and s.org_id = new.org_id and s.authorized) then
    raise exception 'The assessment scope is not authorized' using errcode = '42501'; end if;
  return new;
end $$;
drop trigger if exists assessments_guard on public.assessments;
create trigger assessments_guard before insert or update on public.assessments for each row execute function private.guard_assessment();
drop trigger if exists assessments_touch on public.assessments;
create trigger assessments_touch before update on public.assessments for each row execute function private.touch_updated_at();

create table if not exists public.vulnerability_findings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  assessment_id uuid not null,
  device_id uuid,
  fingerprint text not null,                           -- stable key (device + check + port); the same weakness in two assessments shares it, which enables comparison and recurrence detection
  source text not null check (source in ('nmap','greenbone','zap','cis','spark_check','import','manual','ai')),
  source_ref text,                                     -- scanner plugin / OID / rule id
  title text not null check (char_length(title) between 3 and 300), description text,
  category text not null check (category in ('network','vulnerability','web_app','infrastructure','configuration')),
  severity text not null check (severity in ('info','low','medium','high','critical')),
  cvss numeric(3,1) check (cvss between 0 and 10),
  cve text[] not null default '{}', cwe text[] not null default '{}', mitre text[] not null default '{}',
  provenance text not null check (provenance in ('scanner_verified','analyst_confirmed','ai_hypothesis')),
  confidence text not null default 'medium' check (confidence in ('low','medium','high')),
  evidence jsonb not null default '{}'::jsonb,
  remediation text,
  ai_analysis jsonb,                                   -- explanation, business impact, attack-path reasoning: always labelled as AI output
  status text not null default 'open' check (status in ('open','in_progress','remediated','accepted_risk','false_positive','retest')),
  status_by uuid references auth.users on delete set null, status_at timestamptz, status_note text,
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  unique (org_id, id), unique (assessment_id, fingerprint),
  foreign key (org_id, assessment_id) references public.assessments (org_id, id) on delete cascade,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete set null (device_id),
  -- An AI hypothesis can never be stored as scanner-verified, and "verified" needs a real scanner as its source with evidence.
  check (provenance <> 'scanner_verified' or (source in ('nmap','greenbone','zap','cis','spark_check') and evidence <> '{}'::jsonb)),
  check (source <> 'ai' or provenance = 'ai_hypothesis')
);
create index if not exists findings_assessment on public.vulnerability_findings (org_id, assessment_id, severity);
create index if not exists findings_device on public.vulnerability_findings (org_id, device_id);
create index if not exists findings_fp on public.vulnerability_findings (org_id, fingerprint);
create index if not exists findings_open on public.vulnerability_findings (org_id, severity) where status in ('open','in_progress','retest');

create or replace function private.guard_finding() returns trigger language plpgsql as $$
begin
  if private.is_human() and tg_op = 'UPDATE' and new.status is distinct from old.status then
    new.status_by := auth.uid(); new.status_at := now();
  end if;
  return new;
end $$;
drop trigger if exists findings_guard on public.vulnerability_findings;
create trigger findings_guard before update on public.vulnerability_findings for each row execute function private.guard_finding();

create table if not exists public.assessment_reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  assessment_id uuid not null,
  version int not null default 1,
  format text not null default 'pdf' check (format in ('pdf')),
  storage_path text not null, sha256 text not null, size_bytes bigint not null check (size_bytes > 0),
  generated_by uuid references auth.users on delete set null,
  generated_at timestamptz not null default now(),
  foreign key (org_id, assessment_id) references public.assessments (org_id, id) on delete cascade,
  unique (assessment_id, version)
);

do $$ declare t text; begin
  foreach t in array array['assessments','vulnerability_findings','assessment_reports'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('drop policy if exists %I on public.%I', t || '_select', t);
    execute format('create policy %I on public.%I for select to authenticated using (private.has_role(org_id, array[''owner'',''it_admin'',''security_analyst'',''executive_readonly'']))', t || '_select', t);
  end loop; end $$;

grant insert on public.assessments to authenticated;
grant update (name, status, profile, categories, tools, window_start, window_end, authorization_confirmed_at, authorization_statement, limitations) on public.assessments to authenticated;
drop policy if exists assessments_insert on public.assessments;
create policy assessments_insert on public.assessments for insert to authenticated with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));
drop policy if exists assessments_update on public.assessments;
create policy assessments_update on public.assessments for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','security_analyst'])) with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));

grant update (status, status_note) on public.vulnerability_findings to authenticated;
drop policy if exists findings_update on public.vulnerability_findings;
create policy findings_update on public.vulnerability_findings for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','security_analyst'])) with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));

insert into private.app_migrations (version, name) values ('0104', 'assessments_findings') on conflict do nothing;
commit;

-- ===== 0105_legacy_tables_org.sql =====
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

