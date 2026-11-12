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
