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
