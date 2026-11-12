-- 0106_org_api_keys.sql  |  Per-organization collector API keys (replaces the shared SOC_INGEST_TOKEN for customers). Additive; nothing existing is changed.
-- Only a SHA-256 hash of each key is stored. The table is reachable by the server (service role) only.
begin;
create table if not exists public.org_api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete restrict,
  name text not null check (char_length(btrim(name)) between 2 and 60),
  key_prefix text not null,
  key_hash text not null unique,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz
);
create index if not exists org_api_keys_org_idx on public.org_api_keys (org_id);
alter table public.org_api_keys enable row level security;
revoke all on public.org_api_keys from anon, authenticated;     -- no policies: unreachable through the public API; the server uses the service role
insert into private.app_migrations (version, name) values ('0106', 'org_api_keys') on conflict do nothing;
commit;
