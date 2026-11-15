-- 0111 | Collector key scopes and IP allowlists. Additive; existing keys keep working (null scopes = all scopes).
-- DO NOT APPLY TO PRODUCTION without explicit owner approval. Staging / scratch only.
begin;
alter table public.org_api_keys
  add column if not exists scopes text[] check (scopes is null or scopes <@ array['soc','noc','executor','discovery']::text[]),
  add column if not exists allowed_ips text[] check (allowed_ips is null or cardinality(allowed_ips) <= 20);
insert into private.app_migrations (version, name) values ('0111', 'collector_key_scopes') on conflict do nothing;
commit;
