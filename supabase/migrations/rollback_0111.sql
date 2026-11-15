begin;
alter table public.org_api_keys drop column if exists scopes, drop column if exists allowed_ips;
delete from private.app_migrations where version = '0111';
commit;
