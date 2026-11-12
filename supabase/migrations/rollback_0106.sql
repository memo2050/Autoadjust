-- Rollback for 0106. Drops only the collector-key table (keys stop working; collectors fall back to the legacy shared token if still enabled).
begin;
drop table if exists public.org_api_keys;
delete from private.app_migrations where version = '0106';
commit;
