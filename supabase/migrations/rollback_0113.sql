begin;
drop function if exists public.hard_delete_org(uuid, uuid, text);
drop table if exists public.org_tombstones; drop table if exists public.org_deletion_requests;
delete from private.app_migrations where version = '0113';
commit;
