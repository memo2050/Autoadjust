begin;
drop table if exists public.demo_requests;
delete from private.app_migrations where version = '0114';
commit;
