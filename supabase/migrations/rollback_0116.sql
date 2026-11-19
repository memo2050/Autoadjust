begin;
drop table if exists public.support_messages; drop table if exists public.support_tickets;
delete from private.app_migrations where version = '0116';
commit;
