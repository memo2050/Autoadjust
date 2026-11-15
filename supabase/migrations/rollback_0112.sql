begin;
drop function if exists public.rate_limit_hit(text, integer);
drop table if exists public.rate_limits;
delete from private.app_migrations where version = '0112';
commit;
