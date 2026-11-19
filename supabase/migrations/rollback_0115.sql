begin;
delete from public.billing_plans where id in ('basic','standard','professional','business');
alter table public.billing_plans drop constraint if exists billing_plans_id_check;
alter table public.billing_plans add constraint billing_plans_id_check check (id in ('free','pro','enterprise'));
delete from private.app_migrations where version = '0115';
commit;
