-- 0115: allow the five launch pricing tiers in billing_plans (ADDITIVE; NOT applied anywhere yet; staging first, after explicit approval).
-- Display pricing lives in lib/billing/pricing.ts; payments stay disabled. This only widens the id check.
begin;
alter table public.billing_plans drop constraint if exists billing_plans_id_check;
alter table public.billing_plans add constraint billing_plans_id_check check (id in ('free','pro','enterprise','basic','standard','professional','business'));
insert into private.app_migrations (version, name) values ('0115', 'billing_tiers') on conflict do nothing;
commit;
