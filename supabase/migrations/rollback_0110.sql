-- Rollback for 0110 (scratch/dev only). Drops only objects created by 0110.
begin;
drop table if exists public.billing_payments, public.billing_invoices, public.billing_settings, public.billing_plans;
alter table public.org_billing drop column if exists billing_interval, drop column if exists trial_started_at, drop column if exists trial_ends_at, drop column if exists overrides, drop column if exists last_payment_failed_at;
delete from private.app_migrations where version = '0110';
commit;
