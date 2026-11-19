begin;
drop trigger if exists sales_audit_no_change on public.sales_audit;
drop table if exists public.sales_followups; drop table if exists public.sales_activities; drop table if exists public.sales_audit; drop table if exists public.sales_leads;
drop function if exists public.sales_audit_immutable();
delete from private.app_migrations where version = '0118';
commit;
