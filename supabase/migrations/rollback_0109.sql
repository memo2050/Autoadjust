-- Rolls back 0109 (drops billing state only; organizations.plan is untouched).
begin; drop table if exists public.billing_events; drop table if exists public.org_billing; delete from private.app_migrations where version = '0109'; commit;
