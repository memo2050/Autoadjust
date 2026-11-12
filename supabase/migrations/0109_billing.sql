-- 0109_billing.sql | Stripe subscription state per organization + webhook idempotency. Additive. DO NOT APPLY TO PRODUCTION without explicit owner approval.
begin;
create table if not exists public.org_billing (
  org_id uuid primary key references public.organizations(id) on delete restrict,
  customer_id text unique, subscription_id text unique,
  plan text not null default 'free' check (plan in ('free','pro','enterprise')),
  status text not null default 'none', current_period_end timestamptz, cancel_at_period_end boolean not null default false,
  last_event_at bigint not null default 0, updated_at timestamptz not null default now()
);
create table if not exists public.billing_events (id text primary key, type text not null, org_id uuid, processed_at timestamptz not null default now());
alter table public.org_billing enable row level security; alter table public.billing_events enable row level security;
revoke all on public.org_billing, public.billing_events from anon, authenticated;     -- server (service role) only; no policies
insert into private.app_migrations (version, name) values ('0109', 'billing') on conflict do nothing;
commit;
