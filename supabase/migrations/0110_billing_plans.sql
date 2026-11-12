-- 0110 | Configurable plans, trials, per-organization overrides, invoices and payments. Additive only (no existing table or row is changed destructively).
-- DO NOT APPLY TO PRODUCTION without explicit owner approval. Tested on a scratch database only.
begin;
alter table public.org_billing
  add column if not exists billing_interval text check (billing_interval in ('month','year')),
  add column if not exists trial_started_at timestamptz, add column if not exists trial_ends_at timestamptz,
  add column if not exists overrides jsonb not null default '{}'::jsonb,
  add column if not exists last_payment_failed_at timestamptz;
create table if not exists public.billing_plans (
  id text primary key check (id in ('free','pro','enterprise')), name text not null,
  max_devices integer not null check (max_devices >= 0), max_api_keys integer not null check (max_api_keys >= 0), max_executors integer not null check (max_executors >= 0),
  retention_days integer not null check (retention_days >= 1), trial_days integer not null default 0 check (trial_days between 0 and 365),
  price_monthly_cents integer check (price_monthly_cents >= 0), price_annual_cents integer check (price_annual_cents >= 0),
  features jsonb not null default '[]'::jsonb, active boolean not null default true, updated_at timestamptz not null default now()
);
create table if not exists public.billing_settings (key text primary key, value text not null, updated_at timestamptz not null default now());
create table if not exists public.billing_invoices (
  id text primary key, org_id uuid not null references public.organizations(id) on delete restrict, number text, status text not null,
  amount_due bigint not null default 0, amount_paid bigint not null default 0, currency text not null default 'usd',
  hosted_url text, pdf_url text, period_start timestamptz, period_end timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists billing_invoices_org on public.billing_invoices (org_id, created_at desc);
create table if not exists public.billing_payments (
  id text primary key, org_id uuid not null references public.organizations(id) on delete restrict, invoice_id text, status text not null,
  amount bigint not null default 0, refunded bigint not null default 0, currency text not null default 'usd', created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists billing_payments_org on public.billing_payments (org_id, created_at desc);
alter table public.billing_plans enable row level security; alter table public.billing_settings enable row level security;
alter table public.billing_invoices enable row level security; alter table public.billing_payments enable row level security;
revoke all on public.billing_plans, public.billing_settings, public.billing_invoices, public.billing_payments from anon, authenticated;   -- server (service role) only
insert into private.app_migrations (version, name) values ('0110', 'billing_plans') on conflict do nothing;
commit;
