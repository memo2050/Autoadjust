-- 0118 | AI Sales Agent: leads, activity timeline, follow-up drafts, sales audit log. Additive. NOT applied anywhere; staging first, after explicit approval.
-- Operator-side (AutoAdjust's own sales data): NOT tenant/organization data. RLS on with no policies and no grants: only the service-role API routes can touch it; authorization (sales_admin/rep/viewer) is enforced in the API.
begin;
create table if not exists public.sales_leads (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  name text not null check (char_length(name) between 1 and 120),
  email text not null check (char_length(email) between 3 and 200),
  company text not null default '' check (char_length(company) <= 160),
  job_title text not null default '' check (char_length(job_title) <= 120),
  country text not null default '' check (char_length(country) <= 80),
  lang text not null default 'en' check (lang in ('en','ar')),
  source text not null default 'form' check (source in ('form','agent','manual')),
  endpoints integer check (endpoints between 0 and 100000), devices integer check (devices between 0 and 100000), users integer check (users between 0 and 10000), retention_days integer check (retention_days between 0 and 3650),
  budget_monthly_usd integer check (budget_monthly_usd >= 0),
  needs text[] not null default '{}', timeline text not null default 'unknown' check (timeline in ('now','1-3m','3-6m','later','unknown')),
  message text not null default '' check (char_length(message) <= 2000), demo_slots text[] not null default '{}',
  consent_contact boolean not null default false, unsubscribed boolean not null default false,
  status text not null default 'new' check (status in ('new','contacted','qualified','demo_requested','demo_scheduled','proposal','won','lost','disqualified')),
  score integer not null default 0 check (score between 0 and 100), grade text not null default 'D' check (grade in ('A','B','C','D')),
  qualification jsonb not null default '{}'::jsonb, recommended_plan text check (recommended_plan in ('basic','standard','professional','business','enterprise')), recommendation jsonb not null default '{}'::jsonb,
  owner_user_id uuid, lost_reason text check (char_length(lost_reason) <= 300), anonymized boolean not null default false
);
create unique index if not exists sales_leads_email_uidx on public.sales_leads (lower(email)) where anonymized = false;
create index if not exists sales_leads_status_idx on public.sales_leads (status, created_at desc);
create table if not exists public.sales_activities (
  id uuid primary key default gen_random_uuid(), lead_id uuid not null references public.sales_leads(id) on delete cascade,
  at timestamptz not null default now(), actor text not null check (char_length(actor) <= 200),
  kind text not null check (kind in ('created','note','status','qualification','assigned','updated','followup','resubmitted','anonymized')),
  body text not null default '' check (char_length(body) <= 4000)
);
create index if not exists sales_activities_lead_idx on public.sales_activities (lead_id, at desc);
create table if not exists public.sales_followups (
  id uuid primary key default gen_random_uuid(), lead_id uuid not null references public.sales_leads(id) on delete cascade,
  step integer not null check (step between 0 and 20), template text not null check (char_length(template) <= 40),
  subject text not null check (char_length(subject) between 1 and 200), body text not null check (char_length(body) between 1 and 6000), lang text not null default 'en' check (lang in ('en','ar')),
  status text not null default 'draft' check (status in ('draft','approved','dry_run','sent','cancelled')),
  due_at timestamptz not null, approved_by text, approved_at timestamptz, processed_at timestamptz, created_at timestamptz not null default now()
);
create index if not exists sales_followups_due_idx on public.sales_followups (status, due_at);
create table if not exists public.sales_audit (
  id bigint generated always as identity primary key, at timestamptz not null default now(),
  actor text not null check (char_length(actor) <= 200), action text not null check (char_length(action) <= 80), target text not null default '' check (char_length(target) <= 120), meta jsonb not null default '{}'::jsonb
);
alter table public.sales_leads enable row level security; alter table public.sales_activities enable row level security; alter table public.sales_followups enable row level security; alter table public.sales_audit enable row level security;
revoke all on public.sales_leads, public.sales_activities, public.sales_followups, public.sales_audit from public, anon, authenticated;
-- the audit log is append-only even for the service role through the API: no update/delete is ever issued by the app; this trigger enforces it at the database too.
create or replace function public.sales_audit_immutable() returns trigger language plpgsql as $$ begin raise exception 'sales_audit is append-only'; end $$;
drop trigger if exists sales_audit_no_change on public.sales_audit;
create trigger sales_audit_no_change before update or delete on public.sales_audit for each row execute function public.sales_audit_immutable();
insert into private.app_migrations (version, name) values ('0118', 'sales_agent') on conflict do nothing;
commit;
