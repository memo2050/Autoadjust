-- 0114 | "Request a Demo" submissions from the public website. Additive. Staging / scratch only until the owner approves a production migration.
-- No customer data: only what the visitor types into the form. RLS on with no policies = only the service role (server route) can read or write.
begin;
create table if not exists public.demo_requests (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 1 and 120),
  email text not null check (char_length(email) between 3 and 200),
  company text check (char_length(company) <= 160),
  message text check (char_length(message) <= 2000),
  source text not null default 'website' check (char_length(source) <= 40)
);
alter table public.demo_requests enable row level security;
revoke all on public.demo_requests from anon, authenticated;
insert into private.app_migrations (version, name) values ('0114', 'demo_requests') on conflict do nothing;
commit;
