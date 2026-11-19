-- 0116 | Customer support tickets (chatbot / website). Additive. NOT applied anywhere yet; staging first, after explicit approval.
-- Server-only: RLS on with no policies and no grants, so only the service-role API routes can read/write. The tracking token is stored hashed (sha256).
begin;
create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  ref text not null unique check (ref ~ '^AA-[0-9A-F]{8}$'),
  token_hash text not null check (char_length(token_hash) = 64),
  user_id uuid, name text not null check (char_length(name) between 1 and 120), email text not null check (char_length(email) between 3 and 200),
  subject text not null check (char_length(subject) between 3 and 160),
  category text not null default 'general' check (category in ('general','technical','billing','security','account')),
  status text not null default 'open' check (status in ('open','in_progress','waiting_customer','resolved','closed')),
  lang text not null default 'en' check (lang in ('en','ar')),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid not null references public.support_tickets(id) on delete cascade,
  author text not null check (author in ('customer','support')),
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index if not exists support_messages_ticket_idx on public.support_messages(ticket_id, created_at);
alter table public.support_tickets enable row level security; alter table public.support_messages enable row level security;
create index if not exists support_tickets_user_idx on public.support_tickets(user_id) where user_id is not null;
revoke all on public.support_tickets, public.support_messages from public, anon, authenticated;
insert into private.app_migrations (version, name) values ('0116', 'support_tickets') on conflict do nothing;
commit;
