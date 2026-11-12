-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
-- Built-in database for generated apps (run once in the Supabase SQL editor)
create table if not exists app_records (
  id uuid primary key default gen_random_uuid(),
  app_id text not null,
  collection text not null,
  data jsonb not null,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index if not exists app_records_lookup on app_records (app_id, collection, created_at desc);
alter table app_records enable row level security; -- no policies: only the server (service role) can read/write
