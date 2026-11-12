-- Spark NOC telemetry (phase 4). Run once in the Supabase SQL editor after 004. Safe to run twice.
create table if not exists noc_devices (
  id text primary key, name text, type text not null, ip text, source text default 'live', up boolean default true,
  metrics jsonb default '{}', links jsonb default '[]', config jsonb, history jsonb default '[]', received_at text, collector text
);
alter table noc_devices enable row level security;
