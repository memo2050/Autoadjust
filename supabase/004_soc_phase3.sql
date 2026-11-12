-- Spark SOC phase 3. Run once in the Supabase SQL editor AFTER 003_soc.sql. Safe to run twice.
alter table soc_assets   add column if not exists last_contact_at text, add column if not exists collector text, add column if not exists collector_version text, add column if not exists last_batch int;
alter table soc_events   add column if not exists severity text;
alter table soc_incidents add column if not exists owner text;
alter table soc_audit    add column if not exists seq int, add column if not exists prev_hash text, add column if not exists hash text;
create index if not exists soc_events_ingested on soc_events (ingested_at);
-- Audit hash chain: each record has the next position in the chain; two writers cannot take the same position.
create unique index if not exists soc_audit_seq on soc_audit (seq) where seq is not null;
-- Immutable audit records: even the service role cannot change or delete them (drop these triggers deliberately to purge).
create or replace function soc_audit_immutable() returns trigger language plpgsql as $$ begin raise exception 'soc_audit is append-only'; end $$;
drop trigger if exists soc_audit_no_update on soc_audit; create trigger soc_audit_no_update before update on soc_audit for each row execute function soc_audit_immutable();
drop trigger if exists soc_audit_no_delete on soc_audit; create trigger soc_audit_no_delete before delete on soc_audit for each row execute function soc_audit_immutable();
-- Agent task runs with measured steps.
create table if not exists soc_tasks (
  id text primary key, role text not null, task text, actor text, status text not null, steps jsonb default '[]', steps_done int default 0, steps_total int default 0,
  progress int default 0, state jsonb default '{}', result jsonb, error text, context jsonb, retry_of text, investigation_id text, source text,
  created_at text, started_at text, ended_at text
);
create index if not exists soc_tasks_created on soc_tasks (created_at desc);
alter table soc_tasks enable row level security;
