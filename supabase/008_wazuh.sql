-- Spark Wazuh integration. Run once in the Supabase SQL editor AFTER 007. Safe to run twice.
alter table soc_assets add column if not exists agent_id text, add column if not exists agent_status text, add column if not exists agent_version text,
  add column if not exists agent_synced_at text, add column if not exists wazuh_groups jsonb, add column if not exists last_contact_at text,
  add column if not exists collector text, add column if not exists collector_version text, add column if not exists last_batch int;
-- Sync state (cursor, last success/error, last connection test) is stored as JSON in soc_meta.
alter table soc_meta add column if not exists data jsonb;
