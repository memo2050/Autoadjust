-- Extras so the local database behaves like Supabase for the hardening tests (applied after ../00_supabase_stub.sql).
alter table auth.users add column if not exists instance_id uuid, add column if not exists aud text, add column if not exists role text;
-- Same definition Supabase uses: reads the JWT claims JSON that PostgREST sets, with the legacy per-claim setting as fallback.
create or replace function auth.uid() returns uuid language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''), (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'))::uuid $$;
