-- Minimal stand-ins for what a real Supabase project already provides (plain scratch Postgres only).
create schema if not exists auth;
create or replace function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create or replace function auth.jwt() returns jsonb language sql stable as $$ select '{}'::jsonb $$;
create schema if not exists extensions; create extension if not exists pgcrypto schema extensions;
create table if not exists auth.users (id uuid primary key, email text);
