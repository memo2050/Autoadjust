-- 0113 | Customer data lifecycle: deletion requests (14-day hold + platform approval), tombstones, and an atomic hard-delete function. Additive.
-- DO NOT APPLY TO PRODUCTION without explicit owner approval. Staging / scratch only.
begin;
do $$ begin
  if to_regclass('public.org_members') is null or to_regclass('public.audit_log') is null or to_regclass('public.org_billing') is null or to_regclass('public.soc_audit') is null then
    raise exception '0113 requires 0100, 0101, 0107 and 0109 to be applied first';
  end if;
end $$;
create table if not exists public.org_deletion_requests (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,                                   -- no foreign key: the request outlives the organization
  requested_by uuid, requested_by_email text,
  requested_at timestamptz not null default now(),
  hold_until timestamptz not null,
  status text not null default 'requested' check (status in ('requested','cancelled','approved','completed','failed')),
  approved_by text, approved_at timestamptz, completed_at timestamptz, cancelled_at timestamptz, note text, error text
);
create unique index if not exists org_deletion_one_active on public.org_deletion_requests (org_id) where status in ('requested','approved');
create table if not exists public.org_tombstones (
  org_id uuid primary key, name_sha256 text not null, deleted_at timestamptz not null default now(),
  request_id uuid, approved_by text, row_counts jsonb not null default '{}'::jsonb, final_audit_seq bigint, final_audit_hash text
);
alter table public.org_deletion_requests enable row level security; alter table public.org_tombstones enable row level security;
revoke all on public.org_deletion_requests, public.org_tombstones from anon, authenticated;

-- Deletes EVERY row of one organization in a single transaction: all public tables with an org_id column (found dynamically, so tables added later are covered),
-- soc_meta rows namespaced "<org>:", then the organization itself. Leaves a tombstone (name hashed) holding the final audit-chain head. User accounts in auth.users are not touched.
create or replace function public.hard_delete_org(p_org uuid, p_request uuid, p_approver text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r record; req record; org record; counts jsonb := '{}'::jsonb; n bigint; pass int := 0; pending text[]; all_tables text[]; t text; fk_hit boolean; seq_v bigint; hash_v text;
begin
  if p_org = '00000000-0000-0000-0000-000000000001' then raise exception 'The Default organization cannot be deleted'; end if;
  select * into req from org_deletion_requests where id = p_request and org_id = p_org for update;
  if not found or req.status <> 'approved' then raise exception 'No approved deletion request for this organization'; end if;
  if req.hold_until > now() then raise exception 'The 14-day hold has not ended'; end if;
  select * into org from organizations where id = p_org for update; if not found then raise exception 'Organization not found'; end if;
  begin select seq, hash into seq_v, hash_v from soc_audit where org_id = p_org order by seq desc nulls last limit 1; exception when undefined_table then seq_v := null; hash_v := null; end;
  select array_agg(c.table_name::text order by c.table_name) into pending from information_schema.columns c join information_schema.tables tt on tt.table_schema = c.table_schema and tt.table_name = c.table_name and tt.table_type = 'BASE TABLE'
    where c.table_schema = 'public' and c.column_name = 'org_id' and c.table_name not in ('org_tombstones','org_deletion_requests');
  -- Append-only / last-owner guards are lifted only inside this function (one transaction, one organization), table by table; foreign-key checks stay on.
  foreach t in array pending loop execute format('alter table public.%I disable trigger user', t); end loop;
  all_tables := pending;
  while coalesce(array_length(pending, 1), 0) > 0 and pass < 8 loop
    pass := pass + 1; fk_hit := false;
    foreach t in array pending loop
      begin execute format('delete from public.%I where org_id = $1', t) using p_org; get diagnostics n = row_count; counts := counts || jsonb_build_object(t, coalesce((counts ->> t)::bigint, 0) + n); pending := array_remove(pending, t);
      exception when foreign_key_violation then fk_hit := true; end;
    end loop;
    exit when not fk_hit;
  end loop;
  foreach t in array all_tables loop execute format('alter table public.%I enable trigger user', t); end loop;
  if coalesce(array_length(pending, 1), 0) > 0 then raise exception 'Could not delete from: %', pending; end if;
  begin delete from public.soc_meta where id like p_org::text || ':%'; get diagnostics n = row_count; counts := counts || jsonb_build_object('soc_meta', n); exception when undefined_table then null; end;
  delete from public.organizations where id = p_org;
  insert into org_tombstones (org_id, name_sha256, request_id, approved_by, row_counts, final_audit_seq, final_audit_hash)
    values (p_org, encode(sha256(convert_to(org.name, 'UTF8')), 'hex'), p_request, p_approver, counts, seq_v, hash_v);
  update org_deletion_requests set status = 'completed', completed_at = now() where id = p_request;
  return jsonb_build_object('org_id', p_org, 'counts', counts, 'final_audit_seq', seq_v);
end $$;
revoke all on function public.hard_delete_org(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.hard_delete_org(uuid, uuid, text) to service_role;
insert into private.app_migrations (version, name) values ('0113', 'org_data_lifecycle') on conflict do nothing;
commit;
