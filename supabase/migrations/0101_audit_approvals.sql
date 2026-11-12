-- 0101_audit_approvals.sql  |  Immutable hash-chained audit log and approval records (per organization).
begin;

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete restrict,
  at timestamptz not null default now(),
  actor_type text not null check (actor_type in ('user','agent','system')),
  actor_user_id uuid,
  actor_agent_id uuid,
  actor_label text,
  action text not null check (char_length(action) between 3 and 120),
  target_type text, target_id text,
  detail jsonb not null default '{}'::jsonb,
  prev_hash text, hash text
);
create index if not exists audit_log_org_id on public.audit_log (org_id, id desc);
create index if not exists audit_log_org_action on public.audit_log (org_id, action, at desc);

-- Each row stores the hash of the previous row of the same organization, so any edit or removal breaks the chain.
create or replace function private.audit_chain() returns trigger language plpgsql security definer set search_path = '' as $$
declare p text;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.org_id::text, 17));
  select hash into p from public.audit_log where org_id = new.org_id order by id desc limit 1;
  new.prev_hash := p;
  new.hash := encode(sha256(convert_to(coalesce(p,'') || '|' || new.org_id::text || '|' || new.at::text || '|' || new.actor_type || '|' ||
    coalesce(new.actor_user_id::text,'') || coalesce(new.actor_agent_id::text,'') || '|' || new.action || '|' || coalesce(new.target_type,'') || '|' ||
    coalesce(new.target_id,'') || '|' || new.detail::text, 'utf8')), 'hex');
  return new;
end $$;
drop trigger if exists audit_log_chain on public.audit_log;
create trigger audit_log_chain before insert on public.audit_log for each row execute function private.audit_chain();

create or replace function private.audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_log is append-only' using errcode = '42501'; end $$;
drop trigger if exists audit_log_no_change on public.audit_log;
create trigger audit_log_no_change before update or delete on public.audit_log for each row execute function private.audit_immutable();
drop trigger if exists audit_log_no_truncate on public.audit_log;
create trigger audit_log_no_truncate before truncate on public.audit_log for each statement execute function private.audit_immutable();

create or replace function private.verify_audit_chain(p_org uuid) returns table (ok boolean, checked bigint, broken_at bigint)
language plpgsql stable security definer set search_path = '' as $$
declare r record; p text := null; n bigint := 0; h text;
begin
  for r in select * from public.audit_log where org_id = p_org order by id loop
    h := encode(sha256(convert_to(coalesce(p,'') || '|' || r.org_id::text || '|' || r.at::text || '|' || r.actor_type || '|' ||
      coalesce(r.actor_user_id::text,'') || coalesce(r.actor_agent_id::text,'') || '|' || r.action || '|' || coalesce(r.target_type,'') || '|' ||
      coalesce(r.target_id,'') || '|' || r.detail::text, 'utf8')), 'hex');
    n := n + 1;
    if r.prev_hash is distinct from p or r.hash <> h then return query select false, n, r.id; return; end if;
    p := r.hash;
  end loop;
  return query select true, n, null::bigint;
end $$;
revoke all on function private.verify_audit_chain(uuid) from public, anon, authenticated;
grant execute on function private.verify_audit_chain(uuid) to service_role;

create table if not exists public.approvals (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete restrict,
  kind text not null check (kind in ('scan','assessment','config_change','remediation','agent_command','other')),
  subject_type text not null, subject_id text not null,
  summary text not null check (char_length(summary) between 3 and 500),
  impact text,
  risk text not null default 'medium' check (risk in ('low','medium','high','critical')),
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','rejected','expired','cancelled','executed','failed')),
  requested_by uuid references auth.users on delete set null,
  requested_at timestamptz not null default now(),
  decided_by uuid references auth.users on delete set null,
  decided_at timestamptz,
  decision_note text,
  expires_at timestamptz,
  executed_at timestamptz,
  result jsonb,
  unique (org_id, id),
  check (status not in ('approved','rejected','executed','failed') or decided_at is not null)
);
create index if not exists approvals_org_status on public.approvals (org_id, status, requested_at desc);
create index if not exists approvals_subject on public.approvals (org_id, subject_type, subject_id);

-- People may only move a pending approval to approved or rejected, may not edit what is being approved,
-- and (unless the organization allows it) may not approve their own request.
create or replace function private.guard_approval() returns trigger language plpgsql as $$
declare allow_self boolean;
begin
  if tg_op = 'INSERT' then
    if private.is_human() then
      if new.status <> 'pending' then raise exception 'An approval request starts as pending' using errcode = '42501'; end if;
      new.requested_by := auth.uid(); new.requested_at := now();
      new.decided_by := null; new.decided_at := null; new.executed_at := null; new.result := null;
    end if;
    return new;
  end if;
  if private.is_human() then
    if old.status <> 'pending' then raise exception 'This approval is already %', old.status using errcode = '42501'; end if;
    if new.status not in ('approved','rejected') then raise exception 'Only approve or reject is allowed' using errcode = '42501'; end if;
    if (new.org_id, new.kind, new.subject_type, new.subject_id, new.summary, new.impact, new.risk, new.payload, new.requested_by, new.requested_at, new.expires_at)
       is distinct from (old.org_id, old.kind, old.subject_type, old.subject_id, old.summary, old.impact, old.risk, old.payload, old.requested_by, old.requested_at, old.expires_at) then
      raise exception 'The request cannot be edited while deciding' using errcode = '42501'; end if;
    if old.expires_at is not null and old.expires_at < now() then raise exception 'This approval has expired' using errcode = '42501'; end if;
    select coalesce((settings->>'allow_self_approval')::boolean, false) into allow_self from public.organizations where id = old.org_id;
    if new.status = 'approved' and old.requested_by = auth.uid() and not allow_self then
      raise exception 'You cannot approve your own request (organization setting allow_self_approval is off)' using errcode = '42501'; end if;
    new.decided_by := auth.uid(); new.decided_at := now();
  end if;
  return new;
end $$;
drop trigger if exists approvals_guard on public.approvals;
create trigger approvals_guard before insert or update on public.approvals for each row execute function private.guard_approval();

-- privileges and RLS
alter table public.audit_log enable row level security;
alter table public.approvals enable row level security;
revoke all on public.audit_log, public.approvals from anon, authenticated;
grant select on public.audit_log to authenticated;
grant select, insert on public.approvals to authenticated;
grant update (status, decision_note) on public.approvals to authenticated;

drop policy if exists audit_log_select on public.audit_log;
create policy audit_log_select on public.audit_log for select to authenticated using (private.has_role(org_id, array['owner','it_admin','security_analyst']));
drop policy if exists approvals_select on public.approvals;
create policy approvals_select on public.approvals for select to authenticated using (private.is_member(org_id));
drop policy if exists approvals_insert on public.approvals;
create policy approvals_insert on public.approvals for insert to authenticated
  with check (private.has_role(org_id, array['owner','it_admin','noc_operator','security_analyst']) and status = 'pending');
drop policy if exists approvals_decide on public.approvals;
create policy approvals_decide on public.approvals for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));

insert into private.app_migrations (version, name) values ('0101', 'audit_approvals') on conflict do nothing;
commit;
