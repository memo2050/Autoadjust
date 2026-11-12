-- 0104_assessments_findings.sql  |  Security assessments, vulnerability findings, reports.
-- Security data is visible only to owner, it_admin, security_analyst and executive_readonly. NOC operators do not see it.
begin;

create table if not exists public.assessments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 160),
  scope_id uuid not null,
  status text not null default 'draft' check (status in ('draft','scope_validation','awaiting_authorization','awaiting_approval','scanning','analyzing','awaiting_review','remediation_planning','reporting','completed','cancelled','failed')),
  profile text not null default 'safe' check (profile in ('safe','standard')),
  categories text[] not null default '{network,vulnerability}' check (categories <@ array['network','vulnerability','web_app','infrastructure','configuration'] and cardinality(categories) > 0),
  tools text[] not null default '{}' check (tools <@ array['nmap','greenbone','zap','cis','spark_check']),
  window_start timestamptz, window_end timestamptz,
  authorization_confirmed_by uuid references auth.users on delete set null,
  authorization_confirmed_at timestamptz,
  authorization_statement text,
  approval_id uuid,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  started_at timestamptz, finished_at timestamptz,
  posture_score int check (posture_score between 0 and 100),
  summary jsonb not null default '{}'::jsonb,
  limitations text,
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete restrict,
  foreign key (org_id, approval_id) references public.approvals (org_id, id) on delete set null (approval_id),
  check (window_end is null or window_start is null or window_end > window_start),
  -- No scanning, analysis or reporting stage can exist without an administrator's explicit authorization.
  check (status in ('draft','scope_validation','awaiting_authorization','cancelled')
         or (authorization_confirmed_at is not null and authorization_statement is not null and char_length(authorization_statement) >= 20))
);
create index if not exists assessments_org on public.assessments (org_id, created_at desc);
create index if not exists assessments_scope on public.assessments (org_id, scope_id);

create or replace function private.guard_assessment() returns trigger language plpgsql as $$
begin
  if private.is_human() then
    if tg_op = 'INSERT' then new.created_by := auth.uid(); end if;
    if new.authorization_confirmed_at is not null and (tg_op = 'INSERT' or old.authorization_confirmed_at is null) then
      if not private.has_role(new.org_id, array['owner','it_admin']) then raise exception 'Only an owner or IT administrator can confirm authorization' using errcode = '42501'; end if;
      new.authorization_confirmed_by := auth.uid(); new.authorization_confirmed_at := now();
    end if;
    if tg_op = 'UPDATE' and old.authorization_confirmed_at is not null
       and (new.authorization_confirmed_at, new.authorization_statement, new.scope_id) is distinct from (old.authorization_confirmed_at, old.authorization_statement, old.scope_id) then
      raise exception 'The confirmed authorization and scope cannot be changed; start a new assessment' using errcode = '42501'; end if;
  end if;
  if new.status in ('scanning','analyzing') and not exists (select 1 from public.scan_scopes s where s.id = new.scope_id and s.org_id = new.org_id and s.authorized) then
    raise exception 'The assessment scope is not authorized' using errcode = '42501'; end if;
  return new;
end $$;
drop trigger if exists assessments_guard on public.assessments;
create trigger assessments_guard before insert or update on public.assessments for each row execute function private.guard_assessment();
drop trigger if exists assessments_touch on public.assessments;
create trigger assessments_touch before update on public.assessments for each row execute function private.touch_updated_at();

create table if not exists public.vulnerability_findings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  assessment_id uuid not null,
  device_id uuid,
  fingerprint text not null,                           -- stable key (device + check + port); the same weakness in two assessments shares it, which enables comparison and recurrence detection
  source text not null check (source in ('nmap','greenbone','zap','cis','spark_check','import','manual','ai')),
  source_ref text,                                     -- scanner plugin / OID / rule id
  title text not null check (char_length(title) between 3 and 300), description text,
  category text not null check (category in ('network','vulnerability','web_app','infrastructure','configuration')),
  severity text not null check (severity in ('info','low','medium','high','critical')),
  cvss numeric(3,1) check (cvss between 0 and 10),
  cve text[] not null default '{}', cwe text[] not null default '{}', mitre text[] not null default '{}',
  provenance text not null check (provenance in ('scanner_verified','analyst_confirmed','ai_hypothesis')),
  confidence text not null default 'medium' check (confidence in ('low','medium','high')),
  evidence jsonb not null default '{}'::jsonb,
  remediation text,
  ai_analysis jsonb,                                   -- explanation, business impact, attack-path reasoning: always labelled as AI output
  status text not null default 'open' check (status in ('open','in_progress','remediated','accepted_risk','false_positive','retest')),
  status_by uuid references auth.users on delete set null, status_at timestamptz, status_note text,
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  unique (org_id, id), unique (assessment_id, fingerprint),
  foreign key (org_id, assessment_id) references public.assessments (org_id, id) on delete cascade,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete set null (device_id),
  -- An AI hypothesis can never be stored as scanner-verified, and "verified" needs a real scanner as its source with evidence.
  check (provenance <> 'scanner_verified' or (source in ('nmap','greenbone','zap','cis','spark_check') and evidence <> '{}'::jsonb)),
  check (source <> 'ai' or provenance = 'ai_hypothesis')
);
create index if not exists findings_assessment on public.vulnerability_findings (org_id, assessment_id, severity);
create index if not exists findings_device on public.vulnerability_findings (org_id, device_id);
create index if not exists findings_fp on public.vulnerability_findings (org_id, fingerprint);
create index if not exists findings_open on public.vulnerability_findings (org_id, severity) where status in ('open','in_progress','retest');

create or replace function private.guard_finding() returns trigger language plpgsql as $$
begin
  if private.is_human() and tg_op = 'UPDATE' and new.status is distinct from old.status then
    new.status_by := auth.uid(); new.status_at := now();
  end if;
  return new;
end $$;
drop trigger if exists findings_guard on public.vulnerability_findings;
create trigger findings_guard before update on public.vulnerability_findings for each row execute function private.guard_finding();

create table if not exists public.assessment_reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  assessment_id uuid not null,
  version int not null default 1,
  format text not null default 'pdf' check (format in ('pdf')),
  storage_path text not null, sha256 text not null, size_bytes bigint not null check (size_bytes > 0),
  generated_by uuid references auth.users on delete set null,
  generated_at timestamptz not null default now(),
  foreign key (org_id, assessment_id) references public.assessments (org_id, id) on delete cascade,
  unique (assessment_id, version)
);

do $$ declare t text; begin
  foreach t in array array['assessments','vulnerability_findings','assessment_reports'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('drop policy if exists %I on public.%I', t || '_select', t);
    execute format('create policy %I on public.%I for select to authenticated using (private.has_role(org_id, array[''owner'',''it_admin'',''security_analyst'',''executive_readonly'']))', t || '_select', t);
  end loop; end $$;

grant insert on public.assessments to authenticated;
grant update (name, status, profile, categories, tools, window_start, window_end, authorization_confirmed_at, authorization_statement, limitations) on public.assessments to authenticated;
drop policy if exists assessments_insert on public.assessments;
create policy assessments_insert on public.assessments for insert to authenticated with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));
drop policy if exists assessments_update on public.assessments;
create policy assessments_update on public.assessments for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','security_analyst'])) with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));

grant update (status, status_note) on public.vulnerability_findings to authenticated;
drop policy if exists findings_update on public.vulnerability_findings;
create policy findings_update on public.vulnerability_findings for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','security_analyst'])) with check (private.has_role(org_id, array['owner','it_admin','security_analyst']));

insert into private.app_migrations (version, name) values ('0104', 'assessments_findings') on conflict do nothing;
commit;
