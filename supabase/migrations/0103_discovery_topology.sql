-- 0103_discovery_topology.sql  |  Scan scopes (internal networks only), scan jobs, discovered devices, topology.
-- Tenant isolation is enforced twice: row level security AND composite foreign keys (org_id, id), so a row can never point at another organization's row.
begin;

-- ---------- internal-only scope rule, enforced in the database ----------
create or replace function private.cidr_ok(c cidr) returns boolean language sql immutable as $$
  select case family(c)
    when 4 then masklen(c) >= 16 and (c <<= '10.0.0.0/8'::cidr or c <<= '172.16.0.0/12'::cidr or c <<= '192.168.0.0/16'::cidr or c <<= '169.254.0.0/16'::cidr)
    else masklen(c) >= 112 and (c <<= 'fc00::/7'::cidr or c <<= 'fe80::/10'::cidr) end
$$;
create or replace function private.all_cidr_ok(cs cidr[]) returns boolean language sql immutable as $$
  select coalesce(bool_and(private.cidr_ok(x)), false) from unnest(cs) as x
$$;

create or replace function private.vlans_ok(v int[]) returns boolean language sql immutable as $$
  select coalesce(bool_and(x between 1 and 4094), true) from unnest(v) as x
$$;

create table if not exists public.scan_scopes (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 120),
  description text,
  kind text not null default 'internal' check (kind = 'internal'),   -- 'external' is added by a later migration, together with domain ownership verification
  targets cidr[] not null check (cardinality(targets) between 1 and 256 and private.all_cidr_ok(targets)),
  exclusions cidr[] not null default '{}',
  vlan_ids int[] not null default '{}' check (private.vlans_ok(vlan_ids)),
  agent_id uuid,                                                       -- the local agent / worker that scans this scope
  max_pps int not null default 50 check (max_pps between 1 and 1000),
  testing_window jsonb,                                                -- e.g. {"tz":"America/Los_Angeles","days":[1,2,3,4,5],"from":"20:00","to":"05:00"}
  authorized boolean not null default false,
  authorized_by uuid references auth.users on delete set null,
  authorized_at timestamptz,
  attestation text,                                                    -- the statement the administrator confirmed
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, id), unique (org_id, name),
  foreign key (org_id, agent_id) references public.network_agents (org_id, id) on delete set null (agent_id),
  check (not authorized or (authorized_at is not null and attestation is not null and char_length(attestation) >= 20))
);
create index if not exists scan_scopes_org on public.scan_scopes (org_id);

create or replace function private.guard_scope() returns trigger language plpgsql as $$
begin
  if private.is_human() then
    if new.authorized and (tg_op = 'INSERT' or not old.authorized) then
      if not private.has_role(new.org_id, array['owner','it_admin']) then raise exception 'Only an owner or IT administrator can authorize a scope' using errcode = '42501'; end if;
      new.authorized_by := auth.uid(); new.authorized_at := now();
    end if;
    if tg_op = 'INSERT' then new.created_by := auth.uid(); end if;
  end if;
  if not new.authorized then new.authorized_by := null; new.authorized_at := null; end if;
  return new;
end $$;
drop trigger if exists scan_scopes_guard on public.scan_scopes;
create trigger scan_scopes_guard before insert or update on public.scan_scopes for each row execute function private.guard_scope();
drop trigger if exists scan_scopes_touch on public.scan_scopes;
create trigger scan_scopes_touch before update on public.scan_scopes for each row execute function private.touch_updated_at();

-- Withdrawing authorization stops work that has not finished.
create or replace function private.scope_deauthorized() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.authorized and not new.authorized then
    update public.scan_jobs set status = 'cancelled', finished_at = now(), message = 'Scope authorization was withdrawn'
      where scope_id = new.id and org_id = new.org_id and status in ('pending_approval','queued');
    update public.scan_jobs set cancel_requested = true where scope_id = new.id and org_id = new.org_id and status in ('claimed','running');
  end if;
  return new;
end $$;
drop trigger if exists scan_scopes_deauth on public.scan_scopes;
create trigger scan_scopes_deauth after update on public.scan_scopes for each row execute function private.scope_deauthorized();

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  scope_id uuid not null,
  agent_id uuid,
  kind text not null check (kind in ('discovery','service_discovery','port_scan','vuln_assessment','config_review')),
  profile text not null default 'safe' check (profile in ('safe','standard')),       -- no destructive profile exists
  methods text[] not null default '{icmp,arp,dns,tcp}' check (methods <@ array['icmp','arp','dns','tcp','snmp','lldp','cdp','service']),
  options jsonb not null default '{}'::jsonb,
  status text not null default 'pending_approval' check (status in ('pending_approval','queued','claimed','running','completed','failed','cancelled','expired')),
  approval_id uuid,
  requested_by uuid references auth.users on delete set null,
  scheduled_for timestamptz,
  schedule_id uuid,
  total_targets int, done int not null default 0, found int not null default 0,
  rejected_out_of_scope int not null default 0,       -- hosts the agent reported outside the approved scope; they are dropped and counted
  cancel_requested boolean not null default false,
  message text, error text,
  created_at timestamptz not null default now(),
  claimed_at timestamptz, started_at timestamptz, last_beat_at timestamptz, finished_at timestamptz,
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete restrict,
  foreign key (org_id, agent_id) references public.network_agents (org_id, id) on delete set null (agent_id),
  foreign key (org_id, approval_id) references public.approvals (org_id, id) on delete set null (approval_id)
);
create index if not exists scan_jobs_org_status on public.scan_jobs (org_id, status, created_at desc);
create index if not exists scan_jobs_queue on public.scan_jobs (org_id, created_at) where status = 'queued';
create index if not exists scan_jobs_scope on public.scan_jobs (org_id, scope_id, created_at desc);

-- A job cannot be queued or run unless its scope is authorized, and probing jobs need an approved approval record.
create or replace function private.guard_scan_job() returns trigger language plpgsql as $$
declare s public.scan_scopes; a public.approvals;
begin
  if private.is_human() then
    if tg_op = 'INSERT' then
      if new.status not in ('pending_approval','queued') then raise exception 'A job starts as pending_approval or queued' using errcode = '42501'; end if;
      new.requested_by := auth.uid();
    end if;
  end if;
  if tg_op = 'INSERT' or new.status is distinct from old.status then
    if new.status in ('queued','claimed','running') then
      select * into s from public.scan_scopes where id = new.scope_id and org_id = new.org_id;
      if not found then raise exception 'Scope not found in this organization' using errcode = '23503'; end if;
      if not s.authorized then raise exception 'The scan scope is not authorized' using errcode = '42501'; end if;
      if new.kind in ('vuln_assessment','config_review') then
        select * into a from public.approvals where id = new.approval_id and org_id = new.org_id;
        if not found or a.status not in ('approved','executed') then raise exception '% jobs need an approved approval record', new.kind using errcode = '42501'; end if;
      end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists scan_jobs_guard on public.scan_jobs;
create trigger scan_jobs_guard before insert or update on public.scan_jobs for each row execute function private.guard_scan_job();

create table if not exists public.scan_schedules (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  scope_id uuid not null,
  kind text not null check (kind in ('discovery','service_discovery')),
  methods text[] not null default '{icmp,arp,dns,tcp}' check (methods <@ array['icmp','arp','dns','tcp','snmp','lldp','cdp','service']),
  options jsonb not null default '{}'::jsonb,
  cron text not null check (char_length(cron) between 9 and 60),
  enabled boolean not null default true,
  next_run_at timestamptz, last_run_at timestamptz,
  created_by uuid references auth.users on delete set null,
  created_at timestamptz not null default now(),
  unique (org_id, id),
  foreign key (org_id, scope_id) references public.scan_scopes (org_id, id) on delete cascade
);
create index if not exists scan_schedules_due on public.scan_schedules (next_run_at) where enabled;

-- Atomic job hand-out to an agent (the backend calls this after authenticating the agent). No two agents get the same job.
create or replace function private.claim_next_job(p_agent uuid) returns public.scan_jobs
language plpgsql security definer set search_path = '' as $$
declare a public.network_agents; j public.scan_jobs;
begin
  select * into a from public.network_agents where id = p_agent and status <> 'revoked' and revoked_at is null;
  if not found then return null; end if;
  select * into j from public.scan_jobs
   where org_id = a.org_id and status = 'queued' and (agent_id is null or agent_id = a.id) and (scheduled_for is null or scheduled_for <= now())
     and case kind when 'discovery' then 'discovery' = any(a.capabilities)
                   when 'service_discovery' then a.capabilities && array['discovery','scanner']
                   else 'scanner' = any(a.capabilities) end
   order by created_at limit 1 for update skip locked;
  if not found then return null; end if;
  update public.scan_jobs set status = 'claimed', agent_id = a.id, claimed_at = now(), last_beat_at = now() where id = j.id returning * into j;
  update public.network_agents set last_seen_at = now(), status = 'online' where id = a.id;
  return j;
end $$;
revoke all on function private.claim_next_job(uuid) from public, anon, authenticated;
grant execute on function private.claim_next_job(uuid) to service_role;

-- ---------- discovered inventory ----------
create table if not exists public.net_devices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  identity_key text not null,                         -- stable key computed by the backend (MAC when confirmed, otherwise address within the scope)
  primary_ip inet, primary_mac macaddr, hostname text, fqdn text,
  device_type text not null default 'unknown' check (device_type in ('router','switch','firewall','server','vm','hypervisor','workstation','printer','access_point','storage','load_balancer','appliance','unknown')),
  type_confidence text not null default 'unknown' check (type_confidence in ('confirmed','inferred','unknown')),
  vendor text, vendor_confidence text not null default 'unknown' check (vendor_confidence in ('confirmed','inferred','unknown')),
  model text, serial text, sys_descr text, sys_object_id text,
  os_name text, os_version text, os_confidence text not null default 'unknown' check (os_confidence in ('confirmed','inferred','unknown')),
  adapter_key text,                                   -- which fingerprint profile matched (cisco, fortinet, ubiquiti, mikrotik, aruba_hp, juniper, generic_snmp, windows, linux, ...). Vendor modules plug in here later.
  capabilities jsonb not null default '{}'::jsonb,
  status text not null default 'unknown' check (status in ('online','offline','warning','unknown')),
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz, missing_since timestamptz,
  discovery_methods text[] not null default '{}',
  last_scan_job_id uuid,
  label text, description text, location text, owner_label text,
  criticality text not null default 'normal' check (criticality in ('low','normal','high','critical')),
  group_name text, tags text[] not null default '{}',
  attrs jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (org_id, id), unique (org_id, identity_key)
);
create index if not exists net_devices_org_status on public.net_devices (org_id, status);
create index if not exists net_devices_org_type on public.net_devices (org_id, device_type);
create index if not exists net_devices_org_ip on public.net_devices (org_id, primary_ip);
create index if not exists net_devices_org_host on public.net_devices (org_id, lower(hostname));
create index if not exists net_devices_org_seen on public.net_devices (org_id, last_seen_at desc);
drop trigger if exists net_devices_touch on public.net_devices;
create trigger net_devices_touch before update on public.net_devices for each row execute function private.touch_updated_at();

create table if not exists public.net_device_interfaces (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  device_id uuid not null,
  name text not null, if_index int, mac macaddr, ips inet[] not null default '{}',
  speed_mbps bigint, admin_up boolean, oper_up boolean, vlan_id int check (vlan_id between 1 and 4094), description text,
  last_seen_at timestamptz,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete cascade,
  unique (device_id, name)
);
create index if not exists net_if_org_device on public.net_device_interfaces (org_id, device_id);

create table if not exists public.net_device_services (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  device_id uuid not null,
  port int not null check (port between 1 and 65535), proto text not null default 'tcp' check (proto in ('tcp','udp')),
  state text not null default 'open' check (state in ('open','closed','filtered')),
  service_name text, product text, version text,
  confidence text not null default 'confirmed' check (confidence in ('confirmed','inferred')),
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete cascade,
  unique (device_id, proto, port)
);
create index if not exists net_services_org_device on public.net_device_services (org_id, device_id);

create table if not exists public.net_links (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  a_device_id uuid not null, b_device_id uuid not null,
  a_port text, b_port text,
  protocol text not null check (protocol in ('lldp','cdp','arp','fdb','snmp','inferred')),
  confidence text not null check (confidence in ('confirmed','inferred')),     -- never present an inferred link as confirmed
  evidence jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
  foreign key (org_id, a_device_id) references public.net_devices (org_id, id) on delete cascade,
  foreign key (org_id, b_device_id) references public.net_devices (org_id, id) on delete cascade,
  check (a_device_id < b_device_id),                  -- one canonical direction, so a link cannot be stored twice
  check (confidence = 'inferred' or protocol in ('lldp','cdp','snmp'))
);
create unique index if not exists net_links_unique on public.net_links (org_id, a_device_id, b_device_id, coalesce(a_port,''), coalesce(b_port,''), protocol);
create index if not exists net_links_a on public.net_links (org_id, a_device_id);
create index if not exists net_links_b on public.net_links (org_id, b_device_id);

create table if not exists public.net_segments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 120),
  kind text not null default 'subnet' check (kind in ('subnet','vlan','site','custom')),
  cidr cidr, vlan_id int check (vlan_id between 1 and 4094), location text, description text,
  created_by uuid references auth.users on delete set null, created_at timestamptz not null default now(),
  unique (org_id, name)
);

-- High-volume, append-only observations (the table to partition by time when an organization reaches millions of rows).
create table if not exists public.scan_results (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid not null,
  device_id uuid,
  ip inet not null, observed_at timestamptz not null default now(),
  up boolean not null, rtt_ms numeric(9,2), methods text[] not null default '{}',
  data jsonb not null default '{}'::jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete cascade,
  foreign key (org_id, device_id) references public.net_devices (org_id, id) on delete set null (device_id)
);
create index if not exists scan_results_job on public.scan_results (org_id, job_id);
create index if not exists scan_results_device on public.scan_results (org_id, device_id, observed_at desc);

create table if not exists public.topology_snapshots (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid, taken_at timestamptz not null default now(),
  device_count int not null, link_count int not null, online_count int not null default 0,
  summary jsonb not null default '{}'::jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete set null (job_id)
);
create index if not exists topology_snapshots_org on public.topology_snapshots (org_id, taken_at desc);

create table if not exists public.topology_changes (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.organizations on delete cascade,
  job_id uuid, at timestamptz not null default now(),
  change_type text not null check (change_type in ('device_added','device_removed','device_changed','device_status','link_added','link_removed')),
  entity_type text not null check (entity_type in ('device','link')), entity_id uuid not null,
  before jsonb, after jsonb,
  foreign key (org_id, job_id) references public.scan_jobs (org_id, id) on delete set null (job_id)
);
create index if not exists topology_changes_org on public.topology_changes (org_id, at desc);
create index if not exists topology_changes_entity on public.topology_changes (org_id, entity_id, at desc);

-- ---------- privileges and RLS ----------
do $$ declare t text; begin
  foreach t in array array['scan_scopes','scan_jobs','scan_schedules','net_devices','net_device_interfaces','net_device_services','net_links','net_segments','scan_results','topology_snapshots','topology_changes'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('drop policy if exists %I on public.%I', t || '_select', t);
    execute format('create policy %I on public.%I for select to authenticated using (private.is_member(org_id))', t || '_select', t);
  end loop; end $$;

-- scopes and schedules: owners and IT administrators manage them
grant insert, update, delete on public.scan_scopes, public.scan_schedules to authenticated;
drop policy if exists scan_scopes_write on public.scan_scopes;
create policy scan_scopes_write on public.scan_scopes for all to authenticated using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));
drop policy if exists scan_schedules_write on public.scan_schedules;
create policy scan_schedules_write on public.scan_schedules for all to authenticated using (private.has_role(org_id, array['owner','it_admin'])) with check (private.has_role(org_id, array['owner','it_admin']));

-- jobs: discovery by operators, assessment jobs by security analysts; everyone with a role may only request cancellation afterwards
grant insert on public.scan_jobs to authenticated;
grant update (cancel_requested) on public.scan_jobs to authenticated;
drop policy if exists scan_jobs_insert on public.scan_jobs;
create policy scan_jobs_insert on public.scan_jobs for insert to authenticated with check (
  case when kind in ('discovery','service_discovery') then private.has_role(org_id, array['owner','it_admin','noc_operator'])
       else private.has_role(org_id, array['owner','it_admin','security_analyst']) end);
drop policy if exists scan_jobs_cancel on public.scan_jobs;
create policy scan_jobs_cancel on public.scan_jobs for update to authenticated
  using (case when kind in ('discovery','service_discovery') then private.has_role(org_id, array['owner','it_admin','noc_operator'])
              else private.has_role(org_id, array['owner','it_admin','security_analyst']) end)
  with check (private.is_member(org_id));

-- devices: discovery data is written only by the backend; people edit documentation fields only
grant update (label, description, location, owner_label, criticality, group_name, tags) on public.net_devices to authenticated;
drop policy if exists net_devices_document on public.net_devices;
create policy net_devices_document on public.net_devices for update to authenticated
  using (private.has_role(org_id, array['owner','it_admin','noc_operator'])) with check (private.has_role(org_id, array['owner','it_admin','noc_operator']));

grant insert, update, delete on public.net_segments to authenticated;
drop policy if exists net_segments_write on public.net_segments;
create policy net_segments_write on public.net_segments for all to authenticated using (private.has_role(org_id, array['owner','it_admin','noc_operator'])) with check (private.has_role(org_id, array['owner','it_admin','noc_operator']));

insert into private.app_migrations (version, name) values ('0103', 'discovery_topology') on conflict do nothing;
commit;
