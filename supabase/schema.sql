-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
create table projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  name text not null,
  site_url text,
  created_at timestamptz default now()
);
create table versions (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references projects on delete cascade not null,
  prompt text not null,
  html text not null,
  created_at timestamptz default now()
);
create table usage (
  user_id uuid references auth.users not null,
  day date default current_date,
  generations int default 0,
  primary key (user_id, day)
);
alter table projects enable row level security;
alter table versions enable row level security;
alter table usage enable row level security;
create policy own_projects on projects for all using (user_id = auth.uid());
create policy own_versions on versions for all using (
  project_id in (select id from projects where user_id = auth.uid()));
create policy own_usage on usage for select using (user_id = auth.uid());
create function increment_usage(uid uuid) returns void language sql security definer as $$
  insert into usage (user_id, day, generations) values (uid, current_date, 1)
  on conflict (user_id, day) do update set generations = usage.generations + 1;
$$;
