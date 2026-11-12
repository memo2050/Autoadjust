-- LEGACY (Website Builder removed from the app). Not used by the application any more; the tables are kept in the database on purpose. Do not run on a new project unless you need them.
-- Hosting: published sites served by this app (subdomains + custom domains)
create table sites (
  slug text primary key check (slug ~ '^[a-z0-9-]{3,40}$'),
  project_id uuid references projects on delete cascade not null unique,
  html text not null,
  custom_domain text unique,
  published_at timestamptz default now()
);
alter table sites enable row level security;
create policy sites_public_read on sites for select using (true);
create policy sites_owner_write on sites for all using (
  project_id in (select id from projects where user_id = auth.uid()))
  with check (project_id in (select id from projects where user_id = auth.uid()));
