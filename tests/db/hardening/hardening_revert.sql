-- Rollback for hardening.sql: restores the permissions and the policy to exactly what they were before.
-- (capture_rollback.sql generates an even more exact script from the live database; use whichever you prefer.)
begin;
grant execute on function public.increment_usage(uuid) to public, anon, authenticated;
grant all on table public.app_records, public.soc_kev, public.soc_meta to anon, authenticated;
grant all on table public.projects, public.versions, public.usage to anon;
revoke select (slug, html, custom_domain, published_at) on table public.sites from anon;
grant all on table public.sites to anon;
drop policy if exists sites_public_read on public.sites;
create policy sites_public_read on public.sites for select using (true);
commit;
