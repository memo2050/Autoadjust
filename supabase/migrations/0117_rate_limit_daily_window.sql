-- 0117 | Allow 24 h windows in the shared rate limiter (0112 caps windows at 1 h) so daily AI caps can be persistent. Replaces ONE function; no table changes. Additive for existing callers (60 s / 1 h windows behave identically). NOT applied anywhere; staging first, after explicit approval. Requires 0112.
begin;
create or replace function public.rate_limit_hit(p_key text, p_window integer default 60)
returns integer language plpgsql security definer set search_path = public as $$
declare w bigint := (floor(extract(epoch from now()) / p_window) * p_window)::bigint; c integer;
begin
  if p_key is null or length(p_key) > 200 or p_window < 1 or p_window > 86400 then raise exception 'invalid rate limit arguments'; end if;
  insert into public.rate_limits as r (key, window_start, hits) values (p_key, w, 1)
    on conflict (key, window_start) do update set hits = r.hits + 1 returning r.hits into c;
  if random() < 0.01 then delete from public.rate_limits where window_start < w - 172800; end if;
  return c;
end $$;
revoke all on function public.rate_limit_hit(text, integer) from public, anon, authenticated;
grant execute on function public.rate_limit_hit(text, integer) to service_role;
insert into private.app_migrations (version, name) values ('0117', 'rate_limit_daily_window') on conflict do nothing;
commit;
