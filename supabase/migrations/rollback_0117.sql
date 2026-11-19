-- Restores the 0112 definition (windows capped at 1 h).
begin;
create or replace function public.rate_limit_hit(p_key text, p_window integer default 60)
returns integer language plpgsql security definer set search_path = public as $$
declare w bigint := (floor(extract(epoch from now()) / p_window) * p_window)::bigint; c integer;
begin
  if p_key is null or length(p_key) > 200 or p_window < 1 or p_window > 3600 then raise exception 'invalid rate limit arguments'; end if;
  insert into public.rate_limits as r (key, window_start, hits) values (p_key, w, 1)
    on conflict (key, window_start) do update set hits = r.hits + 1 returning r.hits into c;
  if random() < 0.01 then delete from public.rate_limits where window_start < w - 7200; end if;
  return c;
end $$;
revoke all on function public.rate_limit_hit(text, integer) from public, anon, authenticated;
grant execute on function public.rate_limit_hit(text, integer) to service_role;
delete from private.app_migrations where version = '0117';
commit;
