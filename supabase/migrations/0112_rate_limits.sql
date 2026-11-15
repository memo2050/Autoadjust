-- 0112 | Shared rate limiter (fixed 60 s windows, atomic counter). Additive. Staging / scratch only until the owner approves a production migration.
begin;
create table if not exists public.rate_limits (
  key text not null,
  window_start bigint not null,                -- unix seconds of the window start
  hits integer not null default 0,
  primary key (key, window_start)
);
alter table public.rate_limits enable row level security;        -- no policies: only the service role (which bypasses RLS) can touch it
revoke all on public.rate_limits from anon, authenticated;

-- Atomically add one hit and return the count in the current window. Old windows are cleaned up opportunistically.
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
insert into private.app_migrations (version, name) values ('0112', 'rate_limits') on conflict do nothing;
commit;
