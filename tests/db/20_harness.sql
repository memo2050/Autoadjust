-- Test harness: run one statement as a given database role / user, expect success (optionally a row count) or an error, then roll it back.
create schema test;
create table test.results (n serial primary key, name text not null, ok boolean not null, detail text);
create or replace function test.run(p_name text, p_user uuid, p_role text, p_sql text, p_expect text default 'ok', p_rows int default null)
returns void language plpgsql as $$
declare n int := 0; ok boolean := false; detail text; r record;
begin
  for r in select label, id from test.ids loop p_sql := replace(p_sql, '{' || r.label || '}', r.id::text); end loop;
  begin
    perform set_config('request.jwt.claim.sub', coalesce(p_user::text, ''), true);
    execute 'set local role ' || quote_ident(p_role);
    execute p_sql;
    get diagnostics n = row_count;
    if p_expect = 'ok' then
      ok := p_rows is null or n = p_rows; detail := 'rows=' || n || coalesce(' expected ' || p_rows, '');
    else ok := false; detail := 'expected an error but it succeeded (rows=' || n || ')'; end if;
    raise exception using errcode = 'P0001', message = '__rollback__';
  exception when others then
    if sqlerrm <> '__rollback__' then
      if p_expect = 'error' then ok := true; detail := left(sqlerrm, 110); else ok := false; detail := 'unexpected error: ' || left(sqlerrm, 160); end if;
    end if;
  end;
  insert into test.results (name, ok, detail) values (p_name, ok, detail);
end $$;
create or replace function test.check(p_name text, p_ok boolean, p_detail text default null) returns void language sql as
$$ insert into test.results (name, ok, detail) values (p_name, coalesce(p_ok, false), p_detail) $$;
