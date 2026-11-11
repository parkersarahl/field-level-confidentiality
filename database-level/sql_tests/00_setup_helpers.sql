-- 00_setup_helpers.sql
-- Run ONCE, first. Connect to database "flc" as the postgres superuser, open this file, press Alt+X (Execute script).
-- Creates a small schema "dbtest" with two helper functions the other scripts use. 99_cleanup.sql removes it.

create schema if not exists dbtest;

-- try_as(role, sql, viewer): run ONE statement as an application role and report what happened.
--   'OK: <value>'  the statement ran (value = first column of first row)
--   'NO ROW'       it ran but returned no row (e.g. row-level security hid the row)
--   'DENIED'       Postgres refused it: permission denied
--   'ERROR: ...'   it failed for another reason (e.g. our integrity check)
-- p_viewer sets app.employee_id, the setting the real app uses to say "this request is employee N".
create or replace function dbtest.try_as(p_role text, p_sql text, p_viewer int default null)
returns text language plpgsql as $$
declare v text; is_select boolean := p_sql ~* '^\s*(select|with)';
begin
  execute format('set local role %I', p_role);
  perform set_config('app.employee_id', coalesce(p_viewer::text, ''), true);
  begin
    if is_select then
      execute p_sql into v;
    else
      execute p_sql;
    end if;
    reset role;
    return case when is_select and v is null then 'NO ROW' when v is null then 'OK' else 'OK: ' || v end;
  exception
    when insufficient_privilege then
      reset role;
      return 'DENIED';
    when others then
      reset role;
      return 'ERROR: ' || sqlerrm;
  end;
end $$;

-- swap_test(): as a DBA would, swap employee 1's and employee 2's encrypted salaries, try to read
-- employee 1's salary, then undo the swap. Returns the error the read produced.
create or replace function dbtest.swap_test() returns text language plpgsql as $$
declare c1 bytea; c2 bytea; before_val text; after_val text; msg text := 'NO ERROR: the swap was accepted';
begin
  before_val := dbenc.salary_of(1)::text;
  select salary_enc into c1 from dbenc.compensation where emp_id = 1;
  select salary_enc into c2 from dbenc.compensation where emp_id = 2;
  begin
    update dbenc.compensation set salary_enc = c2 where emp_id = 1;
    update dbenc.compensation set salary_enc = c1 where emp_id = 2;
    begin
      perform dbenc.salary_of(1);
    exception when others then
      msg := sqlerrm;
    end;
    raise exception 'undo the swap' using errcode = 'P0099';
  exception when sqlstate 'P0099' then
    null;
  end;
  after_val := dbenc.salary_of(1)::text;
  if after_val is distinct from before_val then
    msg := msg || ' | WARNING: data was not restored';
  end if;
  return msg;
end $$;

select 'helpers installed' as status, count(*) as functions
from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'dbtest';
