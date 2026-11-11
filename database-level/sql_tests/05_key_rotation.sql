-- 05_key_rotation.sql   (run as postgres)
-- Rotates ALL FOUR field keys (salary, ssn, acct, dependents) and proves: every row of every field moved to its new key,
-- nothing was lost, and the ciphertext really changed. This CHANGES the database (adds four key versions).
-- Safe to run again; each run adds one more version per field. To start from version 1 again, rebuild with: python -m flc.init_db
-- Press Alt+X. The last tab is the PASS/FAIL summary.

drop table if exists pg_temp.dbtest_rot;

create temp table dbtest_rot (step int, what text, value text);

-- BEFORE
insert into dbtest_rot select 1, 'keys in key_store, before', count(*)::text from dbenc.key_store;

insert into dbtest_rot select 2, 'newest version per field, before', string_agg(field || ' v' || v, ', ' order by field) from (select field, max(ver) as v from dbenc.key_store group by field) m;

insert into dbtest_rot select 3, 'checksum of all decrypted salary, SSN, account and dependents, before', md5(string_agg(dbenc.salary_of(emp_id)::text || '|' || dbenc.ssn_of(emp_id) || '|' || dbenc.acct_of(emp_id) || '|' || dbenc.dependents_of(emp_id), ';' order by emp_id)) from dbenc.employees;

insert into dbtest_rot select 4, 'employee 1 salary ciphertext (first 12 bytes), before', encode(substring(salary_enc for 12), 'hex') from dbenc.compensation where emp_id = 1;

insert into dbtest_rot select 5, 'employee 1 salary key version byte, before', get_byte(salary_enc, 0)::text from dbenc.compensation where emp_id = 1;

-- ROTATE all four fields (timed inside one block so the figure does not include client round-trips)
do $$
declare t0 timestamptz := clock_timestamp(); f text;
begin
  foreach f in array array['salary', 'ssn', 'acct', 'dependents'] loop
    perform dbenc.rotate_key(f);
  end loop;
  insert into dbtest_rot values (6, 'rotation time in ms (4 fields, every row re-encrypted)', round(extract(epoch from clock_timestamp() - t0) * 1000)::text);
end $$;

-- AFTER
insert into dbtest_rot select 7, 'keys in key_store, after', count(*)::text from dbenc.key_store;

insert into dbtest_rot select 8, 'newest version per field, after', string_agg(field || ' v' || v, ', ' order by field) from (select field, max(ver) as v from dbenc.key_store group by field) m;

insert into dbtest_rot select 9, 'checksum of all decrypted salary, SSN, account and dependents, after', md5(string_agg(dbenc.salary_of(emp_id)::text || '|' || dbenc.ssn_of(emp_id) || '|' || dbenc.acct_of(emp_id) || '|' || dbenc.dependents_of(emp_id), ';' order by emp_id)) from dbenc.employees;

insert into dbtest_rot select 10, 'employee 1 salary ciphertext (first 12 bytes), after', encode(substring(salary_enc for 12), 'hex') from dbenc.compensation where emp_id = 1;

insert into dbtest_rot select 11, 'employee 1 salary key version byte, after', get_byte(salary_enc, 0)::text from dbenc.compensation where emp_id = 1;

insert into dbtest_rot select 12, 'encrypted values not on their field''s newest key version, after', sum(c)::text from (select count(*) as c from dbenc.compensation where get_byte(salary_enc, 0) <> (select max(ver) from dbenc.key_store where field = 'salary') union all select count(*) from dbenc.tax_bank where get_byte(ssn_enc, 0) <> (select max(ver) from dbenc.key_store where field = 'ssn') union all select count(*) from dbenc.tax_bank where get_byte(acct_enc, 0) <> (select max(ver) from dbenc.key_store where field = 'acct') union all select count(*) from dbenc.benefits where get_byte(dependents_enc, 0) <> (select max(ver) from dbenc.key_store where field = 'dependents')) x;

insert into dbtest_rot select 13, 'encrypted values in the database (4 fields x rows)', (4 * count(*))::text from dbenc.employees;

insert into dbtest_rot select 14, 'newest salary key version', max(ver)::text from dbenc.key_store where field = 'salary';

-- the raw log, in order
select step, what, value from dbtest_rot order by step;

-- PASS/FAIL summary
select s.test, case when s.ok then 'PASS' else 'FAIL' end as result, s.detail
from (
 select 'one new key version per field (4 new keys) was added' as test,
        (select value::int from dbtest_rot where step = 7) = (select value::int from dbtest_rot where step = 1) + 4 as ok,
        (select value from dbtest_rot where step = 1) || ' keys -> ' || (select value from dbtest_rot where step = 7) || ' keys' as detail
 union all
 select 'every encrypted value now uses its field''s newest key version', (select value from dbtest_rot where step = 12) = '0',
        (select value from dbtest_rot where step = 12) || ' of ' || (select value from dbtest_rot where step = 13) || ' values still on an older version'
 union all
 select 'all four fields still decrypt to exactly the same data', (select value from dbtest_rot where step = 9) = (select value from dbtest_rot where step = 3),
        'checksum ' || (select value from dbtest_rot where step = 3) || ' = ' || (select value from dbtest_rot where step = 9)
 union all
 select 'the stored ciphertext actually changed', (select value from dbtest_rot where step = 10) <> (select value from dbtest_rot where step = 4),
        (select value from dbtest_rot where step = 4) || ' -> ' || (select value from dbtest_rot where step = 10)
 union all
 select 'employee 1''s salary version byte moved to the new version', (select value from dbtest_rot where step = 11) = (select value from dbtest_rot where step = 14),
        'version byte ' || (select value from dbtest_rot where step = 5) || ' -> ' || (select value from dbtest_rot where step = 11)
) s;
