-- 04_attack_scenarios.sql   (needs 00_setup_helpers.sql; run as postgres)
-- Three attacks against the DB-level implementation. Some are SUPPOSED to succeed: they show the limits of this design.
-- Press Alt+X. Result tabs: 1 = analyst injection, 2 = forged identity, 3 = DBA keys, 4 = DBA decrypts.

-- ATTACK 1: SQL injection while running as the reporting analyst. Expected: every probe DENIED.
select p.probe, 'DENIED' as expected, dbtest.try_as('r_analyst', p.probe) as actual,
       case when dbtest.try_as('r_analyst', p.probe) = 'DENIED' then 'PASS' else 'FAIL' end as result
from (values
 ('select * from dbenc.compensation'),
 ('select salary_enc from dbenc.compensation'),
 ('select * from dbenc.tax_bank'),
 ('select ssn_enc, acct_enc from dbenc.tax_bank'),
 ('select * from dbenc.benefits'),
 ('select * from dbenc.key_store'),
 ('select dbenc.ssn_of(1)'),
 ('select dbenc.salary_of(1)'),
 ('select dbenc._dec(''ssn'', emp_id, ssn_enc) from dbenc.tax_bank')
) as p(probe);
-- Not testable here: "set role r_payroll". Postgres checks SET ROLE against the original login, and this script's login is the
-- superuser, so it would wrongly succeed. The Python tests log in as r_analyst for real and show it is denied.

-- ATTACK 2: injection as an employee who overwrites the "who am I" setting (app.employee_id).
-- The app says "this request is employee 5"; the injected SQL changes it to 1 and calls my_salary().
-- KNOWN LIMIT of this design: it works, because the database trusts that setting.
select 'employee 5, honest request' as scenario, dbtest.try_as('r_employee', 'select dbenc.my_salary()::text', 5) as salary_returned,
       'employee 5''s own salary: ' || dbenc.salary_of(5)::text as truth, 'expected' as note
union all
select 'employee 5, injected: set app.employee_id = 1',
       dbtest.try_as('r_employee', $q$with forged as materialized (select set_config('app.employee_id', '1', true) as s) select dbenc.my_salary()::text from forged$q$, 5),
       'employee 1''s real salary: ' || dbenc.salary_of(1)::text,
       'KNOWN LIMIT: victim''s salary leaks (fix: separate DB login per user)';

-- ATTACK 3a: a DBA (superuser) looks for keys inside the database. Expected: he finds all of them.
select field, ver as key_version, left(key, 12) || '...' as key_starts_with, 'EXPOSED: key readable by the DBA' as result
from dbenc.key_store order by field, ver;

-- ATTACK 3b: ...and uses a key to decrypt employee 1's SSN himself, with plain pgcrypto and no help from our functions.
select split_part(pgp_sym_decrypt(substring(t.ssn_enc from 2),
         (select k.key from dbenc.key_store k where k.field = 'ssn' and k.ver = get_byte(t.ssn_enc, 0))), '|', 3) as ssn_recovered_by_dba,
       dbenc.ssn_of(1) as real_ssn,
       case when split_part(pgp_sym_decrypt(substring(t.ssn_enc from 2),
         (select k.key from dbenc.key_store k where k.field = 'ssn' and k.ver = get_byte(t.ssn_enc, 0))), '|', 3) = dbenc.ssn_of(1)
         then 'EXPOSED: DBA decrypted the SSN' else 'PROTECTED' end as result
from dbenc.tax_bank t where t.emp_id = 1;

-- (Stolen backup: a plain pg_dump of schema dbenc contains the key_store rows too, so it is exposed the same way.
--  That attack needs pg_dump, so it lives in the Python tests (pytest) and in python -m flc.evaluate.)
