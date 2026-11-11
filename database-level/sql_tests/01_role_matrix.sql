-- 01_role_matrix.sql   (needs 00_setup_helpers.sql)
-- Who can read what? Every check runs as that role (SET LOCAL ROLE inside dbtest.try_as), so table, column and function
-- grants and row-level security apply exactly as for a real login of that role.
-- Press Alt+X. The result tabs: 1 = every check with PASS/FAIL, 2 = summary.

drop table if exists pg_temp.dbtest_roles;

create temp table dbtest_roles as
-- Part A: the 7 sensitive fields of employee 1, for each of the 4 roles (per-employee salary band: HR only) (the employee role is "logged in" as employee 1)
select 'A: field access' as part, c.role || ' -> ' || c.field as test, c.expected,
       dbtest.try_as(c.role, c.q, case when c.role = 'r_employee' then 1 end) as actual
from (values
 ('r_employee','salary',       'select dbenc.my_salary()::text', 'OK%'),
 ('r_employee','salary band',  'select salary_band from dbenc.compensation where emp_id = 1', 'DENIED'),
 ('r_employee','SSN (full)',   'select dbenc.ssn_of(1)', 'DENIED'),
 ('r_employee','SSN last 4',   'select ssn_last4 from dbenc.tax_bank where emp_id = 1', 'OK%'),
 ('r_employee','account (full)','select dbenc.acct_of(1)', 'DENIED'),
 ('r_employee','account last 4','select acct_last4 from dbenc.tax_bank where emp_id = 1', 'OK%'),
 ('r_employee','dependents',   'select dbenc.my_dependents()', 'OK%'),
 ('r_payroll','salary',        'select dbenc.salary_of(1)::text', 'OK%'),
 ('r_payroll','salary band',   'select salary_band from dbenc.compensation where emp_id = 1', 'DENIED'),
 ('r_payroll','SSN (full)',    'select dbenc.ssn_of(1)', 'OK%'),
 ('r_payroll','SSN last 4',    'select ssn_last4 from dbenc.tax_bank where emp_id = 1', 'OK%'),
 ('r_payroll','account (full)','select dbenc.acct_of(1)', 'OK%'),
 ('r_payroll','account last 4','select acct_last4 from dbenc.tax_bank where emp_id = 1', 'OK%'),
 ('r_payroll','dependents',    'select dbenc.dependents_of(1)', 'DENIED'),
 ('r_hr','salary',             'select dbenc.salary_of(1)::text', 'OK%'),
 ('r_hr','salary band',        'select salary_band from dbenc.compensation where emp_id = 1', 'OK%'),
 ('r_hr','SSN (full)',         'select dbenc.ssn_of(1)', 'DENIED'),
 ('r_hr','SSN last 4',         'select ssn_last4 from dbenc.tax_bank where emp_id = 1', 'OK%'),
 ('r_hr','account (full)',     'select dbenc.acct_of(1)', 'DENIED'),
 ('r_hr','account last 4',     'select acct_last4 from dbenc.tax_bank where emp_id = 1', 'DENIED'),
 ('r_hr','dependents',         'select dbenc.dependents_of(1)', 'OK%'),
 ('r_analyst','salary',        'select dbenc.salary_of(1)::text', 'DENIED'),
 ('r_analyst','salary band',   'select salary_band from dbenc.compensation where emp_id = 1', 'DENIED'),
 ('r_analyst','SSN (full)',    'select dbenc.ssn_of(1)', 'DENIED'),
 ('r_analyst','SSN last 4',    'select ssn_last4 from dbenc.tax_bank where emp_id = 1', 'DENIED'),
 ('r_analyst','account (full)','select dbenc.acct_of(1)', 'DENIED'),
 ('r_analyst','account last 4','select acct_last4 from dbenc.tax_bank where emp_id = 1', 'DENIED'),
 ('r_analyst','dependents',    'select dbenc.dependents_of(1)', 'DENIED')
) as c(role, field, q, expected)
union all
-- Part B: no role may read a ciphertext column directly (4 roles x 4 columns)
select 'B: ciphertext columns', r.role || ' reads ' || c.col, 'DENIED',
       dbtest.try_as(r.role, format('select %s from dbenc.%s where emp_id = 1', c.col, c.tbl), case when r.role = 'r_employee' then 1 end)
from (values ('r_employee'),('r_payroll'),('r_hr'),('r_analyst')) as r(role)
cross join (values ('salary_enc','compensation'),('ssn_enc','tax_bank'),('acct_enc','tax_bank'),('dependents_enc','benefits')) as c(col, tbl)
union all
-- Part C: row-level security and the analyst report
select 'C: row-level security', t.test, t.expected, t.actual
from (values
 ('employee 5 cannot see employee 1''s pay frequency', 'NO ROW',
    dbtest.try_as('r_employee', 'select pay_freq from dbenc.compensation where emp_id = 1', 5)),
 ('employee 5 cannot see employee 1''s name or profile', 'NO ROW',
    dbtest.try_as('r_employee', 'select full_name from dbenc.employees where emp_id = 1', 5)),
 ('employee 5 sees exactly one row of the employee table: their own', 'OK: 1',
    dbtest.try_as('r_employee', 'select count(*)::text from dbenc.employees', 5)),
 ('employee 5 can look colleagues up by name or ID (name only)', 'OK: 1',
    dbtest.try_as('r_employee', 'select count(*)::text from dbenc.directory(''1'')', 5)),
 ('payroll sees every employee row', 'OK: 1000',
    dbtest.try_as('r_payroll', 'select count(*)::text from dbenc.employees')),
 ('no role can read the users table (password hashes)', 'DENIED',
    dbtest.try_as('r_hr', 'select pw_hash from dbenc.app_users')),
 ('employee 5''s my_salary() returns employee 5''s own salary', 'OK: ' || dbenc.salary_of(5)::text,
    dbtest.try_as('r_employee', 'select dbenc.my_salary()::text', 5)),
 ('analyst can read the range-limited report', 'OK%',
    dbtest.try_as('r_analyst', 'select count(*)::text from dbenc.salary_band_report')),
 ('report hides Legal and Internal Audit (groups under 5)', 'OK: 0',
    dbtest.try_as('r_analyst', 'select count(*)::text from dbenc.salary_band_report where department in (''Legal'', ''Internal Audit'')'))
) as t(test, expected, actual);

select part, test, expected, actual, case when actual like expected then 'PASS' else 'FAIL' end as result
from dbtest_roles order by part, test;

select case when actual like expected then 'PASS' else 'FAIL' end as result, count(*) as checks
from dbtest_roles group by 1 order by 1;
