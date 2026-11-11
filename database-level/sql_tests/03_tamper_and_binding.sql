-- 03_tamper_and_binding.sql   (needs 00_setup_helpers.sql; run as postgres)
-- What happens when ciphertext is copied, swapped, corrupted or cut short?
-- Every case must FAIL to decrypt (ERROR), and the control case must succeed. Press Alt+X.

drop table if exists pg_temp.dbtest_tamper;

create temp table dbtest_tamper as
select * from (values
 ('control: employee 1''s own salary ciphertext decrypts for employee 1', 'OK%',
    dbtest.try_as('postgres', $q$select dbenc._dec('salary', 1, (select salary_enc from dbenc.compensation where emp_id = 1))$q$)),
 ('ciphertext moved to another employee (claims to be employee 2)', 'ERROR: integrity check failed%',
    dbtest.try_as('postgres', $q$select dbenc._dec('salary', 2, (select salary_enc from dbenc.compensation where emp_id = 1))$q$)),
 ('salary ciphertext presented as an SSN (wrong field, wrong key)', 'ERROR:%',
    dbtest.try_as('postgres', $q$select dbenc._dec('ssn', 1, (select salary_enc from dbenc.compensation where emp_id = 1))$q$)),
 ('one bit flipped in the last byte', 'ERROR:%',
    dbtest.try_as('postgres', $q$select dbenc._dec('salary', 1, (select set_byte(salary_enc, length(salary_enc) - 1, get_byte(salary_enc, length(salary_enc) - 1) # 1) from dbenc.compensation where emp_id = 1))$q$)),
 ('ciphertext cut short (first 20 bytes only)', 'ERROR:%',
    dbtest.try_as('postgres', $q$select dbenc._dec('salary', 1, (select substring(salary_enc for 20) from dbenc.compensation where emp_id = 1))$q$)),
 ('key-version byte changed to 99 (no such key)', 'ERROR: no key for salary version 99',
    dbtest.try_as('postgres', $q$select dbenc._dec('salary', 1, (select set_byte(salary_enc, 0, 99) from dbenc.compensation where emp_id = 1))$q$)),
 ('DBA swaps employee 1 and 2 salaries in the table, then payroll reads employee 1', 'integrity check failed%',
    dbtest.swap_test())
) as t(test, expected, actual);

-- The swap test undoes itself; if it ever failed to restore the data, its message would contain "WARNING" and the row would FAIL.
select test, expected, actual, case when actual like expected and actual not like '%WARNING%' then 'PASS' else 'FAIL' end as result
from dbtest_tamper;
