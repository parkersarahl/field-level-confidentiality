-- 06_query_usefulness.sql   (run as postgres)
-- What can you still do with encrypted data? Press Alt+X; each statement gives its own result tab.
-- If a statement fails halfway, run:  reset role;   before continuing.

reset role;

-- 1. Range-limited report, as the reporting analyst: headcount by department and $20k salary band, groups under 5 hidden.
set role r_analyst;

select * from dbenc.salary_band_report order by department, salary_band limit 15;

reset role;

-- 2. Payroll run, as the payroll clerk: gross pay per period and the account to pay into, decrypted inside Postgres.
set role r_payroll;

select * from dbenc.payroll_run() limit 5;

reset role;

-- 3. Salary filter, as HR: "who earns over 120k?" Postgres must decrypt every row (no index can help).
--    Look at "Execution Time" at the bottom of the plan.
set role r_hr;

explain (analyze, costs off, timing off, summary on) select count(*) from dbenc.compensation where dbenc.salary_of(emp_id) > 120000;

select count(*) as employees_over_120k from dbenc.compensation where dbenc.salary_of(emp_id) > 120000;

reset role;

-- 4. Search by full SSN. Encrypting the same SSN again gives different bytes, so matching ciphertext finds nothing.
select count(*) as matches_by_comparing_ciphertext from dbenc.tax_bank where ssn_enc = dbenc._enc('ssn', 1, dbenc.ssn_of(1));

-- ...the only way is to decrypt every row and compare (slow, full scan):
select count(*) as matches_by_decrypting_every_row from dbenc.tax_bank where dbenc.ssn_of(emp_id) = dbenc.ssn_of(1);

-- 5. Masked lookup: the last 4 digits are stored in plaintext, so an ordinary indexable lookup works.
select emp_id, ssn_last4, acct_last4 from dbenc.tax_bank where ssn_last4 = right(dbenc.ssn_of(1), 4);
