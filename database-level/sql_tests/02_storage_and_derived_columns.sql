-- 02_storage_and_derived_columns.sql   (run as postgres; no helper functions needed)
-- Is the data really stored encrypted, and do the plaintext companion columns (band, last 4) agree with it?
-- Press Alt+X. One result grid with PASS/FAIL per check.

drop table if exists pg_temp.dbtest_storage;

create temp table dbtest_storage as
select * from (values
 ('the four tables hold the same number of employees', 'true',
    (select (count(distinct n) = 1)::text from (select count(*) n from dbenc.employees union all select count(*) from dbenc.compensation union all select count(*) from dbenc.tax_bank union all select count(*) from dbenc.benefits) x)),
 ('no ciphertext column contains NULL', '0',
    (select count(*)::text from dbenc.compensation c join dbenc.tax_bank t using (emp_id) join dbenc.benefits b using (emp_id) where c.salary_enc is null or t.ssn_enc is null or t.acct_enc is null or b.dependents_enc is null)),
 ('every salary ciphertext starts with a key version that exists', '0',
    (select count(*)::text from dbenc.compensation c where not exists (select 1 from dbenc.key_store k where k.field = 'salary' and k.ver = get_byte(c.salary_enc, 0)))),
 ('every SSN ciphertext starts with a key version that exists', '0',
    (select count(*)::text from dbenc.tax_bank t where not exists (select 1 from dbenc.key_store k where k.field = 'ssn' and k.ver = get_byte(t.ssn_enc, 0)))),
 ('every account ciphertext starts with a key version that exists', '0',
    (select count(*)::text from dbenc.tax_bank t where not exists (select 1 from dbenc.key_store k where k.field = 'acct' and k.ver = get_byte(t.acct_enc, 0)))),
 ('every dependents ciphertext starts with a key version that exists', '0',
    (select count(*)::text from dbenc.benefits b where not exists (select 1 from dbenc.key_store k where k.field = 'dependents' and k.ver = get_byte(b.dependents_enc, 0)))),
 ('employee 1''s salary does not appear inside its ciphertext', 'false',
    (select (position(convert_to(dbenc.salary_of(1)::text, 'UTF8') in salary_enc) > 0)::text from dbenc.compensation where emp_id = 1)),
 ('employee 1''s SSN does not appear inside its ciphertext', 'false',
    (select (position(convert_to(dbenc.ssn_of(1), 'UTF8') in ssn_enc) > 0)::text from dbenc.tax_bank where emp_id = 1)),
 ('employee 1''s account number does not appear inside its ciphertext', 'false',
    (select (position(convert_to(dbenc.acct_of(1), 'UTF8') in acct_enc) > 0)::text from dbenc.tax_bank where emp_id = 1)),
 ('encrypting the same value twice gives different ciphertext', 'false',
    (select (dbenc._enc('ssn', 1, '900-00-0000') = dbenc._enc('ssn', 1, '900-00-0000'))::text)),
 ('salary_band equals the band of the decrypted salary (all rows)', '0',
    (select count(*)::text from dbenc.compensation where salary_band <> dbenc.band(dbenc.salary_of(emp_id)))),
 ('ssn_last4 equals the last 4 of the decrypted SSN (all rows)', '0',
    (select count(*)::text from dbenc.tax_bank where ssn_last4 <> right(dbenc.ssn_of(emp_id), 4))),
 ('acct_last4 equals the last 4 of the decrypted account (all rows)', '0',
    (select count(*)::text from dbenc.tax_bank where acct_last4 <> right(dbenc.acct_of(emp_id), 4))),
 ('all four fields have a key', '4',
    (select count(distinct field)::text from dbenc.key_store)),
 ('key versions are numbered without gaps for every field', 'true',
    (select bool_and(n = mx)::text from (select field, count(*) n, max(ver) mx from dbenc.key_store group by field) s)),
 ('every key is 64 hex characters (256 bits)', 'true',
    (select bool_and(key ~ '^[0-9a-f]{64}$')::text from dbenc.key_store))
) as t(test, expected, actual);

select test, expected, actual, case when actual = expected then 'PASS' else 'FAIL' end as result
from dbtest_storage;
