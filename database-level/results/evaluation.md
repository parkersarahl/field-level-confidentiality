# Evaluation: field-level confidentiality (database-level encryption, pgcrypto)

Data: 1000 synthetic employees (Faker seed 42), freshly initialised. Encryption and decryption happen inside Postgres (pgcrypto); the keys are rows in the same database. Everything below was measured by running the scenario against Postgres, not asserted.

## 1. Unauthorized-disclosure resistance

| Scenario | Outcome | Encrypted fields recovered | Why |
|---|---|---|---|
| DBA with superuser: SELECT * then hunt for a key | **EXPOSED** | 4/4 | SELECT key FROM dbenc.key_store returns every key; pgp_sym_decrypt() then opens all four fields. (key-like objects found in DB: 4) |
| Attacker restores a stolen backup | **EXPOSED** | 4/4 | Dump contains the key table, so the restored copy decrypts everything. (plaintext visible in dump text: False; key material in dump: True) |
| Attacker restores a stolen backup (key_store data excluded from dump) | **PROTECTED** | 0/4 | Dump has ciphertext but no key rows; restored copy cannot decrypt (needs the key kept elsewhere). (plaintext visible in dump text: False; key material in dump: False) |
| SQL injection as the reporting analyst | **PROTECTED** | 0/4 | 10 probes (direct reads, key table, decrypt functions, SET ROLE): 10 denied |
| SQL injection as an employee: forge app.employee_id | **EXPOSED** | 2/4 | Identity comes from a client-settable setting, so the forged id passes RLS, and the SECURITY DEFINER my_*() functions decrypt the victim's data inside Postgres. Masked values read: ssn_last4, acct_last4. |
| DBA swaps two encrypted salaries | **DETECTED** | 0/4 | Payroll read of employee 1 fails: integrity check failed: salary ciphertext does not belong to employee 1. The ciphertext carries its own field and employee id, and dbenc._dec() checks them. |

## 2. Query usefulness

| Workflow | Result |
|---|---|
| Range-limited report (dept x salary band, groups < 5 hidden) | works, 28 cells, Legal/Audit suppressed: True |
| Payroll run (1000 employees: gross pay + account) | 55 ms (decrypt inside Postgres) |
| Salary filter, salary > $120k (HR) -> 219 rows | 43 ms (SQL WHERE over a decrypt function, no index) |
| Equality search on a full SSN / account | not possible: ciphertext is randomized |
| Masked lookups (last 4, band) | works in SQL, indexable |

## 3. Key-management overhead

| Item | Result |
|---|---|
| Keys (4 fields, versioned) | 4 -> 8 after rotating all four |
| Where keys live | table dbenc.key_store, inside the database |
| Who can read keys | owner role + any superuser (DBA) |
| Who may decrypt which field | GRANT EXECUTE on decrypt functions |
| Rotate all 4 field keys (1000 rows each) | 0.28 s, plaintext never leaves Postgres |
| Data intact after rotation | True |
| Keys travel with a full DB backup | yes (key_store is a table) unless excluded |

## 4. Sensitive information exposed to each role

Per employee record, 7 sensitive fields (4 encrypted + 3 masked). `full` = plaintext, `masked` = derived value, `-` = denied.

| Role | Salary | Salary band ($20k) | SSN (full) | SSN last 4 | Bank account (full) | Account last 4 | Benefit dependents | full / masked / denied |
|---|---|---|---|---|---|---|---|---|
| Employee (self-service) | full | - | - | masked | - | masked | full | 2 / 2 / 3 |
| Payroll clerk | full | - | full | masked | full | masked | - | 3 / 2 / 2 |
| HR partner | full | masked | - | masked | - | - | full | 2 / 2 / 3 |
| Reporting analyst | - | - | - | - | - | - | - | 0 / 0 / 7 |

Non-role actors (encrypted fields recovered, of 4):

| Actor | Fields recovered |
|---|---|
| DBA with superuser: SELECT * then hunt for a key | 4 |
| Attacker restores a stolen backup | 4 |
| SQL injection as the reporting analyst | 0 |
| SQL injection as an employee: forge app.employee_id | 2 |
| DBA swaps two encrypted salaries | 0 |
