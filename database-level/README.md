# Field-Level Confidentiality for a Payroll & Benefits Database: database-level encryption

An HR system where salary, bank details, tax identifiers and benefits need stronger protection than
ordinary profile fields. This project protects them with **encryption inside PostgreSQL** (pgcrypto): the
database encrypts, decrypts and decides who may decrypt, and the application never sees a key or a ciphertext.
Design details are in `docs/DB_LEVEL.md`.

| | |
|---|---|
| Schema | `dbenc` |
| Encryption | pgcrypto `pgp_sym_encrypt` (AES-256), random 256-bit keys, one per field, versioned |
| Keys | table `dbenc.key_store` |
| Decryption path | `SECURITY DEFINER` functions; `GRANT EXECUTE` decides who may call them |
| Ciphertext bound to row/column? | yes: `<field>|<emp id>|` is inside the encrypted payload and checked on decrypt |

## The four tables

| Table | Protected columns (ciphertext) | Plaintext columns |
|---|---|---|
| `employees` | none (ordinary profile) | name, email, department, title, hire date |
| `compensation` | `salary_enc` | `salary_band` ($20k band), pay frequency |
| `tax_bank` | `ssn_enc`, `acct_enc` | `ssn_last4`, `acct_last4`, bank name |
| `benefits` | `dependents_enc` | plan name, coverage tier |

`salary_band` and the `*_last4` columns are written together with the ciphertext (by the `put_*` SQL functions),
so masked lookups and range-limited reporting keep working in SQL. Each ciphertext starts with one byte naming its key version.

## Who can see what

Four application roles plus the pre-login `r_auth`, each its own `LOGIN` role (no `SET ROLE` escalation path). Measured, not asserted.

| Role | Salary | Band | SSN | SSN last 4 | Account | Acct last 4 | Dependents |
|---|---|---|---|---|---|---|---|
| Employee (own record) | full | - | - | masked | - | masked | full |
| Payroll clerk | full | - | full | masked | full | masked | - |
| HR partner | full | **yes** | - | masked | - | - | full |
| Reporting analyst | - | - | - | - | - | - | - |

- **Salary band** as a per-employee column is visible to HR only, not to payroll and not to the employee. The analyst never sees an individual's band.
- **An employee sees only their own row in every table, the profile included.** Row-level security on `employees` hides everyone else's pay, bank, benefits, email, department and title. The one exception is the directory search, which returns a colleague's ID and name and nothing more. Payroll, HR and the analyst can see every profile row.
- The analyst has no per-employee sensitive access at all. Its only salary view is the **range-limited report** (`salary_band_report`): aggregate headcount by department and salary band, cells under 5 people suppressed (Legal has 1 employee and Internal Audit 2, so they never appear).

## Run it

Needs Postgres 16 (pgcrypto is in the standard contrib package) and Python 3.11+.

```bash
pip install -r requirements.txt
export PGHOST=localhost FLC_ADMIN_PASSWORD=postgres     # add PGPORT=... if Postgres is not on 5432

python -m flc.init_db --employees 1000         # 1. roles + 4 tables + keys inside Postgres, 2. load and encrypt the data
./demo/run_tests.sh                            # 3. rebuild, run the tests, save results/pytest.txt
python -m flc.evaluate                         # 4. THE RESULTS: results/evaluation.md and .json (re-initialises first)
./demo/run_demo.sh                             # raw psql proof, no application involved
flask --app app run                            # the HR portal: http://localhost:5000
```

Settings: `PGHOST`, `PGPORT`, `FLC_DB`, `FLC_ADMIN_USER`, `FLC_ADMIN_PASSWORD`, `FLC_EMPLOYEES`.
The stolen-backup scenario needs `pg_dump` on PATH.

**Where the results are:** `results/evaluation.md` (readable tables for the report), `results/evaluation.json` (raw data),
`results/pytest.txt` (when run through `demo/run_tests.sh`).

## SQL tests for DBeaver

`sql_tests/` has the checks as separate scripts (00 setup, 01-06 tests, 99 cleanup). Open each in DBeaver as `postgres` on
database `flc` and press Alt+X. See `sql_tests/README.md`.

## Evaluation (the four criteria)

`python -m flc.evaluate` runs everything below for real and writes the tables to `results/evaluation.md`.

1. **Unauthorized-disclosure resistance.** Six scenarios: curious DBA with `SELECT *` then a key hunt; attacker restores a stolen `pg_dump` (with and without the key table data); SQL injection as the analyst; SQL injection as an employee who forges the viewer id; DBA swaps two employees' encrypted salaries.
2. **Query usefulness.** Range report, payroll run, salary filter, SSN equality search, masked lookups, with timings.
3. **Key-management overhead.** Key inventory, where keys live and who can read them, and a timed rotation of all four field keys (each re-encrypting every row), with a check that data stays intact.
4. **Exposure per role.** The matrix above, with full / masked / denied counts, plus non-role actors (DBA, stolen backup, injected SQL).

### What the results show (1,000 employees)

- **DBA and stolen backup:** 4 of 4 encrypted fields are lost, because the key is a row in the same database (`SELECT key FROM dbenc.key_store`, and `pg_dump` takes it along). Excluding `key_store` data from dumps closes the backup case (0 of 4) but not the DBA case.
- **Tampering:** swapping two salary ciphertexts is **detected**. This needed an explicit design step: the field and employee id are placed inside the encrypted payload and checked by `dbenc._dec`. Without it, plain pgcrypto accepts the swapped value silently (payroll read a salary of 106,500 instead of 74,500 in the first version).
- **Injected SQL as an employee:** the viewer identity comes from a client-settable setting (`app.employee_id`). A forged id makes `my_salary()` / `my_dependents()` decrypt the victim's data inside Postgres (2 fields).
- **Injected SQL as the analyst:** blocked; the role can read only the profile columns and the aggregate band report, has no grant on any ciphertext column, the per-employee `salary_band`, any decrypt function, `app_users` or `key_store`, and cannot `SET ROLE`.
- **Speed:** with pgcrypto's default password-style key stretching, 1,000 encrypt+decrypt operations took 2.07 s versus 12 ms with `s2k-mode=0`. The keys are random 256-bit values, not passwords, so `s2k-mode=0` is used. After that, a 1,000-row payroll run takes tens of milliseconds and rotating all four keys about 0.2 s. These are single runs on a small sandbox; read the shape, not the milliseconds.
- **Query usefulness:** encrypted values cannot be matched, ranged or aggregated by SQL directly. Masked columns carry lookups and reporting. Salary can still be filtered server-side through the decrypt function (a sequential scan, no index).

## The HR portal (`flask --app app run`)

A mock HR, payroll and benefits site with a standard username and password login. The password is checked inside Postgres
(`dbenc.authenticate`), which also says which database role and employee the user is. After signing in, the top bar shows the
user's name and employee ID. Staff roles get **Employees**, a search by name or ID, and open records whose fields are filtered by
the database for that role. Employees can search for colleagues too, but the search returns only the ID and name (through `dbenc.directory()`); opening anyone else's record is refused.

**Passwords are hashed, not encrypted.** `dbenc.app_users.pw_hash` holds a salted bcrypt hash (`crypt` + `gen_salt('bf')`), so
the stored value cannot be turned back into a password, even by someone who finds the keys. The pre-login connection, `r_auth`,
can run `authenticate()` and nothing else; no role can read the table.

| Username | Password | Role | Employee |
|---|---|---|---|
| `employee1` | `Harbor-emp1-2026` | Employee | #1 (the demo record) |
| `employee2` | `Harbor-emp2-2026` | Employee | #2 |
| `payroll.clerk` | `Harbor-payroll-2026` | Payroll clerk | #49 |
| `hr.partner` | `Harbor-hr-2026` | HR partner | #25 |
| `analyst` | `Harbor-analyst-2026` | Reporting analyst | #16 |
| `dba` | `Harbor-dba-2026` | Database administrator (superuser) | - |

Demo passwords only; `python -m flc.init_db` prints this list when it finishes.

**SQL panel (split screen).** The right-hand side shows "What Postgres ran" for the page you are on: every statement,
grouped by database connection and role, with an OK / REFUSED / ERROR tag, row count, timing and a one-line explanation.
Refusals show Postgres's own message, so you can watch an analyst or HR role get denied. Binary values and long strings
are shown by size only, so no key or ciphertext ever appears in the panel. The **SQL panel** button in the top bar hides
or shows it.

## Demo script (4 beats)

1. **Employee:** sign in as `employee1`, see your own pay and dependents (no salary band), then open employee #5: Postgres returns no row, so not even a name.
2. **Payroll, then HR:** open employee #1 as each. Payroll sees SSN and account but no benefits and no band; HR sees dependents and the band but never the SSN or account.
3. **Analyst:** no exact pay and no individual's band; opening a record shows every sensitive field as Restricted. The Salary report shows aggregate headcount by band with Legal and Internal Audit hidden.
4. **Database administrator:** the same record is ciphertext, and the key hunt recovers all four fields. (`./demo/psql_demo.sh` shows the same in raw SQL.)

## Limitations 

- **Viewer identity is trusted.** `app.employee_id` is set by the application per transaction, and an injected statement can overwrite it. Fix: separate DB login per user or a signed identity token verified in the database.
- **Key custody is weak by design:** keys sit in the same database as the ciphertext. Better: an external KMS or a master key supplied per session (then it is a hybrid), separation of duties between DBA and security officer, `key_store` excluded from backups.
- **Report suppression is cell-level only.** No complementary suppression, so differencing across cells or repeated queries is not blocked.
- **Plaintext transits the setters:** the `put_*` functions receive plaintext in statements (watch `log_statement`). The demo roles share one password and the demo superuser is local; this is a coursework build, with synthetic data only.


## Layout

```
db/00_roles.sql            roles, pgcrypto
db/10_schema.sql.tmpl      4 tables, RLS, column grants, report view (init_db fills in the schema name)
db/20_dbenc_crypto.sql     key_store, encrypt/decrypt, decrypt-path functions, payroll_run, rotation
flc/impl_dbenc.py          Python access layer (one real login per role)
flc/seed.py                synthetic data     flc/init_db.py       build everything
flc/attacks.py             attack scenarios   flc/evaluate.py      evaluation tables
app.py, templates/, static/   the HR portal    tests/test_project.py   tests
sql_tests/                 the same checks as SQL scripts for DBeaver
demo/                      run_tests.sh, run_demo.sh, psql_demo.sh
docs/DB_LEVEL.md           design write-up    results/             last evaluation run
```
