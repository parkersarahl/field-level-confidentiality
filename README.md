# Field-Level Confidentiality for a Payroll and Benefits Database

Course project, CPSC 5270 Fall 2026. Two independent implementations of field-level confidentiality for the
same payroll and benefits schema, built so they can be compared head to head on the **same 1,000
synthetic employees**.

- **Database-level encryption** (`database-level/`) — PostgreSQL encrypts and decrypts with `pgcrypto`;
  the keys live in the database and Postgres roles enforce access. *Author: Sarah Parker.*
- **Application-level encryption** (`application-level/`) — a Python/Flask app encrypts and decrypts with
  AES-256-GCM; the key lives in a file outside the database and the application enforces access.
  *Author: Deponker Depto.*

Both protect the same four fields — salary, SSN, bank account and dependents — while keeping payroll
runs, a range-limited salary report and employee self-service working.

## Repository layout

```
field-level-confidentiality/
├── README.md              this file
├── requirements.txt       Python dependencies for BOTH sides
├── .gitignore
├── database-level/        Sarah's implementation (pgcrypto, keys in the DB)
│   ├── db/                schema + crypto/role SQL
│   ├── flc/               Python package (init, seed, access, attacks, evaluation)
│   ├── app.py             Flask demo portal with a live "what Postgres ran" SQL panel
│   ├── tests/             pytest suite (43 tests)
│   ├── sql_tests/         85 standalone SQL checks (run in any client)
│   ├── demo/              one-command demo + test scripts
│   └── README.md          full details of this side
└──  application-level/     Teammate's implementation (AES-GCM, key in a file)
    ├── db/schema.sql      schema
    ├── crypto.py          AES-256-GCM encrypt/decrypt
    ├── security.py        the three access gates (clearance, need-to-know, row)
    ├── app.py             Flask demo app
    ├── populate_db.py     original 8-employee demo seed
    ├── seed_1000.py       seeds the SAME 1,000 employees as the db-level side
    └── compare.py         head-to-head comparison harness (writes results/comparison.md)
```

## Prerequisites

- **PostgreSQL 16**, reachable as user `postgres` / password `postgres`.
- **Python 3.11+**. Install everything for both sides from the repo root:
  ```
  pip install -r requirements.txt
  ```

The two sides use **different database names** (`flc` and `flc_payroll`), so they coexist on one server.

### Connection settings

Set these once in the shell; **every command below reads them** — both apps, the seeders, the test
suite, the SQL checks (via `psql`) and the comparison harness. On a stock local server the defaults
already match, so you only need to export what differs (a non-default port, say 5433).

```bash
export PGHOST=localhost PGPORT=5433 PGUSER=postgres #use the port your postgres is on
export FLC_ADMIN_PASSWORD=postgres        # the postgres password
```

## Running the database-level side (Sarah)

From `database-level/`:

```bash
python -m flc.init_db                      # creates DB "flc", schema, roles, keys, 1,000 employees
./demo/run_tests.sh                        # pytest -> 43 passed, saved to results/pytest.txt
python -m flc.evaluate                     # regenerates results/evaluation.md (attacks, timings, rotation)
flask --app app run                        # the demo portal at http://127.0.0.1:5000
```

The 85 SQL checks run in any client, e.g.:

```bash
psql -h localhost -U postgres -d flc -f sql_tests/00_setup_helpers.sql -f sql_tests/01_role_matrix.sql
```

Demo sign-ins and the role-by-field access matrix are documented in `database-level/README.md`.

## Running the application-level side (Deponker)

From `application-level/`:

```bash
python init_db.py                          # creates DB "flc_payroll" (if needed) and its schema
python seed_1000.py                        # loads the SAME 1,000 employees as the db-level side
python app.py                              # the demo app
```

`seed_1000.py` reuses the encrypt_text()` and the db-level project's deterministic
generator (Faker seed 42), so both databases hold identical people. His original 8 demo logins
(`alice` … `samuel`, passwords `alice123` …) are kept on employees 1–8. The demo key is written to
`application-level/secrets/aes_key.bin` on first run — it is a **demo-only** key, not a real secret.

## Running the head-to-head comparison

Build **both** databases first (steps above), then from `application-level/`:

```bash
python compare.py                          # writes results/comparison.md and .json
```

It uses the same connection settings as everything else and queries each database directly, reporting on the same data: where the key lives and what each compromise exposes, how much an injected query can read past the app, whether the two enforce the same role scope, and decryption timings.

## What the comparison shows

The two designs move the **same risk to opposite custodians**:

| | Database level | Application level |
|---|---|---|
| Key location | In the database | File outside the database |
| A DBA or full `pg_dump` alone | **decrypts everything** | sees ciphertext only |
| SQL that bypasses the app layer | reads **0** rows (role has no grant) | reads **all 1,000** (connection is superuser) |
| A compromised application | limited to that role's grants | holds the key → **every field** |
| Role scope (7 checks) | — | **identical on all 7** |

Database-level is strong against a compromised application and weak against a trusted administrator;
application-level is the reverse. Neither removes the tension; each chooses which principal to trust.

## Tests included

- **43 Python tests** — `database-level/tests/test_project.py` (role scope, storage format, tamper
  detection, key rotation, attacks, the login/users table, and the Flask portal).
- **85 SQL checks** — `database-level/sql_tests/` (role-by-field matrix, storage, tamper/binding,
  analyst injection probes, key rotation, query usefulness).
- **Comparison harness** — `application-level/compare.py`, which exercises both implementations on the
  same 1,000-employee dataset.

The comparison harness is what exercises it alongside the database-level suite.
