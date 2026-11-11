# Database-level vs application-level encryption

Same 1,000 synthetic employees (Faker seed 42) in both databases. Field-level confidentiality for salary, SSN, bank account and dependents.

## 1. Where the key lives, and what a compromise exposes

| Question | Database level | Application level |
|---|---|---|
| A raw table read returns ciphertext | yes | yes |
| Key stored outside the database | no | yes |
| A DBA alone can decrypt every field | yes | no (needs the key file too) |
| A plain `pg_dump` carries the keys with the data | yes | no |
| Every DB connection is the superuser | no | yes |

The two designs move the risk to opposite places. The database-level version keeps the key inside Postgres, so a DBA or a full backup gets everything, but each role is a limited Postgres login and injected SQL as a low role reads nothing. The application-level version keeps the key in a file outside the database, so a DBA or a dump sees only ciphertext, but the app connects as the superuser and holds the key in its own process, so a compromise of the app exposes all fields.

## 2. SQL that bypasses the application layer

| | Database level | Application level |
|---|---|---|
| Ciphertext rows a bypassing query can read | 0 (role has no grant) | 1000 (connection is superuser) |

In the database-level design the analyst role cannot read the ciphertext column at all. In the application-level design the enforcement is in Python, so any query that reaches the database outside that code runs as the superuser and sees every encrypted row (still ciphertext, but all of it).

## 3. Role scope (does each role see the right field?)

Both should answer the same way; this confirms the two enforce the same policy.

| Request | Database level | Application level | Match |
|---|---|---|---|
| employee own salary | yes | yes | same |
| employee other salary | no | no | same |
| payroll any ssn | yes | yes | same |
| hr any ssn | no | no | same |
| hr any dependents | yes | yes | same |
| analyst exact salary | no | no | same |
| analyst salary band | no | no | same |

All role-scope checks agree: both designs expose the same field to the same role, including the analyst, who in each design sees only the aggregate salary-band report and never an individual's band.

## 4. Timings (median, same machine)

Single small sandbox; read the shape, not the milliseconds.

| Workflow | Database level | Application level |
|---|---|---|
| Payroll run: decrypt 1,000 salaries | 60.8 ms | 33.4 ms |
| One access decision | 17.8 ms | 14.9 ms |
| Salary-band report | 14.7 ms | 14.9 ms |

Where the decryption runs is the difference: the database-level payroll run decrypts inside Postgres in one round trip, while the application-level run pulls every ciphertext to Python and decrypts there.
