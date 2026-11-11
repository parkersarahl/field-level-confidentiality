# SQL tests for DBeaver (DB-level implementation)

The same checks as the Python tests, as plain SQL you can run and read in DBeaver. They need the database built first
(`python -m flc.init_db`).

## How to run a script

1. In DBeaver, connect to database **flc** as the **postgres** superuser (the scripts switch roles themselves).
2. Open the file (File > Open File), check the active connection in the toolbar is `flc`, then press **Alt+X**
   (Execute SQL Script). Do not use Ctrl+Enter: that runs only one statement.
3. Results appear as tabs at the bottom, one per query. Look for the `result` column: `PASS` or `FAIL`.
4. If DBeaver pops up an error dialog, choose Stop and tell us which line it names.

| Order | Script | What it shows |
| --- | --- | --- |
| 1 (once) | `00_setup_helpers.sql` | Creates schema `dbtest` with two helper functions the other scripts use |
| 2 | `01_role_matrix.sql` | 53 checks: who can read which field (salary band: HR and analyst only), ciphertext columns closed to every role, employees limited to their own row (directory lookup gives names only), users table closed, analyst report |
| 3 | `02_storage_and_derived_columns.sql` | 16 checks: data really stored encrypted; band and last-4 columns agree with the decrypted values; keys well-formed |
| 4 | `03_tamper_and_binding.sql` | 7 checks: moved, swapped, corrupted or truncated ciphertext is rejected |
| 5 | `04_attack_scenarios.sql` | Injection as the analyst (blocked), forged identity (known limit), DBA reads keys and decrypts (exposed) |
| 6 | `05_key_rotation.sql` | Rotates all four field keys and proves every row moved, nothing was lost. **Changes the database** (adds four key versions; rebuild with `init_db` to start from version 1 again) |
| 7 | `06_query_usefulness.sql` | Range report, payroll run, salary filter with timing, SSN search, masked lookup (no PASS/FAIL, you read the output) |
| last | `99_cleanup.sql` | Removes schema `dbtest`. Your data is untouched |

Scripts 01 to 06 can be run in any order and as often as you like, after 00.

## Things worth knowing

- **Some results are supposed to look bad.** In `04`, the "EXPOSED" and "KNOWN LIMIT" rows are the honest limits of
  database-level encryption (the DBA can read the keys; a forged identity setting leaks one employee). They are findings, not failures.
- **How roles are tested.** Each check runs as the role through `SET LOCAL ROLE`, so grants and row-level security apply
  exactly as for a real login. The one thing this cannot show is `SET ROLE` itself, because Postgres checks it against the
  original login (the superuser). The Python tests log in as `r_analyst` for real and cover that case.
- **The stolen-backup attack** needs `pg_dump`, so it is only in the Python tests and `python -m flc.evaluate`.
- **Harmless notice:** `schema "pg_temp" does not exist, skipping` on the first run in a session.
- **If you edit a script,** do not put blank lines inside a statement. DBeaver treats a blank line as the end of a statement.
- **Manual commit mode:** if your DBeaver connection is not in Auto-commit, press Commit after `05_key_rotation.sql`.
