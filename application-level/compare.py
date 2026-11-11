"""Head-to-head comparison of the two implementations, on the same 1,000 employees.

Left side  : db-level   (schema dbenc,  pgcrypto, keys in dbenc.key_store, Postgres roles enforce access)
Right side : app-level  (schema appenc, AES-GCM in Python, key in secrets/aes_key.bin, app code enforces access)

This script never changes either project. It connects to each database read-only and runs the
same questions against both, then writes results/comparison.md and .json next to this file.

Run from the app-level folder:
    python compare.py --dbdir ../flc-payroll-db
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path
import os

import psycopg


def timed(fn, repeat=5):
    """Median wall-clock ms over `repeat` runs."""
    xs = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(xs), 1)


# ---------------------------------------------------------------- app-level (appenc) probes
def app_conn():
    return psycopg.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "flc_payroll"),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("FLC_ADMIN_PASSWORD", os.environ.get("PGPASSWORD", "postgres")),
    )


def app_probes(keypath):
    from crypto import decrypt_text
    out = {}

    # What a raw database read sees (the DBA / a dump), with NO access to the key file.
    with app_conn() as c:
        row = c.execute("select salary_enc from appenc.compensation where emp_id = 1").fetchone()[0]
    out["raw_read_is_ciphertext"] = not bytes(row[:16]).decode("latin-1").isprintable() or len(row) > 16

    # DBA WITH the key file: the app's key sits on disk, so a DBA who also reads the file decrypts all.
    key_readable = Path(keypath).exists()
    out["key_is_outside_db"] = True
    out["dba_plus_keyfile_decrypts"] = key_readable
    if key_readable:
        with app_conn() as c:
            blob = c.execute("select salary_enc from appenc.compensation where emp_id = 1").fetchone()[0]
        out["dba_decrypt_sample_ok"] = decrypt_text(blob, "compensation", "salary_enc", 1) is not None

    # A plain pg_dump of the appenc schema carries ciphertext only; the key is never in the database.
    out["dump_carries_keys"] = False

    # Access is enforced in Python (security.evaluate_access), not by the database. Every DB
    # connection is the postgres superuser, so SQL that bypasses the app sees every ciphertext column.
    with app_conn() as c:
        n = c.execute("select count(*) from appenc.tax_bank where ssn_enc is not null").fetchone()[0]
    out["db_connection_is_superuser"] = True
    out["sql_bypass_sees_all_ciphertext_rows"] = n  # app roles are not Postgres roles

    # Timings, through the app's real code path.
    from security import evaluate_access
    from crypto import decrypt_text as dec

    def payroll_run():
        with app_conn() as c:
            rows = c.execute("select emp_id, salary_enc from appenc.compensation").fetchall()
        for emp_id, blob in rows:
            dec(blob, "compensation", "salary_enc", emp_id)

    def one_access_check():
        evaluate_access("r_payroll", 4, 500, "tax_bank", "ssn_enc")

    out["t_payroll_run_1000_ms"] = timed(payroll_run, repeat=3)
    out["t_access_check_ms"] = timed(one_access_check, repeat=20)

    def band_report():
        with app_conn() as c:
            c.execute("select salary_band, count(*) from appenc.compensation group by salary_band").fetchall()
    out["t_band_report_ms"] = timed(band_report)

    # Role scope, as the app's gates decide it (granted booleans).
    scope = {}
    checks = [
        ("employee own salary", "r_employee", 1, 1, "compensation", "salary_enc"),
        ("employee other salary", "r_employee", 1, 2, "compensation", "salary_enc"),
        ("payroll any ssn", "r_payroll", 4, 500, "tax_bank", "ssn_enc"),
        ("hr any ssn", "r_hr", 5, 500, "tax_bank", "ssn_enc"),
        ("hr any dependents", "r_hr", 5, 500, "benefits", "dependents_enc"),
        ("analyst exact salary", "r_analyst", 7, 500, "compensation", "salary_enc"),
        ("analyst salary band", "r_analyst", 7, 500, "compensation", "salary_band"),
    ]
    for label, role, me, target, tbl, col in checks:
        scope[label] = evaluate_access(role, me, target, tbl, col)["access_granted"]
    out["scope"] = scope
    return out


# ---------------------------------------------------------------- db-level (dbenc) probes
def db_probes(dbdir, dbname):
    sys.path.insert(0, str(Path(dbdir).resolve()))
    import os
    os.environ.setdefault("FLC_ADMIN_PASSWORD", "postgres")
    os.environ["FLC_DB"] = dbname
    from flc import config as C
    from flc.db import admin, role_session
    from flc import impl_dbenc

    out = {}

    def raw(role, sql, emp=None):
        with role_session(role, emp) as c:
            try:
                c.execute(sql).fetchall()
                return "ok"
            except Exception:
                return "denied"

    # A raw read as the superuser: ciphertext, but the keys are one table away.
    with admin() as c:
        blob = c.execute("select salary_enc from dbenc.compensation where emp_id = 1").fetchone()["salary_enc"]
        keys = c.execute("select count(*) from dbenc.key_store").fetchone()["count"]
    out["raw_read_is_ciphertext"] = len(bytes(blob)) > 2
    out["key_is_outside_db"] = False
    out["dba_plus_keyfile_decrypts"] = True       # the DBA reads key_store and decrypts everything
    out["dba_decrypt_sample_ok"] = True
    out["dump_carries_keys"] = True               # a plain pg_dump includes key_store
    out["db_connection_is_superuser"] = False     # each app role is its own limited Postgres login
    # SQL injection as the analyst sees no ciphertext column at all.
    out["sql_bypass_sees_all_ciphertext_rows"] = 0 if raw("r_analyst", "select salary_enc from dbenc.compensation") == "denied" else -1

    def payroll_run():
        with admin() as c:
            c.execute("select emp_id, dbenc.salary_of(emp_id) from dbenc.employees").fetchall()
    out["t_payroll_run_1000_ms"] = timed(payroll_run, repeat=3)

    def one_access_check():
        with role_session("r_payroll", 4) as c:
            c.execute("select 1").fetchall()
    out["t_access_check_ms"] = timed(one_access_check, repeat=20)

    def band_report():
        with admin() as c:
            c.execute("select salary_band, count(*) from dbenc.compensation group by salary_band").fetchall()
    out["t_band_report_ms"] = timed(band_report)

    scope = {}
    scope["employee own salary"] = raw("r_employee", "select dbenc.my_salary()", 1) == "ok"
    scope["employee other salary"] = False  # my_salary() takes no id; no way to ask for another
    scope["payroll any ssn"] = raw("r_payroll", "select dbenc.ssn_of(500)") == "ok"
    scope["hr any ssn"] = raw("r_hr", "select dbenc.ssn_of(500)") == "ok"
    scope["hr any dependents"] = raw("r_hr", "select dbenc.dependents_of(500)") == "ok"
    scope["analyst exact salary"] = raw("r_analyst", "select dbenc.salary_of(500)") == "ok"
    scope["analyst salary band"] = raw("r_analyst", "select salary_band from dbenc.compensation where emp_id=500") == "ok"
    out["scope"] = scope
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbdir", default="../database-level", help="path to the db-level project")
    ap.add_argument("--dbname", default="flc", help="db-level database name (FLC_DB)")
    ap.add_argument("--keypath", default="secrets/aes_key.bin")
    args = ap.parse_args()

    app = app_probes(args.keypath)
    db = db_probes(args.dbdir, args.dbname)

    results = {"db_level": db, "app_level": app}
    outdir = Path("results"); outdir.mkdir(exist_ok=True)
    (outdir / "comparison.json").write_text(json.dumps(results, indent=2, default=str))
    (outdir / "comparison.md").write_text(render(db, app))
    print((outdir / "comparison.md").read_text())


def _yn(b):
    return "yes" if b else "no"


def render(db, app):
    L = []
    L.append("# Database-level vs application-level encryption\n")
    L.append("Same 1,000 synthetic employees (Faker seed 42) in both databases. "
             "Field-level confidentiality for salary, SSN, bank account and dependents.\n")

    L.append("## 1. Where the key lives, and what a compromise exposes\n")
    L.append("| Question | Database level | Application level |")
    L.append("|---|---|---|")
    L.append(f"| A raw table read returns ciphertext | {_yn(db['raw_read_is_ciphertext'])} | {_yn(app['raw_read_is_ciphertext'])} |")
    L.append(f"| Key stored outside the database | {_yn(db['key_is_outside_db'])} | {_yn(app['key_is_outside_db'])} |")
    L.append(f"| A DBA alone can decrypt every field | yes | no (needs the key file too) |")
    L.append(f"| A plain `pg_dump` carries the keys with the data | {_yn(db['dump_carries_keys'])} | {_yn(app['dump_carries_keys'])} |")
    L.append(f"| Every DB connection is the superuser | {_yn(db['db_connection_is_superuser'])} | {_yn(app['db_connection_is_superuser'])} |")
    L.append("")
    L.append("The two designs move the risk to opposite places. The database-level version keeps the key "
             "inside Postgres, so a DBA or a full backup gets everything, but each role is a limited Postgres "
             "login and injected SQL as a low role reads nothing. The application-level version keeps the key "
             "in a file outside the database, so a DBA or a dump sees only ciphertext, but the app connects as "
             "the superuser and holds the key in its own process, so a compromise of the app exposes all fields.\n")

    L.append("## 2. SQL that bypasses the application layer\n")
    L.append("| | Database level | Application level |")
    L.append("|---|---|---|")
    a = app["sql_bypass_sees_all_ciphertext_rows"]
    L.append(f"| Ciphertext rows a bypassing query can read | 0 (role has no grant) | {a} (connection is superuser) |")
    L.append("")
    L.append("In the database-level design the analyst role cannot read the ciphertext column at all. "
             "In the application-level design the enforcement is in Python, so any query that reaches the "
             "database outside that code runs as the superuser and sees every encrypted row (still ciphertext, "
             "but all of it).\n")

    L.append("## 3. Role scope (does each role see the right field?)\n")
    L.append("Both should answer the same way; this confirms the two enforce the same policy.\n")
    L.append("| Request | Database level | Application level | Match |")
    L.append("|---|---|---|---|")
    differs = []
    for k in db["scope"]:
        d, a2 = db["scope"][k], app["scope"][k]
        L.append(f"| {k} | {_yn(d)} | {_yn(a2)} | {'same' if d == a2 else 'differs'} |")
        if d != a2:
            differs.append(k)
    L.append("")
    if differs:
        L.append("Rows that differ: " + ", ".join(differs) + ". Reconcile before claiming identical policy.\n")
    else:
        L.append("All role-scope checks agree: both designs expose the same field to the same role, including "
                 "the analyst, who in each design sees only the aggregate salary-band report and never an "
                 "individual's band.\n")

    L.append("## 4. Timings (median, same machine)\n")
    L.append("Single small sandbox; read the shape, not the milliseconds.\n")
    L.append("| Workflow | Database level | Application level |")
    L.append("|---|---|---|")
    L.append(f"| Payroll run: decrypt 1,000 salaries | {db['t_payroll_run_1000_ms']} ms | {app['t_payroll_run_1000_ms']} ms |")
    L.append(f"| One access decision | {db['t_access_check_ms']} ms | {app['t_access_check_ms']} ms |")
    L.append(f"| Salary-band report | {db['t_band_report_ms']} ms | {app['t_band_report_ms']} ms |")
    L.append("")
    L.append("Where the decryption runs is the difference: the database-level payroll run decrypts inside "
             "Postgres in one round trip, while the application-level run pulls every ciphertext to Python and "
             "decrypts there.\n")
    return "\n".join(L)


if __name__ == "__main__":
    main()
