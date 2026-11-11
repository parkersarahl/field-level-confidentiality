"""Attack scenarios, run for real against the database-level encryption.

Every function returns a dict:  {"scenario", "outcome", "recovered": [fields], "detail"}
`recovered` lists the *encrypted* fields whose plaintext the attacker obtained (verified against
the plaintext that was originally loaded).
"""
import os
import re
import subprocess

import psycopg

from . import config as C
from . import impl_dbenc
from . import seed as seed_mod
from .db import admin, attempt, role_session

ENC_COLS = {"salary": ("compensation", "salary_enc"), "ssn": ("tax_bank", "ssn_enc"),
            "acct": ("tax_bank", "acct_enc"), "dependents": ("benefits", "dependents_enc")}


def _same(field, got, truth):
    return str(got).strip() == str(truth[field]).strip()


def _result(scenario, outcome, recovered, detail):
    return {"scenario": scenario, "outcome": outcome, "recovered": sorted(recovered), "detail": detail}


# ---------------------------------------------------------------------------------------
def ciphertext_preview(emp_id):
    """What a DBA's `SELECT *` shows for the protected columns of one employee."""
    out = {}
    with admin() as conn:
        for f, (table, col) in ENC_COLS.items():
            blob = conn.execute(f"select {col} as v from dbenc.{table} where emp_id = %s", (emp_id,)).fetchone()["v"]
            out[f] = bytes(blob).hex()
        row = conn.execute("select salary_band, ssn_last4, acct_last4 from dbenc.compensation "
                           "join dbenc.tax_bank using (emp_id) where emp_id = %s", (emp_id,)).fetchone()
    out.update(row)
    return out


def dba_key_hunt(emp_id=1):
    """S1. A curious DBA (superuser) sees ciphertext in SELECT *, then looks for a key in the database."""
    truth = seed_mod.truth(emp_id)
    recovered = []
    with admin() as conn:
        keys = conn.execute("select field, ver, key from dbenc.key_store").fetchall()
        for f, (table, col) in ENC_COLS.items():
            blob = bytes(conn.execute(f"select {col} as v from dbenc.{table} where emp_id = %s", (emp_id,)).fetchone()["v"])
            key = next(k["key"] for k in keys if k["field"] == f and k["ver"] == blob[0])
            # the DBA calls pgcrypto directly with the key he just read
            got = conn.execute("select pgp_sym_decrypt(%s, %s) as v", (blob[1:], key)).fetchone()["v"]
            got = got.split("|", 2)[2]          # strip the visible '<field>|<emp>|' context prefix
            if _same(f, got, truth):
                recovered.append(f)
    return _result("DBA with superuser: SELECT * then hunt for a key",
                   "EXPOSED" if recovered else "PROTECTED", recovered,
                   "SELECT key FROM dbenc.key_store returns every key; pgp_sym_decrypt() then opens all four fields. "
                   f"(key-like objects found in DB: {len(keys)})")


def stolen_backup(emp_id=1, exclude_keys=False):
    """S2. Attacker obtains a pg_dump file and restores it on a machine they control."""
    truth = seed_mod.truth(emp_id)
    cmd = C.PG_DUMP.split()
    if "docker" not in C.PG_DUMP:                # a pg_dump run inside the container reaches Postgres locally
        cmd += ["-h", C.HOST, "-p", str(C.PORT)]
    cmd += ["-U", C.ADMIN_USER, "-d", C.DBNAME, "-n", "dbenc", "--inserts", "--no-owner", "--no-privileges"]
    if exclude_keys:
        cmd += ["--exclude-table-data=dbenc.key_store"]
    env = dict(os.environ)
    if C.ADMIN_PASSWORD:                         # pg_dump does not read FLC_ADMIN_PASSWORD
        env["PGPASSWORD"] = C.ADMIN_PASSWORD
    dump = subprocess.run(cmd, capture_output=True, check=True, env=env).stdout.decode()
    plaintext_in_dump = any(truth[k] in dump for k in ("ssn", "acct")) or str(truth["salary"]) in re.findall(r"\b\d{5,6}\b", dump)
    with admin() as conn:
        key_hexes = [r["key"] for r in conn.execute("select key from dbenc.key_store").fetchall()]
    key_in_dump = any(h in dump for h in key_hexes)

    scratch = "flc_stolen"
    recovered = []
    with admin("postgres", autocommit=True) as conn:
        conn.execute(f'drop database if exists "{scratch}"')
        conn.execute(f'create database "{scratch}" encoding \'UTF8\' template template0')
    try:
        with admin(scratch, autocommit=True) as conn:
            conn.execute("create extension pgcrypto")
            # drop psql meta-commands, and settings a newer pg_dump writes that an older server rejects
            conn.execute("\n".join(l for l in dump.splitlines()
                                   if not l.startswith("\\") and not l.startswith("SET transaction_timeout")))
            for f, fn in (("salary", "salary_of"), ("ssn", "ssn_of"), ("acct", "acct_of"), ("dependents", "dependents_of")):
                try:                             # the decrypt functions travel with the dump
                    got = conn.execute(f"select dbenc.{fn}(%s) as v", (emp_id,)).fetchone()["v"]
                except psycopg.Error:
                    continue
                if got is not None and _same(f, got, truth):
                    recovered.append(f)
    finally:
        with admin("postgres", autocommit=True) as conn:
            conn.execute(f'drop database if exists "{scratch}"')

    label = "stolen backup" + (" (key_store data excluded from dump)" if exclude_keys else "")
    detail = ("Dump contains the key table, so the restored copy decrypts everything." if not exclude_keys else
              "Dump has ciphertext but no key rows; restored copy cannot decrypt (needs the key kept elsewhere).")
    return _result(f"Attacker restores a {label}", "EXPOSED" if recovered else "PROTECTED", recovered,
                   f"{detail} (plaintext visible in dump text: {plaintext_in_dump}; key material in dump: {key_in_dump})")


def sqli_analyst():
    """S3. SQL injection in a request running as the reporting analyst: try to reach protected data."""
    probes = ["select * from dbenc.compensation", "select salary_enc from dbenc.compensation",
              "select * from dbenc.tax_bank", "select ssn_enc, acct_enc from dbenc.tax_bank",
              "select * from dbenc.benefits", "set role r_payroll",
              "select * from dbenc.key_store", "select dbenc.ssn_of(1)", "select dbenc.salary_of(1)",
              "select dbenc._dec('ssn', emp_id, ssn_enc) from dbenc.tax_bank"]
    results = []
    with role_session("r_analyst", viewer_id=1) as conn:
        for sql in probes:
            status, _ = attempt(conn, sql)
            results.append((sql, status))
    leaked = [sql for sql, st in results if st == "ok"]
    return _result("SQL injection as the reporting analyst", "EXPOSED" if leaked else "PROTECTED", [],
                   f"{len(results)} probes (direct reads, key table, decrypt functions, SET ROLE): "
                   f"{len(results) - len(leaked)} denied" + (f"; allowed: {leaked}" if leaked else ""))


def sqli_employee_forge(viewer=5, victim=1):
    """S4. SQL injection in an employee-self-service request: forge the viewer identity GUC."""
    truth = seed_mod.truth(victim)
    recovered, derived = [], []
    with role_session("r_employee", viewer_id=viewer) as conn:
        conn.execute("select set_config('app.employee_id', %s, true)", (str(victim),))   # the injected statement
        for f, fn in (("salary", "my_salary"), ("dependents", "my_dependents")):
            st, rows = attempt(conn, f"select dbenc.{fn}() as v")
            if st == "ok" and rows and rows[0]["v"] is not None and _same(f, rows[0]["v"], truth):
                recovered.append(f)
        for col, table in (("salary_band", "compensation"), ("ssn_last4", "tax_bank"), ("acct_last4", "tax_bank")):
            st, rows = attempt(conn, f"select {col} as v from dbenc.{table} where emp_id = %s", (victim,))
            if st == "ok" and rows:
                derived.append(col)
    return _result("SQL injection as an employee: forge app.employee_id", "EXPOSED", recovered,
                   "Identity comes from a client-settable setting, so the forged id passes RLS, and the "
                   "SECURITY DEFINER my_*() functions decrypt the victim's data inside Postgres. "
                   f"Masked values read: {', '.join(derived)}.")


def tamper_swap(a=1, b=2):
    """S5. A DBA with write access swaps two employees' encrypted salaries (a silent raise for one of them)."""
    truth_a, truth_b = seed_mod.truth(a), seed_mod.truth(b)
    with admin() as conn:
        blobs = {i: bytes(conn.execute("select salary_enc as v from dbenc.compensation where emp_id = %s", (i,)).fetchone()["v"])
                 for i in (a, b)}
        try:
            for i, blob in ((a, blobs[b]), (b, blobs[a])):
                conn.execute("update dbenc.compensation set salary_enc = %s where emp_id = %s", (blob, i))
            conn.commit()
            seen = impl_dbenc.read_record("r_payroll", a)["salary"]
        finally:
            for i, blob in blobs.items():
                conn.execute("update dbenc.compensation set salary_enc = %s where emp_id = %s", (blob, i))
            conn.commit()
    state, value = seen
    if state == "PLAIN" and str(value) == str(truth_b["salary"]):
        return _result("DBA swaps two encrypted salaries", "UNDETECTED", [],
                       f"Payroll now reads employee {a}'s salary as {value} (really {truth_a['salary']}). "
                       "pgcrypto decrypts a ciphertext copied to another row without complaint.")
    return _result("DBA swaps two encrypted salaries", "DETECTED", [],
                   f"Payroll read of employee {a} fails: {value}. "
                   "The ciphertext carries its own field and employee id, and dbenc._dec() checks them.")


def run_all(emp_id=1):
    return [dba_key_hunt(emp_id), stolen_backup(emp_id), stolen_backup(emp_id, exclude_keys=True),
            sqli_analyst(), sqli_employee_forge(), tamper_swap()]
