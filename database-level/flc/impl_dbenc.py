from . import config as C
from .db import admin, attempt, role_session

SCHEMA = "dbenc"


def band(salary):
    """The $20k salary band, as text. Python mirror of dbenc.band() in db/20_dbenc_crypto.sql (used by tests)."""
    lo = int(salary // 20000) * 20
    return f"${lo}k-{lo + 20}k"


# --- loading (admin) ---------------------------------------------------------------
def load(conn, emps):
    """Insert secure rows through the put_* functions: plaintext goes in, ciphertext is stored."""
    with conn.cursor() as cur:
        cur.executemany("select dbenc.put_compensation(%s, %s, %s)",
                        [(e["emp_id"], e["salary"], e["pay_freq"]) for e in emps])
        cur.executemany("select dbenc.put_tax_bank(%s, %s, %s, %s)",
                        [(e["emp_id"], e["ssn"], e["bank_name"], e["acct"]) for e in emps])
        cur.executemany("select dbenc.put_benefits(%s, %s, %s, %s)",
                        [(e["emp_id"], e["plan_name"], e["coverage_tier"], e["dependents"]) for e in emps])


# --- sign-in ----------------------------------------------------------------------------
def authenticate(username, password):
    """Check a username and password inside Postgres. Returns {role, emp_id, full_name, title} or None.

    Runs as r_auth, a login that can execute dbenc.authenticate() and nothing else."""
    with role_session("r_auth") as conn:
        rows = conn.execute("select * from dbenc.authenticate(%s, %s)", (username.strip(), password)).fetchall()
    return rows[0] if rows else None


# --- per-role access -----------------------------------------------------------------
def _sql(role, field, self_view):
    mine = role == "r_employee" and self_view
    return {
        "salary": "select dbenc.my_salary() as v" if mine else "select dbenc.salary_of(%(id)s) as v",
        "ssn": "select dbenc.ssn_of(%(id)s) as v",
        "acct": "select dbenc.acct_of(%(id)s) as v",
        "dependents": "select dbenc.my_dependents() as v" if mine else "select dbenc.dependents_of(%(id)s) as v",
        "salary_band": "select salary_band as v from dbenc.compensation where emp_id = %(id)s",
        "ssn_last4": "select ssn_last4 as v from dbenc.tax_bank where emp_id = %(id)s",
        "acct_last4": "select acct_last4 as v from dbenc.tax_bank where emp_id = %(id)s",
    }[field]


def read_record(role, emp_id, viewer_id=None, **_):
    """What this role actually gets for each sensitive field of one employee.

    Returns {field: (state, value_or_reason)}; state is PLAIN, MASKED or DENIED.
    Every field is a real attempt against Postgres as that role.
    """
    out = {}
    with role_session(role, viewer_id) as conn:
        for f in C.SENSITIVE_FIELDS:
            status, rows = attempt(conn, _sql(role, f, viewer_id == emp_id), {"id": emp_id})
            if status == "denied":
                out[f] = ("DENIED", "permission denied")
            elif status == "error":
                out[f] = ("DENIED", rows)          # e.g. "integrity check failed: ..."
            elif not rows or rows[0]["v"] is None:
                out[f] = ("DENIED", "no row visible")
            else:
                out[f] = ("PLAIN" if f in C.ENC_FIELDS else "MASKED", rows[0]["v"])
    return out


def read_profile(role, emp_id, viewer_id=None):
    """Profile row plus the plaintext companion columns, each fetched as the role. None = not visible to it."""
    out = {}
    with role_session(role, viewer_id) as conn:
        st, rows = attempt(conn, "select emp_id, full_name, email, department, title, hire_date "
                                 "from dbenc.employees where emp_id = %(id)s", {"id": emp_id})
        out["employee"] = rows[0] if st == "ok" and rows else None
        for key, table in (("pay_freq", "compensation"), ("bank_name", "tax_bank"),
                           ("plan_name", "benefits"), ("coverage_tier", "benefits")):
            st, rows = attempt(conn, f"select {key} as v from dbenc.{table} where emp_id = %(id)s", {"id": emp_id})
            out[key] = rows[0]["v"] if st == "ok" and rows else None
    return out


def search(q, role=None, viewer_id=None, limit=25):
    """Employee directory search by id or name. role=None uses the superuser (the DBA). Employees see names only."""
    q = q.strip().lstrip("#")
    if not q:
        return []
    if role == "r_employee":                  # employees get names and IDs only, through a function; never the profile
        with role_session(role, viewer_id) as conn:
            rows = conn.execute("select emp_id, full_name from dbenc.directory(%s, %s)", (q, int(limit))).fetchall()
        return [{**r, "department": None, "title": None} for r in rows]
    cols = "select emp_id, full_name, department, title from dbenc.employees"
    if q.isdigit():
        sql, args = f"{cols} where emp_id = %s order by emp_id", (int(q),)
    else:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql, args = f"{cols} where full_name ilike %s order by full_name limit {int(limit)}", (like,)
    if role is None:
        with admin() as conn:
            return conn.execute(sql, args).fetchall()
    with role_session(role, viewer_id) as conn:
        return conn.execute(sql, args).fetchall()


def payroll_run(role="r_payroll", periods=C.PAY_PERIODS, **_):
    with role_session(role) as conn:
        return conn.execute("select * from dbenc.payroll_run(%s)", (periods,)).fetchall()


def high_earners(threshold, role="r_hr", **_):
    """Employees above a salary threshold: decrypts every row server-side (no index possible)."""
    with role_session(role) as conn:
        rows = conn.execute(
            "select emp_id from dbenc.compensation where dbenc.salary_of(emp_id) > %s order by emp_id",
            (threshold,)).fetchall()
    return [r["emp_id"] for r in rows]


def salary_report(role="r_analyst", **_):
    with role_session(role) as conn:
        return conn.execute(
            "select department, salary_band, headcount from dbenc.salary_band_report order by 1, 2").fetchall()


# --- key management --------------------------------------------------------------------
def rotate(field, **_):
    """New key version, all rows of the field re-encrypted inside the database."""
    with admin() as conn:
        ver = conn.execute("select dbenc.rotate_key(%s) as v", (field,)).fetchone()["v"]
        conn.commit()
    return ver


def key_inventory():
    with admin() as conn:
        rows = conn.execute(
            "select field, array_agg(ver order by ver) as vers from dbenc.key_store group by field order by field"
        ).fetchall()
    return {r["field"]: r["vers"] for r in rows}
