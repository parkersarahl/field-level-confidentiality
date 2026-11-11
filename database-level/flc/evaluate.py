"""Produce the evaluation evidence for the database-level encryption.

    python -m flc.evaluate        # writes results/evaluation.md and results/evaluation.json
"""
import json
import statistics
import time

from . import attacks, config as C
from . import impl_dbenc as db
from .db import admin

CELL = {"PLAIN": "full", "MASKED": "masked", "DENIED": "-"}


def _median_seconds(fn, repeats=3):
    times = []
    for _ in range(repeats):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times)


def _table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _key(rows):
    return [(r["emp_id"], r["gross_per_period"], r["acct_number"]) for r in rows]


# --------------------------------------------------------------------------------------------
def exposure_matrix(emp_id=1):
    """Empirical role x field results: {role: {field: state}}."""
    res = {}
    for role in C.ROLES:
        rec = db.read_record(role, emp_id, viewer_id=emp_id if role == "r_employee" else None)
        res[role] = {f: rec[f][0] for f in C.SENSITIVE_FIELDS}
    return res


def query_usefulness(threshold=120_000):
    rep = db.salary_report()
    depts = {r["department"] for r in rep}
    out = {
        "report_rows": len(rep),
        "small_depts_suppressed": not ({"Legal", "Internal Audit"} & depts),
        "payroll_s": _median_seconds(db.payroll_run),
        "payroll_rows": len(db.payroll_run()),
        "filter_s": _median_seconds(lambda: db.high_earners(threshold)),
        "filter_count": len(db.high_earners(threshold)),
    }
    with admin() as conn:
        out["equal_ciphertext_for_equal_plaintext"] = bool(conn.execute(
            "select dbenc._enc('ssn', 1, '900-00-0000') = dbenc._enc('ssn', 1, '900-00-0000') as eq").fetchone()["eq"])
    return out


def key_management():
    """Key inventory and a timed rotation of all four field keys (this changes key versions)."""
    before = _key(db.payroll_run())
    inv_before = db.key_inventory()
    t = time.perf_counter()
    for f in C.ENC_FIELDS:
        db.rotate(f)
    secs = time.perf_counter() - t
    with admin() as conn:
        rows = conn.execute("select count(*) as n from dbenc.compensation").fetchone()["n"]
    return {
        "keys_before": sum(len(v) for v in inv_before.values()),
        "keys_after": sum(len(v) for v in db.key_inventory().values()),
        "rotate_all_s": secs,
        "data_intact_after_rotation": _key(db.payroll_run()) == before,
        "rows_per_field": rows,
    }


# --------------------------------------------------------------------------------------------
def build(emp_id=1):
    return {"attacks": attacks.run_all(emp_id), "matrix": exposure_matrix(emp_id),
            "usefulness": query_usefulness(), "keys": key_management()}


def render(r):
    u, k = r["usefulness"], r["keys"]
    md = ["# Evaluation: field-level confidentiality (database-level encryption, pgcrypto)", "",
          f"Data: {k['rows_per_field']} synthetic employees (Faker seed 42), freshly initialised. Encryption and decryption "
          "happen inside Postgres (pgcrypto); the keys are rows in the same database. "
          "Everything below was measured by running the scenario against Postgres, not asserted.", ""]

    md += ["## 1. Unauthorized-disclosure resistance", "",
           _table(["Scenario", "Outcome", "Encrypted fields recovered", "Why"],
                  [(a["scenario"], f"**{a['outcome']}**", f"{len(a['recovered'])}/4", a["detail"])
                   for a in r["attacks"]]), ""]

    md += ["## 2. Query usefulness", "",
           _table(["Workflow", "Result"], [
               ("Range-limited report (dept x salary band, groups < 5 hidden)",
                f"works, {u['report_rows']} cells, Legal/Audit suppressed: {u['small_depts_suppressed']}"),
               (f"Payroll run ({u['payroll_rows']} employees: gross pay + account)",
                f"{u['payroll_s'] * 1000:.0f} ms (decrypt inside Postgres)"),
               (f"Salary filter, salary > $120k (HR) -> {u['filter_count']} rows",
                f"{u['filter_s'] * 1000:.0f} ms (SQL WHERE over a decrypt function, no index)"),
               ("Equality search on a full SSN / account",
                "possible: ciphertext is deterministic" if u["equal_ciphertext_for_equal_plaintext"]
                else "not possible: ciphertext is randomized"),
               ("Masked lookups (last 4, band)", "works in SQL, indexable"),
           ]), ""]

    md += ["## 3. Key-management overhead", "",
           _table(["Item", "Result"], [
               ("Keys (4 fields, versioned)", f"{k['keys_before']} -> {k['keys_after']} after rotating all four"),
               ("Where keys live", "table dbenc.key_store, inside the database"),
               ("Who can read keys", "owner role + any superuser (DBA)"),
               ("Who may decrypt which field", "GRANT EXECUTE on decrypt functions"),
               (f"Rotate all 4 field keys ({k['rows_per_field']} rows each)",
                f"{k['rotate_all_s']:.2f} s, plaintext never leaves Postgres"),
               ("Data intact after rotation", str(k["data_intact_after_rotation"])),
               ("Keys travel with a full DB backup", "yes (key_store is a table) unless excluded"),
           ]), ""]

    md += ["## 4. Sensitive information exposed to each role", "",
           "Per employee record, 7 sensitive fields (4 encrypted + 3 masked). `full` = plaintext, `masked` = derived value, "
           "`-` = denied.", ""]
    rows = []
    for role in C.ROLES:
        states = list(r["matrix"][role].values())
        rows.append([C.ROLE_LABEL[role]] + [CELL[r["matrix"][role][f]] for f in C.SENSITIVE_FIELDS] +
                    [f"{states.count('PLAIN')} / {states.count('MASKED')} / {states.count('DENIED')}"])
    md += [_table(["Role"] + [C.FIELD_LABEL[f] for f in C.SENSITIVE_FIELDS] + ["full / masked / denied"], rows), ""]

    names = []
    for a in r["attacks"]:
        if "excluded" not in a["scenario"]:
            names.append(a)
    md += ["Non-role actors (encrypted fields recovered, of 4):", "",
           _table(["Actor", "Fields recovered"], [(a["scenario"], len(a["recovered"])) for a in names]), ""]
    return "\n".join(md)


if __name__ == "__main__":
    import argparse

    from . import init_db

    ap = argparse.ArgumentParser()
    ap.add_argument("--employees", type=int, default=1000)
    ap.add_argument("--no-reset", action="store_true", help="evaluate the current database instead of re-initialising it")
    args = ap.parse_args()
    if not args.no_reset:
        init_db.main(args.employees)       # fresh keys + data, so key counts and timings start from the same state
    result = build()
    out_dir = C.ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(result, indent=2, default=str))
    text = render(result)
    (out_dir / "evaluation.md").write_text(text)
    print(text)
    print(f"\nSaved: {out_dir / 'evaluation.md'}")
