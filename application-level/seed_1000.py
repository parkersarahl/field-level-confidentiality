"""Seed the app-level database with the SAME 1,000 synthetic employees as the db-level project.

This script ADDS data only; it changes nothing about the schema, crypto, or app code.
It reuses populate_db.py's own encrypt_text() and salary_band() so every row is stored
exactly the way the app expects, and it pulls the employee data from the db-level
project's deterministic generator (Faker seed 42), so both databases hold identical people.

Run after init_db.py:
    python seed_1000.py             (expects ../flc-payroll-db next to this folder)
    python seed_1000.py --src PATH  (path to the flc-payroll-db project)

The 8 demo logins from populate_db.py (alice ... samuel) are kept, attached to
employees 1-8 with the same roles as before.
"""
import argparse
import json
import sys
from pathlib import Path

import psycopg
from werkzeug.security import generate_password_hash

from populate_db import DB_CONFIG, USERS, encrypt_text, get_or_create_key, salary_band


def load_generator(src):
    """Import flc.seed.generate from the db-level project without installing it."""
    src = Path(src).resolve()
    if not (src / "flc" / "seed.py").exists():
        sys.exit(f"Cannot find the db-level project at {src} (flc/seed.py missing). Use --src PATH.")
    sys.path.insert(0, str(src))
    from flc.seed import generate
    return generate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(Path(__file__).resolve().parent.parent / "database-level"))
    ap.add_argument("--employees", type=int, default=1000)
    args = ap.parse_args()

    generate = load_generator(args.src)
    emps = generate(args.employees)
    key = get_or_create_key()

    conn = psycopg.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                TRUNCATE TABLE
                    appenc.app_users,
                    appenc.benefits,
                    appenc.tax_bank,
                    appenc.compensation,
                    appenc.employees;
            """)

            for e in emps:
                emp_id = e["emp_id"]
                cur.execute("""
                    INSERT INTO appenc.employees (emp_id, full_name, email, department, title, hire_date)
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (emp_id, e["full_name"], e["email"], e["department"], e["title"], e["hire_date"]))

                cur.execute("""
                    INSERT INTO appenc.compensation (emp_id, salary_enc, salary_band, pay_freq)
                    VALUES (%s, %s, %s, %s);
                """, (emp_id,
                      encrypt_text(e["salary"], "compensation", "salary_enc", emp_id, key),
                      salary_band(e["salary"]),
                      e["pay_freq"]))

                digits = "".join(c for c in e["ssn"] if c.isdigit())
                cur.execute("""
                    INSERT INTO appenc.tax_bank (emp_id, ssn_enc, ssn_last4, bank_name, acct_enc, acct_last4)
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (emp_id,
                      encrypt_text(e["ssn"], "tax_bank", "ssn_enc", emp_id, key),
                      digits[-4:],
                      e["bank_name"],
                      encrypt_text(e["acct"], "tax_bank", "acct_enc", emp_id, key),
                      e["acct"][-4:]))

                # dependents is already a JSON string in the generator's output
                deps = e["dependents"] if isinstance(e["dependents"], str) else json.dumps(e["dependents"])
                cur.execute("""
                    INSERT INTO appenc.benefits (emp_id, plan_name, coverage_tier, dependents_enc)
                    VALUES (%s, %s, %s, %s);
                """, (emp_id,
                      e["plan_name"],
                      e["coverage_tier"],
                      encrypt_text(deps, "benefits", "dependents_enc", emp_id, key)))

            # Keep the original 8 demo logins, now pointing at employees 1-8 of the shared dataset.
            for u in USERS:
                cur.execute("""
                    INSERT INTO appenc.app_users (user_id, password_hash, role_name, emp_id)
                    VALUES (%s, %s, %s, %s);
                """, (u["user_id"], generate_password_hash(u["password"]), u["role"], u["emp_id"]))

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print(f"Seeded appenc with {len(emps)} employees (same dataset as the db-level project).")
    print("Logins kept from populate_db.py:")
    for u in USERS:
        print(f"  {u['user_id']:<10} password={u['password']:<12} role={u['role']:<11} emp {u['emp_id']}")


if __name__ == "__main__":
    main()
