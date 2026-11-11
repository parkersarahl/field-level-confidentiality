"""Create the database, roles, schema and keys, then seed.

    python -m flc.init_db [--employees 1000]
"""
import argparse

from . import config as C
from .db import admin
from .seed import DEMO_USERS, seed

SQL_DIR = C.ROOT / "db"


def _run(conn, text):
    conn.execute(text)            


def main(n=1000):
    with admin("postgres", autocommit=True) as conn:
        if not conn.execute("select 1 from pg_database where datname = %s", (C.DBNAME,)).fetchone():
            conn.execute(f'create database "{C.DBNAME}" encoding \'UTF8\' template template0')

    with admin(autocommit=True) as conn:
        _run(conn, (SQL_DIR / "00_roles.sql").read_text())
        tmpl = (SQL_DIR / "10_schema.sql.tmpl").read_text()
        _run(conn, tmpl.replace("__S__", C.SCHEMA).replace("__OWNER__", C.SCHEMA_OWNER))   
        _run(conn, (SQL_DIR / "20_dbenc_crypto.sql").read_text())                           
    count = seed(n)
    print(f"initialised {C.DBNAME}: {count} employees loaded, encrypted inside Postgres")
    with admin() as conn:
        accounts = conn.execute("select username, role, emp_id from dbenc.app_users order by role, username").fetchall()
    pw = {u: p for u, p, _r, _c in DEMO_USERS}
    print("\nsign-in accounts (passwords are stored as bcrypt hashes):")
    for a in accounts:
        print(f"  {a['username']:<14} {pw[a['username']]:<22} {a['role']:<11} emp {a['emp_id'] or '-'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--employees", type=int, default=1000)
    main(ap.parse_args().employees)
