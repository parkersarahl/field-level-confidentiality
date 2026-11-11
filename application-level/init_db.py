import os
from pathlib import Path

import psycopg

# Connection settings from the environment; defaults match a stock local PostgreSQL on 5432.
# For a server on another port: PGPORT=5433 python init_db.py
CONN = dict(
    host=os.environ.get("PGHOST", "localhost"),
    port=os.environ.get("PGPORT", "5432"),
    user=os.environ.get("PGUSER", "postgres"),
    password=os.environ.get("FLC_ADMIN_PASSWORD", os.environ.get("PGPASSWORD", "postgres")),
)
DBNAME = os.environ.get("PGDATABASE", "flc_payroll")

# Create the database if it does not exist yet (CREATE DATABASE cannot run in a transaction,
# so this connection is autocommit and talks to the maintenance database "postgres").
with psycopg.connect(dbname="postgres", autocommit=True, **CONN) as conn:
    exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DBNAME,)).fetchone()
    if not exists:
        conn.execute(f'CREATE DATABASE "{DBNAME}" ENCODING \'UTF8\' TEMPLATE template0')
        print(f'Created database "{DBNAME}".')

sql = (Path("db") / "schema.sql").read_text(encoding="utf-8")
with psycopg.connect(dbname=DBNAME, **CONN) as conn:
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()

print("Database schema initialized successfully!")
