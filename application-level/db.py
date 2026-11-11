import os

import psycopg


def get_connection():
    # Connection settings come from the environment so the app runs on any host/port
    # (e.g. PGPORT=5433); the defaults match a stock local PostgreSQL on 5432.
    return psycopg.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "flc_payroll"),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("FLC_ADMIN_PASSWORD", os.environ.get("PGPASSWORD", "postgres")),
    )
