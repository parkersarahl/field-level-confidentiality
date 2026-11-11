"""Shared configuration: connection settings, roles and the field catalogue."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# --- connection (override with environment variables) -------------------------
HOST = os.getenv("PGHOST", "localhost")
PORT = int(os.getenv("PGPORT", "5432"))
DBNAME = os.getenv("FLC_DB", "flc")
ADMIN_USER = os.getenv("FLC_ADMIN_USER", "postgres")      # the "DBA" / superuser
ADMIN_PASSWORD = os.getenv("FLC_ADMIN_PASSWORD") or None
ROLE_PASSWORD = os.getenv("FLC_ROLE_PASSWORD", "demo")    # demo only: one password for all app roles
# command used to run pg_dump (needed only by the stolen-backup scenario); must write SQL to stdout
PG_DUMP = os.getenv("FLC_PGDUMP", "pg_dump")

# --- schema ----------------------------------------------------------------------
SCHEMA = "dbenc"          # everything lives in this schema (tables, key_store, functions)
SCHEMA_OWNER = "dbenc_owner"

# --- application roles (each is its own LOGIN role: no SET ROLE escalation path) -
ROLES = ("r_employee", "r_payroll", "r_hr", "r_analyst")
ROLE_LABEL = {
    "r_employee": "Employee (self-service)",
    "r_payroll": "Payroll clerk",
    "r_hr": "HR partner",
    "r_analyst": "Reporting analyst",
}

# --- fields ---------------------------------------------------------------------
# Encrypted fields (ciphertext in the table). Four fields, four independent keys.
ENC_FIELDS = ("salary", "ssn", "acct", "dependents")
# Plaintext values derived at write time so masked views and range reports still work.
DERIVED_FIELDS = ("salary_band", "ssn_last4", "acct_last4")
SENSITIVE_FIELDS = ("salary", "salary_band", "ssn", "ssn_last4", "acct", "acct_last4", "dependents")
FIELD_LABEL = {
    "salary": "Salary",
    "salary_band": "Salary band ($20k)",
    "ssn": "SSN (full)",
    "ssn_last4": "SSN last 4",
    "acct": "Bank account (full)",
    "acct_last4": "Account last 4",
    "dependents": "Benefit dependents",
}

PAY_PERIODS = 26  # biweekly
