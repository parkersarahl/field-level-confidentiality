from pathlib import Path
import os
import json

import psycopg
from werkzeug.security import generate_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DB_CONFIG = {
    "host": os.environ.get("PGHOST", "localhost"),
    "port": os.environ.get("PGPORT", "5432"),
    "dbname": os.environ.get("PGDATABASE", "flc_payroll"),
    "user": os.environ.get("PGUSER", "postgres"),
    "password": os.environ.get("FLC_ADMIN_PASSWORD", os.environ.get("PGPASSWORD", "postgres")),
}


# =========================================================
# AES-GCM CONFIGURATION
# =========================================================

KEY_VERSION = 1
KEY_PATH = Path("secrets") / "aes_key.bin"


def get_or_create_key():
    """
    Load the existing AES-256 key.
    If this is the first run and no key exists, create one.
    """
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()

    key = AESGCM.generate_key(bit_length=256)
    KEY_PATH.write_bytes(key)

    print(f"Created AES-256 key: {KEY_PATH}")

    return key


def encrypt_text(plaintext, table_name, column_name, emp_id, key):
    """
    Stored ciphertext format:
    [1-byte key version][12-byte nonce][ciphertext + GCM tag]

    AAD binds the ciphertext to a particular table, column, and employee.
    """
    aes = AESGCM(key)
    nonce = os.urandom(12)

    aad = f"{table_name}.{column_name}:{emp_id}".encode("utf-8")

    ciphertext = aes.encrypt(
        nonce,
        str(plaintext).encode("utf-8"),
        aad
    )

    return bytes([KEY_VERSION]) + nonce + ciphertext


def salary_band(salary):
    """
    $20,000-wide salary bands.
    Example: 105000 -> $100,000-$119,999
    """
    lower = (salary // 20000) * 20000
    upper = lower + 19999

    return f"${lower:,}-${upper:,}"


# =========================================================
# DEMO DATA
# =========================================================

# These are synthetic/demo values only.
USERS = [
    {
        "emp_id": 1,
        "name": "Alice",
        "email": "alice@company.com",
        "department": "Engineering",
        "title": "Software Engineer",
        "hire_date": "2026-01-01",
        "user_id": "alice",
        "password": "alice123",
        "role": "r_employee",
        "salary": 105000,
        "pay_freq": "Biweekly",
        "ssn": "900-01-1001",
        "bank_name": "Truist",
        "bank_account": "1000001001",
        "plan_name": "Gold",
        "coverage_tier": "Employee Only",
        "dependents": [],
    },
    {
        "emp_id": 2,
        "name": "Bob",
        "email": "bob@company.com",
        "department": "Engineering",
        "title": "Technician",
        "hire_date": "2026-01-01",
        "user_id": "bob",
        "password": "bob123",
        "role": "r_employee",
        "salary": 72000,
        "pay_freq": "Biweekly",
        "ssn": "900-01-1002",
        "bank_name": "Bank of America",
        "bank_account": "1000001002",
        "plan_name": "Silver",
        "coverage_tier": "Employee + Children",
        "dependents": [
            {"name": "Kevin Jr.", "relation": "Child"}
        ],
    },
    {
        "emp_id": 3,
        "name": "Mallory",
        "email": "mallory@company.com",
        "department": "Engineering",
        "title": "Chemical Engineer",
        "hire_date": "2026-01-01",
        "user_id": "mallory",
        "password": "mallory123",
        "role": "r_employee",
        "salary": 98000,
        "pay_freq": "Monthly",
        "ssn": "900-01-1003",
        "bank_name": "Chase",
        "bank_account": "1000001003",
        "plan_name": "Gold",
        "coverage_tier": "Family",
        "dependents": [
            {"name": "Alex", "relation": "Spouse"},
            {"name": "Mia", "relation": "Child"},
        ],
    },
    {
        "emp_id": 4,
        "name": "Mike",
        "email": "mike@company.com",
        "department": "Admin",
        "title": "Payroll Assistant",
        "hire_date": "2026-01-01",
        "user_id": "mike",
        "password": "mike123",
        "role": "r_payroll",
        "salary": 68000,
        "pay_freq": "Biweekly",
        "ssn": "900-01-1004",
        "bank_name": "Wells Fargo",
        "bank_account": "1000001004",
        "plan_name": "Silver",
        "coverage_tier": "Employee Only",
        "dependents": [],
    },
    {
        "emp_id": 5,
        "name": "Mark",
        "email": "mark@company.com",
        "department": "Admin",
        "title": "HR Manager",
        "hire_date": "2026-01-01",
        "user_id": "mark",
        "password": "mark123",
        "role": "r_hr",
        "salary": 115000,
        "pay_freq": "Monthly",
        "ssn": "900-01-1005",
        "bank_name": "Truist",
        "bank_account": "1000001005",
        "plan_name": "Gold",
        "coverage_tier": "Family",
        "dependents": [
            {"name": "Rose", "relation": "Spouse"},
            {"name": "Noah", "relation": "Child"},
        ],
    },
    {
        "emp_id": 6,
        "name": "Kevin",
        "email": "kevin@company.com",
        "department": "Admin",
        "title": "HR Assistant",
        "hire_date": "2026-01-01",
        "user_id": "kevin",
        "password": "kevin123",
        "role": "r_hr",
        "salary": 62000,
        "pay_freq": "Biweekly",
        "ssn": "900-01-1006",
        "bank_name": "Chase",
        "bank_account": "1000001006",
        "plan_name": "Silver",
        "coverage_tier": "Employee + Spouse",
        "dependents": [
            {"name": "Emma", "relation": "Spouse"}
        ],
    },
    {
        "emp_id": 7,
        "name": "Peter",
        "email": "peter@company.com",
        "department": "Business",
        "title": "Senior Analyst",
        "hire_date": "2026-01-01",
        "user_id": "peter",
        "password": "peter123",
        "role": "r_analyst",
        "salary": 102000,
        "pay_freq": "Monthly",
        "ssn": "900-01-1007",
        "bank_name": "Bank of America",
        "bank_account": "1000001007",
        "plan_name": "Gold",
        "coverage_tier": "Employee Only",
        "dependents": [],
    },
    {
        "emp_id": 8,
        "name": "Samuel",
        "email": "samuel@company.com",
        "department": "Business",
        "title": "Junior Analyst",
        "hire_date": "2026-01-01",
        "user_id": "samuel",
        "password": "samuel123",
        "role": "r_analyst",
        "salary": 76000,
        "pay_freq": "Biweekly",
        "ssn": "900-01-1008",
        "bank_name": "Wells Fargo",
        "bank_account": "1000001008",
        "plan_name": "Silver",
        "coverage_tier": "Employee Only",
        "dependents": [],
    },
]


# =========================================================
# DATABASE POPULATION
# =========================================================

def main():
    key = get_or_create_key()

    conn = psycopg.connect(**DB_CONFIG)

    try:
        with conn.cursor() as cur:

            # -------------------------------------------------
            # Clear existing demo/business data.
            # Security policy tables are left intact.
            # -------------------------------------------------

            cur.execute("""
                TRUNCATE TABLE
                    appenc.app_users,
                    appenc.benefits,
                    appenc.tax_bank,
                    appenc.compensation,
                    appenc.employees;
            """)

            for user in USERS:

                emp_id = user["emp_id"]

                # ---------------------------------------------
                # Employee profile
                # ---------------------------------------------

                cur.execute("""
                    INSERT INTO appenc.employees (
                        emp_id,
                        full_name,
                        email,
                        department,
                        title,
                        hire_date
                    )
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (
                    emp_id,
                    user["name"],
                    user["email"],
                    user["department"],
                    user["title"],
                    user["hire_date"],
                ))

                # ---------------------------------------------
                # Login account
                # ---------------------------------------------

                password_hash = generate_password_hash(
                    user["password"]
                )

                cur.execute("""
                    INSERT INTO appenc.app_users (
                        user_id,
                        password_hash,
                        role_name,
                        emp_id
                    )
                    VALUES (%s, %s, %s, %s);
                """, (
                    user["user_id"],
                    password_hash,
                    user["role"],
                    emp_id,
                ))

                # ---------------------------------------------
                # Compensation
                # ---------------------------------------------

                salary_enc = encrypt_text(
                    user["salary"],
                    "compensation",
                    "salary_enc",
                    emp_id,
                    key,
                )

                cur.execute("""
                    INSERT INTO appenc.compensation (
                        emp_id,
                        salary_enc,
                        salary_band,
                        pay_freq
                    )
                    VALUES (%s, %s, %s, %s);
                """, (
                    emp_id,
                    salary_enc,
                    salary_band(user["salary"]),
                    user["pay_freq"],
                ))

                # ---------------------------------------------
                # Tax / bank
                # ---------------------------------------------

                ssn_enc = encrypt_text(
                    user["ssn"],
                    "tax_bank",
                    "ssn_enc",
                    emp_id,
                    key,
                )

                acct_enc = encrypt_text(
                    user["bank_account"],
                    "tax_bank",
                    "acct_enc",
                    emp_id,
                    key,
                )

                ssn_last4 = "".join(
                    c for c in user["ssn"] if c.isdigit()
                )[-4:]

                acct_last4 = "".join(
                    c for c in user["bank_account"] if c.isdigit()
                )[-4:]

                cur.execute("""
                    INSERT INTO appenc.tax_bank (
                        emp_id,
                        ssn_enc,
                        ssn_last4,
                        bank_name,
                        acct_enc,
                        acct_last4
                    )
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (
                    emp_id,
                    ssn_enc,
                    ssn_last4,
                    user["bank_name"],
                    acct_enc,
                    acct_last4,
                ))

                # ---------------------------------------------
                # Benefits
                # ---------------------------------------------

                dependents_json = json.dumps(
                    user["dependents"]
                )

                dependents_enc = encrypt_text(
                    dependents_json,
                    "benefits",
                    "dependents_enc",
                    emp_id,
                    key,
                )

                cur.execute("""
                    INSERT INTO appenc.benefits (
                        emp_id,
                        plan_name,
                        coverage_tier,
                        dependents_enc
                    )
                    VALUES (%s, %s, %s, %s);
                """, (
                    emp_id,
                    user["plan_name"],
                    user["coverage_tier"],
                    dependents_enc,
                ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    print()
    print("Database populated successfully.")
    print()
    print("Demo login accounts:")
    print("-" * 55)

    for user in USERS:
        print(
            f"{user['user_id']:<10} "
            f"password={user['password']:<12} "
            f"role={user['role']}"
        )

    print()
    print("Sensitive salary, SSN, bank account, and dependents")
    print("were encrypted before being stored in PostgreSQL.")


if __name__ == "__main__":
    main()
