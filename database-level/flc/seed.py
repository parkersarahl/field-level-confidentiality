"""Deterministic synthetic employees (Faker seed 42)."""
import json
import random
from datetime import date, timedelta

from faker import Faker

from . import config as C
from . import impl_dbenc
from .db import admin

# department -> (salary range, titles, weight)
DEPTS = {
    "Engineering": ((95_000, 175_000), ["Software Engineer", "Senior Engineer", "QA Analyst", "DevOps Engineer"], 24),
    "Sales":       ((55_000, 140_000), ["Account Executive", "Sales Manager", "Sales Associate"], 18),
    "Operations":  ((48_000, 105_000), ["Operations Analyst", "Logistics Coordinator", "Plant Supervisor"], 18),
    "Finance":     ((62_000, 135_000), ["Accountant", "Financial Analyst", "Payroll Specialist"], 10),
    "Support":     ((38_000, 72_000),  ["Support Agent", "Support Lead", "Technical Writer"], 16),
    "Marketing":   ((52_000, 118_000), ["Marketing Specialist", "Brand Manager", "Content Strategist"], 8),
    "HR":          ((58_000, 112_000), ["HR Generalist", "Recruiter", "Benefits Analyst"], 6),
}
# Deliberately tiny departments: inference-attack targets for the range report.
TINY = {"Legal": (1, (110_000, 190_000), ["General Counsel"]),
        "Internal Audit": (2, (85_000, 140_000), ["Internal Auditor", "Audit Manager"])}

REF_DATE = date(2026, 10, 1)      # fixed "today" for ages: generate() must not depend on the real date


def _dob(rng, min_age, max_age):
    """A birth date min_age..max_age years before REF_DATE. (Faker's date_of_birth uses the real
    today, which made the expected data change from one day to the next and broke the tests.)"""
    return REF_DATE - timedelta(days=rng.randint(min_age * 365, max_age * 365 + 364))


BANKS = ["Riverbend Credit Union", "First Demo Bank", "Summit Federal", "Lakeshore Savings"]
PLANS = ["PPO Gold", "PPO Silver", "HDHP + HSA", "HMO Basic", "Waived"]


def generate(n, seed=42):
    fake = Faker("en_US")
    Faker.seed(seed)
    rng = random.Random(seed)
    slots = []                                   # (department, salary range, titles)
    names = list(DEPTS)
    for _ in range(n - sum(v[0] for v in TINY.values())):
        d = rng.choices(names, weights=[DEPTS[k][2] for k in names])[0]
        slots.append((d, DEPTS[d][0], DEPTS[d][1]))
    for d, (count, rng_sal, titles) in TINY.items():
        slots += [(d, rng_sal, titles)] * count

    emps = []
    for i, (dept, (lo, hi), titles) in enumerate(slots, start=1):
        first, last = fake.first_name(), fake.last_name()
        deps = []
        for _ in range(rng.choice([0, 0, 1, 2, 3])):
            rel = rng.choice(["spouse", "child", "child"])
            deps.append({"name": f"{fake.first_name()} {last}", "relation": rel,
                         "dob": _dob(rng, 1, 60 if rel == "spouse" else 17).isoformat()})
        if i == 1 and len(deps) < 2:             # employee 1 is the demo record: make it interesting
            deps = [{"name": f"Robin {last}", "relation": "spouse", "dob": "1988-04-12"},
                    {"name": f"Casey {last}", "relation": "child", "dob": "2016-09-30"}]
        plan = rng.choice(PLANS) if i != 1 else "PPO Gold"
        if plan == "Waived":
            deps = []
        kinds = {d["relation"] for d in deps}
        tier = ("None" if plan == "Waived" else "Employee only" if not deps else
                "Family" if kinds == {"spouse", "child"} else "Employee + spouse" if "spouse" in kinds
                else "Employee + children")
        emps.append({
            "emp_id": i, "full_name": f"{first} {last}", "email": f"{first}.{last}{i}@example.test".lower(),
            "department": dept, "title": rng.choice(titles),
            "hire_date": fake.date_between(start_date=date(2014, 1, 1), end_date=date(2026, 9, 30)),
            "salary": rng.randrange(lo, hi, 500), "pay_freq": rng.choice(["biweekly"] * 4 + ["monthly"]),
            # synthetic SSNs use area 900-999 (never issued)
            "ssn": f"{rng.randint(900, 999)}-{rng.randint(1, 49):02d}-{rng.randint(1, 9999):04d}",
            "bank_name": rng.choice(BANKS), "acct": str(rng.randint(10**9, 10**11 - 1)),
            "plan_name": plan, "coverage_tier": tier, "dependents": json.dumps(deps),
        })
    return emps


def truth(emp_id):
    """The plaintext originally loaded for one employee (for verifying what an attacker recovered)."""
    with admin() as conn:
        n = conn.execute(f"select count(*) as n from dbenc.employees").fetchone()["n"]
    return generate(n)[emp_id - 1]


# Demo sign-ins: (username, password, database role, how to pick the employee). Passwords are for the demo only.
DEMO_USERS = [
    ("employee1", "Harbor-emp1-2026", "r_employee", "emp_id = 1"),
    ("employee2", "Harbor-emp2-2026", "r_employee", "emp_id = 2"),
    ("payroll.clerk", "Harbor-payroll-2026", "r_payroll", "title = 'Payroll Specialist' and emp_id <> 1"),
    ("hr.partner", "Harbor-hr-2026", "r_hr", "department = 'HR' and title in ('Benefits Analyst', 'HR Generalist')"),
    ("analyst", "Harbor-analyst-2026", "r_analyst", "title = 'Operations Analyst'"),
    ("dba", "Harbor-dba-2026", "dba", None),
]


def seed_users(conn):
    """Create the sign-in accounts. Each is tied to a real employee row; the password is hashed inside Postgres."""
    out = []
    for username, password, role, cond in DEMO_USERS:
        emp = None
        if cond:
            row = (conn.execute(f"select emp_id from dbenc.employees where {cond} order by emp_id limit 1").fetchone()
                   or conn.execute("select emp_id from dbenc.employees order by emp_id limit 1").fetchone())
            emp = row["emp_id"]
        conn.execute("select dbenc.put_user(%s, %s, %s, %s)", (username, password, role, emp))
        out.append((username, password, role, emp))
    return out


def seed(n=1000):
    emps = generate(n)
    with admin() as conn:
        conn.execute("truncate dbenc.app_users, dbenc.benefits, dbenc.tax_bank, dbenc.compensation, dbenc.employees")
        with conn.cursor() as cur:
            cur.executemany(
                "insert into dbenc.employees values (%(emp_id)s, %(full_name)s, %(email)s, %(department)s, %(title)s, %(hire_date)s)",
                emps)
        impl_dbenc.load(conn, emps)
        seed_users(conn)
        conn.commit()
    return len(emps)
