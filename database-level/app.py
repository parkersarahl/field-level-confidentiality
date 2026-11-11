"""Mock HR, payroll and benefits portal for the database-level encryption.

    flask --app app run        then open http://localhost:5000

Sign in with a username and password. The password is checked inside Postgres 
which also says which database role and employee the user is. The portal then talks to Postgres as that role's
own login, so visibility of every field is decided by the database, not by this page.
"""
import json
import os
from decimal import Decimal
from functools import wraps

import psycopg
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

from flc import attacks, config as C, trace
from flc import impl_dbenc as db
from flc.db import admin

app = Flask(__name__)
app.secret_key = os.getenv("FLC_SECRET") or os.urandom(24)   # restarting the app signs everyone out

COMPANY = "The Canyons"     

ROLES = {
    "r_employee": dict(title="Employee self-service",
                       blurb="Your own record only: pay, bank details and benefits. Nobody else's, not even their name."),
    "r_payroll": dict(title="Payroll clerk",
                      blurb="Run payroll: salary, SSN and bank account for every employee. No benefit data."),
    "r_hr": dict(title="HR partner",
                 blurb="Salaries, salary bands and benefit dependents. Never the SSN or the bank account."),
    "r_analyst": dict(title="Reporting analyst",
                      blurb="Aggregate headcount by department and salary band only. No individual's band, no exact pay."),
    "dba": dict(title="Database administrator", 
                blurb="Superuser. Sees the stored ciphertext, and what else the database lets an operator do."),
}

# ----------------------------------------------------------------------------------- helpers
def user():
    return session.get("user")


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not user():
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper


def db_role():
    return None if user()["role"] == "dba" else user()["role"]


def viewer():
    return user()["emp_id"]


@app.template_filter("money")
def money(v):
    return f"${float(v):,.0f}"


@app.before_request
def start_trace():
    g.trace = trace.start() if request.endpoint not in (None, "static") else []


@app.teardown_request
def stop_trace(_exc):
    trace.stop()


@app.context_processor
def inject():
    entries = getattr(g, "trace", [])
    groups = []                                   # statements grouped by the database connection that ran them
    for e in entries:
        if not groups or groups[-1]["pid"] != e["pid"]:
            groups.append({"pid": e["pid"], "role": e["role"], "stmts": []})
        groups[-1]["stmts"].append(e)
    return dict(company=COMPANY, user=user(), roles=ROLES, sql_groups=groups, sql_count=len(entries),
                sql_refused=sum(e["status"] != "ok" for e in entries),
                sql_note=trace.note, sql_html=trace.highlight)


# ----------------------------------------------------------------------------------- login
@app.route("/")
def index():
    if user():
        return redirect(url_for("home"))
    return render_template("login.html")


@app.post("/login")
def login():
    username, password = request.form.get("username", ""), request.form.get("password", "")
    try:
        who = db.authenticate(username, password) if username and password else None
    except psycopg.Error as exc:
        return render_template("setup_needed.html", error=str(exc).strip().splitlines()[0]), 503
    if not who:
        flash("Wrong username or password.", "error")
        return render_template("login.html", username=username), 401
    session.clear()
    session["user"] = dict(role=who["role"], emp_id=who["emp_id"], name=who["full_name"] or "postgres",
                           title=who["title"] or "superuser", username=username.strip().lower())
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ----------------------------------------------------------------------------------- pages
@app.route("/home")
@login_required
def home():
    q = request.args.get("q", "").strip()
    results = db.search(q, role=db_role(), viewer_id=viewer()) if q else []
    if q and len(results) == 1 and request.args.get("go"):
        return redirect(url_for("employee", emp_id=results[0]["emp_id"]))
    return render_template("home.html", q=q, results=results)


@app.route("/employee/<int:emp_id>")
@login_required
def employee(emp_id):
    if user()["role"] == "dba":
        with admin() as conn:
            emp = conn.execute("select * from dbenc.employees where emp_id = %s", (emp_id,)).fetchone()
        if not emp:
            abort(404)
        return render_template("employee_dba.html", emp=emp, raw=attacks.ciphertext_preview(emp_id),
                               hunt=attacks.dba_key_hunt(emp_id), enc=C.ENC_FIELDS)
    # Everyone on staff is also an employee: their own record opens through employee self-service,
    # the same view any employee gets, not through the work role they signed in with.
    mine = emp_id == viewer()
    acting = "r_employee" if mine else db_role()
    prof = db.read_profile(acting, emp_id, viewer())
    if not prof["employee"]:
        if user()["role"] == "r_employee":        # Postgres returned no row: row-level security hides everyone else
            return render_template("denied.html", emp_id=emp_id), 403
        abort(404)
    rec = db.read_record(acting, emp_id, viewer_id=viewer())
    deps = None
    if rec["dependents"][0] == "PLAIN":
        deps = json.loads(rec["dependents"][1])
    return render_template("employee.html", p=prof, e=prof["employee"], rec=rec, deps=deps, mine=mine,
                           role_title=ROLES[acting]["title"], work_role=ROLES[user()["role"]]["title"],
                           switched=acting != user()["role"])


@app.route("/report")
@login_required
def report():
    denied, rows = None, []
    if user()["role"] == "dba":
        with admin() as conn:
            rows = conn.execute("select department, salary_band, headcount from dbenc.salary_band_report order by 1, 2").fetchall()
    else:
        try:
            rows = db.salary_report(db_role())
        except psycopg.errors.InsufficientPrivilege as exc:
            denied = str(exc).splitlines()[0]
    depts = {}
    for r in rows:
        depts.setdefault(r["department"], []).append(r)
    return render_template("report.html", depts=depts, denied=denied)


@app.route("/payroll")
@login_required
def payroll():
    denied, rows, total = None, [], Decimal(0)
    if user()["role"] == "dba":
        denied = "The superuser could run this, but this portal only shows the payroll run to the payroll role."
    else:
        try:
            rows = db.payroll_run(db_role())
            total = sum(r["gross_per_period"] for r in rows)
        except psycopg.errors.InsufficientPrivilege as exc:
            denied = str(exc).splitlines()[0]
    return render_template("payroll.html", denied=denied, rows=rows[:12], count=len(rows), total=total)


if __name__ == "__main__":
    app.run(debug=False)
