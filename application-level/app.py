from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash

from db import get_connection
from security import evaluate_access
from crypto import decrypt_text


app = Flask(__name__)
app.secret_key = "database-security-project-secret-key"


# =========================================================
# ALLOWED REQUESTABLE FIELDS
# =========================================================
#
# User UI থেকে যেকোন option select করতে পারবে,
# কিন্তু backend শুধুমাত্র এই whitelist-এর field accept করবে.
#

FIELD_MAP = {

    # Employee profile
    "employees.full_name": {
        "table": "employees",
        "column": "full_name",
        "label": "Full Name",
        "encrypted": False
    },

    "employees.email": {
        "table": "employees",
        "column": "email",
        "label": "Email",
        "encrypted": False
    },

    "employees.department": {
        "table": "employees",
        "column": "department",
        "label": "Department",
        "encrypted": False
    },

    "employees.title": {
        "table": "employees",
        "column": "title",
        "label": "Job Title",
        "encrypted": False
    },

    "employees.hire_date": {
        "table": "employees",
        "column": "hire_date",
        "label": "Hire Date",
        "encrypted": False
    },


    # Compensation
    "compensation.salary_enc": {
        "table": "compensation",
        "column": "salary_enc",
        "label": "Exact Salary",
        "encrypted": True
    },

    "compensation.salary_band": {
        "table": "compensation",
        "column": "salary_band",
        "label": "Salary Band",
        "encrypted": False
    },

    "compensation.pay_freq": {
        "table": "compensation",
        "column": "pay_freq",
        "label": "Pay Frequency",
        "encrypted": False
    },


    # Tax / bank
    "tax_bank.ssn_enc": {
        "table": "tax_bank",
        "column": "ssn_enc",
        "label": "Full SSN",
        "encrypted": True
    },

    "tax_bank.ssn_last4": {
        "table": "tax_bank",
        "column": "ssn_last4",
        "label": "SSN Last 4",
        "encrypted": False
    },

    "tax_bank.bank_name": {
        "table": "tax_bank",
        "column": "bank_name",
        "label": "Bank Name",
        "encrypted": False
    },

    "tax_bank.acct_enc": {
        "table": "tax_bank",
        "column": "acct_enc",
        "label": "Full Bank Account",
        "encrypted": True
    },

    "tax_bank.acct_last4": {
        "table": "tax_bank",
        "column": "acct_last4",
        "label": "Bank Account Last 4",
        "encrypted": False
    },


    # Benefits
    "benefits.plan_name": {
        "table": "benefits",
        "column": "plan_name",
        "label": "Benefits Plan",
        "encrypted": False
    },

    "benefits.coverage_tier": {
        "table": "benefits",
        "column": "coverage_tier",
        "label": "Coverage Tier",
        "encrypted": False
    },

    "benefits.dependents_enc": {
        "table": "benefits",
        "column": "dependents_enc",
        "label": "Dependents",
        "encrypted": True
    },
}


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return redirect(url_for("access_request"))


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        user_id = request.form["user_id"]
        password = request.form["password"]

        conn = get_connection()

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    u.user_id,
                    u.password_hash,
                    u.role_name,
                    u.emp_id,
                    e.full_name
                FROM appenc.app_users AS u
                JOIN appenc.employees AS e
                    ON u.emp_id = e.emp_id
                WHERE u.user_id = %s;
            """, (user_id,))

            user = cur.fetchone()

        conn.close()


        if user is not None:

            if check_password_hash(
                user[1],
                password
            ):

                session.clear()

                session["user_id"] = user[0]
                session["role_name"] = user[2]
                session["emp_id"] = user[3]
                session["full_name"] = user[4]

                return redirect(
                    url_for("access_request")
                )

        error = "Invalid User ID or password."


    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# GENERIC FIELD-LEVEL ACCESS REQUEST
# =========================================================

@app.route("/request-access", methods=["GET", "POST"])
def access_request():

    if "user_id" not in session:
        return redirect(url_for("login"))


    role_name = session["role_name"]
    logged_in_emp_id = session["emp_id"]


    # -----------------------------------------------------
    # Get logged-in user's clearance
    # -----------------------------------------------------

    conn = get_connection()

    with conn.cursor() as cur:

        cur.execute("""
            SELECT clearance_level
            FROM appenc.role_clearance
            WHERE role_name = %s;
        """, (role_name,))

        clearance_row = cur.fetchone()

    conn.close()

    clearance = clearance_row[0]


    # Default page state
    decision = None
    requested_label = None
    requested_value = None


    # =====================================================
    # PROCESS ACCESS REQUEST
    # =====================================================

    if request.method == "POST":

        target_emp_id = request.form.get(
            "target_emp_id",
            type=int
        )

        requested_field = request.form.get(
            "requested_field"
        )


        # -------------------------------------------------
        # Reject invalid/unrecognized fields
        # -------------------------------------------------

        if requested_field not in FIELD_MAP:

            return "Invalid field request.", 400


        field = FIELD_MAP[requested_field]

        table_name = field["table"]
        column_name = field["column"]

        requested_label = field["label"]


        # -------------------------------------------------
        # Run the three confidentiality gates
        # -------------------------------------------------

        decision = evaluate_access(
            role_name,
            logged_in_emp_id,
            target_emp_id,
            table_name,
            column_name
        )


        # -------------------------------------------------
        # IMPORTANT:
        # Do not retrieve/decrypt the value unless access
        # has already been granted.
        # -------------------------------------------------

        if decision["access_granted"]:

            conn = get_connection()

            with conn.cursor() as cur:

                # table/column come ONLY from FIELD_MAP,
                # not directly from user input.
                query = f"""
                    SELECT {column_name}
                    FROM appenc.{table_name}
                    WHERE emp_id = %s;
                """

                cur.execute(
                    query,
                    (target_emp_id,)
                )

                row = cur.fetchone()

            conn.close()


            if row is not None:

                stored_value = row[0]


                # -----------------------------------------
                # Decrypt protected fields
                # -----------------------------------------

                if field["encrypted"]:

                    requested_value = decrypt_text(
                        stored_value,
                        table_name,
                        column_name,
                        target_emp_id
                    )

                else:

                    requested_value = stored_value


                # -----------------------------------------
                # Display formatting
                # -----------------------------------------

                if requested_field == "compensation.salary_enc":

                    requested_value = (
                        f"${int(requested_value):,}"
                    )

            else:

                requested_value = "No record found."


    return render_template(
        "access_request.html",

        title="Field-Level Confidentiality Demo",

        dashboard_url="/request-access",

        full_name=session["full_name"],
        user_id=session["user_id"],
        emp_id=session["emp_id"],
        role_name=session["role_name"],
        clearance=clearance,

        decision=decision,
        requested_label=requested_label,
        requested_value=requested_value
    )



# =========================================================
# Summary report
# =========================================================


MIN_GROUP_SIZE = 5


@app.route("/salary-band-report")
def salary_band_report():

    # Must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Only Analyst can access this report
    if session["role_name"] != "r_analyst":
        return render_template(
            "salary_band_report.html",
            access_granted=False,
            rows=[],
            min_group_size=MIN_GROUP_SIZE
        )

    conn = get_connection()

    try:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    salary_band,
                    COUNT(*) AS employee_count
                FROM appenc.compensation
                GROUP BY salary_band
                ORDER BY salary_band;
            """)

            result = cur.fetchall()

    finally:
        conn.close()

    rows = []

    for salary_band, employee_count in result:

        if employee_count < MIN_GROUP_SIZE:
            rows.append({
                "salary_band": salary_band,
                "employee_count": None,
                "suppressed": True
            })
        else:
            rows.append({
                "salary_band": salary_band,
                "employee_count": employee_count,
                "suppressed": False
            })

    return render_template(
        "salary_band_report.html",
        access_granted=True,
        rows=rows,
        min_group_size=MIN_GROUP_SIZE
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)