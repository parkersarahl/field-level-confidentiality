from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


# -------------------------------------------------
# LOGIN
# -------------------------------------------------

@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        user_id = request.form["user_id"]
        password = request.form["password"]

        # TEMPORARY UI PREVIEW LOGIN
        users = {
            "employee": "employee_dashboard",
            "payroll": "payroll_dashboard",
            "hr": "hr_dashboard",
            "analyst": "analyst_dashboard"
        }

        if password == "1234" and user_id in users:
            return redirect(url_for(users[user_id]))

        return "Invalid demo login"

    return render_template("login.html")


# -------------------------------------------------
# EMPLOYEE
# -------------------------------------------------

@app.route("/employee/dashboard")
def employee_dashboard():
    return render_template(
        "employee_dashboard.html",
        title="Employee Dashboard",
        dashboard_url="/employee/dashboard"
    )


@app.route("/employee/profile")
def employee_profile():
    return render_template(
        "employee_profile.html",
        title="My Profile",
        dashboard_url="/employee/dashboard"
    )


@app.route("/employee/pay-benefits")
def employee_pay_benefits():
    return render_template(
        "employee_pay_benefits.html",
        title="My Pay & Benefits",
        dashboard_url="/employee/dashboard"
    )


# -------------------------------------------------
# PAYROLL
# -------------------------------------------------

@app.route("/payroll/dashboard")
def payroll_dashboard():
    return render_template(
        "payroll_dashboard.html",
        title="Payroll Dashboard",
        dashboard_url="/payroll/dashboard"
    )


@app.route("/payroll/setup")
def payroll_setup():
    return render_template(
        "payroll_setup.html",
        title="Complete Payroll Setup",
        dashboard_url="/payroll/dashboard"
    )


@app.route("/payroll/records")
def payroll_records():
    return render_template(
        "payroll_records.html",
        title="Payroll Records",
        dashboard_url="/payroll/dashboard"
    )


# -------------------------------------------------
# HR
# -------------------------------------------------

@app.route("/hr/dashboard")
def hr_dashboard():
    return render_template(
        "hr_dashboard.html",
        title="HR Dashboard",
        dashboard_url="/hr/dashboard"
    )


@app.route("/hr/add-employee")
def hr_add_employee():
    return render_template(
        "hr_add_employee.html",
        title="Add New Employee",
        dashboard_url="/hr/dashboard"
    )


@app.route("/hr/employees")
def hr_employees():
    return render_template(
        "hr_employees.html",
        title="Employees",
        dashboard_url="/hr/dashboard"
    )


# -------------------------------------------------
# ANALYST
# -------------------------------------------------

@app.route("/analyst/dashboard")
def analyst_dashboard():
    return render_template(
        "analyst_dashboard.html",
        title="Analyst Dashboard",
        dashboard_url="/analyst/dashboard"
    )


@app.route("/analyst/salary-report")
def analyst_salary_report():
    return render_template(
        "analyst_salary_report.html",
        title="Salary Band Report",
        dashboard_url="/analyst/dashboard"
    )


@app.route("/analyst/department-summary")
def analyst_department_summary():
    return render_template(
        "analyst_department_summary.html",
        title="Department Summary",
        dashboard_url="/analyst/dashboard"
    )


# -------------------------------------------------
# START SERVER
# -------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)