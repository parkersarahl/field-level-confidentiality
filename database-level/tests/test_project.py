"""Tests for the database-level encryption: role x field matrix, attack outcomes, tamper detection, rotation."""
import json

import psycopg
import pytest

from flc import attacks, config as C
from flc import impl_dbenc as db
from flc import seed
from flc.db import admin, attempt, role_session

try:
    with admin() as _c:
        _c.execute("select 1 from dbenc.employees limit 1")
    DB_OK = True
except Exception as _err:                           # no server / wrong password / not initialised
    DB_OK = False
    DB_ERR = str(_err).strip().splitlines()[0] if str(_err).strip() else type(_err).__name__
needs_db = pytest.mark.skipif(
    not DB_OK, reason="DATABASE TESTS SKIPPED, cannot use the database: " + (DB_ERR if not DB_OK else ""))

P, M, D = "PLAIN", "MASKED", "DENIED"
EXPECTED = {   # salary, band, ssn, ssn4, acct, acct4, dependents
    "r_employee": dict(salary=P, salary_band=D, ssn=D, ssn_last4=M, acct=D, acct_last4=M, dependents=P),
    "r_payroll": dict(salary=P, salary_band=D, ssn=P, ssn_last4=M, acct=P, acct_last4=M, dependents=D),
    "r_hr": dict(salary=P, salary_band=M, ssn=D, ssn_last4=M, acct=D, acct_last4=D, dependents=P),
    "r_analyst": {f: D for f in C.SENSITIVE_FIELDS},     # analyst sees no per-employee field, band included
}


def _viewer(role, emp_id=1):
    return emp_id if role == "r_employee" else None


# ---------------------------------------------------------------------------------- unit (no DB)
def test_seed_data_is_deterministic_and_independent_of_todays_date():
    a, b = seed.generate(200), seed.generate(200)
    assert a == b
    for e in a:                                       # all dependents were born before the fixed reference date
        assert all(d["dob"] < seed.REF_DATE.isoformat() for d in json.loads(e["dependents"]))


def test_band_function():
    assert db.band(74500) == "$60k-80k" and db.band(80000) == "$80k-100k" and db.band(19999) == "$0k-20k"


# ---------------------------------------------------------------------------------- role x field
@needs_db
@pytest.mark.parametrize("role", C.ROLES)
def test_role_field_matrix(role):
    rec = db.read_record(role, 1, viewer_id=_viewer(role))
    assert {f: rec[f][0] for f in C.SENSITIVE_FIELDS} == EXPECTED[role]


@needs_db
def test_band_function_matches_the_database():
    with admin() as conn:
        for s in (19999, 20000, 74500, 80000, 190000):
            assert conn.execute("select dbenc.band(%s) as b", (s,)).fetchone()["b"] == db.band(s)


@needs_db
def test_plaintext_values_are_correct():
    t = seed.truth(1)
    pay = db.read_record("r_payroll", 1)
    assert pay["ssn"][1] == t["ssn"] and pay["acct"][1] == t["acct"] and float(pay["salary"][1]) == t["salary"]
    assert pay["ssn_last4"][1] == t["ssn"][-4:]
    assert db.read_record("r_hr", 1)["salary_band"][1] == db.band(t["salary"])
    assert json.loads(db.read_record("r_hr", 1)["dependents"][1]) == json.loads(t["dependents"])


@needs_db
def test_employee_cannot_read_someone_elses_record():
    rec = db.read_record("r_employee", 1, viewer_id=5)
    assert all(state == D for state, _ in rec.values())


@needs_db
def test_postgres_itself_denies_direct_reads():
    with role_session("r_analyst", 1) as conn:
        for sql in ("select * from dbenc.tax_bank", "select salary_enc from dbenc.compensation"):
            assert attempt(conn, sql)[0] == "denied"
    with role_session("r_hr", 1) as conn:
        assert attempt(conn, "select ssn_enc from dbenc.tax_bank")[0] == "denied"   # HR has no SSN column grant


# ---------------------------------------------------------------------------------- sign-in and the stricter scopes
@needs_db
def test_passwords_are_stored_as_bcrypt_hashes_and_checked_in_the_database():
    with admin() as conn:
        rows = conn.execute("select username, pw_hash from dbenc.app_users").fetchall()
    assert len(rows) == len(seed.DEMO_USERS)
    plain = {p for _u, p, _r, _c in seed.DEMO_USERS}
    assert all(r["pw_hash"].startswith("$2a$10$") and r["pw_hash"] not in plain for r in rows)
    user, pw = _account("r_payroll")
    who = db.authenticate(user.upper(), pw)                                  # username is case-insensitive
    assert who["role"] == "r_payroll" and who["emp_id"] == _emp_of("r_payroll")
    assert db.authenticate(user, pw.swapcase()) is None                      # password is case-sensitive
    assert db.authenticate(user, "") is None and db.authenticate("nobody", "x") is None
    assert db.authenticate(*_account("dba"))["emp_id"] is None


@needs_db
def test_same_password_gets_a_different_hash_per_user():
    with admin() as conn:
        conn.execute("select dbenc.put_user('tmp.a', 'same', 'r_analyst', 16), dbenc.put_user('tmp.b', 'same', 'r_analyst', 16)")
        h = [r["pw_hash"] for r in conn.execute("select pw_hash from dbenc.app_users where username like 'tmp.%'").fetchall()]
        conn.rollback()
    assert len(h) == 2 and h[0] != h[1]


@needs_db
def test_no_role_can_read_the_users_table_and_the_login_connection_can_only_authenticate():
    for role in (*C.ROLES, "r_auth"):
        with role_session(role, 1) as conn:
            assert attempt(conn, "select * from dbenc.app_users")[0] == "denied"
            assert attempt(conn, "select pw_hash from dbenc.app_users")[0] == "denied"
    with role_session("r_auth") as conn:
        for sql in ("select * from dbenc.employees", "select dbenc.salary_of(1)", "select * from dbenc.key_store"):
            assert attempt(conn, sql)[0] == "denied"


@needs_db
def test_per_employee_salary_band_is_visible_to_hr_only():
    # HR reads an individual's band column; everyone else, the analyst included, is denied.
    # The analyst's only salary view is the aggregated salary_band_report (tested separately).
    sql = "select salary_band from dbenc.compensation where emp_id = 1"
    for role, expected in (("r_hr", "ok"), ("r_analyst", "denied"), ("r_payroll", "denied"), ("r_employee", "denied")):
        with role_session(role, 1) as conn:
            assert attempt(conn, sql)[0] == expected, role


@needs_db
def test_analyst_sees_only_the_aggregate_band_report_not_an_individual_band():
    with role_session("r_analyst", None) as conn:
        assert attempt(conn, "select salary_band from dbenc.compensation where emp_id = 1")[0] == "denied"
        assert attempt(conn, "select emp_id, salary_band from dbenc.compensation")[0] == "denied"
        status, rows = attempt(conn, "select department, salary_band, headcount from dbenc.salary_band_report")
        assert status == "ok" and len(rows) > 0          # the aggregate report still works


@needs_db
def test_an_employee_sees_only_their_own_row_even_in_plaintext_tables():
    with role_session("r_employee", 5) as conn:
        assert [r["emp_id"] for r in conn.execute("select emp_id from dbenc.employees").fetchall()] == [5]
        assert conn.execute("select * from dbenc.employees where emp_id = 1").fetchall() == []
        assert conn.execute("select pay_freq from dbenc.compensation where emp_id = 1").fetchall() == []
        assert conn.execute("select bank_name from dbenc.tax_bank where emp_id = 1").fetchall() == []
        assert conn.execute("select plan_name from dbenc.benefits where emp_id = 1").fetchall() == []
    found = db.search("1", role="r_employee", viewer_id=5)       # the directory finds a colleague, but gives only the name
    assert [r["emp_id"] for r in found] == [1] and found[0]["full_name"] == seed.truth(1)["full_name"]
    assert found[0]["department"] is None and found[0]["title"] is None
    with role_session("r_employee", 5) as conn:
        cols = [d.name for d in conn.execute("select * from dbenc.directory('a')").description]
    assert cols == ["emp_id", "full_name"]


@needs_db
def test_staff_roles_still_see_every_employee_row():
    for role in ("r_payroll", "r_hr", "r_analyst"):
        with role_session(role, None) as conn:
            assert conn.execute("select count(*) as n from dbenc.employees").fetchone()["n"] == 1000


# ---------------------------------------------------------------------------------- storage + reports
@needs_db
def test_columns_hold_ciphertext_and_no_plaintext():
    t = seed.truth(1)
    inventory = db.key_inventory()
    with admin() as conn:
        for f, (table, col) in attacks.ENC_COLS.items():
            blob = bytes(conn.execute(f"select {col} as v from dbenc.{table} where emp_id = 1").fetchone()["v"])
            assert blob[0] == max(inventory[f]) and str(t[f]).encode() not in blob   # first byte = key version


@needs_db
def test_report_suppresses_small_groups():
    rows = db.salary_report()
    assert rows and all(r["headcount"] >= 5 for r in rows)
    assert not {"Legal", "Internal Audit"} & {r["department"] for r in rows}


@needs_db
def test_key_rotation_keeps_data_readable():
    before = db.read_record("r_hr", 1)["dependents"][1]
    versions_before = max(db.key_inventory()["dependents"])
    assert db.rotate("dependents") == versions_before + 1
    assert db.read_record("r_hr", 1)["dependents"][1] == before
    with admin() as conn:
        assert bytes(conn.execute("select dependents_enc as v from dbenc.benefits where emp_id = 1").fetchone()["v"])[0] == versions_before + 1


# ---------------------------------------------------------------------------------- attacks
@pytest.fixture(scope="module")
def attack_results():
    return {a["scenario"]: a for a in attacks.run_all(1)}


def _find(results, text):
    return next(v for s, v in results.items() if text in s)


@needs_db
@pytest.mark.parametrize("text,outcome,count", [
    ("hunt for a key", "EXPOSED", 4),
    ("key_store data excluded", "PROTECTED", 0),
    ("reporting analyst", "PROTECTED", 0),
    ("forge app.employee_id", "EXPOSED", 2),
    ("swaps two encrypted", "DETECTED", 0),
])
def test_attack_outcomes(attack_results, text, outcome, count):
    a = _find(attack_results, text)
    assert a["outcome"] == outcome and len(a["recovered"]) == count


@needs_db
def test_stolen_full_backup_exposes_everything(attack_results):
    full = attack_results["Attacker restores a stolen backup"]
    assert full["outcome"] == "EXPOSED" and len(full["recovered"]) == 4


@needs_db
def test_rejects_ciphertext_moved_to_another_row_or_field():
    with admin() as conn:
        ct = conn.execute("select salary_enc from dbenc.compensation where emp_id = 1").fetchone()["salary_enc"]
        assert conn.execute("select dbenc._dec('salary', 1, %s) as v", (ct,)).fetchone()["v"]   # right row: fine
        for field, emp in (("salary", 2), ("ssn", 1)):           # wrong row, wrong field
            with pytest.raises(psycopg.errors.Error):
                conn.execute("select dbenc._dec(%s, %s, %s)", (field, emp, ct))
            conn.rollback()


@needs_db
def test_ciphertext_is_randomised():
    with admin() as conn:
        a, b = (conn.execute("select dbenc._enc('ssn', 1, '900-00-0000') as v").fetchone()["v"] for _ in range(2))
    assert bytes(a) != bytes(b)


@needs_db
def test_swap_attack_leaves_data_restored(attack_results):
    t = seed.truth(1)
    assert float(db.read_record("r_payroll", 1)["salary"][1]) == t["salary"]


# ---------------------------------------------------------------------------------- the portal (flask test client)
@pytest.fixture()
def portal():
    import app as portal_app
    portal_app.app.config["TESTING"] = True
    return portal_app.app.test_client()


def _account(role):
    """(username, password) of the first demo account with this database role ('dba' for the superuser)."""
    for username, password, r, _cond in seed.DEMO_USERS:
        if r == role:
            return username, password
    raise LookupError(f"no demo account with role {role}")


def _sign_in(client, who, password=None):
    """who is a role name (r_hr, r_payroll, ...) or 'dba'; signs in as that role's demo account."""
    username, pw = _account(who)
    return client.post("/login", data={"username": username, "password": password or pw}, follow_redirects=True)


def _emp_of(who):
    with admin() as conn:
        return conn.execute("select emp_id from dbenc.app_users where username = %s", (_account(who)[0],)).fetchone()["emp_id"]


def _someone_else(*avoid):
    return next(i for i in range(1, 50) if i not in avoid)


@needs_db
def test_portal_front_page_is_a_standard_login_form(portal):
    html = portal.get("/").get_data(as_text=True)
    assert 'name="username"' in html and 'type="password"' in html and "/login/" not in html


@needs_db
def test_portal_rejects_wrong_password_and_unknown_user(portal):
    user, pw = _account("r_payroll")
    for u, p in ((user, "wrong"), ("nobody", pw), (user, "")):
        resp = portal.post("/login", data={"username": u, "password": p})
        assert resp.status_code == 401 and "Wrong username or password" in resp.get_data(as_text=True)
    assert portal.get("/home").status_code == 302                        # still signed out


@needs_db
def test_portal_shows_user_name_and_emp_id_after_sign_in(portal):
    me = _emp_of("r_employee")
    html = _sign_in(portal, "r_employee").get_data(as_text=True)
    assert seed.truth(me)["full_name"] in html and f"Emp ID #{me}" in html


@needs_db
def test_portal_search_by_name_and_by_id(portal):
    _sign_in(portal, "r_hr")
    first = seed.truth(7)["full_name"].split()[0]
    by_name = portal.get(f"/home?q={first}").get_data(as_text=True)
    assert seed.truth(7)["full_name"] in by_name
    by_id = portal.get("/home?q=7").get_data(as_text=True)
    assert seed.truth(7)["full_name"] in by_id


@needs_db
def test_portal_record_follows_the_role_scope(portal):
    t = seed.truth(1)
    _sign_in(portal, "r_payroll")                 # payroll: sees SSN and account, not dependents, not the band
    html = portal.get("/employee/1").get_data(as_text=True)
    assert t["ssn"] in html and t["acct"] in html and "Restricted" in html and db.band(t["salary"]) not in html
    portal.get("/logout")
    _sign_in(portal, "r_hr")                    # HR: sees dependents and the band, never the SSN or account
    html = portal.get("/employee/1").get_data(as_text=True)
    first_dependent = json.loads(t["dependents"])[0]["name"]
    assert t["ssn"] not in html and t["acct"] not in html and first_dependent in html and db.band(t["salary"]) in html
    portal.get("/logout")
    _sign_in(portal, "r_analyst")                       # analyst: no exact pay, and not even the band of one person
    html = portal.get("/employee/1").get_data(as_text=True)
    assert db.band(t["salary"]) not in html and "Restricted" in html
    assert f"{int(t['salary']):,}" not in html and t["ssn"] not in html


@needs_db
def test_portal_employee_sees_only_own_record(portal):
    me = _emp_of("r_employee"); other_id = _someone_else(me)
    mine, other_t = seed.truth(me), seed.truth(other_id)
    _sign_in(portal, "r_employee")
    own = portal.get(f"/employee/{me}").get_data(as_text=True)
    assert f"{int(mine['salary']):,}" in own and db.band(mine["salary"]) not in own      # band: HR and analyst only
    other = portal.get(f"/employee/{other_id}")
    body = other.get_data(as_text=True)
    assert other.status_code == 403 and "only open your own record" in body
    assert other_t["full_name"] not in body and f"{int(other_t['salary']):,}" not in body


@needs_db
def test_portal_employee_can_search_colleagues_but_only_sees_names(portal):
    me = _emp_of("r_employee"); cid = _someone_else(me)
    t = seed.truth(cid)
    _sign_in(portal, "r_employee")
    html = portal.get(f"/home?q={t['full_name'].split()[0]}").get_data(as_text=True)
    assert t["full_name"] in html and t["department"] not in html.split("<table")[1] and t["email"] not in html
    by_id = portal.get(f"/home?q={cid}").get_data(as_text=True)
    assert t["full_name"] in by_id and t["title"] not in by_id.split("<table")[1]
    assert portal.get(f"/employee/{cid}").status_code == 403                 # opening the record is still refused


@needs_db
def test_portal_dba_sees_ciphertext_and_the_key_hunt(portal):
    _sign_in(portal, "dba")
    html = portal.get("/employee/1").get_data(as_text=True)
    assert "Ciphertext" in html and "EXPOSED" in html


@needs_db
def test_portal_pages_the_database_refuses_show_its_message(portal):
    _sign_in(portal, "r_analyst")
    assert "permission denied" in portal.get("/payroll").get_data(as_text=True)
    portal.get("/logout")
    _sign_in(portal, "r_payroll")
    assert "permission denied" in portal.get("/report").get_data(as_text=True)


@needs_db
def test_portal_requires_sign_in(portal):
    assert portal.get("/home").status_code == 302


@needs_db
def test_portal_staff_open_their_own_record_through_employee_self_service(portal):
    me = _emp_of("r_payroll")
    t = seed.truth(me)
    _sign_in(portal, "r_payroll")
    html = portal.get(f"/employee/{me}").get_data(as_text=True)
    assert "Employee self-service" in html                       # not the payroll clerk's view of themselves
    assert t["ssn"] not in html and t["acct"] not in html        # an employee never sees their own full SSN or account here
    assert f"{int(t['salary']):,}" in html                       # but does see their own salary
    other = 1 if me != 1 else 2
    assert seed.truth(other)["ssn"] in portal.get(f"/employee/{other}").get_data(as_text=True)   # others: still payroll's view


# ---------------------------------------------------------------------------------- the SQL panel
@needs_db
def test_sql_panel_shows_the_statements_postgres_ran_for_the_page(portal):
    _sign_in(portal, "r_payroll")
    html = portal.get("/employee/1").get_data(as_text=True)
    assert "What Postgres ran" in html
    assert "logged in as <b>r_payroll</b>" in html
    assert "set_config(" in html and "dbenc.ssn_of" in html and "dbenc.acct_of" in html
    assert "REFUSED" in html                                       # payroll has no right to dependents


@needs_db
def test_sql_panel_shows_refusals_and_never_shows_secrets(portal):
    t = seed.truth(1)
    _sign_in(portal, "r_analyst")
    html = portal.get("/employee/1").get_data(as_text=True)
    assert "permission denied" in html
    assert t["ssn"] not in html and t["acct"] not in html          # the panel lists statements, never values
    portal.get("/logout")
    _sign_in(portal, "dba")
    html = portal.get("/employee/1").get_data(as_text=True)
    assert "key_store" in html and "superuser" in html
    with admin() as conn:
        keys = [r["key"] for r in conn.execute("select key from dbenc.key_store").fetchall()]
    assert not any(k in html for k in keys)                        # the key hunt runs, but no key is printed


@needs_db
def test_sql_panel_uses_the_self_service_functions_for_your_own_record(portal):
    _sign_in(portal, "r_employee")
    html = portal.get(f"/employee/{_emp_of('r_employee')}").get_data(as_text=True)
    assert "dbenc.my_salary" in html and "logged in as <b>r_employee</b>" in html
