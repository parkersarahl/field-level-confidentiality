"""Statement tracing for the demo portal: records the SQL each request sends to Postgres.

Off by default. app.py switches it on per request, so the seeding, the tests and the evaluation are not affected.
The trace holds the statement text, the role that ran it and the outcome. It never holds result values.
"""
import contextvars
import re
import time

import psycopg

_active = contextvars.ContextVar("flc_trace", default=None)


def start():
    log = []
    _active.set(log)
    return log


def stop():
    _active.set(None)


def _lit(v):
    """A parameter as shown in the panel. Binary data and long strings (ciphertext, keys) are shown by size only."""
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return f"'<{len(bytes(v))} bytes>'"
    s = str(v)
    if len(s) > 32:
        return f"'<{len(s)} characters>'"
    return "'" + s.replace("'", "''") + "'"


def render(query, params):
    """The statement as a person would read it: placeholders replaced by their values."""
    q = query if isinstance(query, str) else str(query)
    if "authenticate(" in q:                      # never show a password, even though the panel appears only after sign-in
        return re.sub(r"\s+", " ", q).strip().replace("%s", "'<hidden>'")
    if params is not None:
        if isinstance(params, dict):
            q = re.sub(r"%\((\w+)\)s", lambda m: _lit(params[m.group(1)]), q)
        else:
            it = iter(params)
            q = re.sub(r"%s", lambda m: _lit(next(it)), q)
        q = q.replace("%%", "%")
    return re.sub(r"\s+", " ", q).strip()


class TracingCursor(psycopg.Cursor):
    def execute(self, query, params=None, **kw):
        log = _active.get()
        if log is None:
            return super().execute(query, params, **kw)
        info = self.connection.info
        entry = {"pid": info.backend_pid, "role": info.user, "sql": render(query, params),
                 "status": "ok", "rows": None, "detail": ""}
        t0 = time.perf_counter()
        try:
            result = super().execute(query, params, **kw)
            entry["rows"] = self.rowcount
            return result
        except psycopg.errors.InsufficientPrivilege as exc:
            entry.update(status="denied", detail=str(exc).splitlines()[0])
            raise
        except psycopg.Error as exc:
            entry.update(status="error", detail=str(exc).splitlines()[0])
            raise
        finally:
            entry["ms"] = (time.perf_counter() - t0) * 1000
            log.append(entry)


# --- how the panel explains a statement ---------------------------------------------------------
_DECRYPT = re.compile(r"dbenc\.(salary_of|ssn_of|acct_of|dependents_of|my_salary|my_dependents|payroll_run)\(")


def note(e):
    s = e["sql"]
    if e["status"] == "denied":
        return "Refused by Postgres: this role has no privilege for it."
    if e["status"] == "error":
        return "Postgres raised an error."
    if "set_config('app.employee_id'" in s:
        return "Tells Postgres which employee this request is for."
    if _DECRYPT.search(s):
        return "Decrypts inside Postgres. The application never sees a key."
    if "authenticate(" in s:
        return "Password checked inside Postgres against a bcrypt hash."
    if "salary_band_report" in s:
        return "A view: groups of fewer than 5 people are hidden."
    if "key_store" in s:
        return "The key table. Only the superuser can read it."
    if e["rows"] == 0:
        return "No row came back: row-level security hid it."
    if "dbenc.employees" in s:
        return "Ordinary profile columns, not encrypted."
    if re.search(r"salary_band|ssn_last4|acct_last4|pay_freq|bank_name|plan_name|coverage_tier", s):
        return "Plaintext column, limited by column grants and row-level security."
    return ""


_KEYWORDS = re.compile(r"\b(select|from|where|order by|group by|limit|join|on|and|or|as|with|having|using|set|local|role)\b", re.I)


def highlight(sql):
    """HTML for a statement: escaped, with keywords, strings and dbenc functions picked out."""
    from markupsafe import Markup, escape
    out = str(escape(sql))
    out = re.sub(r"(&#39;.*?&#39;)", r'<span class="s">\1</span>', out)
    out = re.sub(r"(dbenc\.\w+)", r'<span class="f">\1</span>', out)
    out = _KEYWORDS.sub(lambda m: f'<span class="k">{m.group(1)}</span>', out)
    return Markup(out)
