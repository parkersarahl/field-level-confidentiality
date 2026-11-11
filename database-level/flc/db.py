"""Connections: one admin (superuser) connection and one LOGIN connection per application role."""
import contextlib

import psycopg
from psycopg.rows import dict_row

from . import config as C
from .trace import TracingCursor


def _connect(user, password, dbname=None):
    return psycopg.connect(
        host=C.HOST, port=C.PORT, dbname=dbname or C.DBNAME,
        user=user, password=password, row_factory=dict_row, cursor_factory=TracingCursor,
    )


def admin(dbname=None, autocommit=False):
    """Superuser connection: the DBA, and the seeding / rotation tooling."""
    conn = _connect(C.ADMIN_USER, C.ADMIN_PASSWORD, dbname)
    conn.autocommit = autocommit
    return conn


@contextlib.contextmanager
def role_session(role, viewer_id=None):
    """A read-only transaction as an application role.

    The application tells Postgres who the viewer is through the transaction-local
    setting app.employee_id (read by <schema>.me() in the RLS policies).
    """
    conn = _connect(role, C.ROLE_PASSWORD)
    try:
        conn.execute(
            "select set_config('app.employee_id', %s, true)",
            ("" if viewer_id is None else str(viewer_id),),
        )
        yield conn
    finally:
        conn.rollback()
        conn.close()


def attempt(conn, sql, params=None):
    """Run one statement inside a savepoint.

    Returns ("ok", rows), ("denied", first line of the error) for a missing privilege, or
    ("error", first line) when a database function raised, e.g. a failed integrity check.
    """
    try:
        with conn.transaction():
            return "ok", conn.execute(sql, params).fetchall()
    except psycopg.errors.InsufficientPrivilege as exc:
        return "denied", str(exc).splitlines()[0]
    except psycopg.errors.RaiseException as exc:
        return "error", str(exc).splitlines()[0]
