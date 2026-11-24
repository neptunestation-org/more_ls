"""Column defaults (#76) on Postgres 15-18: drift is clean on a deployed spec and reports a
default that is no longer the one the insert proofs count on."""
from __future__ import annotations

import pytest

from mls.compile import compile_spec
from mls.pg.drift import drift
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg


def test_drift_reports_a_changed_default(pg_dsn):
    spec = specs.defaults_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_defaults")
    h.deploy()
    try:
        res = drift(h.conn, spec, h.script)
        assert res.ok, [str(i) for i in res.items]
        for sql, what in (("alter table user_emails alter column is_verified set default true", "is_verified"),
                          ("alter table user_emails alter column user_id drop default", "user_id")):
            with h.conn.transaction(force_rollback=True):
                h.conn.execute(sql)
                res = drift(h.conn, spec, h.script)
            items = [i.object for i in res.items if i.kind == "differs"]
            assert any(f"column user_emails.{what}" in x and "default" in x for x in items), [str(i) for i in res.items]
    finally:
        h.close()
