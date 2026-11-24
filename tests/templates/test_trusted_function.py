"""The trusted_function adapter (#72) on Postgres 15-18: drift is clean on a deployed spec and
reports, as hardening, each way the trusted function can stop being the one the spec pins."""
from __future__ import annotations

import pytest

from mls.compile import compile_spec
from mls.pg.drift import DriftError, drift
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg

FN = '"mls_ident"."current_uid"()'
TAMPERS = {
    "body": (f"create or replace function {FN} returns uuid language sql stable as $$ select null::uuid $$",
             "mls_ident.current_uid() has a new body"),
    "volatile": (f"alter function {FN} volatile", "mls_ident.current_uid() is VOLATILE"),
    "owner": (f"alter function {FN} owner to authenticated", "mls_ident.current_uid() is owned by app role authenticated"),
}


@pytest.fixture
def deployed(pg_dsn):
    spec = specs.function_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_trusted_fn")
    h.deploy()
    yield spec, h
    h.close()


def test_drift_is_clean_after_a_deploy(deployed):
    spec, h = deployed
    res = drift(h.conn, spec, h.script)
    assert res.ok, [str(i) for i in res.items]


@pytest.mark.parametrize("tamper", sorted(TAMPERS))
def test_drift_reports_a_changed_function(deployed, tamper):
    spec, h = deployed
    sql, expected = TAMPERS[tamper]
    with h.conn.transaction(force_rollback=True):
        h.conn.execute(sql)
        res = drift(h.conn, spec, h.script)
    hard = [i.object for i in res.items if i.kind == "hardening"]
    assert any(expected in x for x in hard), [str(i) for i in res.items]


def test_drift_stops_when_the_function_is_gone(deployed):
    spec, h = deployed
    with h.conn.transaction(force_rollback=True):
        h.conn.execute(f"drop function {FN} cascade")
        with pytest.raises(DriftError, match=r"mls_ident.current_uid\(\) is gone"):
            drift(h.conn, spec, h.script)
