"""D13: the emitted hardening is verifiable in the catalog, and its mutation is detected."""
from __future__ import annotations

import psycopg
import pytest

from mls.compile import Mutation, compile_spec
from mls.pg.harness import Harness

pytestmark = pytest.mark.pg


def catalog_problems(conn: psycopg.Connection, spec) -> list[str]:
    problems = []
    with conn.cursor() as cur:
        for t in spec.tables:
            cur.execute("select relrowsecurity, relforcerowsecurity from pg_class where relname = %s", (t,))
            rls, force = cur.fetchone()
            if not rls:
                problems.append(f"{t}: RLS not enabled")
            if not force:
                problems.append(f"{t}: RLS not forced")
            cur.execute("select tableowner from pg_tables where tablename = %s", (t,))
            owner = cur.fetchone()[0]
            for r in spec.roles:
                if owner == r:
                    problems.append(f"{t}: owned by app role {r}")
                cur.execute("select has_table_privilege(%s, %s, 'TRUNCATE')", (r, t))
                if cur.fetchone()[0]:
                    problems.append(f"{t}: {r} may TRUNCATE")
        for r in spec.roles:
            cur.execute("select rolbypassrls, rolsuper from pg_roles where rolname = %s", (r,))
            bypass, su = cur.fetchone()
            if bypass or su:
                problems.append(f"{r}: BYPASSRLS/superuser")
            cur.execute("select has_parameter_privilege(%s, 'session_replication_role', 'SET')", (r,))
            if cur.fetchone()[0]:
                problems.append(f"{r}: may SET session_replication_role")
    return problems


@pytest.mark.parametrize("mutations,expect_problems", [(set(), False), ({Mutation.HARDENING_NO_FORCE}, True)])
def test_hardening_in_catalog(pg_dsn, example_spec, mutations, expect_problems):
    h = Harness(example_spec, compile_spec(example_spec, mutations), pg_dsn, "mls_hardening")
    try:
        h.deploy()
        problems = catalog_problems(h.conn, example_spec)
    finally:
        h.close()
    assert bool(problems) == expect_problems, problems


@pytest.mark.parametrize("mutations,refused", [(set(), True), ({Mutation.ROLE_ESCALATION_UNCHECKED}, False)])
def test_an_app_role_that_can_become_a_bypassing_role_is_refused(pg_dsn, example_spec, mutations, refused):
    """#68: an app role that can become, through another role, one that bypasses the policies
    makes every upper bound about it false; the deploy refuses it with the way out, and the
    mutation that leaves the check out deploys."""
    h = None
    try:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute("drop role if exists mls_t_mid; drop role if exists mls_t_bypass")
            admin.execute("create role mls_t_bypass bypassrls; create role mls_t_mid; grant mls_t_bypass to mls_t_mid")
            admin.execute("do $$ begin if not exists (select from pg_roles where rolname = 'authenticated') then "
                          "create role authenticated nologin; end if; end $$")
            admin.execute("grant mls_t_mid to authenticated")
        h = Harness(example_spec, compile_spec(example_spec, mutations), pg_dsn, "mls_hardening_esc")
        if refused:
            with pytest.raises(psycopg.errors.RaiseException) as ei:
                h.deploy()
            assert "app role authenticated can become mls_t_bypass" in str(ei.value)
        else:
            h.deploy()
    finally:
        if h is not None:
            h.close()
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute("drop role if exists mls_t_mid; drop role if exists mls_t_bypass")
