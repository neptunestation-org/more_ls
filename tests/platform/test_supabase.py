"""Supabase as a target platform (D55): the Supabase examples deploy as Supabase's `postgres` role
(not a superuser) on the `supabase/postgres` image, the differential test passes on the deployed
database, and drift is clean."""
from __future__ import annotations

import os

import psycopg
import pytest

from mls.compile import compile_spec
from mls.pg.drift import drift
from mls.pg.harness import Harness, run_differential
from mls.spec import load_checked
from tests.conftest import ROOT

pytestmark = [pytest.mark.pg, pytest.mark.supabase]

EXAMPLES = ["tenant_docs", "org_tree", "team_tasks"]


@pytest.fixture(scope="module")
def supabase():
    if os.environ.get("MLS_SKIP_PG"):
        pytest.skip("MLS_SKIP_PG set")
    from mls.pg.server import supabase_container

    with supabase_container() as server:
        yield server


@pytest.fixture(scope="module", params=EXAMPLES)
def deployed(request, supabase):
    spec = load_checked(ROOT / "examples" / f"{request.param}.mls")
    h = Harness(spec, compile_spec(spec), supabase.dsn, f"mls_supa_{request.param}", prepare=supabase.prepare)
    h.deploy()
    yield request.param, spec, h
    h.close()


def test_deploys_as_postgres_and_passes_the_differential_test(deployed):
    name, spec, h = deployed
    with h.conn.cursor() as cur:
        cur.execute("select current_user, rolsuper from pg_roles where rolname = current_user")
        assert cur.fetchone() == ("postgres", False)
    res = run_differential(spec, h.script, h.dsn, h.dbname, harness=h, seed=1,
                           rows_per_table=30, n_contexts=16, ops_per_context=25)
    assert res.ok, f"{name}: {res.summary()}\n" + "\n".join(str(m) for m in res.mismatches[:10])
    assert res.visible_rows > 0 and res.outcomes["ok"] > 0


def test_anon_loses_the_default_grants_and_service_role_keeps_them(deployed):
    """Supabase's default privileges grant every new table and function to its API roles; the
    deploy revokes them from the untrusted ones the spec does not use (anon) and leaves the
    trusted backend role, which the proof report names."""
    from mls.props.report import assumptions

    name, spec, h = deployed
    with h.conn.cursor() as cur:
        for t in spec.governed():
            cur.execute("select has_table_privilege('anon', %s, 'SELECT'), "
                        "has_table_privilege('service_role', %s, 'SELECT')", (f'"{t}"', f'"{t}"'))
            assert cur.fetchone() == (False, True), t
        cur.execute("select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
                    "where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE') "
                    "and exists (select 1 from aclexplode(p.proacl) x where x.grantee = 'anon'::regrole)")
        assert cur.fetchall() == []
    assert any("service_role has BYPASSRLS" in a for a in assumptions(spec, []))


def test_drift_is_clean(deployed):
    name, spec, h = deployed
    res = drift(h.conn, spec, compile_spec(spec))
    assert res.ok, [str(i) for i in res.items]


def test_the_platform_service_roles_deploy_and_keep_their_rules(supabase):
    """#68: authenticator (a member of service_role) and supabase_auth_admin (CREATEROLE, reserved)
    are named by a spec's rules: the deploy, as postgres, leaves both roles alone, keeps their
    policies, and drift is clean; the differential test agrees for every role."""
    from mls.spec import check_spec
    from mls.spec.syntax import parse
    from tests.props.test_properties import SERVICE

    spec = check_spec(parse(SERVICE % ""))
    h = Harness(spec, compile_spec(spec), supabase.dsn, "mls_supa_service", prepare=supabase.prepare)
    try:
        h.deploy()
        with h.conn.cursor() as cur:
            cur.execute("select rolcreaterole from pg_roles where rolname = 'supabase_auth_admin'")
            assert cur.fetchone() == (True,)
            cur.execute("select roles::text[] from pg_policies where tablename = 'claims' order by policyname")
            assert ["authenticator"] in [r[0] for r in cur.fetchall()]
        res = drift(h.conn, spec, compile_spec(spec))
        assert res.ok, [str(i) for i in res.items]
        # the harness acts as each role by SET ROLE; only the image's superuser may grant that one
        with psycopg.connect(supabase.admin_dsn, autocommit=True) as admin:
            admin.execute("grant supabase_auth_admin to postgres")
        diff = run_differential(spec, h.script, h.dsn, h.dbname, harness=h, seed=1,
                                rows_per_table=20, n_contexts=8, ops_per_context=15)
        assert diff.ok, diff.summary()
    finally:
        h.close()
        with psycopg.connect(supabase.admin_dsn, autocommit=True) as admin:
            admin.execute("revoke supabase_auth_admin from postgres")
