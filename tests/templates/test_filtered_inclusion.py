"""#54 on real Postgres: an inclusion into a relation with a condition is two constraint triggers
checked at commit (mutation INCLUSION_NOT_DEFERRED refuses a project written before its lead's
row), they follow the rows the transaction keeps, and the referencing side reads the referenced
row FOR SHARE: a writer that demotes a lead while another names them on a new project waits for
neither without it (mutation INCLUSION_NO_LOCK), and both commit."""
from __future__ import annotations

import threading
import time

import psycopg
import pytest

from mls.compile import compile_spec
from mls.compile.mutations import Mutation
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg

LEAD = "insert into team_members (user_id, team_id, role) values (%s, 1, %s)"
PROJECT = "insert into projects (id, team_id, name, lead_id) values (%s, 1, 'p', %s)"


def deployed(pg_dsn, mutations=frozenset()) -> Harness:
    spec = specs.filtered_inclusion_spec()
    h = Harness(spec, compile_spec(spec, set(mutations)), pg_dsn, "mls_filtered_incl")
    h.deploy()
    h.conn.autocommit = True
    return h


def outcome(conn: psycopg.Connection, *statements: tuple[str, tuple]) -> str:
    """'ok', or 'refused' when an inclusion's trigger raised (at the statement or at commit)."""
    try:
        with conn.transaction():
            for sql, args in statements:
                conn.execute(sql, args)
    except psycopg.errors.ForeignKeyViolation:
        return "refused"
    return "ok"


@pytest.mark.parametrize("mutated", [False, True])
def test_a_project_and_its_lead_go_together_in_one_transaction(pg_dsn, mutated):
    h = deployed(pg_dsn, {Mutation.INCLUSION_NOT_DEFERRED} if mutated else set())
    u, v = h.adapter.harness_user_values(2)
    try:
        assert outcome(h.conn, (PROJECT, (1, u)), (LEAD, (u, "a"))) == ("refused" if mutated else "ok")
        if mutated:
            return
        # still enforced at commit: a lead who is a member but not with role 'a', and a demotion
        assert outcome(h.conn, (LEAD, (v, "b")), (PROJECT, (2, v))) == "refused"
        assert outcome(h.conn, ("update team_members set role = null where user_id = %s", (u,)),) == "refused"
        assert outcome(h.conn, ("delete from team_members where user_id = %s", (u,)),) == "refused"
        # what the transaction leaves is what counts: demoted and promoted back, or a project
        # without a lead that is gone again by commit
        assert outcome(h.conn, ("update team_members set role = 'b' where user_id = %s", (u,)),
                       ("update team_members set role = 'a' where user_id = %s", (u,))) == "ok"
        assert outcome(h.conn, (PROJECT, (3, v)), ("delete from projects where id = %s", (3,))) == "ok"
        # the lead moves to another member along with the role
        assert outcome(h.conn, (LEAD, (v, "a")), ("update projects set lead_id = %s where id = 1", (v,)),
                       ("update team_members set role = 'b' where user_id = %s", (u,))) == "ok"
    finally:
        h.close()


def _demote_while_naming(pg_dsn: str, dbname: str, lead) -> dict[str, str]:
    """Writer `demote` changes the lead's role and runs its checks at once (no project names the
    lead yet), then holds its transaction open; writer `name` then adds a project led by them and
    runs its checks.  The outcomes, by writer."""
    db_dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    checked = threading.Event()
    out: dict[str, str] = {}

    def demote():
        with psycopg.connect(db_dsn, autocommit=True) as conn:
            try:
                with conn.transaction():
                    conn.execute("update team_members set role = 'b' where user_id = %s", (lead,))
                    conn.execute("set constraints all immediate")
                    checked.set()
                    time.sleep(0.5)
                out["demote"] = "ok"
            except psycopg.errors.ForeignKeyViolation:
                out["demote"] = "refused"
            finally:
                checked.set()

    def name():
        checked.wait()
        with psycopg.connect(db_dsn, autocommit=True) as conn:
            out["name"] = outcome(conn, (PROJECT, (1, lead)), ("set constraints all immediate", ()))

    threads = [threading.Thread(target=demote), threading.Thread(target=name)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


@pytest.mark.parametrize("mutations,holds", [(set(), True), ({Mutation.INCLUSION_NO_LOCK}, False)])
def test_a_lead_demoted_while_named_on_a_project(pg_dsn, mutations, holds):
    """The demotion's check sees no project (the other is not committed); the naming's check reads
    the lead's row FOR SHARE, so it waits for the demotion to commit and then finds no lead.
    Without the lock it reads the committed row, still a lead, and both commit."""
    h = deployed(pg_dsn, mutations)
    lead = h.adapter.harness_user_values(1)[0]
    try:
        h.conn.execute(LEAD, (lead, "a"))
        out = _demote_while_naming(pg_dsn, h.dbname, lead)
        led = h.conn.execute("select count(*) from projects p join team_members m on m.user_id = p.lead_id "
                             "and m.team_id = p.team_id and m.role = 'a'").fetchone()[0]
        projects = h.conn.execute("select count(*) from projects").fetchone()[0]
    finally:
        h.close()
    if holds:
        assert out == {"demote": "ok", "name": "refused"} and projects == 0, out
    else:
        assert out == {"demote": "ok", "name": "ok"} and projects == 1 and led == 0, out


def test_preflight_reads_the_rows_the_triggers_would_refuse_and_drift_is_clean(pg_dsn):
    """A trigger, unlike a foreign key's VALIDATE, never reads the rows already there, so preflight
    does: a project whose lead is a member with another role, before the inclusion is added.  The
    deployed triggers and functions are what drift expects."""
    from mls.pg.drift import drift
    from mls.pg.preflight import preflight

    base, full = specs.filtered_inclusion_base_spec(), specs.filtered_inclusion_spec()
    h = Harness(base, compile_spec(base), pg_dsn, "mls_filtered_incl")
    h.deploy()
    h.conn.autocommit = True
    u = h.adapter.harness_user_values(1)[0]
    try:
        h.conn.execute(LEAD, (u, "b"))
        h.conn.execute(PROJECT, (1, u))
        v = preflight(h.conn, full, base).violations
        assert [(x.rule_id, x.table, x.count) for x in v] == [("I1", "projects", 1)], [str(x) for x in v]
        assert "not in lead_of" in v[0].what
        h.conn.execute("update team_members set role = 'a'")
        assert preflight(h.conn, full, base).violations == []
    finally:
        h.close()
    h = deployed(pg_dsn)
    try:
        d = drift(h.conn, full, compile_spec(full))
        assert d.ok, [str(i) for i in d.items]
    finally:
        h.close()
