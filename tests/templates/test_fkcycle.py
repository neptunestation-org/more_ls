"""#35 on real Postgres: a deferred inclusion's foreign key is checked at commit (mutation
INCLUSION_NOT_DEFERRED makes the first of two inserts fail), a cycle the database's own foreign
keys close with an inclusion is refused by `mls check --dsn` and `mls preflight`, and the import
reads a deferred key as a deferred inclusion and leaves a cycle of immediate ones foreign."""
from __future__ import annotations

import uuid

import psycopg
import pytest

from mls.compile import compile_spec
from mls.compile.mutations import Mutation
from mls.pg.adopt import import_schema, verify_adopted
from mls.pg.drift import drift
from mls.pg.harness import Harness
from mls.pg.preflight import preflight
from mls.spec import check_spec
from mls.spec.model import Spec
from tests.templates import specs

pytestmark = pytest.mark.pg


def two_inserts(conn: psycopg.Connection) -> str:
    """An admins row before its memberships row, in one transaction: 'ok', or where it failed."""
    u = uuid.uuid4()
    try:
        with conn.transaction():
            conn.execute("insert into admins (user_id, tenant_id) values (%s, 1)", (u,))
            conn.execute("insert into memberships (user_id, tenant_id) values (%s, 1)", (u,))
    except psycopg.errors.ForeignKeyViolation:
        return "first insert"
    return "ok"


@pytest.mark.parametrize("mutated", [False, True])
def test_a_deferred_inclusion_is_checked_at_commit(pg_dsn, mutated):
    spec = specs.deferred_spec()
    script = compile_spec(spec, {Mutation.INCLUSION_NOT_DEFERRED} if mutated else set())
    h = Harness(spec, script, pg_dsn, "mls_deferred")
    h.deploy()
    try:
        h.conn.autocommit = True
        assert two_inserts(h.conn) == ("first insert" if mutated else "ok")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):  # still enforced: at commit
            with h.conn.transaction():
                h.conn.execute("insert into admins (user_id, tenant_id) values (%s, 2)", (uuid.uuid4(),))
    finally:
        h.close()


CYCLE_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create table orgs (id bigint primary key, owner_id bigint not null, unique (owner_id, id));
create table members (user_id bigint not null, org_id bigint not null references orgs (id),
                      primary key (user_id, org_id));
alter table orgs enable row level security;
alter table members enable row level security;
create policy read_orgs on orgs for select to app using (true);
create policy read_members on members for select to app using (true);
grant select on orgs, members to app;
"""


@pytest.fixture
def cycle_db(pg_dsn):
    dbname = "mls_fkcycle"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(CYCLE_SQL)
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def with_owner_inclusion(conn, deferred: bool) -> Spec:
    """The imported schema plus `orgs(owner_id, id) ⊆ members(user_id, org_id)`, which closes a
    cycle with the database's own members.org_id -> orgs.id (the spec does not declare it)."""
    d = import_schema(conn).spec
    d["relations"]["org_members"] = {"table": "members", "key": "user_id", "value": "org_id"}
    d["rules"].append({"id": "OWN", "kind": "inclusion", "name": "owner_is_member", "table": "orgs",
                       "columns": ["owner_id", "id"], "relation": "org_members", "on_delete": "restrict",
                       **({"deferred": True} if deferred else {})})
    return check_spec(Spec.model_validate(d))  # the spec alone has no cycle


def test_a_cycle_through_the_databases_own_key_is_refused_before_the_deploy(cycle_db):
    spec = with_owner_inclusion(cycle_db, deferred=False)
    errs = verify_adopted(cycle_db, spec)
    assert any("closes a cycle of foreign keys" in e.message and "orgs -> members -> orgs" in e.message
               and "members_org_id_fkey on members" in e.message for e in errs), errs
    res = preflight(cycle_db, spec)
    assert not res.ok and len(res.errors) == 1 and "deferred" in res.errors[0].fix

    spec = with_owner_inclusion(cycle_db, deferred=True)
    assert not [e for e in verify_adopted(cycle_db, spec) if "cycle" in e.message]
    assert preflight(cycle_db, spec).ok


def test_import_reads_a_deferred_key_and_leaves_an_immediate_cycle_foreign(cycle_db):
    cycle_db.execute("alter table orgs add constraint owner_is_member foreign key (owner_id, id) "
                     "references members (user_id, org_id) on update restrict on delete restrict "
                     "deferrable initially deferred")
    res = import_schema(cycle_db)
    inc = [r for r in res.spec["rules"] if r["kind"] == "inclusion"]
    assert [(r["name"], r.get("deferred")) for r in inc] == [("owner_is_member", True)], res.notes
    spec = check_spec(Spec.model_validate(res.spec))
    assert drift(cycle_db, spec, compile_spec(spec)).ok

    # members(user_id, org_id) ⊆ owners (orgs(owner_id, id)) and the reverse, both immediate
    cycle_db.execute("alter table orgs drop constraint owner_is_member; "
                     "alter table members drop constraint members_org_id_fkey; "
                     "alter table members add unique (user_id, org_id); "
                     "alter table orgs add constraint owner_is_member foreign key (owner_id, id) "
                     "references members (user_id, org_id) on update restrict on delete restrict; "
                     "alter table members add constraint member_owns foreign key (user_id, org_id) "
                     "references orgs (owner_id, id) on update restrict on delete restrict")
    res = import_schema(cycle_db)
    inc = [r["name"] for r in res.spec["rules"] if r["kind"] == "inclusion"]
    assert len(inc) == 1, res.notes
    assert any("closes a cycle of foreign keys" in n and "listed as foreign" in n for n in res.notes), res.notes
    check_spec(Spec.model_validate(res.spec))
