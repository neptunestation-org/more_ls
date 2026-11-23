"""#58: a column guard fires before the table's own BEFORE UPDATE triggers.  Postgres fires them in
byte order of their names; one that stamps a column outside the guard's list (scarpar's
`updated_at`) must come after the guard, or every edit the guard applies to is refused.  The
differential harness has no foreign triggers, so this ties the order to Postgres on its own: the
compiled guard lets the owner's edit through, the `GUARD_SORTS_LAST` mutation refuses it, and
`check --dsn` names a trigger of the table's own that still sorts first."""
from __future__ import annotations

import uuid

import psycopg
import pytest

from mls.compile import Mutation, compile_spec
from mls.pg.adopt import verify_adopted
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg

UID = str(uuid.UUID(int=7))


def _owner_edit(h: Harness) -> str:
    """The document's owner (a member, not an admin) changes its level, which the guard allows."""
    with h.conn.cursor() as cur:
        h._begin_ctx(cur, "authenticated", {"uid": UID, "clearance": 3})
        try:
            cur.execute('update "docs" set "level" = 1 where "id" = 1')
            return "ok" if cur.rowcount == 1 else "filtered"
        except psycopg.Error as e:
            return e.sqlstate or "error"
        finally:
            cur.execute("rollback")


def _deploy(pg_dsn, name: str, mutations=frozenset()) -> Harness:
    spec = specs.guard_spec()
    h = Harness(spec, compile_spec(spec, mutations), pg_dsn, name)
    h.deploy()
    h.conn.execute(f"insert into \"memberships\" values ('{UID}', 1)")
    h.conn.execute(f"insert into \"docs\" values (1, 1, '{UID}', 0, 0)")
    # the table's own stamp, on a column the spec does not model (so outside the guard's list)
    h.conn.execute("""
        alter table "docs" add column "stamp" int not null default 0;
        create function stamp() returns trigger language plpgsql as $$
        begin new.stamp := old.stamp + 1; return new; end $$;
        create trigger "a_stamp" before update on "docs" for each row execute function stamp();""")
    return h


def test_the_guard_fires_before_the_tables_own_stamp(pg_dsn):
    h = _deploy(pg_dsn, "mls_guard_order")
    try:
        assert _owner_edit(h) == "ok"
        assert verify_adopted(h.conn, h.spec) == []
        h.conn.execute('alter trigger "a_stamp" on "docs" rename to "0_a_stamp"')  # now it sorts first
        assert _owner_edit(h) == "42501"
        errs = verify_adopted(h.conn, h.spec)
        assert [e.path for e in errs] == [f"$.rules[{h.spec.rules.index(h.spec.column_guards()[0])}]"], errs
        assert "the table's own trigger '0_a_stamp' fires before it" in errs[0].message
    finally:
        h.close()


def test_a_guard_named_to_fire_last_is_caught(pg_dsn):
    h = _deploy(pg_dsn, "mls_guard_order_m", {Mutation.GUARD_SORTS_LAST})
    try:
        assert _owner_edit(h) == "42501", "mutation guard_sorts_last went undetected"
    finally:
        h.close()
