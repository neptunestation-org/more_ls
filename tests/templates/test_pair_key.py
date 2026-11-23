"""#59: the unique key MLS adds for an inclusion whose relation's pair is unique only through a key
column (`docs(id, tenant_id)`, `id` the primary key).  The key changes no row's fate, so the
differential cannot see it; what it makes possible is the foreign key: without it (mutation
`PAIR_KEY_DROPPED`) the deploy fails.  A second deploy of the script on the same tables keeps
the key (the adopted form is idempotent)."""
from __future__ import annotations

import psycopg
import pytest

from mls.compile import Mutation, compile_spec
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg


def test_the_foreign_key_needs_the_key_mls_adds(pg_dsn):
    spec = specs.implied_key_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_pair_key")
    try:
        h.deploy()
        rows = h.conn.execute("select conname, pg_get_constraintdef(oid) from pg_constraint "
                              "where conrelid = '\"docs\"'::regclass and contype = 'u'").fetchall()
        assert rows == [("mls_key_docs_id_tenant_id", "UNIQUE (id, tenant_id)")]
    finally:
        h.close()
    h = Harness(spec, compile_spec(spec, {Mutation.PAIR_KEY_DROPPED}), pg_dsn, "mls_pair_key_m")
    try:
        with pytest.raises(psycopg.errors.InvalidForeignKey):
            h.deploy()
    finally:
        h.close()


def test_the_key_on_an_adopted_table_is_added_once(pg_dsn):
    from mls.compile.table import implied_key_ddl

    spec = specs.implied_key_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_pair_key_a")
    try:
        h.deploy()
        ddl = implied_key_ddl("docs", "mls_key_docs_id_tenant_id", ("id", "tenant_id"), adopted=True)
        h.conn.execute(ddl)  # already there: nothing happens
        n = h.conn.execute("select count(*) from pg_constraint where conrelid = '\"docs\"'::regclass "
                           "and contype = 'u'").fetchone()[0]
        assert n == 1
    finally:
        h.close()
