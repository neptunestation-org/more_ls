"""D4: the bound holds under READ COMMITTED with parallel writers because the trigger locks the
parent row first; without the lock (mutation) the writers overshoot."""
from __future__ import annotations

import json
import threading
import time

import psycopg
import pytest

from mls.compile import Mutation, compile_spec
from mls.pg.harness import Harness
from tests.templates import specs

pytestmark = pytest.mark.pg

WRITERS, ATTEMPTS, MAX = 8, 6, 5


def hammer(dsn: str, dbname: str, adapter, n_writers: int, attempts: int, hold: float) -> int:
    """Each writer, as the app role, tries `attempts` inserts into tenant 1 (group 1), holding
    every successful insert open for `hold` seconds before commit so the writers overlap."""
    db_dsn = psycopg.conninfo.make_conninfo(dsn, dbname=dbname)
    ctx = {"uid": adapter.harness_user_values(1)[0]}
    next_id = [1000]
    lock = threading.Lock()

    def writer():
        with psycopg.connect(db_dsn, autocommit=True) as conn:
            for _ in range(attempts):
                with lock:
                    next_id[0] += 1
                    fid = next_id[0]
                try:
                    with conn.transaction():
                        with conn.cursor() as cur:
                            for s in adapter.harness_context_sql("authenticated", ctx):
                                cur.execute(s)
                            cur.execute('insert into "files" ("id", "group_id", "tenant_id", "size") '
                                        'values (%s, 1, 1, 1)', (fid,))
                            time.sleep(hold)
                except psycopg.errors.CheckViolation:
                    pass

    threads = [threading.Thread(target=writer) for _ in range(n_writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with psycopg.connect(db_dsn) as conn:
        return conn.execute('select count(*) from "files" where "tenant_id" = 1').fetchone()[0]


@pytest.mark.parametrize("mutations,within_bound", [(set(), True), ({Mutation.CARDINALITY_NO_LOCK}, False)])
def test_parallel_writers(pg_dsn, mutations, within_bound):
    spec = specs.org_base_spec()
    h = Harness(spec, compile_spec(spec, mutations), pg_dsn, "mls_card")
    h.deploy()
    try:
        with h.conn.cursor() as cur:
            cur.execute('insert into "tenants" ("id") values (1)')
            cur.execute('insert into "groups" ("id", "parent_id", "depth", "tenant_id") values (1, null, 0, 1)')
            cur.execute('insert into "group_members" ("user_id", "group_id") values (%s, 1)',
                        (h.adapter.harness_user_values(1)[0],))
        n = hammer(pg_dsn, h.dbname, h.adapter, WRITERS, ATTEMPTS, hold=0.05)
    finally:
        h.close()
    if within_bound:
        assert n == MAX, n
    else:
        assert n > MAX, f"the unlocked trigger did not overshoot ({n} rows); contention too low?"


def _remove_together(dsn: str, dbname: str, adapter, ids: list[int], hold: float) -> list[str]:
    """One writer per file, as the app role: delete it, fire the deferred checks at once (so the
    count runs while the other writer's delete is still open), hold, commit.  The outcomes."""
    db_dsn = psycopg.conninfo.make_conninfo(dsn, dbname=dbname)
    ctx = {"uid": adapter.harness_user_values(1)[0]}
    out: list[str] = []

    def writer(fid: int):
        with psycopg.connect(db_dsn, autocommit=True) as conn:
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        for s in adapter.harness_context_sql("authenticated", ctx):
                            cur.execute(s)
                        cur.execute('delete from "files" where "id" = %s', (fid,))
                        cur.execute("set constraints all immediate")
                        time.sleep(hold)
                out.append("ok")
            except psycopg.errors.CheckViolation:
                out.append("refused")

    threads = [threading.Thread(target=writer, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


@pytest.mark.parametrize("mutations,keeps_one", [(set(), True), ({Mutation.CARDINALITY_NO_LOCK}, False)])
def test_two_writers_cannot_remove_the_last_rows_together(pg_dsn, mutations, keeps_one):
    """#61: a tenant has two large files and must keep one; two writers each delete one at the same
    time.  The minimum's trigger locks the tenant row before counting, so the second waits and
    then sees the first's delete; without the lock (mutation) both see the other's file and both
    succeed."""
    d = json.loads(specs.min_count_spec().model_dump_json(by_alias=True, exclude_none=True))
    next(r for r in d["rules"] if r["id"] == "M1")["min"] = 1
    spec = specs.make(d)
    h = Harness(spec, compile_spec(spec, mutations), pg_dsn, "mls_card_min")
    h.deploy()
    try:
        with h.conn.cursor() as cur:
            cur.execute('insert into "tenants" ("id") values (1)')
            cur.execute('insert into "groups" ("id", "parent_id", "depth", "tenant_id") values (1, null, 0, 1)')
            cur.execute('insert into "group_members" ("user_id", "group_id") values (%s, 1)',
                        (h.adapter.harness_user_values(1)[0],))
            cur.execute('insert into "files" ("id", "group_id", "tenant_id", "size") values (1, 1, 1, 4), (2, 1, 1, 4)')
        outcomes = _remove_together(pg_dsn, h.dbname, h.adapter, [1, 2], hold=0.5)
        left = h.conn.execute('select count(*) from "files" where "tenant_id" = 1').fetchone()[0]
    finally:
        h.close()
    if keeps_one:
        assert sorted(outcomes) == ["ok", "refused"] and left == 1, (outcomes, left)
    else:
        assert outcomes == ["ok", "ok"] and left == 0, f"the unlocked trigger kept the bound ({outcomes}); contention too low?"
