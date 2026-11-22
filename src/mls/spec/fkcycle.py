"""Cycles of foreign keys checked at once (#35).

An inclusion compiles to a foreign key.  When it closes a cycle of foreign keys that Postgres
checks at the end of each statement (organizations(owner_id, id) -> members(user_id, org_id)
while members.org_id -> organizations.id), a row of either table needs the other's row to exist
already, so the usual two inserts, in either order, both fail; only one statement inserting
both (a writable CTE) gets through.  The checker refuses an inclusion that closes such a cycle
and names the fix: mark it deferred, which compiles its foreign key DEFERRABLE INITIALLY
DEFERRED, checked at commit.

The keys are the spec's inclusions, the hierarchy and cardinality templates' keys, and, when
the database is read (`mls check --dsn`, `mls preflight`), the catalog's own foreign keys on the
spec's tables.  A key onto its own table is no cycle (the first row may refer to itself, or
leave it NULL).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from mls.spec.model import Spec


@dataclass(frozen=True)
class Fk:
    name: str
    table: str
    parent: str
    deferred: bool
    rule_id: str | None = None  # the inclusion rule it compiles from; None for a template's or the database's


def spec_fks(spec: Spec) -> list[Fk]:
    from mls.props.effective import simple_fks

    out = [Fk(r.name, r.table, spec.relations[r.relation].table, bool(r.deferred), r.id)
           for r in spec.inclusions() if r.relation in spec.relations]
    return out + [Fk(f.name, f.table, f.parent, False) for f in simple_fks(spec)]


def database_fks(rows: list[dict], spec: Spec) -> list[Fk]:
    """The catalog's foreign keys ({name, table, parent, deferrable}) between the spec's tables,
    except the ones the spec declares (the deploy writes those as the spec says)."""
    own = {(f.table, f.name) for f in spec_fks(spec)}
    return [Fk(r["name"], r["table"], r["parent"], r["deferrable"]) for r in rows
            if r["table"] in spec.tables and r["parent"] in spec.tables and (r["table"], r["name"]) not in own]


def cycles(fks: list[Fk]) -> list[tuple[Fk, list[Fk]]]:
    """Each immediate inclusion that closes a cycle of immediate foreign keys through at least two
    tables, with the shortest path of keys from its parent back to its table."""
    out = []
    seen: set[frozenset[tuple[str, str]]] = set()
    edges = [f for f in fks if not f.deferred and f.table != f.parent]
    for inc in edges:
        if inc.rule_id is None:
            continue
        prev: dict[str, Fk | None] = {inc.parent: None}
        queue = deque([inc.parent])
        while queue and inc.table not in prev:
            t = queue.popleft()
            for f in sorted(edges, key=lambda f: (f.table, f.name)):
                if f.table == t and f.parent not in prev:
                    prev[f.parent] = f
                    queue.append(f.parent)
        if inc.table in prev:
            path, t = [], inc.table
            while prev[t] is not None:
                path.append(prev[t])
                t = prev[t].table
            key = frozenset((f.table, f.name) for f in [inc, *path])
            if key not in seen:  # one error per cycle: deferring any inclusion on it breaks it
                seen.add(key)
                out.append((inc, path[::-1]))
    return out


def cycle_message(inc: Fk, path: list[Fk]) -> tuple[str, str]:
    """The error and its fix, for an inclusion closing a cycle."""
    tables = " -> ".join([inc.table, inc.parent] + [f.parent for f in path])
    via = ", ".join(f"{f.name} on {f.table}" for f in path)
    msg = (f"inclusion {inc.name} closes a cycle of foreign keys checked after each statement ({tables}, with "
           f"{via}): a row of each table needs its row of the next one to exist already, so separate inserts fail "
           f"in any order (only a single statement inserting all of them gets through)")
    fix = ("mark the inclusion deferred (`on_delete restrict deferred`; in JSON \"deferred\": true): its foreign key "
           "is then checked when the transaction commits, so both rows can be written in one transaction; or "
           "remove the inclusion")
    return msg, fix
