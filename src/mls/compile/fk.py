"""Inclusion template: composite FK, MATCH SIMPLE, ON UPDATE RESTRICT, ON DELETE RESTRICT or
CASCADE (#60, D79) or SET NULL (first column) (#62); a deferred inclusion's FK is DEFERRABLE INITIALLY DEFERRED (#35).  RESTRICT is
never deferred by Postgres, nor is a CASCADE action, so removing a referenced pair is refused, or
its referencing rows deleted, at once either way."""
from __future__ import annotations

from mls.compile.mutations import Mutation
from mls.compile.sql import SqlCompiler, q
from mls.spec.model import InclusionRule


def fk_def(r: InclusionRule, sc: SqlCompiler) -> str:
    """The constraint definition (what follows `add constraint <name>`)."""
    rel = sc.spec.relations[r.relation]
    match = "match full" if Mutation.FK_MATCH_FULL in sc.mutations else "match simple"
    on_delete = "restrict" if Mutation.CASCADE_AS_RESTRICT in sc.mutations else r.on_delete
    if r.on_delete == "set_null":  # #62: only the first column (PG 15+), so the row keeps its shop
        on_delete = "set null" + ("" if Mutation.SET_NULL_BOTH in sc.mutations else f" ({q(r.columns[0])})")
    return (f"foreign key ({q(r.columns[0])}, {q(r.columns[1])}) references {q(rel.table)} "
            f"({q(rel.key)}, {q(rel.value)}) {match} on update restrict on delete {on_delete}"
            + (" deferrable initially deferred" if r.deferred and Mutation.INCLUSION_NOT_DEFERRED not in sc.mutations
               else ""))


def fk_ddl(r: InclusionRule, sc: SqlCompiler) -> str:
    return f"alter table {q(r.table)} add constraint {q(r.name)} {fk_def(r, sc)}"
