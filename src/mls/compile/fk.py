"""Inclusion template: composite FK, MATCH SIMPLE, ON UPDATE RESTRICT, ON DELETE RESTRICT or
CASCADE (#60, D79) or SET NULL (first column) (#62); a deferred inclusion's FK is DEFERRABLE INITIALLY DEFERRED (#35).  RESTRICT is
never deferred by Postgres, nor is a CASCADE action, so removing a referenced pair is refused, or
its referencing rows deleted, at once either way.

#54 (D86): an inclusion into a relation with a condition cannot be a foreign key, which
references every row of its table.  It compiles to two constraint triggers, DEFERRABLE INITIALLY
DEFERRED (the checker requires `deferred` and `restrict`), SECURITY DEFINER as mls_internal:

  * `<name>` on the inclusion's table, AFTER INSERT OR UPDATE OF its two columns, function
    `mls_incl_<table>_<name>`: unless a column is NULL (MATCH SIMPLE) or no row holds the pair any
    more (it was changed or deleted later in the transaction), the relation's table must have a row
    with the pair on which the condition is TRUE.  That row is read FOR SHARE, the lock a foreign
    key takes: a concurrent transaction that changes it (and so may take the pair out of the
    relation) waits, and this one reads the row it committed.
  * `<name>_target` on the relation's table, AFTER UPDATE OR DELETE, function
    `mls_incl_<table>_<name>_target`: a row that held the pair with its condition TRUE and no longer
    does (deleted, its pair changed, or its condition FALSE or UNKNOWN) leaves the pair out of the
    relation unless another row still holds it, and then no row of the inclusion's table may name it.

The pair is unique in its table (the checker requires it, or the compiler adds the key, as for a
foreign key), so only one row holds it and the target-side check reads no row two transactions
could both change.  Raised as foreign_key_violation."""
from __future__ import annotations

from mls.compile.guard import on_old
from mls.compile.internal import function_owner_ddl
from mls.compile.mutations import Mutation
from mls.compile.sql import SqlCompiler, q
from mls.spec.model import InclusionRule, Relation, Spec


def is_filtered(spec: Spec, r: InclusionRule) -> bool:
    """#54: an inclusion into a relation with a condition, compiled to triggers, not a foreign key."""
    rel = spec.relations.get(r.relation)
    return isinstance(rel, Relation) and rel.where is not None


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


def incl_fn_name(r: InclusionRule) -> str:
    return f"mls_incl_{r.table}_{r.name}"


def incl_target_fn_name(r: InclusionRule) -> str:
    return f"mls_incl_{r.table}_{r.name}_target"


def incl_target_trigger_name(r: InclusionRule) -> str:
    return f"{r.name}_target"


def _cond(sc: SqlCompiler, rel: Relation, old: bool = False) -> str:
    if Mutation.INCLUSION_CONDITION_DROPPED in sc.mutations:
        return ""
    return f" and ({sc.pred(on_old(rel.where) if old else rel.where, rel.table)}) is true"


def _raise(r: InclusionRule, row: str) -> str:
    c1, c2 = r.columns
    return (f"raise exception 'MLS inclusion {r.name} on {r.table}: ({c1}, {c2}) = (%, %) is not in "
            f"{r.relation}', {row}.{q(c1)}, {row}.{q(c2)} using errcode = 'foreign_key_violation';")


def incl_fn_ddl(spec: Spec, r: InclusionRule, mutations: frozenset[Mutation] = frozenset(),
                replace: bool = False) -> str:
    sc = SqlCompiler(spec, None, mutations)
    rel = spec.relations[r.relation]
    c1, c2 = (q(c) for c in r.columns)
    verb = "create or replace function" if replace else "create function"
    lock = "" if Mutation.INCLUSION_NO_LOCK in mutations else " for share"
    return (
        f"{verb} {q(incl_fn_name(r))}() returns trigger language plpgsql "
        f"security definer set search_path from current as $mls$\n"
        f"begin\n"
        f"  if new.{c1} is null or new.{c2} is null then return null; end if;\n"
        f"  if not exists (select 1 from {q(r.table)} where {c1} = new.{c1} and {c2} = new.{c2}) then return null; end if;\n"
        f"  perform 1 from {q(rel.table)} where {q(rel.key)} = new.{c1} and {q(rel.value)} = new.{c2}"
        f"{_cond(sc, rel)}{lock};\n"
        f"  if not found then\n"
        f"    {_raise(r, 'new')}\n"
        f"  end if;\n"
        f"  return null;\n"
        f"end $mls$")


def incl_trigger_ddl(r: InclusionRule, mutations: frozenset[Mutation] = frozenset()) -> str:
    when = "" if Mutation.INCLUSION_NOT_DEFERRED in mutations else " deferrable initially deferred"
    return (f"create constraint trigger {q(r.name)} after insert or update of {q(r.columns[0])}, {q(r.columns[1])} "
            f"on {q(r.table)}{when} for each row execute function {q(incl_fn_name(r))}()")


def incl_target_fn_ddl(spec: Spec, r: InclusionRule, mutations: frozenset[Mutation] = frozenset(),
                       replace: bool = False) -> str:
    sc = SqlCompiler(spec, None, mutations)
    rel = spec.relations[r.relation]
    k, v = q(rel.key), q(rel.value)
    c1, c2 = (q(c) for c in r.columns)
    verb = "create or replace function" if replace else "create function"
    return (
        f"{verb} {q(incl_target_fn_name(r))}() returns trigger language plpgsql "
        f"security definer set search_path from current as $mls$\n"
        f"begin\n"
        f"  if old.{k} is null or old.{v} is null or not (true{_cond(sc, rel, old=True)}) then return null; end if;\n"
        f"  if exists (select 1 from {q(rel.table)} where {k} = old.{k} and {v} = old.{v}{_cond(sc, rel)}) "
        f"then return null; end if;\n"
        f"  if exists (select 1 from {q(r.table)} where {c1} = old.{k} and {c2} = old.{v}) then\n"
        f"    raise exception 'MLS inclusion {r.name} on {r.table}: ({r.columns[0]}, {r.columns[1]}) = (%, %) is not "
        f"in {r.relation} any more', old.{k}, old.{v} using errcode = 'foreign_key_violation';\n"
        f"  end if;\n"
        f"  return null;\n"
        f"end $mls$")


def incl_target_trigger_ddl(spec: Spec, r: InclusionRule, mutations: frozenset[Mutation] = frozenset()) -> str:
    when = "" if Mutation.INCLUSION_NOT_DEFERRED in mutations else " deferrable initially deferred"
    return (f"create constraint trigger {q(incl_target_trigger_name(r))} after update or delete "
            f"on {q(spec.relations[r.relation].table)}{when} for each row execute function "
            f"{q(incl_target_fn_name(r))}()")


def filtered_inclusion_ddl(spec: Spec, r: InclusionRule, sc: SqlCompiler) -> list[str]:
    out = [incl_fn_ddl(spec, r, sc.mutations), function_owner_ddl(f"{q(incl_fn_name(r))}()"),
           incl_trigger_ddl(r, sc.mutations)]
    if Mutation.INCLUSION_TARGET_UNCHECKED not in sc.mutations:
        out += [incl_target_fn_ddl(spec, r, sc.mutations), function_owner_ddl(f"{q(incl_target_fn_name(r))}()"),
                incl_target_trigger_ddl(spec, r, sc.mutations)]
    return out
