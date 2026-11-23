"""Cardinality template (D4): at most N rows of T per value of `group`.

  * FK  mls_card_<name>_parent: group -> parent(pk), RESTRICT both ways (the parent row must exist
    to be locked)
  * trigger <name> (BEFORE INSERT OR UPDATE OF group, SECURITY DEFINER as mls_internal):
      lock the parent row FOR UPDATE, count rows of T with the same group, raise check_violation
      if count + 1 > N.  NULL groups are not counted; an UPDATE that keeps the group is skipped.
The parent-row lock serializes writers per group; under READ COMMITTED the count after the lock
sees every committed row, so the bound holds (tests/templates/test_cardinality.py runs parallel
writers; the CARDINALITY_NO_LOCK mutation overshoots).  Under REPEATABLE READ the count would use
a stale snapshot: the proof report states the READ COMMITTED assumption.

#61: `where` counts only the rows it is TRUE of (the max trigger then fires on any update, since a
change of the condition's columns can add a row to the count).  `min` is a second trigger,
`<name>_min` calling `mls_card_<table>_<name>_min()`: a constraint trigger AFTER DELETE OR UPDATE,
DEFERRABLE INITIALLY DEFERRED, so at commit, for a row that counted and no longer does in its
group, it locks the parent row and raises if fewer than `min` rows count.  A parent gone by then
(deleted with its rows in the same transaction) has nothing to keep.
"""
from __future__ import annotations

from mls.compile.internal import function_owner_ddl
from mls.compile.mutations import Mutation
from mls.compile.guard import on_old
from mls.compile.sql import SqlCompiler, q
from mls.spec.model import CardinalityRule, Pred, Spec


def card_fn_name(r: CardinalityRule) -> str:
    return f"mls_card_{r.table}_{r.name}"


def parent_fk_def(spec: Spec, r: CardinalityRule) -> str:
    pk = spec.tables[r.parent].primary_key[0]
    return (f"foreign key ({q(r.group)}) references {q(r.parent)} ({q(pk)}) "
            f"on update restrict on delete restrict")


def on_new(p: Pred) -> Pred:
    """The condition with its columns read from the new row."""
    from pydantic import TypeAdapter

    old = on_old(p).model_dump(by_alias=True, exclude_none=True)

    def walk(x):
        if isinstance(x, dict):
            if set(x) == {"old"}:
                return {"new": x["old"]}
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [walk(v) for v in x]
        return x
    return TypeAdapter(Pred).validate_python(walk(old))


def _counts(sc: SqlCompiler, r: CardinalityRule, row: str) -> str:
    """` and (<where of row>) is true`, or nothing: whether the row is one the rule counts."""
    if r.where is None or Mutation.CARDINALITY_WHERE_DROPPED in sc.mutations:
        return ""
    return f" and ({sc.pred(on_new(r.where) if row == 'new' else on_old(r.where), r.table)}) is true"


def _counted_rows(sc: SqlCompiler, r: CardinalityRule) -> str:
    if r.where is None or Mutation.CARDINALITY_WHERE_DROPPED in sc.mutations:
        return ""
    return f" and ({sc.pred(r.where, r.table)}) is true"


def card_fn_ddl(spec: Spec, r: CardinalityRule, mutations: frozenset[Mutation] = frozenset(),
                replace: bool = False) -> str:
    sc = SqlCompiler(spec, None, mutations)
    pk = spec.tables[r.parent].primary_key[0]
    verb = "create or replace function" if replace else "create function"
    lock = "" if Mutation.CARDINALITY_NO_LOCK in mutations else \
        f"  perform 1 from {q(r.parent)} where {q(pk)} = new.{q(r.group)} for update;\n"
    test = f"n > {r.max}" if Mutation.CARDINALITY_OFF_BY_ONE in mutations else f"n + 1 > {r.max}"
    g = q(r.group)
    if r.where is None:
        skip = (f"  if new.{g} is null then return new; end if;\n"
                f"  if tg_op = 'UPDATE' and new.{g} is not distinct from old.{g} then return new; end if;\n")
    else:  # counted only where the condition is TRUE: an update that keeps a counted row counted is skipped
        skip = (f"  if new.{g} is null or not (true{_counts(sc, r, 'new')}) then return new; end if;\n"
                f"  if tg_op = 'UPDATE' and new.{g} is not distinct from old.{g} and (old.{g} is not null"
                f"{_counts(sc, r, 'old')}) then return new; end if;\n")
    return (
        f"{verb} {q(card_fn_name(r))}() returns trigger language plpgsql "
        f"security definer set search_path from current as $mls$\n"
        f"declare n bigint;\n"
        f"begin\n"
        f"{skip}"
        f"{lock}"
        f"  select count(*) into n from {q(r.table)} where {g} = new.{g}{_counted_rows(sc, r)};\n"
        f"  if {test} then\n"
        f"    raise exception 'MLS cardinality {r.name} on {r.table}: more than {r.max} rows for "
        f"{r.group} = %', new.{g} using errcode = 'check_violation';\n"
        f"  end if;\n"
        f"  return new;\n"
        f"end $mls$")


def card_trigger_ddl(r: CardinalityRule) -> str:
    cols = "" if r.where is not None else f" of {q(r.group)}"
    return (f"create trigger {q(r.name)} before insert or update{cols} on {q(r.table)} "
            f"for each row execute function {q(card_fn_name(r))}()")


def card_min_fn_name(r: CardinalityRule) -> str:
    return f"mls_card_{r.table}_{r.name}_min"


def card_min_fn_ddl(spec: Spec, r: CardinalityRule, mutations: frozenset[Mutation] = frozenset(),
                    replace: bool = False) -> str:
    """#61: at commit, a row that counted (old) and no longer does in its group (deleted, moved,
    or its condition no longer TRUE) leaves at least `min` counted rows, unless the parent is gone."""
    sc = SqlCompiler(spec, None, mutations)
    pk = spec.tables[r.parent].primary_key[0]
    g = q(r.group)
    verb = "create or replace function" if replace else "create function"
    lock = "" if Mutation.CARDINALITY_NO_LOCK in mutations else " for update"
    bound = r.min - 1 if Mutation.CARDINALITY_MIN_OFF_BY_ONE in mutations else r.min
    return (
        f"{verb} {q(card_min_fn_name(r))}() returns trigger language plpgsql "
        f"security definer set search_path from current as $mls$\n"
        f"declare n bigint;\n"
        f"begin\n"
        f"  if old.{g} is null or not (true{_counts(sc, r, 'old')}) then return null; end if;\n"
        f"  if tg_op = 'UPDATE' and new.{g} is not distinct from old.{g}{_counts(sc, r, 'new')} then return null; end if;\n"
        f"  perform 1 from {q(r.parent)} where {q(pk)} = old.{g}{lock};\n"
        f"  if not found then return null; end if;\n"
        f"  select count(*) into n from {q(r.table)} where {g} = old.{g}{_counted_rows(sc, r)};\n"
        f"  if n < {bound} then\n"
        f"    raise exception 'MLS cardinality {r.name} on {r.table}: fewer than {r.min} rows for "
        f"{r.group} = %', old.{g} using errcode = 'check_violation';\n"
        f"  end if;\n"
        f"  return null;\n"
        f"end $mls$")


def card_min_trigger_name(r: CardinalityRule) -> str:
    return f"{r.name}_min"


def card_min_trigger_ddl(r: CardinalityRule) -> str:
    return (f"create constraint trigger {q(card_min_trigger_name(r))} after delete or update on {q(r.table)} "
            f"deferrable initially deferred for each row execute function {q(card_min_fn_name(r))}()")


def cardinality_ddl(spec: Spec, r: CardinalityRule, sc: SqlCompiler) -> list[str]:
    out = [f"alter table {q(r.table)} add constraint {q(f'mls_card_{r.name}_parent')} {parent_fk_def(spec, r)}"]
    if r.max is not None:
        out += [card_fn_ddl(spec, r, sc.mutations), function_owner_ddl(f"{q(card_fn_name(r))}()"),
                card_trigger_ddl(r)]
    if r.min is not None:
        out += [card_min_fn_ddl(spec, r, sc.mutations), function_owner_ddl(f"{q(card_min_fn_name(r))}()"),
                card_min_trigger_ddl(r)]
    return out
