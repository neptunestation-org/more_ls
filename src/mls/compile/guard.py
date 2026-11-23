"""Column guard template (#50): one fixed BEFORE UPDATE row trigger for a write column rule with a
condition.  The trigger fires only for the rule's role (`WHEN (current_user = role)`, so the
trusted roles, and the SECURITY DEFINER helpers, are not limited) and raises when the condition
is TRUE of the old row and a column outside the rule's list changed.  The comparison is of the
whole row as jsonb minus the listed columns, so a column the spec does not model (an adopted
table's foreign one) is held too; a hierarchy's depth, which its own trigger recomputes, is not
compared."""
from __future__ import annotations

from pydantic import TypeAdapter

from mls.compile.mutations import Mutation
from mls.compile.sql import SqlCompiler, const_sql, q
from mls.spec.model import ColumnRule, Pred, Spec


def guard_fn_name(r: ColumnRule) -> str:
    return f"mls_cg_{r.table}_{r.name}"


def guard_trigger_name(r: ColumnRule, mutations: frozenset[Mutation] = frozenset()) -> str:
    """#58 (amends D78): Postgres fires a table's BEFORE row triggers in byte order of their names,
    and a trigger of the table's own that rewrites the row (an `updated_at` stamp) must come after
    the guard, or the guard sees a column the caller did not change.  `0` sorts before letters and
    `_`, so before any ordinary trigger name; `check --dsn` refuses one that still sorts first."""
    return f"zz_mls_cg_{r.name}" if Mutation.GUARD_SORTS_LAST in mutations else f"0_mls_cg_{r.name}"


def on_old(p: Pred) -> Pred:
    """The condition with its columns read from the old row (`{"col": c}` -> `{"old": c}`)."""
    def walk(x):
        if isinstance(x, dict):
            if set(x) == {"col"}:
                return {"old": x["col"]}
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [walk(v) for v in x]
        return x
    return TypeAdapter(Pred).validate_python(walk(p.model_dump(by_alias=True, exclude_none=True)))


def kept_columns(spec: Spec, r: ColumnRule) -> list[str]:
    """The columns the comparison leaves out: the rule's, and a hierarchy depth on the table."""
    depth = [h.depth for h in spec.hierarchies.values() if h.table == r.table]
    return sorted(set(r.columns) | set(depth))


def guard_fn_ddl(r: ColumnRule, sc: SqlCompiler, replace: bool = False) -> str:
    when = "true" if Mutation.GUARD_ANY_ROW in sc.mutations else sc.pred(on_old(r.when), r.table)
    cols = "array[" + ", ".join(const_sql(c, "text") for c in kept_columns(sc.spec, r)) + "]::text[]"
    verb = "create or replace function" if replace else "create function"
    fn = guard_fn_name(r)
    return (
        f"{verb} {q(fn)}() returns trigger language plpgsql as $mls$\n"
        f"begin\n"
        f"  if ({when}) is true and (to_jsonb(new) - {cols}) is distinct from (to_jsonb(old) - {cols}) then\n"
        f"    raise exception 'MLS column rule {r.name} on {r.table} violated' "
        f"using errcode = 'insufficient_privilege';\n"
        f"  end if;\n"
        f"  return new;\n"
        f"end $mls$")


def guard_trigger_ddl(r: ColumnRule, mutations: frozenset[Mutation] = frozenset()) -> str:
    return (f"create trigger {q(guard_trigger_name(r, mutations))} before update on {q(r.table)} for each row "
            f"when (current_user = {const_sql(r.role, 'text')}) execute function {q(guard_fn_name(r))}()")


def guard_ddl(r: ColumnRule, sc: SqlCompiler) -> list[str]:
    return [guard_fn_ddl(r, sc), guard_trigger_ddl(r, sc.mutations)]
