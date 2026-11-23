"""Lookup helpers (D67, #34): a membership whose plain subquery would recurse
(`spec/recursion.py`) calls `mls_lookup_<relation>(key)`, a SECURITY DEFINER function owned by
`mls_internal` that returns the relation's values for the key.  Its body is the subquery the
policy would have had (the base relation's rows for the key, its condition, then one level per
hop), read without the caller's policies; `mls_internal` reads every table it names through its
`mls_internal_<table>` policy (`using (true)`).  The policy calls it once per statement:
`col = any ((select mls_lookup_r(<key>))::t[])`, an uncorrelated InitPlan as for hierarchies.
The relation is every stored row's pair, which is what the proofs already assume, so a routed
lookup needs no visibility policy and no column grant on its tables."""
from __future__ import annotations

from mls.compile.internal import function_grant_ddl, function_owner_ddl
from mls.compile.mutations import Mutation
from mls.compile.sql import SqlCompiler, q
from mls.identity.base import SQL_TYPE
from mls.spec.chain import condition, levels
from mls.spec.model import Spec


def lookup_fn_name(relation: str) -> str:
    return f"mls_lookup_{relation}"


def _types(spec: Spec, relation: str) -> tuple[str | None, str]:
    """The SQL types of the helper's key (None for a set relation, #63: no argument) and values."""
    lv = levels(spec, relation)
    kt = None if lv[0].key is None else SQL_TYPE[spec.tables[lv[0].table].columns[lv[0].key].type]
    vt = SQL_TYPE[spec.tables[lv[-1].table].columns[lv[-1].value].type]
    return kt, vt


def lookup_fn_sig(spec: Spec, relation: str) -> str:
    return f"{q(lookup_fn_name(relation))}({_types(spec, relation)[0] or ''})"


def lookup_fn_ddl(spec: Spec, relation: str, sc: SqlCompiler, replace: bool = False) -> str:
    kt, vt = _types(spec, relation)
    lv = levels(spec, relation)
    where = []
    if lv[0].key is not None:  # #63: a set has no key; it keeps every row its condition keeps
        where.append("true" if Mutation.LOOKUP_KEY_DROPPED in sc.mutations else f"{q(lv[0].key)} = k")
    cond = condition(spec, relation)
    if cond is not None and Mutation.RELATION_CONDITION_DROPPED not in sc.mutations:
        where.append(sc.pred(cond, lv[0].table))
    inner = f"select {q(lv[0].value)} from {q(lv[0].table)}" + (f" where {' and '.join(where)}" if where else "")
    for h in lv[1:]:
        inner = f"select {q(h.value)} from {q(h.table)} where {q(h.key)} = any (array({inner}))"
    verb = "create or replace function" if replace else "create function"
    arg = "" if kt is None else f"k {kt}"
    # #63: a set's helper is what keeps its rows from needing the caller's visibility
    security = ("security invoker" if kt is None and Mutation.SET_HELPER_INVOKER in sc.mutations
                else "security definer")
    return (f"{verb} {q(lookup_fn_name(relation))}({arg}) returns {vt}[] language sql stable "
            f"{security} set search_path from current as $mls$\n"
            f"  select coalesce(array({inner}), '{{}}')\n"
            f"$mls$")


def lookup_ddl(spec: Spec, relation: str, sc: SqlCompiler) -> list[str]:
    sig = lookup_fn_sig(spec, relation)
    return [lookup_fn_ddl(spec, relation, sc), function_owner_ddl(sig),
            *function_grant_ddl(sig, list(spec.roles))]


def lookup_call_sql(spec: Spec, relation: str, key_sql: str | None, value_sql: str) -> str:
    _, vt = _types(spec, relation)
    return f"({value_sql} = any ((select {q(lookup_fn_name(relation))}({key_sql or ''}))::{vt}[]))"
