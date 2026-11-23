"""Which lookups go through a helper (D67, #34; the rule is D66's, measured in FINDINGS).

A membership in a policy compiles to a subquery the caller runs, under the SELECT policies of the
relation's tables (the visibility policies D21 and D56 add among them).  When those lead back to
the policy's own table Postgres refuses every statement that reads it ('infinite recursion
detected in policy'): every compiled policy contains a subquery, the context value.  Such a lookup
instead calls a SECURITY DEFINER helper owned by `mls_internal` (`compile/lookup.py`), which reads
the tables without the caller's policies, so its lookup is no step of the expansion.

`routed(spec)` is the set of (policy table, relation) whose lookups go through a helper: those
whose key is a constant (#48: the visibility policy would be `key = <constant>`, every row with
that key whoever asks, so a storefront's "is this product active" would list the active products
of every shop; the helper answers without granting a row), those whose relation reads the
policy's own table, then, in order of policy table and relation name,
each lookup that still closes a cycle once the earlier ones are routed, until none does (an order
of the names, not of the rules, so that listing the same policies differently changes nothing).
A chain whose visibility policies close a cycle of their own is routed as well (#33): one that
reads a table twice (co-members, `member_of . team_members(team_id, user_id)`: the hop's policy
on team_members would read team_members), or a hop whose visibility leads back to its table.  Per role the graph differs (the
subqueries run as the caller), but a helper means the same for every role, so a lookup routed for
one role is routed for all.
"""
from __future__ import annotations

from dataclasses import dataclass

from mls.spec.model import And, Const, Member, MemberBody, Not, Or, PolicyRule, Pred, Spec


@dataclass(frozen=True)
class Use:
    role: str
    table: str          # the policy's table
    rule_id: str
    relation: str
    tables: tuple[str, ...]   # the relation's levels' tables, base first
    reads_rows: bool    # a SELECT (or FOR ALL) policy's USING: a step of a later lookup's expansion
    const_key: bool = False   # keyed by a constant, not a context value


def members(p: Pred | None, out: list[MemberBody]) -> list[MemberBody]:
    if isinstance(p, Member):
        out.append(p.member)
    elif isinstance(p, And):
        for a in p.and_:
            members(a, out)
    elif isinstance(p, Or):
        for a in p.or_:
            members(a, out)
    elif isinstance(p, Not):
        members(p.not_, out)
    return out


def uses(spec: Spec) -> list[Use]:
    from mls.spec.chain import levels

    out = []
    for r, role, table, _ in spec.caller_reads():  # policies, and the column guards' conditions (#50)
        if isinstance(r, PolicyRule):
            exprs = [(r.using, r.command in ("select", "all")), (r.check, False)]
        else:  # a trigger's read is no step of a policy expansion
            exprs = [(r.when, False)]
        for expr, steps in exprs:
            for m in members(expr, []):
                lv = tuple(lvl.table for lvl in levels(spec, m.relation))
                out.append(Use(role, table, r.id, m.relation, lv, steps, isinstance(m.key, Const)))
    return out


def reads(all_uses: list[Use], skip: set[tuple[str, str]]) -> dict[str, dict[str, list[tuple[str, Use]]]]:
    """role -> table -> [(table read, the lookup)]: the SELECT-policy steps, and the visibility
    policy on hop table i reading the levels before it, for every lookup not in `skip`."""
    g: dict[str, dict[str, list[tuple[str, Use]]]] = {}
    for u in all_uses:
        if (u.table, u.relation) in skip:
            continue
        rg = g.setdefault(u.role, {})
        if u.reads_rows:
            for t in u.tables:
                rg.setdefault(u.table, []).append((t, u))
        for h in range(1, len(u.tables)):
            for t in u.tables[:h]:
                rg.setdefault(u.tables[h], []).append((t, u))
    return g


def back_path(g: dict[str, list[tuple[str, Use]]], src: str, dst: str) -> list[tuple[str, Use]] | None:
    """The steps from `src` back to `dst` (breadth first), or None."""
    todo, prev = [src], {src: None}
    while todo:
        t = todo.pop(0)
        if t == dst:
            out = []
            while prev[t] is not None:
                t0, u = prev[t]
                out.append((t, u))
                t = t0
            return out[::-1]
        for nxt, u in g.get(t, []):
            if nxt not in prev:
                prev[nxt] = (t, u)
                todo.append(nxt)
    return None


_cache: dict[int, tuple[Spec, frozenset[tuple[str, str]]]] = {}


def routed(spec: Spec) -> frozenset[tuple[str, str]]:
    hit = _cache.get(id(spec))
    if hit is not None and hit[0] is spec:
        return hit[1]
    # by table and relation, not rule order: the same policies listed in another order (an import
    # lists them by table) route the same lookups
    all_uses = sorted(uses(spec), key=lambda u: (u.table, u.relation, u.role, u.reads_rows))
    out = {(u.table, u.relation) for u in all_uses
           if u.const_key or u.table in u.tables or len(set(u.tables)) < len(u.tables)}
    changed = True
    while changed:
        changed = False
        g = reads(all_uses, out)
        # back to the policy's table first; only then (#33) back to a hop table from the levels its
        # visibility policy reads, so that a spec without such a cycle routes as before
        for closes in (lambda u, rg: any(back_path(rg, t, u.table) for t in dict.fromkeys(u.tables)),
                       lambda u, rg: any(back_path(rg, t, u.tables[h])
                                         for h in range(1, len(u.tables)) for t in u.tables[:h])):
            hit = next((u for u in all_uses if (u.table, u.relation) not in out
                        and closes(u, g.get(u.role, {}))), None)
            if hit is not None:
                out.add((hit.table, hit.relation))
                changed = True
                break
    res = frozenset(out)
    _cache[id(spec)] = (spec, res)
    return res


def is_routed(spec: Spec, table: str, relation: str) -> bool:
    return (table, relation) in routed(spec)
