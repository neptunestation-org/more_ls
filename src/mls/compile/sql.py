"""Predicate -> SQL.  One fixed rendering per atom (SEMANTICS §2)."""
from __future__ import annotations

from mls.compile.mutations import Mutation
from mls.compile.opaque import opaque_sql
from mls.compile.time import now_between_sql
from mls.spec.chain import condition, levels
from mls.spec.recursion import is_routed
from mls.spec.expand import as_in_list
from mls.identity.base import SQL_TYPE, Adapter
from mls.sqltext import col, q  # noqa: F401  (re-exported: the templates import them from here)
from mls.spec.model import (
    And, ColRef, ColType, Const, CtxRef, Cmp, Has, InGroup, IsNull, Lit, Member, NewRef, Not, NowBetween,
    OldRef, OpaqueRef, Or, Pred, Spec,
)


def const_sql(value, type_: ColType | None) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    lit = "'" + value.replace("'", "''") + "'"
    if type_ == "uuid":
        return lit + "::uuid"
    return lit


class SqlCompiler:
    def __init__(self, spec: Spec, adapter: Adapter, mutations: frozenset[Mutation] = frozenset()):
        self.spec = spec
        self.adapter = adapter
        self.mutations = mutations

    def term_type(self, t, table: str) -> ColType | None:
        if isinstance(t, ColRef):
            return self.spec.tables[table].columns[t.col].type
        if isinstance(t, OldRef):
            return self.spec.tables[table].columns[t.old].type
        if isinstance(t, NewRef):
            return self.spec.tables[table].columns[t.new].type
        if isinstance(t, CtxRef):
            return self.spec.context_type(t.ctx)
        return None

    def column(self, name: str, table: str, row: str | None = None) -> str:
        if Mutation.FIELD_OTHER in self.mutations and "." in name:
            c = name.partition(".")[0]
            name = next((o for o in self.spec.tables[table].columns if o != name and o.partition(".")[0] == c), name)
        return col(name, row)

    def term(self, t, table: str, type_hint: ColType | None = None) -> str:
        if isinstance(t, ColRef):
            if Mutation.IDENT_UNQUOTED in self.mutations:
                return t.col  # Postgres folds it: "ownerId" is read as ownerid
            return self.column(t.col, table)
        if isinstance(t, OldRef):
            return self.column(t.old, table, "old")
        if isinstance(t, NewRef):
            return self.column(t.new, table, "new")
        if isinstance(t, CtxRef):
            return self.adapter.ctx_sql(t.ctx)
        if isinstance(t, Const):
            return const_sql(t.const, type_hint)
        raise TypeError(t)

    def pred(self, p: Pred, table: str) -> str:
        if isinstance(p, Lit):
            return "true" if p.lit else "false"
        if isinstance(p, And):
            return "(" + " and ".join(self.pred(a, table) for a in p.and_) + ")"
        if isinstance(p, Or):
            lst = as_in_list(p)
            if lst is not None:
                # an expanded `in` (or a hand-written disjunction of the same shape): one IN list,
                # which the planner turns into a single `= ANY` index condition on every version
                t, consts = lst
                ty = self.term_type(t, table)
                if Mutation.IN_DROP_LAST in self.mutations:
                    consts = consts[:-1]
                lhs = self.term(t, table)
                if Mutation.CITEXT_AS_TEXT in self.mutations and ty == "citext":
                    return f"({lhs}::text in ({', '.join(self.term(c, table, ty) + '::text' for c in consts)}))"
                return f"({lhs} in ({', '.join(self.term(c, table, ty) for c in consts)}))"
            return "(" + " or ".join(self.pred(a, table) for a in p.or_) + ")"
        if isinstance(p, Not):
            return f"(not {self.pred(p.not_, table)})"
        if isinstance(p, IsNull):
            if Mutation.CTX_IS_NULL_FOLDED in self.mutations and isinstance(p.is_null, CtxRef):
                return "false"  # the value taken as always set
            return f"({self.term(p.is_null, table)} is null)"
        if isinstance(p, Has):  # D88: the label's literal takes the element type (text, or the enum)
            col, label = p.has
            c, lab = self.term(col, table), self.term(label, table)
            if Mutation.HAS_NULL_ELEMENT_FALSE in self.mutations:  # `@>`'s reading of a NULL element
                return f"(case when {c} is null then null else coalesce({lab} = any ({c}), false) end)"
            return f"({lab} = any ({c}))"
        if isinstance(p, Cmp):
            l, op, r = p.cmp
            ty = self.term_type(l, table) or self.term_type(r, table)
            ls, rs = self.term(l, table, ty), self.term(r, table, ty)
            if Mutation.CITEXT_AS_TEXT in self.mutations and ty == "citext":
                ls, rs = f"{ls}::text", f"{rs}::text"
            return f"({ls} {op} {rs})"
        if isinstance(p, Member):
            m = p.member
            lv = levels(self.spec, m.relation)
            kt = None if lv[0].key is None else self.spec.tables[lv[0].table].columns[lv[0].key].type
            if is_routed(self.spec, table, m.relation):
                from mls.compile.lookup import lookup_call_sql

                # D67: the plain subquery would recurse; the helper reads without the policies.
                # #63: a set has no key, so its helper takes none (a set is always routed)
                return lookup_call_sql(self.spec, m.relation,
                                       None if m.key is None else self.term(m.key, table, kt),
                                       self.term(m.value, table))
            key_match = f"{q(lv[0].key)} = {self.term(m.key, table, kt)}"
            if Mutation.RELATION_NULL_KEY_MATCHES in self.mutations:
                key_match = f"({key_match} or {q(lv[0].key)} is null)"
            inner = f"select {q(lv[0].value)} from {q(lv[0].table)} where {key_match}"
            cond = condition(self.spec, m.relation)
            if cond is not None and Mutation.RELATION_CONDITION_DROPPED not in self.mutations:
                # D61: the base relation's rows where its condition is TRUE (WHERE drops UNKNOWN);
                # its unqualified columns resolve to the subquery's own table
                inner += f" and {self.pred(cond, lv[0].table)}"
            for h in lv[1:]:  # D56: one uncorrelated InitPlan per level
                inner = f"select {q(h.value)} from {q(h.table)} where {q(h.key)} = any (array({inner}))"
            out = f"({self.term(m.value, table)} = any (array({inner})))"
            if Mutation.MEMBER_CONST_ANY_VALUE in self.mutations and isinstance(m.value, Const):
                out = f"(cardinality(array({inner})) > 0)"
            if Mutation.MEMBER_NULL_PASSES in self.mutations:
                out = f"({self.term(m.value, table)} is null or {out})"
            return out
        if isinstance(p, InGroup):
            from mls.compile.hierarchy import reach_fn_name

            g = p.in_group
            h = self.spec.hierarchies[g.hierarchy]
            rel = self.spec.relations[h.members]
            kt = self.spec.tables[rel.table].columns[rel.key].type
            it = SQL_TYPE[self.spec.tables[h.table].columns[h.id].type]
            # the cast makes the scalar subquery an array expression (ANY (subquery) would compare
            # the value with the whole array row); it stays an uncorrelated InitPlan
            return (f"({self.term(g.value, table)} = any ((select {q(reach_fn_name(g.hierarchy))}"
                    f"({self.term(g.key, table, kt)}))::{it}[]))")
        if isinstance(p, NowBetween):
            nb = p.now_between
            return now_between_sql(
                self.term(nb.from_, table) if nb.from_ is not None else None,
                self.term(nb.until, table) if nb.until is not None else None,
                self.adapter, closed_null=Mutation.TIME_NULL_CLOSED in self.mutations)
        if isinstance(p, OpaqueRef):
            return opaque_sql(self.spec.opaques[p.opaque], self.adapter,
                              invert=Mutation.OPAQUE_INVERT in self.mutations)
        raise TypeError(p)


def sql_type(col) -> str:
    """A column's SQL type: an enum column's is its Postgres type, quoted (D59); an array's is its
    element's with `[]` (D88)."""
    if col.type in ("enum", "enum[]"):
        return q(col.enum) + ("[]" if col.type == "enum[]" else "")
    return "text[]" if col.type == "text[]" else SQL_TYPE[col.type]


def column_ddl(name: str, col) -> str:
    return f"{q(name)} {sql_type(col)}" + ("" if col.nullable else " not null")


def composite_types(spec: Spec) -> dict[str, dict[str, object]]:
    """#94: the composite types the field columns name, each with its fields (name -> a Column)."""
    out: dict[str, dict[str, object]] = {}
    for t in spec.tables.values():
        for c, c_ in t.columns.items():
            parts = c_.field_parts(c)
            if parts is not None and c_.composite is not None:
                out.setdefault(c_.composite, {}).setdefault(parts[1], c_)
    return out


def composite_ddl(spec: Spec) -> list[str]:
    """#94: the types of the adopted composite columns: the harness and drift's shadow create them
    with the fields the spec declares (MLS never creates one in a deployed database)."""
    return [f"create type {q(name)} as ({', '.join(f'{q(f)} {sql_type(c)}' for f, c in fields.items())})"
            for name, fields in composite_types(spec).items()]


def enum_ddl(name: str, labels: list[str]) -> str:
    """The type an adopted enum column has: the harness and drift's shadow create it (MLS never
    creates one in a deployed database)."""
    return f"create type {q(name)} as enum ({', '.join(const_sql(x, None) for x in labels)})"
