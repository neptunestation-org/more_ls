"""Typechecker + fragment checker for MLS specs.

Every error names the JSON path of the offending element and states the allowed alternative
(invariant 7).  `check_spec` returns nothing on success and raises SpecError otherwise.

Scopes (SEMANTICS §2-3):
  policy      USING / WITH CHECK: cols of the table, ctx, const; member(key=ctx|const, value=col);
              now_between; is_null; opaque.  Negated member is rejected (anti-join).
  check       CHECK constraint: cols, const, is_null, opaque without context inputs.
  transition  BEFORE UPDATE trigger: old/new refs and const only.
  invariant   property goals / invariants: cols, const, member (key may be a column), is_null.
  goal        custom property goals: like policy plus member with a column key.
  in_group follows the rules of member everywhere (key is context, value a NOT NULL column).
"""
from __future__ import annotations

import re
import uuid as _uuid
from dataclasses import dataclass

from pydantic import ValidationError

from mls.errors import ErrorSink, MlsError, SpecError
from mls.spec.chain import is_set
from mls.spec.model import (
    MAX_HOPS, ComposedRelation, Relation,
    CONTEXT_NOW, And, BypassAssumed, CardinalityRule, CheckRule, ColRef, ColType, ColumnRule, Cmp, Const, CtxRef,
    INT_RANGE, In, AlwaysOnUpdate, ChangesOnly, Custom, InclusionRule, InGroup, InvariantPreserved, IsNull, Lit, Member, MonotoneIn, MustAllow, NewRef, Not,
    RoleSeparation, ARRAY_TYPES, Has,
    NowBetween, OldRef, OpaqueRef, Or, OwnerAssumed, PathAssumed, InlinedAssumed, DelegateAssumed, DELEGATION, PolicyRule, RlsAssumed, Spec, TenantIsolation,
    ColumnImmutable, WriteSubsetRead, LeastPrivilege, TransitionRule, comparable, pair_unique,
)

IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
# a name of the catalog (table, column, role): case-sensitive, as Postgres keeps a quoted name, and
# quoted wherever MLS emits it (`compile/sql.py:q`).  ASCII letters, digits and underscores, at most
# 63 bytes: no `$` (it could close the compiler's `$mls$` quoting), so no name needs escaping inside
# a literal, a `raise` message or a quoted identifier (D58)
CATALOG_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
CATALOG_IDENT_FIX = ("letters of either case, digits and underscores, starting with a letter or an underscore, "
                     "at most 63 characters (rename it, or leave the table out of the spec)")
ORDERED_TYPES = {"int", "bigint", "timestamp"}
# D54: a bypass path as drift spells it (`pg/catalog.py:bypass_paths`)
BYPASS_PATH = re.compile(r'view\s+[\w."$]+|function\s+[\w."$]+\s*\([^()]*\)')
INLINED = re.compile(r'function\s+[\w."$]+\s*\([^()]*\)\s+md5\s+[0-9a-f]{32}')


def _json_path(loc: tuple) -> str:
    """Pydantic locations carry discriminator tags ('rules', 0, 'policy', 'using', 'and', 'and', 1):
    a tag repeats the field name for single-key unions, and follows the index for rules/properties."""
    parts: list = []
    prev = None
    for i, seg in enumerate(loc):
        if isinstance(seg, str) and seg == prev:
            continue
        if isinstance(seg, str) and isinstance(prev, int) and i >= 2 and loc[i - 2] in ("rules", "properties"):
            prev = seg
            continue
        parts.append(seg)
        prev = seg
    return "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in parts)


LIKE_OPS = ("like", "ilike", "~~", "~~*", "not like", "similar to")


def pydantic_errors_to_mls(e: ValidationError) -> list[MlsError]:
    out = []
    for err in e.errors():
        path, msg, fix = _json_path(err["loc"]), err["msg"], ""
        if err["type"] == "literal_error" and str(err.get("input", "")).lower() in LIKE_OPS:
            # `like` is accepted by the lifter only (D46): never authored
            msg = (f"'{err['input']}' is not a comparison operator of the fragment (LIKE is not leakproof; a "
                   f"pattern test cannot be index-driven below a policy)")
            fix = ("compare with =, <>, <, <=, >, >=; a pattern test is an opaque block over the column "
                   "(the leakproof lint reports it; `mls import` writes one from an existing policy)")
        out.append(MlsError(path=path, message=msg, fix=fix, code="schema"))
    return out


@dataclass(frozen=True)
class Scope:
    name: str
    table: str
    cols: bool = False
    ctx: bool = False
    old_new: bool = False
    member: bool = False
    member_col_key: bool = False
    now_between: bool = False
    opaque: bool = False
    opaque_ctx: bool = False
    reject_negated_member: bool = False
    is_policy: bool = False


def policy_scope(table: str) -> Scope:
    return Scope("policy", table, cols=True, ctx=True, member=True, now_between=True, opaque=True,
                 opaque_ctx=True, reject_negated_member=True, is_policy=True)


def guard_scope(table: str) -> Scope:
    """A column guard's condition (#50): what a policy may say of the row being edited and of who
    is editing, evaluated in the trigger, so no index shape is required."""
    return Scope("column rule condition", table, cols=True, ctx=True, member=True,
                 now_between=True)


def check_scope(table: str) -> Scope:
    return Scope("check", table, cols=True, opaque=True)


def relation_scope(table: str) -> Scope:
    """A relation's condition (D61): the relation's own table's columns and constants, nothing
    that depends on who asks or on other tables."""
    return Scope("relation condition", table, cols=True)


def transition_scope(table: str) -> Scope:
    return Scope("transition", table, old_new=True)


def invariant_scope(table: str) -> Scope:
    return Scope("invariant", table, cols=True, member=True, member_col_key=True)


def goal_scope(table: str) -> Scope:
    return Scope("goal", table, cols=True, ctx=True, member=True, member_col_key=True,
                 now_between=True, opaque=True, opaque_ctx=True)


def must_allow_scope(table: str, command: str) -> Scope:
    """The condition of a must_allow property: a goal predicate that, for update, may also name
    the old and new images."""
    return Scope("must_allow condition", table, cols=True, ctx=True, member=True, member_col_key=True,
                 now_between=True, opaque=True, opaque_ctx=True, old_new=(command == "update"))


class Checker:
    def __init__(self, spec: Spec, rule_paths: list[str] | None = None):
        self.spec = spec
        self.sink = ErrorSink()
        # the JSON path of each rule: an expanded selector rule reports under the selector's path
        self.rule_paths = rule_paths or [f"$.rules[{i}]" for i in range(len(spec.rules))]

    # ------------------------------------------------------------------ helpers
    def err(self, path: str, msg: str, fix: str = "", code: str = "error") -> None:
        self.sink.add(path, msg, fix, code)

    def col_type(self, table: str, col: str) -> ColType | None:
        t = self.spec.tables.get(table)
        if t is None or col not in t.columns:
            return None
        return t.columns[col].type

    def col_nullable(self, table: str, col: str) -> bool:
        return self.spec.tables[table].columns[col].nullable

    def governed(self, table: str, path: str, what: str) -> bool:
        """An `observed` table is mentioned, not governed (D45): nothing may name it but the
        table declaration itself.  Reports and returns False when `table` is observed."""
        t = self.spec.tables.get(table)
        if t is not None and t.mode == "observed":
            self.err(path, f"table '{table}' is observed; {what} cannot name it (an observed table is "
                           f"in the schema but not governed)",
                     f"set tables.{table}.mode to \"adopted\" (the table exists) or \"owned\" (MLS creates it)")
            return False
        return True

    # ------------------------------------------------------------------ terms
    def term_type(self, term, scope: Scope, path: str) -> ColType | None:
        if isinstance(term, ColRef):
            if not scope.cols:
                self.err(path, f"a column reference is not allowed in {'an' if scope.name[0] in 'aeiou' else 'a'} "
                               f"{scope.name} predicate",
                         f"use {{\"old\": col}} / {{\"new\": col}} in {scope.name} predicates" if scope.old_new else
                         "remove the column reference")
                return None
            ty = self.col_type(scope.table, term.col)
            if ty is None:
                self.err(path, f"unknown column '{term.col}' of table '{scope.table}'",
                         f"one of: {', '.join(self.spec.tables[scope.table].columns)}")
            return ty
        if isinstance(term, (OldRef, NewRef)):
            if not scope.old_new:
                self.err(path, f"old/new references are only allowed in transition predicates, in an "
                               f"always_on_update property and in the condition of a must_allow property "
                               f"on update",
                         "use {\"col\": name} here")
                return None
            col = term.old if isinstance(term, OldRef) else term.new
            ty = self.col_type(scope.table, col)
            if ty is None:
                self.err(path, f"unknown column '{col}' of table '{scope.table}'",
                         f"one of: {', '.join(self.spec.tables[scope.table].columns)}")
            return ty
        if isinstance(term, CtxRef):
            if not scope.ctx:
                self.err(path, f"context values are not allowed in a {scope.name} predicate "
                               f"(it must be a function of the row alone)",
                         "move the condition into a policy, or state it without context")
                return None
            ty = self.spec.context_type(term.ctx)
            if ty is None:
                self.err(path, f"unknown context value '{term.ctx}'",
                         f"declare it under identity.context or use one of: "
                         f"{', '.join([*self.spec.identity.context, CONTEXT_NOW])}")
            return ty
        if isinstance(term, Const):
            v = term.const
            if isinstance(v, bool):
                return "bool"
            if isinstance(v, int):
                return "int"
            return "text"  # str; uuid handled by the comparison rule
        self.err(path, "unknown term")
        return None

    def enum_name(self, term, scope: Scope) -> str | None:
        """The enum type of the column `term` names (D59), or None when it names no enum column."""
        if isinstance(term, CtxRef):  # #89: an enum context value
            cv = self.spec.identity.context.get(term.ctx)
            return cv.enum if cv is not None and cv.type == "enum" else None
        col = term.col if isinstance(term, ColRef) else term.old if isinstance(term, OldRef) else \
            term.new if isinstance(term, NewRef) else None
        t = self.spec.tables.get(scope.table) if col is not None and scope.table else None
        c = t.columns.get(col) if t else None
        return c.enum if c is not None and c.type in ("enum", "enum[]") and c.enum else None

    def enum_labels(self, term, scope: Scope) -> list[str] | None:
        """The labels of the enum column `term` names (D59), or None when it names no enum column."""
        name = self.enum_name(term, scope)
        return self.spec.enums.get(name) if name else None

    def const_ok_for(self, term, ty: ColType, path: str) -> bool:
        """Constants: int<->int|bigint (within the type's range), bool<->bool, str<->text|uuid
        (uuid-shaped). No timestamp constants."""
        if not isinstance(term, Const):
            return True
        v = term.const
        if ty in INT_RANGE and isinstance(v, int) and not isinstance(v, bool):
            lo, hi = INT_RANGE[ty]
            if not lo <= v <= hi:
                self.err(path, f"constant {v} is out of range for {ty} ({lo}..{hi})",
                         "declare the column (or context value) bigint" if ty == "int"
                         else "use a constant within the range")
                return False
        if ty == "uuid":
            if isinstance(v, str):
                try:
                    _uuid.UUID(v)
                    return True
                except ValueError:
                    self.err(path, f"'{v}' is not a UUID literal", "use a canonical UUID string")
                    return False
            self.err(path, f"a uuid column needs a UUID string constant, got {v!r}")
            return False
        if ty == "timestamp":
            self.err(path, "timestamp constants are not supported in v1",
                     "compare with {\"ctx\": \"now\"} or use now_between")
            return False
        return True

    # ------------------------------------------------------------------ predicates
    def _cmp(self, l, op, r, scope: Scope, path: str, lpath: str, rpath: str) -> None:
        """The checks of a comparison; `path` names the comparison, `lpath`/`rpath` its operands
        (an expanded `in` reports under the `in` paths)."""
        lt = self.term_type(l, scope, lpath)
        rt = self.term_type(r, scope, rpath)
        if scope.is_policy:
            # sargable shape: column op (ctx | const), or (ctx|const) op (ctx|const)
            lhs_ok = isinstance(l, ColRef) or isinstance(l, (CtxRef, Const))
            rhs_ok = isinstance(r, (CtxRef, Const))
            if not (lhs_ok and rhs_ok):
                self.err(path, "comparisons in policies must be  column op (context | "
                                        "constant)  so they compile to an index condition",
                         "put the column on the left and a context value or constant on the right")
        elif scope.name == "check":
            if isinstance(l, Const) and isinstance(r, Const):
                self.err(path, "comparing two constants is meaningless", "")
        if lt is None or rt is None:
            return
        if lt in ARRAY_TYPES or rt in ARRAY_TYPES:  # D88
            self.err(path, f"an array column is tested only by has: type mismatch {lt} {op} {rt}",
                     "test a constant label among its elements: {\"has\": [{\"col\": name}, {\"const\": label}]}")
            return
        if "citext" in (lt, rt):  # #73: a constant, compared ignoring case (the proofs fold it)
            col, const, cpath = (l, r, rpath) if lt == "citext" else (r, l, lpath)
            if lt == rt or not isinstance(const, Const) or not isinstance(const.const, str) \
                    or isinstance(const.const, bool):
                self.err(path, f"type mismatch: {lt} {op} {rt}: a citext column compares with a constant only",
                         "compare it with a 'string' constant (the case does not matter)")
            elif not const.const.isascii():
                self.err(cpath, f"'{const.const}' is not ASCII: Postgres folds the case of a citext value under "
                                f"the database's collation, which the proofs cannot follow",
                         "use an ASCII constant")
            elif op not in ("=", "<>"):
                self.err(path, f"operator {op} is not allowed on citext values (no ordering: it depends on the "
                               f"collation)", "use = or <>, or in for several values")
            return
        if lt == "enum" and rt == "enum":  # two references of one enum type compare (#39)
            ln, rn = self.enum_name(l, scope), self.enum_name(r, scope)
            if ln != rn:
                self.err(path, f"type mismatch: enum {ln} {op} enum {rn}: values of different enum types "
                               f"do not compare", f"compare a column with another of type {ln}, or with one "
                               f"of its labels: {', '.join(map(repr, self.spec.enums.get(ln, [])))}")
            elif op not in ("=", "<>"):
                self.err(path, f"operator {op} is not allowed on enum values (v1 compares enum for "
                               f"equality only)", "use = or <>")
            return
        if "enum" in (lt, rt):  # otherwise an enum column compares with its own labels only (D59)
            col, const, cpath = (l, r, rpath) if lt == "enum" else (r, l, lpath)
            labels = self.enum_labels(col, scope) or []
            if not isinstance(const, Const) or not isinstance(const.const, str) or isinstance(const.const, bool):
                self.err(path, f"type mismatch: {lt} {op} {rt}",
                         f"compare an enum column with one of its labels: {', '.join(map(repr, labels))}")
            elif const.const not in labels:
                self.err(cpath, f"'{const.const}' is not a label of the column's enum type",
                         f"one of: {', '.join(map(repr, labels))}")
            elif op not in ("=", "<>"):
                self.err(path, f"operator {op} is not allowed on enum values (v1 compares enum for "
                               f"equality only)", "use = or <>, or in for several labels")
            return
        if isinstance(r, Const) and not isinstance(l, Const):
            if not self.const_ok_for(r, lt, rpath):
                return
        if isinstance(l, Const) and not isinstance(r, Const):
            if not self.const_ok_for(l, rt, lpath):
                return
        if not comparable(lt, rt) and not ({lt, rt} == {"uuid", "text"}
                                           and (isinstance(l, Const) or isinstance(r, Const))):
            self.err(path, f"type mismatch: {lt} {op} {rt}",
                     "compare values of the same type")
            return
        if isinstance(l, Const) or isinstance(r, Const):
            ty = rt if isinstance(l, Const) else lt  # a constant takes the other side's type
        else:
            ty = lt
        if op not in ("=", "<>") and ty not in ORDERED_TYPES:
            self.err(path, f"operator {op} is not allowed on {ty} values "
                                    f"(v1 compares {ty} for equality only)", "use = or <>")
        self.const_ok_for(l, ty, lpath)
        self.const_ok_for(r, ty, rpath)

    def _has(self, p: Has, scope: Scope, path: str) -> None:
        """D88: a constant label among an array column's elements (an enum array's: one of its labels)."""
        t, label = p.has
        ty = self.term_type(t, scope, f"{path}[0]")
        if ty is None and isinstance(t, (ColRef, OldRef, NewRef)):
            return  # term_type said what is wrong with the column
        if not isinstance(t, (ColRef, OldRef, NewRef)) or ty not in ARRAY_TYPES:
            arrays = [c for c, col in (self.spec.tables[scope.table].columns.items() if scope.table in
                                       self.spec.tables else []) if col.type in ARRAY_TYPES]
            self.err(f"{path}[0]", f"has tests an array column (text[] or enum[]), not {ty or 'this term'}",
                     f"use one of the table's array columns: {', '.join(arrays) or '(none)'}; compare other "
                     f"columns with cmp or in")
            return
        if not isinstance(label, Const) or not isinstance(label.const, str):
            self.err(f"{path}[1]", "the label is a text constant"
                     + (f", not {label.const!r}" if isinstance(label, Const) else ", not a column or context value"),
                     "write the label as a string; a label taken from a column or the context is not supported")
            return
        if ty == "enum[]":
            labels = self.enum_labels(t, scope) or []
            if label.const not in labels:
                self.err(f"{path}[1]", f"'{label.const}' is not a label of the column's enum type",
                         f"one of: {', '.join(map(repr, labels))}")

    def pred(self, p, scope: Scope, path: str, negated: bool = False) -> None:
        if isinstance(p, Lit):
            return
        if isinstance(p, And):
            for i, a in enumerate(p.and_):
                self.pred(a, scope, f"{path}.and[{i}]", negated)
            return
        if isinstance(p, Or):
            for i, a in enumerate(p.or_):
                self.pred(a, scope, f"{path}.or[{i}]", negated)
            return
        if isinstance(p, Not):
            self.pred(p.not_, scope, f"{path}.not", not negated)
            return
        if isinstance(p, IsNull):
            from mls.identity.base import adapter_anonymous_roles

            ty = self.term_type(p.is_null, scope, f"{path}.is_null")
            if isinstance(p.is_null, Const):
                self.err(f"{path}.is_null", "is_null applies to a column or an optional context value "
                                            "(a constant is never NULL)", "use {\"col\": name}")
            elif isinstance(p.is_null, CtxRef) and not getattr(self.spec.identity.context.get(p.is_null.ctx),
                                                               "optional", False) \
                    and not adapter_anonymous_roles(self.spec.identity.adapter, self.spec.roles):  # #85
                self.err(f"{path}.is_null", f"context value '{p.is_null.ctx}' is always set, so is_null of it is "
                                            f"constant", f"if a caller may lack it (a visitor with no current "
                                            f"user), declare it optional in identity.context.{p.is_null.ctx}; "
                                            f"else remove the test")
            return
        if isinstance(p, Has):
            self._has(p, scope, f"{path}.has")
            return
        if isinstance(p, Cmp):
            l, op, r = p.cmp
            self._cmp(l, op, r, scope, f"{path}.cmp", f"{path}.cmp[0]", f"{path}.cmp[2]")
            return
        if isinstance(p, In):
            t, consts = p.in_
            if isinstance(t, Const):
                self.err(f"{path}.in[0]", "the left side of 'in' must be a column, a context value or "
                                          "an image column, not a constant", "use {\"col\": name}")
                return
            if not consts:
                self.err(f"{path}.in[1]", "'in' needs at least one constant (an empty list is never true)",
                         "list the allowed values, or use {\"lit\": false}")
                return
            # the expansion is  t = c1 or t = c2 ...  (spec/expand.py); each disjunct is checked
            # as the comparison it becomes, under the path of the constant it comes from
            for i, c in enumerate(consts):
                self._cmp(t, "=", c, scope, f"{path}.in", f"{path}.in[0]", f"{path}.in[1][{i}]")
            return
        if isinstance(p, Member):
            if not scope.member:
                self.err(path, f"membership is not allowed in a {scope.name} predicate",
                         "state it in the policy that reads the relation, next to the membership"
                         if scope.name == "relation condition" else
                         "express the relationship as an inclusion rule (foreign key)")
                return
            m = p.member
            rel = self.spec.relations.get(m.relation)
            if rel is None:
                self.err(f"{path}.member.relation", f"unknown relation '{m.relation}'",
                         f"one of: {', '.join(self.spec.relations)}")
                return
            if negated and scope.reject_negated_member:
                self.err(path, "negated membership in a policy is an anti-join and cannot be "
                               "index-driven", "restate positively, or wrap it in an opaque block")
            if isinstance(rel, Relation) and rel.where is not None and scope.name == "invariant":
                self.err(f"{path}.member.relation", f"'{m.relation}' has a condition; an invariant cannot "
                                                    f"read one (an update of the row's other columns would "
                                                    f"change it, which the induction step does not model)",
                         f"state the invariant over a relation without a condition and the columns of "
                         f"'{rel.table}'")
            if isinstance(rel, ComposedRelation) and scope.name == "invariant":
                self.err(f"{path}.member.relation", f"'{m.relation}' is a composed relation; an invariant "
                                                    f"cannot read one (a write to a hop table would change "
                                                    f"it, which the induction step does not model)",
                         f"state the invariant over the base relation '{rel.of}' and the hop tables' columns")
            if self.base_resolves(m.relation) and is_set(self.spec, m.relation):
                if m.key is not None:
                    self.err(f"{path}.member.key", f"'{m.relation}' has no key (a set of "
                                                   f"{self.relation_ends(m.relation)[1][0]} values): a membership "
                                                   f"in it names only the value", f"remove the key: {m.relation}(col)")
                if not isinstance(m.value, (ColRef, OldRef, NewRef)):
                    self.err(f"{path}.member.value", "the membership value must be a column",
                             "use {\"col\": name}")
                if scope.name == "invariant":
                    self.err(f"{path}.member.relation", f"'{m.relation}' is a relation without a key; an "
                                                        f"invariant cannot read one (an update of its table's rows "
                                                        f"would change it, which the induction step does not model)",
                             "state the invariant over the table's columns, or as an inclusion rule")
                vt = self.term_type(m.value, scope, f"{path}.member.value")
                ends = self.relation_ends(m.relation)
                if ends is not None:
                    rvt = self.col_type(*ends[1])
                    if vt is not None and rvt is not None and not comparable(vt, rvt):
                        self.err(f"{path}.member.value", f"value type {vt} does not match relation value "
                                                         f"{ends[1][0]}.{ends[1][1]}: {rvt}")
                return
            if m.key is None:
                self.err(f"{path}.member.key", f"'{m.relation}' has a key: a membership in it names a key "
                                               f"and a value", f"{m.relation}(key, col)")
                return
            kt = self.term_type(m.key, scope, f"{path}.member.key")
            vt = self.term_type(m.value, scope, f"{path}.member.value")
            if isinstance(m.key, ColRef) and not scope.member_col_key:
                self.err(f"{path}.member.key", "the membership key must be a context value or "
                                               "constant (a column key is a per-row correlated "
                                               "subquery)", "use {\"ctx\": name}")
            # #90: a constant value with a key that is no column: a fact of the caller alone, the
            # same for every row (Supabase's authorize('channels.delete'): the caller's role has it)
            const_value = isinstance(m.value, Const) and not isinstance(m.key, (ColRef, OldRef, NewRef)) \
                and m.key is not None
            if not isinstance(m.value, (ColRef, OldRef, NewRef)) and not const_value:
                self.err(f"{path}.member.value", "the membership value must be a column, or a constant when the "
                                                 "key is a context value or constant",
                         "use {\"col\": name}")
            ends = self.relation_ends(m.relation)
            if ends is None:
                return
            (kt_, kc), (vt_, vc) = ends
            rkt, rvt = self.col_type(kt_, kc), self.col_type(vt_, vc)
            if rkt == "enum":
                # an enum key column (D59): the key is one of its labels, e.g. the open sessions,
                # `sessions(status, id)` with key 'IN_PROGRESS' (D60); or a context value of its type (#90)
                key_enum = self.spec.tables[kt_].columns[kc].enum
                labels = self.spec.enums.get(key_enum or "", [])
                if isinstance(m.key, CtxRef) and kt == "enum":
                    if self.enum_name(m.key, scope) != key_enum:
                        self.err(f"{path}.member.key", f"context value '{m.key.ctx}' is enum "
                                                       f"{self.enum_name(m.key, scope)}, relation key {kt_}.{kc} "
                                                       f"is enum {key_enum}",
                                 f"use a context value of type {key_enum}, or one of its labels")
                elif not (isinstance(m.key, Const) and isinstance(m.key.const, str)):
                    self.err(f"{path}.member.key", f"relation key {kt_}.{kc} is an enum column: the key "
                                                   f"must be one of its labels",
                             f"one of: {', '.join(repr(x) for x in labels)}")
                elif m.key.const not in labels:
                    self.err(f"{path}.member.key", f"'{m.key.const}' is not a label of {kt_}.{kc}'s enum type",
                             f"one of: {', '.join(repr(x) for x in labels)}")
                kt = None
            if kt is not None and rkt is not None and not comparable(kt, rkt):
                self.err(f"{path}.member.key", f"key type {kt} does not match relation key "
                                               f"{kt_}.{kc}: {rkt}")
            if rvt == "enum" and const_value:  # #90: a label of the value column's enum type
                labels = self.spec.enums.get(self.spec.tables[vt_].columns[vc].enum or "", [])
                if not isinstance(m.value.const, str) or m.value.const not in labels:
                    self.err(f"{path}.member.value", f"{m.value.const!r} is not a label of {vt_}.{vc}'s enum type",
                             f"one of: {', '.join(repr(x) for x in labels)}")
                vt = None
            if vt is not None and rvt is not None and not comparable(vt, rvt) \
                    and not (const_value and {vt, rvt} == {"uuid", "text"}):
                self.err(f"{path}.member.value", f"value type {vt} does not match relation value "
                                                 f"{vt_}.{vc}: {rvt}")
            return
        if isinstance(p, InGroup):
            if not scope.member:
                self.err(path, f"in_group is not allowed in a {scope.name} predicate", "")
                return
            g = p.in_group
            h = self.spec.hierarchies.get(g.hierarchy)
            if h is None:
                self.err(f"{path}.in_group.hierarchy", f"unknown hierarchy '{g.hierarchy}'",
                         f"one of: {', '.join(self.spec.hierarchies) or 'none'}")
                return
            if negated and scope.reject_negated_member:
                self.err(path, "negated in_group in a policy is an anti-join and cannot be "
                               "index-driven", "restate positively, or wrap it in an opaque block")
            kt = self.term_type(g.key, scope, f"{path}.in_group.key")
            vt = self.term_type(g.value, scope, f"{path}.in_group.value")
            if isinstance(g.key, ColRef) and not scope.member_col_key:
                self.err(f"{path}.in_group.key", "the in_group key must be a context value or "
                                                 "constant", "use {\"ctx\": name}")
            if not isinstance(g.value, (ColRef, OldRef, NewRef)):
                self.err(f"{path}.in_group.value", "the in_group value must be a column", "use {\"col\": name}")
            rel = self.spec.relations.get(h.members)
            if isinstance(rel, Relation) and rel.table in self.spec.tables:
                rkt = self.col_type(rel.table, rel.key)
                if kt is not None and rkt is not None and not comparable(kt, rkt):
                    self.err(f"{path}.in_group.key", f"key type {kt} does not match the members "
                                                     f"relation key {rel.table}.{rel.key}: {rkt}")
            it = self.col_type(h.table, h.id)
            if vt is not None and it is not None and not comparable(vt, it):
                self.err(f"{path}.in_group.value", f"value type {vt} does not match the hierarchy id "
                                                   f"{h.table}.{h.id}: {it}")
            return
        if isinstance(p, NowBetween):
            if not scope.now_between:
                self.err(path, f"now_between is not allowed in a {scope.name} predicate "
                               f"(now() is not immutable)", "move the condition into a policy")
                return
            nb = p.now_between
            if nb.from_ is None and nb.until is None:
                self.err(path, "now_between needs at least one bound", "")
            for name, t in (("from", nb.from_), ("until", nb.until)):
                if t is None:
                    continue
                ty = self.term_type(t, scope, f"{path}.now_between.{name}")
                if not isinstance(t, ColRef):
                    self.err(f"{path}.now_between.{name}", "bounds must be columns", "use {\"col\": name}")
                elif ty is not None and ty != "timestamp":
                    self.err(f"{path}.now_between.{name}", f"bound column must be a timestamp, got {ty}")
            return
        if isinstance(p, OpaqueRef):
            if not scope.opaque:
                self.err(path, f"opaque blocks are not allowed in a {scope.name} predicate", "")
                return
            o = self.spec.opaques.get(p.opaque)
            if o is None:
                self.err(f"{path}.opaque", f"unknown opaque block '{p.opaque}'",
                         f"declare it under opaques; known: {', '.join(self.spec.opaques) or 'none'}")
                return
            if o.table != scope.table:
                self.err(f"{path}.opaque", f"opaque block '{p.opaque}' is declared for table "
                                           f"'{o.table}', not '{scope.table}'")
            if o.context and not scope.opaque_ctx:
                self.err(f"{path}.opaque", f"opaque block '{p.opaque}' reads context values and "
                                           f"cannot be used in a {scope.name} predicate")
            return
        self.err(path, f"unknown predicate node {type(p).__name__}")

    # ------------------------------------------------------------------ top level
    def run(self) -> list[MlsError]:
        s = self.spec
        self.check_identity()
        for i, r in enumerate(s.roles):
            if not CATALOG_IDENT.match(r):
                self.err(f"$.roles[{i}]", f"'{r}' is not a valid role identifier", CATALOG_IDENT_FIX)
        if len(set(s.roles)) != len(s.roles):
            self.err("$.roles", "duplicate role names")
        self.check_enums()
        self.check_tables()
        self.check_relations()
        self.check_hierarchies()
        self.check_opaques()
        self.check_rules()
        self.check_field_uses()
        if not self.sink.errors:
            self.check_fk_cycles()
        self.check_properties()
        return self.sink.errors

    def check_fk_cycles(self, database: list | None = None) -> None:
        """#35: an inclusion closing a cycle of immediate foreign keys (spec/fkcycle.py); the
        catalog's own keys join them when the database is read."""
        from mls.spec.fkcycle import cycle_message, cycles, spec_fks

        for inc, path in cycles(spec_fks(self.spec) + (database or [])):
            i = next(j for j, r in enumerate(self.spec.rules) if r.id == inc.rule_id)
            self.err(self.rule_paths[i], *cycle_message(inc, path))

    def check_identity(self) -> None:
        ident = self.spec.identity
        for name, cv in ident.context.items():
            path = f"$.identity.context.{name}"
            if cv.type == "enum" and (cv.enum is None or cv.enum not in self.spec.enums):  # #89
                self.err(path + ".enum", "an enum context value needs a declared enum type"
                         + (f" ('{cv.enum}' is not declared)" if cv.enum else ""),
                         f"name one of: {', '.join(self.spec.enums) or '(none declared: add an enum)'}")
            elif cv.type != "enum" and cv.enum is not None:
                self.err(path + ".enum", f"context value '{name}' is {cv.type}, not enum", "remove the enum name")
            if cv.type == "enum" and ident.adapter == "pg_roles":
                self.err(path + ".type", "a pg_roles context value is current_user, a role name", "declare it text")
            if cv.type == "citext":
                self.err(path + ".type", "a context value cannot be citext",
                         "declare it text; a citext column compares with constants only")
            if cv.type in ARRAY_TYPES:
                self.err(path + ".type", "a context value cannot be an array",
                         "test an array column with a constant label instead")
            if name == CONTEXT_NOW:
                self.err(path, "'now' is a built-in context value", "remove it")
            if not IDENT.match(name):
                self.err(path, f"'{name}' is not a valid context name")
            if cv.optional and ident.adapter == "pg_roles":
                self.err(path + ".optional", "a pg_roles context value is current_user, which is always set",
                         "remove optional")
            if cv.md5 is not None and ident.adapter != "trusted_function":
                self.err(path + ".md5", f"only a trusted_function source has an md5 (this is {ident.adapter})",
                         "remove md5")
            if ident.adapter == "supabase":
                if cv.source == "auth.uid":
                    if cv.type != "uuid":
                        self.err(path + ".type", "auth.uid is a uuid", "set type to \"uuid\"")
                elif cv.source.startswith("jwt.claims."):
                    claim = cv.source[len("jwt.claims."):]
                    if not claim:
                        self.err(path + ".source", "empty claim name")
                else:
                    self.err(path + ".source", f"unknown supabase source '{cv.source}'",
                             "use 'auth.uid' or 'jwt.claims.<name>'")
            elif ident.adapter == "trusted_function":
                parts = cv.source.split(".")
                if len(parts) != 2 or not all(CATALOG_IDENT.match(x) for x in parts):
                    self.err(path + ".source", f"'{cv.source}' is not a schema-qualified function name",
                             "use '<schema>.<function>', the zero-argument function that returns the value")
                if cv.md5 is None or not re.fullmatch(r"[0-9a-f]{32}", cv.md5):
                    self.err(path + ".md5", "a trusted_function source needs the md5 of its function's body "
                             + ("" if cv.md5 is None else f"(32 hex digits, not '{cv.md5}')"),
                             "copy it from mls import's output, or compute md5(prosrc) from pg_proc")
            elif ident.adapter == "session_setting":
                from mls.identity.session_setting import SOURCE

                if not SOURCE.match(cv.source):
                    self.err(path + ".source", f"unknown session_setting source '{cv.source}'",
                             "use 'app.<name>' (lower-case letters, digits and underscores)")
            else:  # pg_roles
                if cv.source != "current_user":
                    self.err(path + ".source", f"unknown pg_roles source '{cv.source}'",
                             "use 'current_user'")
                elif cv.type != "text":
                    self.err(path + ".type", "current_user is text", "set type to \"text\"")

    def check_tables(self) -> None:
        for tname, t in self.spec.tables.items():
            path = f"$.tables.{tname}"
            if not CATALOG_IDENT.match(tname):
                self.err(path, f"'{tname}' is not a valid table identifier", CATALOG_IDENT_FIX)
            if not t.columns:
                self.err(path + ".columns", "a table needs at least one column")
            for cname, col in t.columns.items():
                if col.composite is not None:
                    self.check_field(tname, t, cname, col, f"{path}.columns.{cname}")
                elif not CATALOG_IDENT.match(cname):
                    self.err(f"{path}.columns.{cname}", f"'{cname}' is not a valid column identifier",
                             CATALOG_IDENT_FIX)
                self.check_enum_column(tname, t, cname, col, f"{path}.columns.{cname}")
                self.check_default(tname, t, cname, col, f"{path}.columns.{cname}")
            if t.primary_key is not None:
                for i, c in enumerate(t.primary_key):
                    if c not in t.columns:
                        self.err(f"{path}.primary_key[{i}]", f"unknown column '{c}'")
                    elif t.columns[c].nullable:
                        self.err(f"{path}.primary_key[{i}]", f"primary key column '{c}' must be NOT NULL",
                                 "set nullable to false")
            for i, u in enumerate(t.unique):
                for j, c in enumerate(u):
                    if c not in t.columns:
                        self.err(f"{path}.unique[{i}][{j}]", f"unknown column '{c}'")
            for i, tag in enumerate(t.tags):
                if not tag.strip():
                    self.err(f"{path}.tags[{i}]", "empty tag")
            self.check_assumptions(tname, t, path)

    def check_field(self, tname: str, t, cname: str, col, path: str) -> None:
        """#94: a field `c.f` of the composite column `c`, of the composite type `col.composite`: on an
        adopted table, nullable (it is NULL when the composite is), with no default of its own, and of
        the same type wherever the spec declares that type's field."""
        parts = col.field_parts(cname)
        if parts is None:
            self.err(path + ".composite", f"'{cname}' names a composite type but is not a field: a field of a "
                                          f"composite column is named 'column.field'",
                     "name it 'column.field', or remove \"composite\"")
            return
        if not all(CATALOG_IDENT.match(x) for x in (*parts, col.composite)):
            self.err(path, f"'{cname}' (composite type '{col.composite}') is not a column and a field, each a "
                           f"valid identifier", CATALOG_IDENT_FIX)
            return
        if t.mode != "adopted":
            self.err(path, f"table '{tname}' is {t.mode}, and MLS creates its tables without composite columns",
                     "adopt the table if the database already has it, or make the field a column of its own")
        if parts[0] in t.columns:
            self.err(path, f"'{parts[0]}' is both a column and the composite column of '{cname}'",
                     f"declare only the fields of '{parts[0]}'")
        if not col.nullable:
            self.err(path + ".nullable", f"field '{cname}' is NULL whenever its composite column is",
                     "declare it nullable (a CHECK rule can refuse the NULL)")
        if col.default is not None:
            self.err(path + ".default", f"field '{cname}' takes its default from its composite column's, "
                                        f"which MLS does not read", "remove the default")
        for t2name, t2 in self.spec.tables.items():
            for c2, col2 in t2.columns.items():
                p2 = col2.field_parts(c2)
                if p2 is None or (t2name, c2) == (tname, cname):
                    continue
                if t2name == tname and p2[0] == parts[0] and col2.composite != col.composite:
                    self.err(path + ".composite", f"the fields of '{parts[0]}' name two composite types, "
                                                  f"'{col.composite}' and '{col2.composite}'",
                             "name the column's one type in each of its fields")
                    return
                if col2.composite == col.composite and p2[1] == parts[1] \
                        and (col2.type, col2.enum) != (col.type, col.enum):
                    self.err(path + ".type", f"field '{parts[1]}' of composite type '{col.composite}' is "
                                             f"{col.type} here and {col2.type} on {t2name}.{c2}",
                             "declare the field's one type everywhere")
                    return

    def check_field_uses(self) -> None:
        """#94: a field is read by predicates only.  Keys, foreign keys, relations, hierarchies,
        cardinality groups and column privileges are per column in Postgres, so they refuse one."""
        def field(table: str, c) -> bool:
            t = self.spec.tables.get(table)
            return (t is not None and isinstance(c, str) and c in t.columns
                    and t.columns[c].field_parts(c) is not None)

        fix = "use a column of the table (or leave the rule to the composite column's own constraints)"

        def refuse(path: str, table: str, c: str, what: str) -> None:
            self.err(path, f"'{c}' is a field of a composite column, and {what} needs a column", fix)

        for tname, t in self.spec.tables.items():
            for i, c in enumerate(t.primary_key or []):
                if field(tname, c):
                    refuse(f"$.tables.{tname}.primary_key[{i}]", tname, c, "a primary key")
            for i, u in enumerate(t.unique):
                for j, c in enumerate(u):
                    if field(tname, c):
                        refuse(f"$.tables.{tname}.unique[{i}][{j}]", tname, c, "a unique constraint")
        from mls.spec.chain import read_columns
        for rname, rel in self.spec.relations.items():
            try:
                reads = read_columns(self.spec, rname)
            except (KeyError, IndexError, AttributeError):
                continue  # an unknown table or relation: reported where it is named
            for table, cols in reads:
                for c in sorted(cols):
                    if field(table, c):
                        refuse(f"$.relations.{rname}", table, c, "a relation")
        for hname, h in self.spec.hierarchies.items():
            for fld in ("id", "parent", "depth"):
                if field(h.table, getattr(h, fld)):
                    refuse(f"$.hierarchies.{hname}.{fld}", h.table, getattr(h, fld), "a hierarchy")
        for i, r in enumerate(self.spec.rules):
            path = self.rule_paths[i]
            if isinstance(r, InclusionRule):
                for j, c in enumerate(r.columns):
                    if field(r.table, c):
                        refuse(f"{path}.columns[{j}]", r.table, c, "an inclusion rule (a foreign key)")
            elif isinstance(r, CardinalityRule) and field(r.table, r.group):
                refuse(path + ".group", r.table, r.group, "a cardinality rule's group")
            elif isinstance(r, ColumnRule):
                for j, c in enumerate(r.columns):
                    if field(r.table, c):
                        self.err(f"{path}.columns[{j}]", f"'{c}' is a field of a composite column, and "
                                 f"privileges are granted per column, never per field",
                                 "leave the field out: a role with a column rule on the table then neither "
                                 "reads nor writes its composite column")

    def check_enums(self) -> None:
        """An enum is a Postgres enum type the database already has (D59): its name is a catalog
        name, its labels non-empty and distinct, in the type's order."""
        for name, labels in self.spec.enums.items():
            path = f"$.enums.{name}"
            if not CATALOG_IDENT.match(name):
                self.err(path, f"'{name}' is not a valid enum type identifier", CATALOG_IDENT_FIX)
            if not labels:
                self.err(path, "an enum needs at least one label", "list the type's labels in order")
            for i, label in enumerate(labels):
                if not label:
                    self.err(f"{path}[{i}]", "empty label", "list the type's labels as the database has them")
                elif labels.index(label) != i:
                    self.err(f"{path}[{i}]", f"duplicate label '{label}'", "list each label once")

    def check_default(self, tname: str, t, cname: str, col, path: str) -> None:
        """#76: a default the insert lower bounds count on: of the column's type, on an adopted table."""
        d, path = col.default, path + ".default"
        if d is None:
            return
        if t.mode != "adopted":
            self.err(path, f"table '{tname}' is {t.mode}: only an adopted table's columns declare defaults "
                           f"(the database's own, which the proofs count on)", "remove the default")
            return
        if d == "fresh":
            if col.type not in ("uuid", "int", "bigint", "text"):
                self.err(path, f"a {col.type} column has no generated value", "declare the constant or context "
                         "value the database writes, or no default")
            return
        if isinstance(d, CtxRef):
            ty = self.spec.context_type(d.ctx)
            if ty is None:
                self.err(path, f"unknown context value '{d.ctx}'", f"one of: {', '.join(self.spec.identity.context)}")
            elif not comparable(ty, col.type) and ty != col.type:
                self.err(path, f"context value '{d.ctx}' is {ty}, the column {col.type}",
                         "use a default of the column's type")
            return
        v = d.const
        want = {"bool": bool, "int": int, "bigint": int}.get(col.type, str)
        if not isinstance(v, want) or (want is int and isinstance(v, bool)):
            self.err(path, f"default {v!r} is not a {col.type} value", "use a constant of the column's type")
        elif col.type == "enum" and v not in self.spec.enums.get(col.enum or "", []):
            self.err(path, f"'{v}' is not a label of the column's enum type", "use one of its labels")
        else:
            self.const_ok_for(d, col.type, path)

    def check_enum_column(self, tname: str, t, cname: str, col, path: str) -> None:
        if col.type == "citext" and t.mode == "owned":
            self.err(path + ".type", f"table '{tname}' is owned, and MLS creates its tables without citext columns",
                     "declare it text, or adopt the table if the database already has it")
        if col.type == "text[]" and t.mode == "owned":
            self.err(path + ".type", f"table '{tname}' is owned, and MLS creates its tables without array columns",
                     "adopt the table if the database already has it")
        if col.type not in ("enum", "enum[]"):
            if col.enum is not None:
                self.err(path + ".enum", f"column '{cname}' is {col.type}, not enum", "remove 'enum'")
            return
        if col.enum is None or col.enum not in self.spec.enums:
            self.err(path + ".enum", f"column '{cname}' needs a declared enum type"
                     + (f" ('{col.enum}' is not declared)" if col.enum else ""),
                     f"declare it under enums, or use one of: {', '.join(self.spec.enums) or '(none declared)'}")
        if t.mode == "owned" and col.type == "enum[]":
            self.err(path + ".type", f"table '{tname}' is owned, and MLS creates its tables without array columns",
                     "adopt the table if the database already has it")
        elif t.mode == "owned":
            self.err(path + ".type", f"table '{tname}' is owned, and MLS creates its tables without enum types",
                     f"declare '{cname}' text with a check rule  {cname} in ('A', 'B', ...);  "
                     f"or adopt the table if the database already has it")

    def check_assumptions(self, tname: str, t, path: str) -> None:
        """`assume` (D45) states the hardening the compiler cannot establish on an adopted table.
        An owned table has none (its hardening is emitted and verified); an observed table is not
        governed; and there is no assumption under which a table without row level security
        means anything (that table is observed)."""
        if t.assume and t.mode == "owned":
            self.err(f"{path}.assume", f"table '{tname}' is owned: the compiler emits its hardening and drift "
                                       f"verifies it, so nothing is assumed (an owned table whose owner "
                                       f"would be an app role is refused, not assumed)",
                     "set mode to \"adopted\" to keep the assumptions, or remove them")
            return
        if t.assume and t.mode == "observed":
            self.err(f"{path}.assume", f"table '{tname}' is observed and not governed; nothing is assumed about it",
                     "set mode to \"adopted\", or remove the assumptions")
            return
        seen: set[tuple[str, str]] = set()
        for i, a in enumerate(t.assume):
            apath = f"{path}.assume[{i}]"
            if isinstance(a, OwnerAssumed):
                key = ("owner", a.owner)
                if a.owner not in self.spec.roles:
                    self.err(f"{apath}.owner", f"'{a.owner}' is not an app role of this spec; only an app-role "
                                               f"owner needs an assumption (any other owner is a trusted role already)",
                             f"one of: {', '.join(self.spec.roles)}; or remove the assumption")
            elif isinstance(a, BypassAssumed):
                key = ("bypassrls", a.bypassrls)
                if a.bypassrls not in self.spec.roles:
                    self.err(f"{apath}.bypassrls", f"'{a.bypassrls}' is not an app role of this spec",
                             f"one of: {', '.join(self.spec.roles)}; or remove the assumption")
            elif isinstance(a, RlsAssumed):
                key = ("rls", a.rls)
                if a.rls != "not_forced":
                    self.err(f"{apath}.rls", f"'{a.rls}' is not an assumption the proofs can state: a policy on a "
                                             f"table without row level security enabled means nothing, so an "
                                             f"adopted table without it is observed",
                             "use \"not_forced\" (the owner bypasses the policies and is trusted), or set "
                             "mode to \"observed\" until row level security is enabled outside MLS")
            elif isinstance(a, PathAssumed):
                key = ("bypass", " ".join(a.bypass.split()))
                if not BYPASS_PATH.fullmatch(a.bypass.strip()):
                    self.err(f"{apath}.bypass", f"'{a.bypass}' is not a bypass path: one is 'view <name>' or "
                                                f"'function <name>(<argument types>)', as mls drift reports it",
                             "copy the path from the drift or import report, e.g. \"view project_overview\" or "
                             "\"function is_team_member(bigint)\"")
            elif isinstance(a, InlinedAssumed):
                key = ("inlined", " ".join(a.inlined.split()))
                if not INLINED.fullmatch(a.inlined.strip()):
                    self.err(f"{apath}.inlined", f"'{a.inlined}' is not an inlined helper: one is "
                                                 f"'function <name>(<argument types>) md5 <32 hex digits>'",
                             "copy it from mls import's output, e.g. \"function is_member(uuid) md5 "
                             "0cc175b9c0f1b6a831c399e269772661\"")
            elif isinstance(a, DelegateAssumed):
                text = " ".join(a.delegate.split())
                key = ("delegate", text.split(" as ")[0])
                m = DELEGATION.fullmatch(text)
                if not m:
                    self.err(f"{apath}.delegate", f"'{a.delegate}' is not a delegation: one is 'view <name> as "
                                                  f"<owner> to <role>, <role>' (or 'to public'), as mls drift reports it",
                             "copy it from the drift or import report, e.g. \"view api.todos as api to anonymous, "
                             "webuser\"")
                elif m["owner"] not in self.spec.roles:
                    self.err(f"{apath}.delegate", f"'{m['owner']}' is not an app role of this spec: a view delegates "
                                                  f"to its owner only when the policies bind the owner, and the "
                                                  f"policies name only app roles",
                             f"one of: {', '.join(self.spec.roles)}; or remove the assumption")
            else:
                self.err(apath, "unknown assumption")
                continue
            if key in seen:
                self.err(apath, "duplicate assumption", "remove it")
            seen.add(key)

    def key_sets(self, table: str) -> list[frozenset[str]]:
        t = self.spec.tables[table]
        out = []
        if t.primary_key:
            out.append(frozenset(t.primary_key))
        out.extend(frozenset(u) for u in t.unique)
        return out

    def base_resolves(self, name: str) -> bool:
        """The relation's base relation exists (a composed relation's `of` may not)."""
        rel = self.spec.relations.get(name)
        return isinstance(rel, Relation) or (isinstance(rel, ComposedRelation)
                                             and isinstance(self.spec.relations.get(rel.of), Relation))

    def relation_ends(self, name: str) -> tuple[tuple[str, str], tuple[str, str]] | None:
        """((table, key column), (table, value column)) of a relation, or None when it does not
        resolve (its own errors are reported by check_relations)."""
        rel = self.spec.relations.get(name)
        if isinstance(rel, Relation):
            return (rel.table, rel.key), (rel.table, rel.value)
        if isinstance(rel, ComposedRelation):
            base = self.spec.relations.get(rel.of)
            if isinstance(base, Relation):
                last = rel.through[-1]
                return (base.table, base.key), (last.table, last.value)
        return None

    def check_composed(self, rname: str, rel: ComposedRelation, path: str) -> None:
        """D56: the base relation is a base relation; at most MAX_HOPS hops; each hop's pair is
        unique in its table (its value a key, a lookup; its key, up a foreign key, #43; or the pair
        itself, a membership table, #33) and its columns NOT NULL, its key of the type of the
        previous level's value."""
        base = self.spec.relations.get(rel.of)
        if base is None:
            self.err(path + ".of", f"unknown relation '{rel.of}'",
                     f"one of: {', '.join(n for n, r in self.spec.relations.items() if isinstance(r, Relation))}")
            return
        if isinstance(base, ComposedRelation):
            self.err(path + ".of", f"'{rel.of}' is itself composed; compose from a base relation",
                     f"set of to '{base.of}' and list all the hops in through")
            return
        if len(rel.through) > MAX_HOPS:
            self.err(path + ".through", f"{len(rel.through)} hops; a composed relation has at most "
                                        f"{MAX_HOPS} (the compiled nesting and the solver's unrolling "
                                        f"are bounded)",
                     "denormalize a column onto a nearer table, with an inclusion rule")
        prev = (base.table, base.value)
        for i, h in enumerate(rel.through):
            hp = f"{path}.through[{i}]"
            t = self.spec.tables.get(h.table)
            if t is None:
                self.err(hp + ".table", f"unknown table '{h.table}'", f"one of: {', '.join(self.spec.tables)}")
                return
            if not self.governed(h.table, hp + ".table", "a relation"):
                return
            ok = True
            for fld in ("key", "value"):
                c = getattr(h, fld)
                if c not in t.columns:
                    self.err(f"{hp}.{fld}", f"unknown column '{c}' of table '{h.table}'")
                    ok = False
                elif t.columns[c].nullable:
                    self.err(f"{hp}.{fld}", f"hop column '{h.table}.{c}' must be NOT NULL (a NULL "
                                            f"breaks the chain the compiled subquery follows)",
                             "set nullable to false")
            if not ok:
                return
            if h.key == h.value:
                self.err(hp, "key and value must be different columns")
            if not pair_unique(self.key_sets(h.table), h.key, h.value):
                self.err(f"{hp}.value", f"no primary key or unique constraint of '{h.table}' lies within "
                                        f"({h.key}, {h.value}), so a pair may occur in many rows (a hop goes "
                                        f"down to the rows a value names, up a foreign key to the row it "
                                        f"refers to, or through a membership table whose key is the pair)",
                         f"make '{h.value}', '{h.key}' or the pair ({h.key}, {h.value}) the primary key or "
                         f"unique")
            pt, kt = self.col_type(*prev), t.columns[h.key].type
            if pt is not None and not comparable(pt, kt):
                self.err(f"{hp}.key", f"type of {h.table}.{h.key} ({kt}) does not match the previous "
                                      f"level's value {prev[0]}.{prev[1]} ({pt})")
            prev = (h.table, h.value)

    def check_relations(self) -> None:
        for rname, rel in self.spec.relations.items():
            path = f"$.relations.{rname}"
            if not IDENT.match(rname):
                self.err(path, f"'{rname}' is not a valid relation identifier")
            if isinstance(rel, ComposedRelation):
                self.check_composed(rname, rel, path)
                continue
            if rel.table not in self.spec.tables:
                self.err(path + ".table", f"unknown table '{rel.table}'",
                         f"one of: {', '.join(self.spec.tables)}")
                continue
            if not self.governed(rel.table, path + ".table", "a relation"):
                continue
            ok = True
            for fld in ("key", "value"):
                c = getattr(rel, fld)
                if c is None:  # #63: a set relation has no key
                    continue
                if c not in self.spec.tables[rel.table].columns:
                    self.err(f"{path}.{fld}", f"unknown column '{c}' of table '{rel.table}'")
                    ok = False
                # #49: a nullable key or value is allowed; a row with NULL in either is no pair
            if not ok:
                continue
            if rel.key is None:
                # #63: a set of values, each one row's: the row axiom `value ∈ R ⇔ T(where(row))` is
                # exact only when no two rows share the value
                if frozenset((rel.value,)) not in self.key_sets(rel.table):
                    self.err(f"{path}.value", f"'{rel.value}' is not a key of '{rel.table}' on its own: a "
                                              f"relation without a key is a set of values, each of them "
                                              f"one row's",
                             f"name the primary key of '{rel.table}' or a single-column unique column, or "
                             f"give the relation a key column")
            elif rel.key == rel.value:
                self.err(path, "key and value must be different columns")
            elif not pair_unique(self.key_sets(rel.table), rel.key, rel.value):
                self.err(path, f"({rel.key}, {rel.value}) is not unique in '{rel.table}': a relation is "
                               f"a set of pairs, so the pair, or one of its columns, must be a primary key "
                               f"or unique constraint of the table",
                         f"add [\"{rel.key}\", \"{rel.value}\"] to tables.{rel.table}.unique, or make "
                         f"'{rel.value}' the table's primary key")
            if rel.where is not None:
                self.pred(rel.where, relation_scope(rel.table), path + ".where")

    def check_hierarchies(self) -> None:
        for hname, h in self.spec.hierarchies.items():
            path = f"$.hierarchies.{hname}"
            if not IDENT.match(hname):
                self.err(path, f"'{hname}' is not a valid identifier")
            t = self.spec.tables.get(h.table)
            if t is None:
                self.err(path + ".table", f"unknown table '{h.table}'", f"one of: {', '.join(self.spec.tables)}")
                continue
            if not self.governed(h.table, path + ".table", "a hierarchy"):
                continue
            ok = True
            for fld in ("id", "parent", "depth"):
                if getattr(h, fld) not in t.columns:
                    self.err(f"{path}.{fld}", f"unknown column '{getattr(h, fld)}' of table '{h.table}'")
                    ok = False
            if not ok:
                continue
            if len({h.id, h.parent, h.depth}) != 3:
                self.err(path, "id, parent and depth must be three different columns")
            if t.primary_key != [h.id]:
                self.err(f"{path}.id", f"'{h.id}' must be the single-column primary key of '{h.table}' "
                                       f"(parents reference it)", f"set tables.{h.table}.primary_key to [\"{h.id}\"]")
            if not t.columns[h.parent].nullable:
                self.err(f"{path}.parent", f"'{h.parent}' must be nullable (roots have no parent)",
                         "set nullable to true")
            if t.columns[h.parent].type != t.columns[h.id].type:
                self.err(f"{path}.parent", f"'{h.parent}' ({t.columns[h.parent].type}) must have the "
                                           f"type of '{h.id}' ({t.columns[h.id].type})")
            if t.columns[h.depth].type != "int" or t.columns[h.depth].nullable:
                self.err(f"{path}.depth", f"'{h.depth}' must be an int NOT NULL column (the compiler "
                                          f"maintains it)", "declare {\"type\": \"int\", \"nullable\": false}")
            rel = self.spec.relations.get(h.members)
            if rel is None:
                self.err(f"{path}.members", f"unknown relation '{h.members}'",
                         f"one of: {', '.join(self.spec.relations) or 'none'}")
            elif isinstance(rel, ComposedRelation):
                self.err(f"{path}.members", f"'{h.members}' is a composed relation; a hierarchy's members "
                                            f"are one table's (key, value)",
                         f"use a base relation, e.g. '{rel.of}'")
            elif rel.key is None:
                self.err(f"{path}.members", f"'{h.members}' has no key; a hierarchy's members are pairs "
                                            f"of a key and a group", "use a relation with a key column")
            elif rel.where is not None:
                self.err(f"{path}.members", f"'{h.members}' has a condition; a hierarchy's members are "
                                            f"one table's every (key, value)",
                         f"use a relation without a condition, or keep the condition's rows in a "
                         f"membership table of their own")
            elif rel.table in self.spec.tables and self.col_type(rel.table, rel.value) is not None \
                    and self.col_type(rel.table, rel.value) != t.columns[h.id].type:
                self.err(f"{path}.members", f"the value of relation '{h.members}' ({rel.table}.{rel.value}: "
                                            f"{self.col_type(rel.table, rel.value)}) must have the type of "
                                            f"'{h.id}' ({t.columns[h.id].type})")

    def check_opaques(self) -> None:
        for oname, o in self.spec.opaques.items():
            path = f"$.opaques.{oname}"
            if not IDENT.match(oname):
                self.err(path, f"'{oname}' is not a valid identifier")
            if o.table not in self.spec.tables:
                self.err(path + ".table", f"unknown table '{o.table}'")
                continue
            if not self.governed(o.table, path + ".table", "an opaque block"):
                continue
            for i, c in enumerate(o.columns):
                if c not in self.spec.tables[o.table].columns:
                    self.err(f"{path}.columns[{i}]", f"unknown column '{c}' of table '{o.table}'")
            for i, c in enumerate(o.context):
                if self.spec.context_type(c) is None:
                    self.err(f"{path}.context[{i}]", f"unknown context value '{c}'")
            for i, r in enumerate(o.relations):
                if r not in self.spec.relations:
                    self.err(f"{path}.relations[{i}]", f"unknown relation '{r}'")
                elif isinstance(self.spec.relations[r], ComposedRelation):
                    self.err(f"{path}.relations[{i}]", f"'{r}' is a composed relation; list the base "
                                                       f"relation an opaque block reads",
                             f"use '{self.spec.relations[r].of}'")
            if not o.sql.strip():
                self.err(path + ".sql", "empty SQL")

    def check_rules(self) -> None:
        ids: set[str] = set()
        names: set[tuple[str, str]] = set()
        colrules: set[tuple[str, str, str]] = set()
        for i, r in enumerate(self.spec.rules):
            path = self.rule_paths[i]
            if r.id in ids:
                self.err(path + ".id", f"duplicate rule id '{r.id}'" + (" (an expansion of a selector rule)"
                                                                        if r.from_ is not None else ""))
            ids.add(r.id)
            if r.name is not None and not IDENT.match(r.name):
                self.err(path + ".name", f"'{r.name}' is not a valid identifier")
            if r.table not in self.spec.tables:
                self.err(path + ".table", f"unknown table '{r.table}'",
                         f"one of: {', '.join(self.spec.tables)}")
                continue
            if not self.governed(r.table, path + ".table", "a rule"):
                continue
            if r.kind != "column_rule":
                if (r.table, r.name) in names:
                    self.err(path + ".name", f"duplicate rule name '{r.name}' on table '{r.table}'")
                names.add((r.table, r.name))
            if isinstance(r, PolicyRule):
                self.check_policy(r, path)
            elif isinstance(r, CheckRule):
                self.pred(r.predicate, check_scope(r.table), path + ".predicate")
            elif isinstance(r, InclusionRule):
                self.check_inclusion(r, path)
            elif isinstance(r, TransitionRule):
                self.pred(r.predicate, transition_scope(r.table), path + ".predicate")
            elif isinstance(r, CardinalityRule):
                self.check_cardinality(r, path)
            elif isinstance(r, ColumnRule):
                if r.role not in self.spec.roles:
                    self.err(path + ".role", f"unknown role '{r.role}'", f"one of: {', '.join(self.spec.roles)}")
                for j, c in enumerate(r.columns):
                    if c not in self.spec.tables[r.table].columns:
                        self.err(f"{path}.columns[{j}]", f"unknown column '{c}' of table '{r.table}'")
                if r.when is not None:
                    if r.access != "write":
                        self.err(path + ".when", "only a write column rule takes a condition",
                                 "remove 'when', or make the rule access write")
                    if r.name is None:
                        self.err(path, "a column rule with a condition needs a name (it names its trigger)",
                                 "add a name")
                    self.pred(r.when, guard_scope(r.table), path + ".when")
                    continue
                k = (r.role, r.table, r.access)
                if k in colrules:
                    self.err(path, f"a second {r.access} column rule for role '{r.role}' on "
                                   f"'{r.table}'", "merge the column lists into one rule")
                colrules.add(k)

    def check_policy(self, r: PolicyRule, path: str) -> None:
        if r.role not in self.spec.roles:
            self.err(path + ".role", f"unknown role '{r.role}'", f"one of: {', '.join(self.spec.roles)}")
        cmd = r.command
        if cmd in ("select", "delete"):
            if r.using is None:
                self.err(path, f"a {cmd} policy needs 'using'")
            if r.check is not None:
                self.err(path + ".check", f"a {cmd} policy has no 'check' (no new row)", "remove it")
        elif cmd == "insert":
            if r.check is None:
                self.err(path, "an insert policy needs 'check'")
            if r.using is not None:
                self.err(path + ".using", "an insert policy has no 'using' (no existing row)", "remove it")
        else:  # update, all
            if r.using is None:
                self.err(path, f"an {cmd} policy needs 'using' ('check' defaults to 'using' "
                               f"when omitted, as in Postgres)")
        scope = policy_scope(r.table)
        if r.using is not None:
            self.pred(r.using, scope, path + ".using")
        if r.check is not None:
            self.pred(r.check, scope, path + ".check")

    def check_cardinality(self, r: CardinalityRule, path: str) -> None:
        t = self.spec.tables[r.table]
        if r.max is None and r.min is None:
            self.err(path, "a cardinality rule needs a max, a min or both",
                     "add \"max\": N (at most N rows per group) or \"min\": N (no transaction leaves a "
                     "group it lowered below N)")
        elif r.max is not None and r.min is not None and r.min > r.max:
            self.err(path + ".min", f"min {r.min} is above max {r.max}", "make min at most max")
        if r.where is not None:  # #61: which rows count, read of the row alone
            self.pred(r.where, Scope("cardinality condition", r.table, cols=True), path + ".where")
        if r.group not in t.columns:
            self.err(path + ".group", f"unknown column '{r.group}' of table '{r.table}'")
            return
        parent = self.spec.tables.get(r.parent)
        if parent is None:
            self.err(path + ".parent", f"unknown table '{r.parent}'",
                     "the parent table whose row is locked while counting")
            return
        if r.parent == r.table:
            self.err(path + ".parent", "the parent table must be a different table")
            return
        if not self.governed(r.parent, path + ".parent", "a cardinality rule's parent"):
            return
        if not parent.primary_key or len(parent.primary_key) != 1:
            self.err(path + ".parent", f"'{r.parent}' needs a single-column primary key that '{r.group}' "
                                       f"references")
            return
        pk = parent.primary_key[0]
        if not comparable(parent.columns[pk].type, t.columns[r.group].type):
            self.err(path + ".group", f"type of {r.table}.{r.group} ({t.columns[r.group].type}) does not "
                                      f"match {r.parent}.{pk} ({parent.columns[pk].type})")

    def check_inclusion(self, r: InclusionRule, path: str) -> None:
        rel = self.spec.relations.get(r.relation)
        if rel is None:
            self.err(path + ".relation", f"unknown relation '{r.relation}'",
                     f"one of: {', '.join(self.spec.relations)}")
            return
        if isinstance(rel, ComposedRelation):
            self.err(path + ".relation", f"'{r.relation}' is a composed relation; an inclusion rule is a "
                                         f"foreign key, which references one table's (key, value)",
                     f"name a base relation, e.g. '{rel.of}'")
            return
        if rel.key is None:
            self.err(path + ".relation", f"'{r.relation}' has no key; an inclusion rule is a foreign key "
                                         f"onto a pair of columns",
                     f"name a relation with a key on '{rel.table}', or a foreign key the schema keeps")
            return
        if rel.where is not None:
            # #54 (D86): not a foreign key, which references every row of its table, but constraint
            # triggers checked when the transaction commits; a referenced row whose condition stops
            # holding is refused, never followed
            if r.on_delete != "restrict":
                self.err(path + ".on_delete", f"'{r.relation}' has a condition, so inclusion '{r.name}' is checked "
                                              f"by triggers, not a foreign key, and a delete or an update that takes "
                                              f"a pair out of '{r.relation}' can only be refused",
                         "use on_delete restrict, or name a relation without a condition")
            if not r.deferred:
                self.err(path + ".deferred", f"'{r.relation}' has a condition, so inclusion '{r.name}' is checked "
                                             f"by triggers when the transaction commits",
                         "mark it deferred (`on_delete restrict deferred`; in JSON \"deferred\": true)")
            if rel.table in self.spec.tables and self.spec.tables[rel.table].mode == "observed":
                self.err(path + ".relation", f"'{r.relation}' has a condition, so inclusion '{r.name}' needs a "
                                             f"trigger on '{rel.table}', and MLS changes nothing on an observed table",
                         f"adopt '{rel.table}' (mode adopted), or name a relation without a condition")
        t = self.spec.tables[r.table]
        ok = True
        for j, c in enumerate(r.columns):
            if c not in t.columns:
                self.err(f"{path}.columns[{j}]", f"unknown column '{c}' of table '{r.table}'")
                ok = False
        if not ok or rel.table not in self.spec.tables:
            return
        if r.columns[0] == r.columns[1]:
            self.err(path + ".columns", "the two columns must differ")
        if rel.key in self.spec.tables[rel.table].columns and rel.value in self.spec.tables[rel.table].columns \
                and frozenset((rel.key, rel.value)) not in self.key_sets(rel.table) \
                and not (pair_unique(self.key_sets(rel.table), rel.key, rel.value)
                         and self.spec.tables[rel.table].mode != "observed"):
            # D60: a foreign key references exactly a key; #59: the compiler adds one itself when a
            # key of the table lies within the pair, so only a pair that is not unique is refused
            self.err(path + ".relation", f"relation '{r.relation}' is ({rel.key}, {rel.value}) of "
                                         f"'{rel.table}', and an inclusion rule is a foreign key, which "
                                         f"references a unique pair; no primary key or unique constraint "
                                         f"of '{rel.table}' lies within ({rel.key}, {rel.value})"
                                         + (" (and MLS adds no key to an observed table)"
                                            if self.spec.tables[rel.table].mode == "observed" else ""),
                     f"add [\"{rel.key}\", \"{rel.value}\"] to tables.{rel.table}.unique, or use a relation "
                     f"whose key or value is a key of '{rel.table}'")
        if r.on_delete == "set_null" and r.columns[0] in t.columns and not t.columns[r.columns[0]].nullable:
            self.err(path + ".on_delete", f"on_delete set_null sets {r.table}.{r.columns[0]} NULL, and it is "
                                          f"NOT NULL",
                     f"make {r.columns[0]} nullable, or use on_delete restrict or cascade")
        if r.on_delete != "restrict":
            # #60 (D79): the proofs see a cascade only as rows of r.table that are gone; nothing
            # else may read those rows, or a delete would change it unmodelled
            uses = ([f"relation '{n}' reads it" for n, b in self.spec.base_relations().items() if b.table == r.table]
                    + [f"hierarchy '{n}' is on it" for n, h in self.spec.hierarchies.items() if h.table == r.table]
                    + [f"cardinality rule '{c.name}' counts it" for c in self.spec.cardinalities()
                       if r.table in (c.table, c.parent)])
            if uses:
                what = "deletes" if r.on_delete == "cascade" else "updates"
                self.err(path + ".on_delete", f"on_delete {r.on_delete} {what} rows of '{r.table}' along with the "
                                              f"referenced row, and {'; '.join(uses)}, so the delete would change "
                                              f"it without the proofs seeing it",
                         "use on_delete restrict (the referencing rows are deleted first), or state the "
                         "rule on a table nothing else reads")
        for j, (c, rc) in enumerate(zip(r.columns, (rel.key, rel.value))):
            ct, rt = self.col_type(r.table, c), self.col_type(rel.table, rc)
            if ct is not None and rt is not None and not comparable(ct, rt):
                self.err(f"{path}.columns[{j}]", f"type of {r.table}.{c} ({ct}) does not match "
                                                 f"{rel.table}.{rc} ({rt})")

    def check_properties(self) -> None:
        ids: set[str] = set()
        for i, p in enumerate(self.spec.properties):
            path = f"$.properties[{i}]"
            if p.id in ids:
                self.err(path + ".id", f"duplicate property id '{p.id}'")
            ids.add(p.id)
            if isinstance(p, (TenantIsolation, ColumnImmutable, WriteSubsetRead, AlwaysOnUpdate, ChangesOnly, Custom,
                              MustAllow, RoleSeparation)):
                if p.table not in self.spec.tables:
                    self.err(path + ".table", f"unknown table '{p.table}'")
                    continue
                if not self.governed(p.table, path + ".table", "a property"):
                    continue
            if isinstance(p, TenantIsolation):
                if p.column not in self.spec.tables[p.table].columns:
                    self.err(path + ".column", f"unknown column '{p.column}'")
                if p.relation not in self.spec.relations:
                    self.err(path + ".relation", f"unknown relation '{p.relation}'")
                elif self.base_resolves(p.relation) and is_set(self.spec, p.relation):
                    self.err(path + ".relation", f"'{p.relation}' has no key; tenant isolation is per key",
                             "name a relation with a key column")
                self.term_type(p.key, policy_scope(p.table), path + ".key")
                if not isinstance(p.key, (CtxRef, Const)):
                    self.err(path + ".key", "the key must be a context value", "use {\"ctx\": name}")
            elif isinstance(p, ColumnImmutable):
                if p.column not in self.spec.tables[p.table].columns:
                    self.err(path + ".column", f"unknown column '{p.column}'")
            elif isinstance(p, MonotoneIn):
                if p.relation not in self.spec.relations:
                    self.err(path + ".relation", f"unknown relation '{p.relation}'")
                elif isinstance(self.spec.relations[p.relation], ComposedRelation):
                    self.err(path + ".relation", f"'{p.relation}' is a composed relation; monotone_in is "
                                                 f"about one table's facts",
                             f"state it for the base relation '{self.spec.relations[p.relation].of}'")
            elif isinstance(p, LeastPrivilege):
                # D63: the allowance is the whole grant set, every role at once; a second one could
                # only be refuted by the first one's roles
                first = next(j for j, q in enumerate(self.spec.properties) if isinstance(q, LeastPrivilege))
                if first != i:
                    self.err(path, f"a second least_privilege property: '{self.spec.properties[first].id}' "
                                   f"already declares the allowance, and a role it does not list is allowed "
                                   f"nothing, so each would be refuted by the other's roles",
                             f"merge the two allowances into '{self.spec.properties[first].id}' and remove '{p.id}'")
                for role, tabs in p.allowed.items():
                    if role not in self.spec.roles:
                        self.err(f"{path}.allowed.{role}", f"unknown role '{role}'")
                    self.service_role(role, f"{path}.allowed.{role}", "least_privilege")
                    for t in tabs:
                        if t not in self.spec.tables:
                            self.err(f"{path}.allowed.{role}.{t}", f"unknown table '{t}'")
                        else:
                            self.governed(t, f"{path}.allowed.{role}.{t}", "a property")
            elif isinstance(p, InvariantPreserved):
                for j, inv in enumerate(p.invariants):
                    ipath = f"{path}.invariants[{j}]"
                    if inv.rule is not None:
                        try:
                            rule = self.spec.rule(inv.rule)
                        except KeyError:
                            self.err(ipath + ".rule", f"unknown rule '{inv.rule}'")
                            continue
                        if not isinstance(rule, (CheckRule, InclusionRule, CardinalityRule)):
                            self.err(ipath + ".rule", f"rule '{inv.rule}' is a {rule.kind}; only "
                                                      f"check, inclusion and cardinality rules are invariants")
                        elif isinstance(rule, InclusionRule) and isinstance(self.spec.relations.get(rule.relation),
                                                                            Relation) \
                                and self.spec.relations[rule.relation].where is not None:
                            # #54: an invariant cannot read a relation with a condition (an update of
                            # its table can take a pair out without changing the pair's columns)
                            self.err(ipath + ".rule", f"inclusion '{inv.rule}' is into '{rule.relation}', which has "
                                                      f"a condition; an invariant cannot read one, and the "
                                                      f"inclusion holds only when a transaction commits",
                                     "leave it out of the invariants (the compiler enforces it)")
                        elif isinstance(rule, CardinalityRule) and rule.max is None:
                            # #61: a new parent may start with fewer than `min`, so it is no invariant
                            self.err(ipath + ".rule", f"cardinality rule '{inv.rule}' sets only a minimum, "
                                                      f"which is no invariant: a new '{rule.parent}' row may "
                                                      f"start with fewer than {rule.min} rows; it only keeps "
                                                      f"a transaction from lowering a count below it",
                                     "leave it out of the invariants (the compiler enforces it)")
                    else:
                        if inv.table not in self.spec.tables:
                            self.err(ipath + ".table", f"unknown table '{inv.table}'")
                            continue
                        if not self.governed(inv.table, ipath + ".table", "an invariant"):
                            continue
                        self.pred(inv.predicate, invariant_scope(inv.table), ipath + ".predicate")
            elif isinstance(p, AlwaysOnUpdate):
                self.pred(p.predicate, Scope("always_on_update property", p.table, old_new=True), path + ".predicate")
            elif isinstance(p, ChangesOnly):
                if p.role not in self.spec.roles:
                    self.err(path + ".role", f"unknown role '{p.role}'")
                self.service_role(p.role, path + ".role", "changes_only")
                cols = self.spec.tables[p.table].columns
                for j, c in enumerate(p.columns):
                    if c not in cols:
                        self.err(f"{path}.columns[{j}]", f"unknown column '{c}' of table '{p.table}'",
                                 f"one of: {', '.join(cols)}")
                if p.when is not None:  # the condition a column guard would carry (#56)
                    self.pred(p.when, guard_scope(p.table), path + ".when")
            elif isinstance(p, Custom):
                if p.role not in self.spec.roles:
                    self.err(path + ".role", f"unknown role '{p.role}'")
                self.service_role(p.role, path + ".role", "custom")
                self.pred(p.goal, goal_scope(p.table), path + ".goal")
            elif isinstance(p, MustAllow):
                if p.role not in self.spec.roles:
                    self.err(path + ".role", f"unknown role '{p.role}'")
                self.pred(p.when, must_allow_scope(p.table, p.command), path + ".when")
            elif isinstance(p, RoleSeparation):
                for j, role in enumerate(p.roles):
                    if role not in self.spec.roles:
                        self.err(f"{path}.roles[{j}]", f"unknown role '{role}'")
                    self.service_role(role, f"{path}.roles[{j}]", "role_separation")

    def service_role(self, role: str, path: str, template: str) -> None:
        """#68: no upper bound holds for a platform service role (it can act as a trusted role)."""
        from mls.identity import get_adapter

        if role in self.spec.roles and role in get_adapter(self.spec).service_roles:
            self.err(path, f"'{role}' is a platform service role: it can act as a trusted role, so a "
                           f"{template} property cannot bound what it reaches",
                     f"state what it must be able to do with must_allow, and leave it out of {template}")


def fk_cycle_errors(spec: Spec, database: list) -> list[MlsError]:
    """#35, with the database read: the cycles the catalog's own foreign keys close with the
    spec's inclusions (`database` is `fkcycle.database_fks`); the spec's own are check_spec's."""
    from mls.spec.fkcycle import cycles, spec_fks

    own = {frozenset((f.table, f.name) for f in [inc, *path]) for inc, path in cycles(spec_fks(spec))}
    c = Checker(spec)
    for inc, path in cycles(spec_fks(spec) + database):
        if frozenset((f.table, f.name) for f in [inc, *path]) not in own:
            from mls.spec.fkcycle import cycle_message

            i = next(j for j, r in enumerate(spec.rules) if r.id == inc.rule_id)
            c.err(c.rule_paths[i], *cycle_message(inc, path))
    return c.sink.errors


# confdeltype letters (pg_constraint) and the delete actions that, beside an inclusion's on the
# same referencing rows, make the outcome of a delete depend on which key's trigger fires first
FK_ACTIONS = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}
_CLASHES = {"restrict": {"c", "n", "d"}, "cascade": {"r", "n", "d"}, "set_null": {"r", "c", "d"}}


def fk_action_errors(spec: Spec, rows: list[dict]) -> list[MlsError]:
    """#60, with the database read (`catalog.all_foreign_keys`): an inclusion and one of the
    table's own foreign keys, on columns among the inclusion's and onto the same parent table,
    with delete actions that clash.  A delete of a parent row then fires both keys' triggers, and
    whether it is refused or cascades depends on their order, which the proofs cannot know."""
    c = Checker(spec)
    own = {(r.table, r.name) for r in spec.inclusions()}
    for i, r in enumerate(spec.rules):
        if not isinstance(r, InclusionRule) or r.relation not in spec.relations:
            continue
        if getattr(spec.relations[r.relation], "where", None) is not None:
            continue  # #54: its triggers run at commit, after any action of the table's own keys
        parent = spec.relations[r.relation].table
        for fk in rows:
            if (fk["table"], fk["name"]) in own or fk["table"] != r.table or fk["parent"] != parent \
                    or not set(fk["columns"]) <= set(r.columns) or fk["on_delete"] not in _CLASHES[r.on_delete]:
                continue
            action = FK_ACTIONS[fk["on_delete"]]
            c.err(c.rule_paths[i] + ".on_delete",
                  f"inclusion '{r.name}' is ON DELETE {r.on_delete.upper().replace('_', ' ')}, and the table's own foreign key "
                  f"'{fk['name']}' on ({', '.join(fk['columns'])}) is ON DELETE {action} onto the same table "
                  f"'{parent}': a delete of a '{parent}' row fires both, and whether it is refused or deletes "
                  f"the rows of '{r.table}' depends on which fires first",
                  ("use on_delete cascade to keep the existing key's behaviour" if fk["on_delete"] == "c" else
                   "use on_delete restrict" if fk["on_delete"] == "r" else
                   "use on_delete set_null to keep the existing key's behaviour" if fk["on_delete"] == "n" else
                   f"change '{fk['name']}' to ON DELETE RESTRICT or CASCADE")
                  + f", or drop '{fk['name']}'")
    return c.sink.errors


def guard_order_errors(spec: Spec, rows: list[dict]) -> list[MlsError]:
    """#58, with the database read (`catalog.before_update_triggers`): a BEFORE UPDATE row trigger
    of a guarded table's own that Postgres fires before the guard (byte order of the names).  If
    it rewrites a column outside the guard's list, the guard sees it changed and refuses an edit
    the caller made within the list."""
    from mls.compile.guard import guard_trigger_name

    c = Checker(spec)
    own = {guard_trigger_name(g) for g in spec.column_guards()}
    for i, r in enumerate(spec.rules):
        if r not in spec.column_guards():
            continue
        name = guard_trigger_name(r)
        for tg in rows:
            if tg["table"] == r.table and tg["name"] not in own and tg["name"].encode() < name.encode():
                c.err(c.rule_paths[i], f"column rule '{r.name}' is checked by trigger '{name}' on '{r.table}', "
                                       f"and the table's own trigger '{tg['name']}' fires before it (Postgres "
                                       f"fires a table's BEFORE triggers in name order): if it changes a column "
                                       f"outside the rule's list, every edit by '{r.role}' it applies to is refused",
                      f"rename '{tg['name']}' so that it sorts after '{name}' (a name starting with a letter or "
                      f"'_' does), or drop it")
    return c.sink.errors


def check_spec(spec: Spec) -> Spec:
    """Expand the selectors (spec/selectors.py, D48), typecheck and fragment-check `spec`, then
    return it with its sugar expanded (spec/expand.py).  Every consumer must use the returned
    spec: it is the one with concrete rules and no `in`."""
    from mls.spec.expand import expand_spec
    from mls.spec.selectors import expand_selectors

    spec, errors, paths = expand_selectors(spec)
    errors += Checker(spec, paths).run()
    if errors:
        raise SpecError(errors)
    return expand_spec(spec)
