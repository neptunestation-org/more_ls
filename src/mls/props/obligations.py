"""Property templates (D9) and custom properties as proof obligations (SEMANTICS §7).

Every obligation is "assumptions ∧ ¬goal is UNSAT".  Assumptions always include the engine
constraints that hold on stored rows (CHECKs and FKs are validated), the policies of the role under
examination, and the transition triggers for UPDATE.  Policies are never assumed in invariant
preservation: trusted roles (owner, superuser) bypass them, so invariants must follow from
CHECKs, FKs and triggers alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from mls.compile.column import privileges
from mls.logic.term import (
    FALSE, TRUE, Sort, Term, Var, and_, eq, forall, fun, iff, implies, int_var, le, not_, or_,
)
from mls.logic.tvl import SET_KEY, Encoder, col_null_var, col_value_var, ctx_var, hop_exists_fun, hop_key_fun, rel_fun, up_fun
from mls.spec.chain import base_name, condition, hop_prefix, levels, up_name
from mls.spec.recursion import is_routed
from mls.props.effective import (
    effective, inclusion_pred, members_in, relations_of, row_constraints, transition_constraints,
)
from mls.spec.model import (
    AlwaysOnUpdate, And, CardinalityRule, ChangesOnly, CheckRule, Cmp, ColRef, ColumnImmutable, ComposedRelation, Custom, InclusionRule,
    InvariantPreserved, IsNull, LeastPrivilege, Lit, Member, MemberBody, MonotoneIn, MustAllow, NewRef,
    Not, OldRef, Or, PolicyRule, Pred, Property, RoleSeparation, Spec, TenantIsolation, WriteSubsetRead,
)
from mls.logic.term import IntVal, add


@dataclass
class Obligation:
    property_id: str
    name: str
    assumptions: list[Term]
    goal: Term
    rows: dict[str, str]                               # row name -> table
    relations: list[tuple[str, str | None]] = field(default_factory=list)  # (relation, tag)
    encoders: list[Encoder] = field(default_factory=list)
    note: str = ""
    # for soundness obligations raised as compile errors
    path: str = ""
    failure_message: str = ""
    fix: str = ""
    # propositional obligations carry their verdict
    propositional: bool = False
    verdict: str | None = None
    message: str = ""
    # a witness obligation holds when its assumptions are *satisfiable*; the model is an example
    witness: bool = False

    def opaque_deps(self) -> set[str]:
        out: set[str] = set()
        for e in self.encoders:
            out |= e.opaque_deps
        return out

    def finish(self) -> "Obligation":
        for e in self.encoders:
            self.assumptions = (self.assumptions + e.side_conditions + up_row_axioms(e, self.rows)
                                + hop_row_axioms(e, self.rows) + relation_row_axioms(e, self.rows))
        self.assumptions = self.assumptions + enum_row_axioms(self.encoders, self.rows)
        return self


def enum_row_axioms(encs: list[Encoder], rows: dict[str, str]) -> list[Term]:
    """An enum column (D59) holds NULL or one of its type's labels: Postgres refuses any other
    value.  The labels are interned like any text constant, so they are distinct from each other
    and from every other constant.  Under several encoders (the diff's old and new spec) the
    domain is the union of their labels, and a column is only constrained when every encoder's
    spec declares it enum: the axiom never hides a row one of the specs can meet."""
    if not encs:
        return []
    out: list[Term] = []
    for row, table in rows.items():
        cols = [enc.spec.tables.get(table) for enc in encs]
        if any(t is None for t in cols):
            continue
        for c in cols[0].columns:
            decl = [t.columns.get(c) for t in cols]
            if not all(d is not None and d.type == "enum" for d in decl):
                continue
            labels = sorted({x for enc, d in zip(encs, decl) for x in enc.spec.enums[d.enum]})
            ids = [encs[0].const_id(x) for x in labels]
            assert all(enc.const_id(x) == i for enc in encs for x, i in zip(labels, ids)), \
                "encoders of one obligation must share their constants"
            v, null = col_value_var(row, c), col_null_var(row, c)
            dom = or_(*[eq(v, IntVal(i)) for i in ids])
            out.append(or_(null, dom) if any(d.nullable for d in decl) else dom)
    return out


def relation_row_axioms(enc: Encoder, rows: dict[str, str]) -> list[Term]:
    """A stored row of a relation's table is one of its facts: `rel(row.key, row.value)` (the
    relation is the table's (key, value) projection).  A row with NULL in a nullable key or value
    column is no fact (#49: the subquery's `key = k` never matches it, and a NULL value matches
    nothing), so for those columns the fact is `⇔ ¬null(key) ∧ ¬null(value)`.  With a condition
    (D61) the row is a fact exactly when the condition is TRUE for it: `rel(row.key, row.value) ⇔
    T(cond(row))`, exact because the table holds the pair at most once.  As for the hops,
    `new` is excluded (not yet stored), and so is a relation the obligation reads in a tagged
    state copy (the diff's `@new`, the invariant step's before/after), whose facts other axioms
    relate to the rows."""
    out: list[Term] = []
    for name in sorted(enc.rels_used):
        rel = enc.spec.relations.get(name)
        if rel is None or isinstance(rel, ComposedRelation) or name in enc.rel_tags:
            continue
        for row, rt in rows.items():
            if rt == rel.table and row != "new":
                # #63: a set relation's facts all have the one key SET_KEY
                key = SET_KEY if rel.key is None else col_value_var(row, rel.key)
                fact = rel_fun(name)(key, col_value_var(row, rel.value))
                cols = enc.spec.tables[rel.table].columns
                held = [not_(col_null_var(row, c)) for c in (rel.key, rel.value)
                        if c is not None and cols[c].nullable]
                if rel.where is not None:
                    held.append(enc.T(rel.where, row, rel.table))
                out.append(iff(fact, and_(*held)) if held else fact)
                # #51: a unique value (or key) names this one row, so every fact with it is this
                # row's (a riders row whose user_id is NULL is nobody's, not someone else's)
                single = {next(iter(k)) for k in _key_sets(enc.spec, rel.table) if len(k) == 1}
                for mine, other in ((rel.value, rel.key), (rel.key, rel.value)):
                    if mine not in single or other is None:  # a set's value is its own fact
                        continue
                    o = int_var(f"ax.{name}.{row}.{other}")
                    pair = (o, col_value_var(row, mine)) if mine == rel.value else (col_value_var(row, mine), o)
                    set_ = [not_(col_null_var(row, mine))] if cols[mine].nullable else []
                    out.append(forall([o], implies(and_(*set_, rel_fun(name)(*pair)),
                                                   and_(eq(o, col_value_var(row, other)), *held))))
    return out


def _key_sets(spec: Spec, table: str) -> list[frozenset[str]]:
    t = spec.tables[table]
    return [frozenset(k) for k in ([t.primary_key] if t.primary_key else []) + list(t.unique)]


def hop_row_axioms(enc: Encoder, rows: dict[str, str]) -> list[Term]:
    """A stored row of a hop table (D56) is what the hop's lookups read: its value exists and maps
    to its key.  `new` is excluded: a written image is not in the snapshot the policy's subquery
    reads (an UPDATE's new image may change the key the subquery still sees as the old one)."""
    out: list[Term] = []
    for table, key, value in sorted(enc.hops_used):
        for row, rt in rows.items():
            if rt == table and row != "new":
                v = col_value_var(row, value)
                out.append(and_(hop_exists_fun(table, value)(v),
                                eq(hop_key_fun(table, key, value)(v), col_value_var(row, key))))
    return out


def up_row_axioms(enc: Encoder, rows: dict[str, str]) -> list[Term]:
    """#43: a stored row x of an upward hop's table puts its value in the chain for every key that
    reaches its key: ∀k: prefix(k, x.key) → up(k, x.value).  One way only (a value of the chain
    needs some row behind it, an existential the encoding leaves out), so the chain is an
    over-approximation: sound, and a scenario may hold a pair no row produces.  `new` is excluded
    as in `hop_row_axioms`.  The prefix may read further hops and chains, whose axioms are added in
    turn (runs before `hop_row_axioms`, which reads what this adds)."""
    out: list[Term] = []
    done: set[tuple[str, int, str]] = set()
    todo = True
    while todo:
        todo = False
        for relation, i in sorted(enc.ups_used):
            h = levels(enc.spec, relation)[i]
            for row, rt in sorted(rows.items()):
                if rt != h.table or row == "new" or (relation, i, row) in done:
                    continue
                done.add((relation, i, row))
                todo = True
                k = int_var(f"up.k#{len(done)}")
                before = enc.chain_fact(hop_prefix(enc.spec, relation, i), k, col_value_var(row, h.key))
                tag = enc.rel_tags.get(base_name(enc.spec, relation))
                out.append(forall([k], implies(before, up_fun(up_name(enc.spec, relation, i), tag)(k, col_value_var(row, h.value)))))
    return out


def _rels_in(spec: Spec, p: Pred | None) -> set[str]:
    return relations_of(spec, p)


def _T(enc: Encoder, p: Pred, row: str, table: str) -> Term:
    return enc.T(p, row, table)


def relation_axioms(spec: Spec, enc: Encoder) -> list[Term]:
    """Enforced inclusions between relation tables, as EPR axioms: an inclusion rule on the table
    backing relation A whose columns are exactly (A.key, A.value) and whose target is relation B
    gives ∀x,y: A(x,y) → B(x,y).  (FKs are validated, so stored facts satisfy them.)"""
    out = []
    x, y = int_var("ax.k"), int_var("ax.v")
    for inc in spec.inclusions():
        if inc.deferred:
            continue  # #35: it holds only at commit, not while a policy runs
        for aname, a in spec.base_relations().items():
            if a.table == inc.table and list(inc.columns) == [a.key, a.value]:
                out.append(forall([x, y], implies(enc.rel(aname)(x, y), enc.rel(inc.relation)(x, y))))
    return out + subset_axioms(spec, enc)


def subset_axioms(spec: Spec, enc: Encoder) -> list[Term]:
    """A filtered relation lies within its unfiltered twin (#37): when A has a condition and B has
    none, both over the same table, key and value, every fact of A comes from a row that is also
    a fact of B, so ∀x,y: A(x,y) → B(x,y).  So does one whose condition implies B's on every row
    (#51: the owners among the admins, `role = 'owner'` within `role in ('owner', 'admin')`),
    which the solver decides once per pair of conditions.  Composed relations over them follow
    through the shared hop functions."""
    out = []
    x, y = int_var("ax.k"), int_var("ax.v")
    base = spec.base_relations()
    for aname, a in base.items():
        for bname, b in base.items():
            if aname == bname or a.where is None or (a.table, a.key, a.value) != (b.table, b.key, b.value):
                continue
            if b.where is None or _implies_on_rows(spec, a.table, a.where, b.where):
                out.append(forall([x, y], implies(enc.rel(aname)(x, y), enc.rel(bname)(x, y))))
    return out


_implied_cache: dict[tuple[int, str, str, str], tuple[Spec, bool]] = {}


def _implies_on_rows(spec: Spec, table: str, a: Pred, b: Pred) -> bool:
    """T(a(row)) → T(b(row)) for every row of the table (its stored-row constraints assumed)."""
    from mls.logic.solve import solve

    k = (id(spec), table, a.model_dump_json(by_alias=True), b.model_dump_json(by_alias=True))
    hit = _implied_cache.get(k)
    if hit is not None and hit[0] is spec:
        return hit[1]
    enc = Encoder(spec)
    res = solve([enc.T(row_constraints(spec, table), "x", table), enc.T(a, "x", table), *enc.side_conditions],
                enc.T(b, "x", table), 10000)
    ok = res.status != "unknown" and res.proved
    _implied_cache[k] = (spec, ok)
    return ok


def select_assumptions(enc: Encoder, spec: Spec, table: str, role: str, row: str = "r") -> list[Term]:
    return [*relation_axioms(spec, enc), _T(enc, row_constraints(spec, table), row, table),
            _T(enc, effective(spec, table, role, "select", "using"), row, table)]


def insert_assumptions(enc: Encoder, spec: Spec, table: str, role: str, row: str = "new") -> list[Term]:
    return [*relation_axioms(spec, enc), _T(enc, effective(spec, table, role, "insert", "check"), row, table),
            _T(enc, row_constraints(spec, table), row, table)]


def update_assumptions(enc: Encoder, spec: Spec, table: str, role: str) -> list[Term]:
    return [*relation_axioms(spec, enc), _T(enc, row_constraints(spec, table), "old", table),
            _T(enc, effective(spec, table, role, "update", "using"), "old", table),
            _T(enc, effective(spec, table, role, "update", "check"), "new", table),
            _T(enc, row_constraints(spec, table), "new", table),
            _T(enc, transition_constraints(spec, table), "new", table),
            _T(enc, unwritable_unchanged(spec, table, role), "new", table),
            *guard_terms(spec, table, role, enc)[1]]


def delete_assumptions(enc: Encoder, spec: Spec, table: str, role: str, row: str = "old") -> list[Term]:
    return [*relation_axioms(spec, enc), _T(enc, row_constraints(spec, table), row, table),
            _T(enc, effective(spec, table, role, "delete", "using"), row, table)]


def unwritable_unchanged(spec: Spec, table: str, role: str) -> Pred:
    """Column privileges as a transition predicate: an update by `role` leaves every column it
    may not write unchanged (NULL-safe), so a column rule and a transition rule that pin the same
    column are the same behaviour."""
    allowed = privileges(spec).get((role, table), {}).get("update")
    if allowed is None or allowed == "*":
        return Lit(lit=True)
    return unchanged_except(spec, table, set(allowed))


def guard_columns(spec: Spec, table: str) -> set[str]:
    """The columns a column guard never compares: a hierarchy's depth, which its own trigger
    recomputes from the parent before the guard runs (#50)."""
    return {h.depth for h in spec.hierarchies.values() if h.table == table}


def guard_terms(spec: Spec, table: str, role: str, enc: Encoder) -> tuple[list[Pred], list[Term]]:
    """The column guards of `role` on `table` (#50): when the condition is TRUE of the row being
    edited, every other column keeps its value.  An UNKNOWN condition limits nothing (the trigger
    tests `(when) is true`), which is why this is a term and not a transition predicate.  Returns
    the predicates (for the diff's comparison) and the terms."""
    preds: list[Pred] = []
    terms: list[Term] = []
    for g in spec.column_guards():
        if g.table != table or g.role != role:
            continue
        same = unchanged_except(spec, table, set(g.columns) | guard_columns(spec, table))
        preds += [g.when, same]
        terms.append(implies(enc.T(g.when, "old", table), enc.T(same, "new", table)))
    return preds, terms


def unchanged_except(spec: Spec, table: str, allowed: set[str]) -> Pred:
    """Every column of `table` outside `allowed` keeps its value (NULL-safe)."""
    parts: list[Pred] = []
    for c in spec.tables[table].columns:
        if c in allowed:
            continue
        same: Pred = Cmp(cmp=(NewRef(new=c), "=", OldRef(old=c)))
        if spec.tables[table].columns[c].nullable:
            same = Or.model_construct(or_=[
                And.model_construct(and_=[IsNull(is_null=OldRef(old=c)), IsNull(is_null=NewRef(new=c))]), same])
        parts.append(same)
    return And.model_construct(and_=parts) if len(parts) > 1 else (parts[0] if parts else Lit(lit=True))


def net_terms(spec: Spec, table: str, role: str, cmd: str, enc: Encoder) -> tuple[list[Pred], Term]:
    """What `role` can do with `cmd` on `table`, all layers together: the policies, and for a
    write the stored-row constraints on the written image, the transition rules and the column
    privileges.  The one meaning of "admitted" shared by the behaviour diff and must_allow."""
    if cmd == "select":
        parts = [(effective(spec, table, role, "select", "using"), "r")]
    elif cmd == "delete":
        parts = [(effective(spec, table, role, "delete", "using"), "old")]
    elif cmd == "insert":
        parts = [(effective(spec, table, role, "insert", "check"), "new"), (row_constraints(spec, table), "new")]
    else:
        parts = [(effective(spec, table, role, "update", "using"), "old"),
                 (effective(spec, table, role, "update", "check"), "new"),
                 (row_constraints(spec, table), "new"), (transition_constraints(spec, table), "new"),
                 (unwritable_unchanged(spec, table, role), "new")]
        gp, gt = guard_terms(spec, table, role, enc)
        return [q for q, _ in parts] + gp, and_(*[enc.T(q, img, table) for q, img in parts], *gt)
    return [q for q, _ in parts], and_(*[enc.T(q, img, table) for q, img in parts])


def _rows_for(cmd: str, table: str) -> dict[str, str]:
    if cmd == "select":
        return {"r": table}
    if cmd == "insert":
        return {"new": table}
    if cmd == "update":
        return {"old": table, "new": table}
    return {"old": table}


def _image(cmd: str, which: str = "new") -> str:
    return {"select": "r", "insert": "new", "delete": "old"}.get(cmd, which)


def _relations_of(spec: Spec, *preds: Pred | None, tag: str | None = None) -> list[tuple[str, str | None]]:
    rels: set[str] = set()
    for p in preds:
        rels |= _rels_in(spec, p)
    return [(r, tag) for r in sorted(rels)]


def _all_relations(spec: Spec, table: str, role: str, cmd: str) -> list[tuple[str, str | None]]:
    preds = [effective(spec, table, role, cmd, "using"), effective(spec, table, role, cmd, "check"),
             row_constraints(spec, table)]
    if cmd == "update":
        preds += [g.when for g in spec.column_guards() if g.table == table and g.role == role]
    return _relations_of(spec, *preds)


# ----------------------------------------------------------------------------- templates
def tenant_isolation(spec: Spec, p: TenantIsolation) -> list[Obligation]:
    out = []
    goal_pred = Member(member=MemberBody(relation=p.relation, key=p.key, value=ColRef(col=p.column)))
    for role in spec.roles:
        for cmd in p.commands:
            enc = Encoder(spec)
            if cmd == "select":
                assumptions = select_assumptions(enc, spec, p.table, role)
            elif cmd == "insert":
                assumptions = insert_assumptions(enc, spec, p.table, role)
            elif cmd == "update":
                assumptions = update_assumptions(enc, spec, p.table, role)
            else:
                assumptions = delete_assumptions(enc, spec, p.table, role)
            img = _image(cmd)
            goal = _T(enc, goal_pred, img, p.table)
            out.append(Obligation(
                p.id, f"{cmd} as {role}: {img}.{p.column} ∈ {p.relation}[key]",
                assumptions, goal, _rows_for(cmd, p.table),
                _all_relations(spec, p.table, role, cmd) + [(p.relation, None)], [enc]).finish())
    return out


def column_immutable(spec: Spec, p: ColumnImmutable) -> list[Obligation]:
    out = []
    nullable = spec.tables[p.table].columns[p.column].nullable
    for role in spec.roles:
        enc = Encoder(spec)
        assumptions = update_assumptions(enc, spec, p.table, role)
        ov, nv = col_value_var("old", p.column), col_value_var("new", p.column)
        if nullable:
            on, nn = col_null_var("old", p.column), col_null_var("new", p.column)
            goal = or_(and_(on, nn), and_(not_(on), not_(nn), eq(ov, nv)))
        else:
            goal = eq(ov, nv)
        out.append(Obligation(
            p.id, f"update as {role}: new.{p.column} = old.{p.column}",
            assumptions, goal, _rows_for("update", p.table),
            _all_relations(spec, p.table, role, "update"), [enc]).finish())
    return out


def always_on_update(spec: Spec, p: AlwaysOnUpdate) -> list[Obligation]:
    """Every update by any writer keeps `p.predicate` (#40).  The trusted roles bypass the
    policies and hold every column privilege, so only what binds them too is assumed: the
    stored-row constraints on both images (CHECKs, foreign keys) and the transition triggers."""
    enc = Encoder(spec)
    rc = row_constraints(spec, p.table)
    assumptions = [*relation_axioms(spec, enc), _T(enc, rc, "old", p.table), _T(enc, rc, "new", p.table),
                   _T(enc, transition_constraints(spec, p.table), "new", p.table)]
    return [Obligation(
        p.id, f"update on {p.table} by any writer: the change satisfies the condition",
        assumptions, _T(enc, p.predicate, "new", p.table), _rows_for("update", p.table),
        _relations_of(spec, rc), [enc]).finish()]


def changes_only(spec: Spec, p: ChangesOnly) -> list[Obligation]:
    """#56: an update by `p.role` of a row `p.when` is TRUE of (old image) changes only `p.columns`,
    from everything that binds the role's update: its policies, the constraints and transitions,
    the column privileges and the column guards.  A hierarchy's depth, which its own trigger
    recomputes, counts as listed, as for a guard."""
    enc = Encoder(spec)
    assumptions = update_assumptions(enc, spec, p.table, p.role)
    if p.when is not None:
        assumptions.append(_T(enc, p.when, "old", p.table))
    same = unchanged_except(spec, p.table, set(p.columns) | guard_columns(spec, p.table))
    return [Obligation(
        p.id, f"update on {p.table} by {p.role}: only {', '.join(p.columns)} change",
        assumptions, _T(enc, same, "new", p.table), _rows_for("update", p.table),
        list(dict.fromkeys(_all_relations(spec, p.table, p.role, "update") + _relations_of(spec, p.when))),
        [enc]).finish()]


def monotone_in(spec: Spec, p: MonotoneIn) -> list[Obligation]:
    """Shrinking the relation never grants: effective_small(r) → effective_big(r)."""
    out = []
    u, t = int_var("mono.k"), int_var("mono.v")
    big, small = rel_fun(p.relation, "big"), rel_fun(p.relation, "small")
    shrink = forall([u, t], implies(small(u, t), big(u, t)))
    for table in spec.tables:
        for role in spec.roles:
            for cmd, which in (("select", "using"), ("insert", "check"), ("update", "using"),
                               ("update", "check"), ("delete", "using")):
                pred = effective(spec, table, role, cmd, which)
                if isinstance(pred, Lit) or p.relation not in _rels_in(spec, pred):
                    continue
                consts: dict[str, int] = {}  # one interning for both state copies
                e_big = Encoder(spec, {p.relation: "big"}, consts=consts)
                e_small = Encoder(spec, {p.relation: "small"}, consts=consts)
                row = _image(cmd, "old" if which == "using" else "new")
                goal = implies(_T(e_small, pred, row, table), _T(e_big, pred, row, table))
                # #43: a chain up a foreign key from this relation is its own symbol per copy; the
                # real chains grow with the base relation (the hop tables are the same in both)
                ups = []
                for rel_name, i in sorted(e_small.ups_used | e_big.ups_used):
                    if base_name(spec, rel_name) == p.relation:
                        name = up_name(spec, rel_name, i)
                        ups.append(forall([u, t], implies(up_fun(name, "small")(u, t), up_fun(name, "big")(u, t))))
                out.append(Obligation(
                    p.id, f"{cmd} {which} on {table} as {role}: admitted with fewer "
                          f"{p.relation} facts ⇒ admitted with more",
                    [shrink, *ups, *relation_axioms(spec, e_big), *relation_axioms(spec, e_small)], goal, {row: table},
                    [(p.relation, "small"), (p.relation, "big")] + _relations_of(spec, pred),
                    [e_big, e_small]).finish())
    return out


def write_subset_read(spec: Spec, p: WriteSubsetRead) -> list[Obligation]:
    out = []
    for role in spec.roles:
        sel = effective(spec, p.table, role, "select", "using")
        enc = Encoder(spec)
        out.append(Obligation(
            p.id, f"insert as {role}: insertable ⇒ visible",
            insert_assumptions(enc, spec, p.table, role), _T(enc, sel, "new", p.table),
            _rows_for("insert", p.table), _all_relations(spec, p.table, role, "insert") +
            _relations_of(spec, sel), [enc]).finish())
        enc = Encoder(spec)
        out.append(Obligation(
            p.id, f"update as {role}: new image ⇒ visible",
            update_assumptions(enc, spec, p.table, role), _T(enc, sel, "new", p.table),
            _rows_for("update", p.table), _all_relations(spec, p.table, role, "update") +
            _relations_of(spec, sel), [enc]).finish())
    return out


def least_privilege(spec: Spec, p: LeastPrivilege) -> list[Obligation]:
    extra = []
    for (role, table), g in sorted(privileges(spec).items()):
        allowed = set(p.allowed.get(role, {}).get(table, []))
        for cmd, cols in g.items():
            if cmd not in allowed:
                what = "all columns" if cols == "*" else f"columns {sorted(cols)}"
                extra.append(f"{role} may {cmd} {what} of {table}")
    verdict = "PROVED" if not extra else "REFUTED"
    msg = "granted privileges are within the declared allowance" if not extra else \
        "privileges beyond the declared allowance: " + "; ".join(extra)
    return [Obligation(p.id, "derived grants ⊆ declared", [], TRUE, {}, propositional=True,
                       verdict=verdict, message=msg)]


def custom(spec: Spec, p: Custom) -> list[Obligation]:
    enc = Encoder(spec)
    if p.command == "select":
        assumptions = select_assumptions(enc, spec, p.table, p.role)
    elif p.command == "insert":
        assumptions = insert_assumptions(enc, spec, p.table, p.role)
    elif p.command == "update":
        assumptions = update_assumptions(enc, spec, p.table, p.role)
    else:
        assumptions = delete_assumptions(enc, spec, p.table, p.role)
    img = _image(p.command, p.which)
    goal = _T(enc, p.goal, img, p.table)
    return [Obligation(p.id, f"{p.command} as {p.role}: goal holds for {img}",
                       assumptions, goal, _rows_for(p.command, p.table),
                       _all_relations(spec, p.table, p.role, p.command) + _relations_of(spec, p.goal),
                       [enc]).finish()]


def role_separation(spec: Spec, p: RoleSeparation) -> list[Obligation]:
    """No row admitted to both roles (D49): constraints ∧ policies(a) ∧ policies(b) is UNSAT,
    with the same context values for both.  A model is a row (and user) both roles may touch."""
    enc = Encoder(spec)
    a, b = p.roles
    rows = _rows_for(p.command, p.table)
    assumptions: list[Term] = [*relation_axioms(spec, enc)]
    for row in rows:
        assumptions.append(_T(enc, row_constraints(spec, p.table), row, p.table))
    if p.command == "update":
        assumptions.append(_T(enc, transition_constraints(spec, p.table), "new", p.table))
    sides = {"select": [("using", "r")], "delete": [("using", "old")], "insert": [("check", "new")],
             "update": [("using", "old"), ("check", "new")]}[p.command]
    preds = []
    for role in (a, b):
        for which, img in sides:
            e = effective(spec, p.table, role, p.command, which)
            preds.append(e)
            assumptions.append(_T(enc, e, img, p.table))
    rels = _relations_of(spec, *preds, row_constraints(spec, p.table))
    return [Obligation(p.id, f"{p.command}: no row is admitted to both {a} and {b}",
                       assumptions, FALSE, dict(rows), rels, [enc]).finish()]


def access_terms(spec: Spec, table: str, role: str, cmd: str, enc: Encoder) -> Term:
    """The access layers of `cmd` as `role`: the effective policies and, for an update, the
    transition rules and the column privileges — `net_terms` without the stored-row constraints
    on the written image (D40: a lower bound assumes the written row is valid)."""
    if cmd == "select":
        parts = [(effective(spec, table, role, "select", "using"), "r")]
    elif cmd == "delete":
        parts = [(effective(spec, table, role, "delete", "using"), "old")]
    elif cmd == "insert":
        parts = [(effective(spec, table, role, "insert", "check"), "new")]
    else:
        parts = [(effective(spec, table, role, "update", "using"), "old"),
                 (effective(spec, table, role, "update", "check"), "new"),
                 (transition_constraints(spec, table), "new"),
                 (unwritable_unchanged(spec, table, role), "new")]
        return and_(*[enc.T(q, img, table) for q, img in parts], *guard_terms(spec, table, role, enc)[1])
    return and_(*[enc.T(q, img, table) for q, img in parts])


def must_allow(spec: Spec, p: MustAllow) -> list[Obligation]:
    """Lower bound (D40): constraints(every image) ∧ when → admitted by the access layers
    (policies, transitions, column privileges).  The written image is assumed valid — it satisfies
    the table's CHECKs and FKs — so the condition states what the role can do, not the integrity
    rules.  Plus a witness obligation: the assumptions are satisfiable (a condition no valid row
    meets would make the property vacuous; an over-restrictive CHECK shows up here)."""
    enc = Encoder(spec)
    admitted = access_terms(spec, p.table, p.role, p.command, enc)
    rows = _rows_for(p.command, p.table)
    assumptions: list[Term] = [*relation_axioms(spec, enc)]
    for row in rows:
        assumptions.append(_T(enc, row_constraints(spec, p.table), row, p.table))
    assumptions.append(_T(enc, p.when, _image(p.command, "new"), p.table))
    rels = _all_relations(spec, p.table, p.role, p.command) + _relations_of(spec, p.when)
    witness = Obligation(p.id, f"{p.command} as {p.role}: some row meets the condition",
                         list(assumptions), FALSE, dict(rows), rels, [enc], witness=True).finish()
    main = Obligation(p.id, f"{p.command} as {p.role}: every row meeting the condition is admitted",
                      assumptions, admitted, dict(rows), rels, [enc]).finish()
    return [witness, main]


# ----------------------------------------------------------------------------- induction
@dataclass
class Invariant:
    label: str
    table: str
    pred: Pred


def _invariants(spec: Spec, p: InvariantPreserved) -> list[Invariant]:
    out = []
    for inv in p.invariants:
        if inv.rule is not None:
            r = spec.rule(inv.rule)
            if isinstance(r, CheckRule):
                out.append(Invariant(f"{r.id} ({r.name})", r.table, r.predicate))
            elif isinstance(r, InclusionRule):
                out.append(Invariant(f"{r.id} ({r.name})", r.table, inclusion_pred(spec, r)))
        else:
            out.append(Invariant(f"{inv.table}: custom", inv.table, inv.predicate))
    return out


def cardinality_obligations(spec: Spec, p: InvariantPreserved, r: CardinalityRule) -> list[Obligation]:
    """cnt: group -> int.  Invariant ∀g. cnt(g) ≤ N.  Transitions on the table change one or two
    counts; the compiled trigger guards inserts and group moves with cnt(g) + 1 ≤ N (D4).  #61: a
    row counts when its group is set and `where` is TRUE of it; a minimum is no invariant (a new
    parent may start below it), so only the maximum is proved."""
    if r.max is None:
        return []
    N = IntVal(r.max)
    cnt, cnt2 = fun(f"cnt.{r.id}@before", Sort.INT, ret=Sort.INT), fun(f"cnt.{r.id}@after", Sort.INT, ret=Sort.INT)
    x = int_var("card.g")
    inv_before = forall([x], le(cnt(x), N))
    inv_after = forall([x], le(cnt2(x), N))
    nullable = spec.tables[r.table].columns[r.group].nullable
    out = []
    for cmd in ("insert", "update", "delete"):
        enc = Encoder(spec)
        rows = _rows_for(cmd, r.table)
        axioms: list[Term] = [inv_before]
        ng, og = col_value_var("new", r.group), col_value_var("old", r.group)
        nn = col_null_var("new", r.group) if nullable else FALSE
        on = col_null_var("old", r.group) if nullable else FALSE
        cn = and_(not_(nn), enc.T(r.where, "new", r.table)) if r.where is not None else not_(nn)  # new counted
        co = and_(not_(on), enc.T(r.where, "old", r.table)) if r.where is not None else not_(on)  # old counted
        if cmd == "insert":
            # counted iff the group is set (and the condition TRUE); the trigger requires cnt(g) + 1 ≤ N
            axioms.append(implies(cn, le(add(cnt(ng), IntVal(1)), N)))
            axioms.append(forall([x], iff(eq(cnt2(x), add(cnt(x), IntVal(1))), and_(cn, eq(x, ng)))))
            axioms.append(forall([x], implies(not_(and_(cn, eq(x, ng))), eq(cnt2(x), cnt(x)))))
        elif cmd == "delete":
            axioms.append(forall([x], implies(and_(co, eq(x, og)), eq(cnt2(x), add(cnt(x), IntVal(-1))))))
            axioms.append(forall([x], implies(not_(and_(co, eq(x, og))), eq(cnt2(x), cnt(x)))))
        else:
            stays = and_(co, cn, eq(og, ng))   # counted before and after in the same group
            joins = and_(cn, not_(stays))      # the new group gains one (the trigger checks it)
            leaves = and_(co, not_(stays))     # the old group loses one
            axioms.append(implies(joins, le(add(cnt(ng), IntVal(1)), N)))
            axioms.append(forall([x], implies(and_(leaves, eq(x, og), not_(and_(joins, eq(x, ng)))),
                                              eq(cnt2(x), add(cnt(x), IntVal(-1))))))
            axioms.append(forall([x], implies(and_(joins, eq(x, ng), not_(and_(leaves, eq(x, og)))),
                                              eq(cnt2(x), add(cnt(x), IntVal(1))))))
            axioms.append(forall([x], implies(not_(or_(and_(leaves, eq(x, og)), and_(joins, eq(x, ng)))),
                                              eq(cnt2(x), cnt(x)))))
            axioms.append(forall([x], implies(and_(leaves, eq(x, og), joins, eq(x, ng)), eq(cnt2(x), cnt(x)))))
        out.append(Obligation(p.id, f"{cmd} on {r.table} preserves {r.id} ({r.name}): at most {r.max} "
                                    f"rows per {r.group}", axioms, inv_after, rows,
                              _relations_of(spec, r.where), [enc]).finish())
    return out


def invariant_preserved(spec: Spec, p: InvariantPreserved) -> list[Obligation]:
    out = []
    for inv in p.invariants:
        if inv.rule is not None and isinstance(spec.rule(inv.rule), CardinalityRule):
            out.extend(cardinality_obligations(spec, p, spec.rule(inv.rule)))
    invs = _invariants(spec, p)
    if not invs:
        return out
    tables: set[str] = {i.table for i in invs}
    for i in invs:
        for r in _rels_in(spec, i.pred):
            tables.add(spec.relations[r].table)
    # transitions: INSERT / UPDATE / DELETE on every table the invariants mention
    for t in sorted(tables):
        # a relation with a condition (D61) is never read by an invariant (the checker refuses
        # it), and the change axioms below would be wrong for it: an insert adds its pair only
        # when the condition holds
        backed = {name for name, rel in spec.base_relations().items()
                  if rel.table == t and rel.where is None and rel.key is not None}  # #63: nor a set
        for cmd in ("insert", "update", "delete"):
            out.extend(_induction_step(spec, p, invs, t, cmd, backed))
    return out


def _relation_change(spec: Spec, table: str, cmd: str, backed: set[str]) -> list[Term]:
    """Axioms relating rel@before and rel@after for relations backed by `table`."""
    axioms = []
    x, y = int_var("chg.k"), int_var("chg.v")
    for rname in sorted(backed):
        rel = spec.relations[rname]
        before, after = rel_fun(rname, "before"), rel_fun(rname, "after")
        if cmd == "insert":
            nk, nv = col_value_var("new", rel.key), col_value_var("new", rel.value)
            axioms.append(forall([x, y], iff(after(x, y), or_(before(x, y), and_(eq(x, nk), eq(y, nv))))))
        elif cmd == "delete":
            ok, ov = col_value_var("old", rel.key), col_value_var("old", rel.value)
            axioms.append(before(ok, ov))
            axioms.append(forall([x, y], iff(after(x, y), and_(before(x, y), not_(and_(eq(x, ok), eq(y, ov)))))))
        else:
            ok, ov = col_value_var("old", rel.key), col_value_var("old", rel.value)
            nk, nv = col_value_var("new", rel.key), col_value_var("new", rel.value)
            axioms.append(before(ok, ov))
            axioms.append(forall([x, y], iff(after(x, y), or_(
                and_(before(x, y), not_(and_(eq(x, ok), eq(y, ov)))), and_(eq(x, nk), eq(y, nv))))))
    return axioms


def _references(spec: Spec, inc: InclusionRule, row: str, parent_row: str) -> Term:
    """Row `row` of the inclusion's table refers to row `parent_row` of its relation's table (MATCH
    SIMPLE: a NULL in either column refers to nothing)."""
    rel = spec.relations[inc.relation]
    refs = []
    for c, pc in zip(inc.columns, (rel.key, rel.value)):
        refs.append(eq(col_value_var(row, c), col_value_var(parent_row, pc)))
        if spec.tables[inc.table].columns[c].nullable:
            refs.append(not_(col_null_var(row, c)))
        if spec.tables[rel.table].columns[pc].nullable:
            refs.append(not_(col_null_var(parent_row, pc)))
    return and_(*refs)


def _nulled(spec: Spec, inc: InclusionRule, src: str, dst: str) -> list[Term]:
    """#62: row `dst` is row `src` of the inclusion's table with its first column set NULL, the
    UPDATE an `on_delete set_null` inclusion's key makes."""
    out = []
    for c, col in spec.tables[inc.table].columns.items():
        if c == inc.columns[0]:
            out.append(col_null_var(dst, c))
            continue
        out.append(eq(col_value_var(dst, c), col_value_var(src, c)))
        if col.nullable:
            out.append(iff(col_null_var(dst, c), col_null_var(src, c)))
    return out


def _restrict_guard(spec: Spec, table: str, cmd: str, backed: set[str], row: str, row_table: str) -> list[Term]:
    """ON DELETE/UPDATE RESTRICT as seen by the solver: the arbitrary row `row` of `row_table` does
    not reference the pair removed from a relation backed by `table`.  A cascade inclusion (#60)
    gives the same guard on delete: a row that referenced the pair is gone, so every row left
    does not reference it.  So does a set_null one (#62) for the rows left unchanged; the rows it
    nulls are the induction step's third case."""
    guards = []
    for inc in spec.inclusions():
        if inc.relation not in backed or inc.table != row_table:
            continue
        rel = spec.relations[inc.relation]
        ok, ov = col_value_var("old", rel.key), col_value_var("old", rel.value)
        c1, c2 = inc.columns
        t = spec.tables[row_table]
        refs = [eq(col_value_var(row, c1), ok), eq(col_value_var(row, c2), ov)]
        if t.columns[c1].nullable:
            refs.append(not_(col_null_var(row, c1)))
        if t.columns[c2].nullable:
            refs.append(not_(col_null_var(row, c2)))
        references_old = and_(*refs)
        if cmd == "delete":
            guards.append(not_(references_old))
        else:  # update: only when the pair changes
            nk, nv = col_value_var("new", rel.key), col_value_var("new", rel.value)
            unchanged = and_(eq(ok, nk), eq(ov, nv))
            guards.append(or_(unchanged, not_(references_old)))
    return guards


def _induction_step(spec: Spec, p: InvariantPreserved, invs: list[Invariant], table: str, cmd: str,
                    backed: set[str]) -> list[Obligation]:
    out = []
    consts: dict[str, int] = {}  # one interning for both state copies: 'a' before is 'a' after
    before = Encoder(spec, {r: "before" for r in backed}, consts=consts)
    after = Encoder(spec, {r: "after" for r in backed}, consts=consts)
    change = _relation_change(spec, table, cmd, backed) + relation_axioms(spec, before)
    mod_rows = _rows_for(cmd, table)
    all_rels = [(r, "before") for r in sorted(backed)] + [(r, "after") for r in sorted(backed)]
    for inv in invs:
        touches = bool(_rels_in(spec, inv.pred) & backed)
        rel_list = all_rels + [(r, None) for r in sorted(_rels_in(spec, inv.pred) - backed)]
        # 1. the modified row itself (insert / update on the invariant's own table)
        if inv.table == table and cmd in ("insert", "update"):
            assumptions = list(change)
            if cmd == "update":
                assumptions += [before.T(inv.pred, "old", table),
                                before.T(row_constraints(spec, table), "old", table),
                                after.T(transition_constraints(spec, table), "new", table)]
            assumptions.append(after.T(row_constraints(spec, table), "new", table))
            out.append(Obligation(
                p.id, f"{cmd} on {table} preserves {inv.label} for the written row",
                assumptions, after.T(inv.pred, "new", table), dict(mod_rows), rel_list,
                [before, after]).finish())
        # 2. an arbitrary other row (affected only if the invariant reads a relation backed by table)
        if touches:
            row = f"row_{inv.table}"
            assumptions = list(change) + [before.T(inv.pred, row, inv.table),
                                          before.T(row_constraints(spec, inv.table), row, inv.table)]
            if cmd in ("delete", "update"):
                assumptions += _restrict_guard(spec, table, cmd, backed, row, inv.table)
            rows = dict(mod_rows)
            rows[row] = inv.table
            out.append(Obligation(
                p.id, f"{cmd} on {table} preserves {inv.label} for every other row of {inv.table}",
                assumptions, after.T(inv.pred, row, inv.table), rows, rel_list,
                [before, after]).finish())
        # 3. #62: a row of the invariant's table that a set_null inclusion nulls on this delete
        if cmd == "delete":
            for inc in spec.inclusions():
                if inc.on_delete != "set_null" or inc.table != inv.table or inc.relation not in backed:
                    continue
                row, nrow = f"row_{inv.table}", f"row_{inv.table}_nulled"
                assumptions = list(change) + [before.T(inv.pred, row, inv.table),
                                              before.T(row_constraints(spec, inv.table), row, inv.table),
                                              _references(spec, inc, row, "old"), *_nulled(spec, inc, row, nrow)]
                rows = dict(mod_rows)
                rows[row] = rows[nrow] = inv.table
                out.append(Obligation(
                    p.id, f"{cmd} on {table} preserves {inv.label} for the rows of {inv.table} that "
                          f"{inc.name} sets NULL",
                    assumptions, after.T(inv.pred, nrow, inv.table), rows, rel_list,
                    [before, after]).finish())
    return out


# ----------------------------------------------------------------------------- soundness
def relation_visibility_obligations(spec: Spec, only: set[tuple[str, str]] | None = None) -> list[Obligation]:
    """A policy's membership subquery runs as the role under RLS on the relation table.  For every
    row x of that table with x.key = k, the role's effective SELECT must be TRUE.

    `only` (#41, the import): just the (rule id, relation) pairs given, against the spec's own
    policies without the compiler's visibility policies, which a hand-written database does not
    have; the import passes the memberships it read from subqueries that run as the caller."""
    out = []
    seen: set[tuple[str, int, str, str]] = set()
    for p, role, table, exprs in spec.caller_reads():  # a column guard's condition too (#50)
        what = f"policy '{p.name}'" if isinstance(p, PolicyRule) else f"column rule '{p.name}'"
        for e in exprs:
            for m in members_in(e, []):
                if only is not None:
                    if (p.id, m.relation) not in only:
                        continue
                elif is_routed(spec, table, m.relation):
                    continue  # D67: the helper reads every row, without the role's policies
                for lvl, rel in enumerate(levels(spec, m.relation)):
                    # level 0: the rows with key = k; a hop (D56): the rows whose key is a value of
                    # the previous level for k
                    k = (m.relation, lvl, role, "" if m.key is None else m.key.model_dump_json())
                    if k in seen:
                        continue
                    seen.add(k)
                    enc = Encoder(spec)
                    if lvl == 0 and rel.key is None:  # #63: a set reads every row of its table
                        reach, which = TRUE, f"rows of {rel.table}"
                        cond = condition(spec, m.relation)
                        if cond is not None:
                            reach = enc.T(cond, "x", rel.table)
                            which += " that meet the relation's condition"
                    elif lvl == 0:
                        kv, _ = enc.term(m.key, "x", rel.table)
                        reach = eq(col_value_var("x", rel.key), kv)
                        if spec.tables[rel.table].columns[rel.key].nullable:  # #49: a NULL key is no match
                            reach = and_(reach, not_(col_null_var("x", rel.key)))
                        which = f"rows with {rel.key} = the key"
                        cond = condition(spec, m.relation)
                        if cond is not None:  # D61: only the rows the condition keeps are read
                            reach = and_(reach, enc.T(cond, "x", rel.table))
                            which += " that meet the relation's condition"
                    else:
                        prev = hop_prefix(spec, m.relation, lvl)
                        reach = enc.T(Member(member=MemberBody(relation=prev, key=m.key, value=ColRef(col=rel.key))),
                                      "x", rel.table)
                        which = f"rows whose {rel.key} the previous level reaches from the key"
                    assumptions = [*relation_axioms(spec, enc), reach,
                                   enc.T(row_constraints(spec, rel.table), "x", rel.table)]
                    goal = enc.T(effective(spec, rel.table, role, "select", "using", implicit=only is None),
                                 "x", rel.table)
                    idx = spec.rules.index(p)
                    out.append(Obligation(
                        "soundness", f"relation {m.relation} visible to {role}"
                                     + (f" (hop {lvl}, {rel.table})" if lvl else ""),
                        assumptions, goal, {"x": rel.table}, _relations_of(spec, e), [enc],
                        path=f"$.rules[{idx}]",
                        failure_message=f"{what} uses relation '{m.relation}', but a "
                                        f"restrictive policy on '{rel.table}' can hide {which} from role "
                                        f"'{role}', so the membership subquery would be filtered and the "
                                        f"atom would not mean '(key, value) ∈ {m.relation}'",
                        fix=f"relax the restrictive policies on '{rel.table}' for role '{role}' so "
                            f"that those rows are visible").finish())
    return out


def cascade_obligations(spec: Spec) -> list[Obligation]:
    """#60 (D79): an `on_delete cascade` inclusion deletes the referencing rows as the table owner,
    past their own policies.  For every role that can delete a referenced row, each row that
    refers to it must be one the role could delete itself, so a cascade deletes nothing a direct
    delete could not and the delete properties keep their meaning.  #62: a `set_null` one updates
    them instead (`_set_null_obligations`)."""
    out = []
    privs = privileges(spec)
    for inc in spec.inclusions():
        if inc.on_delete == "set_null":
            out += _set_null_obligations(spec, inc, privs)
        if inc.on_delete != "cascade":
            continue
        rel = spec.relations[inc.relation]
        parent, child = rel.table, inc.table
        for role in spec.roles:
            if "delete" not in privs.get((role, parent), {}):
                continue
            enc = Encoder(spec)
            refs = []
            for c, pc in zip(inc.columns, (rel.key, rel.value)):
                refs.append(eq(col_value_var("c", c), col_value_var("old", pc)))
                if spec.tables[child].columns[c].nullable:  # MATCH SIMPLE: a NULL refers to nothing
                    refs.append(not_(col_null_var("c", c)))
                if spec.tables[parent].columns[pc].nullable:
                    refs.append(not_(col_null_var("old", pc)))
            assumptions = [*delete_assumptions(enc, spec, parent, role), *refs,
                           _T(enc, row_constraints(spec, child), "c", child)]
            goal = _T(enc, effective(spec, child, role, "delete", "using"), "c", child)
            out.append(Obligation(
                "soundness", f"a delete on {parent} by {role} cascades only to rows of {child} it could delete",
                assumptions, goal, {"old": parent, "c": child},
                list(dict.fromkeys(_all_relations(spec, parent, role, "delete")
                                   + _all_relations(spec, child, role, "delete"))),
                [enc], path=f"$.rules[{spec.rules.index(inc)}]",
                failure_message=f"inclusion '{inc.name}' deletes the rows of '{child}' that refer to a deleted "
                                f"'{parent}' row, but role '{role}' can delete a '{parent}' row while some row "
                                f"of '{child}' referring to it is one its own delete policies on '{child}' do "
                                f"not allow, so the cascade would delete it past them",
                fix=f"give role '{role}' a delete policy on '{child}' covering every row that refers to a "
                    f"'{parent}' row it can delete, narrow its delete on '{parent}', or use on_delete "
                    f"restrict").finish())
    return out


def _set_null_obligations(spec: Spec, inc: InclusionRule, privs: dict) -> list[Obligation]:
    """#62: an `on_delete set_null` inclusion's key, on a delete of the referenced row, updates each
    referring row to NULL in its first column, as the table owner: past the policies and the column
    guards (they fire for the app role only), but under the checks and the transition triggers.
    (1) Those allow it, or every such delete would fail; (2) every role that can delete the
    referenced row could make that update itself (`net_terms`: its update policies, the
    constraints, the transitions, its column privileges and its guards)."""
    rel = spec.relations[inc.relation]
    parent, child = rel.table, inc.table
    path = f"$.rules[{spec.rules.index(inc)}]"
    c0 = inc.columns[0]
    rows = {"p": parent, "old": child, "new": child}

    def base(enc: Encoder) -> list[Term]:
        return [_T(enc, row_constraints(spec, child), "old", child), _references(spec, inc, "old", "p"),
                *_nulled(spec, inc, "old", "new")]

    enc = Encoder(spec)
    out = [Obligation(
        "soundness", f"a delete on {parent} may set {child}.{c0} NULL",
        [*relation_axioms(spec, enc), _T(enc, row_constraints(spec, parent), "p", parent), *base(enc)],
        and_(_T(enc, row_constraints(spec, child), "new", child),
             _T(enc, transition_constraints(spec, child), "new", child)),
        rows, _relations_of(spec, row_constraints(spec, child), row_constraints(spec, parent)), [enc],
        path=path,
        failure_message=f"inclusion '{inc.name}' sets {child}.{c0} NULL on the rows that refer to a deleted "
                        f"'{parent}' row, but a check or transition rule on '{child}' refuses that change, so "
                        f"such a delete would fail",
        fix=f"let the checks and transition rules on '{child}' allow {c0} to become NULL with every other "
            f"column unchanged, or use on_delete restrict").finish()]
    for role in spec.roles:
        if "delete" not in privs.get((role, parent), {}):
            continue
        enc = Encoder(spec)
        out.append(Obligation(
            "soundness", f"a delete on {parent} by {role} sets {child}.{c0} NULL only where it could",
            [*delete_assumptions(enc, spec, parent, role, row="p"), *base(enc)],
            net_terms(spec, child, role, "update", enc)[1], rows,
            list(dict.fromkeys(_all_relations(spec, parent, role, "delete")
                               + _all_relations(spec, child, role, "update"))),
            [enc], path=path,
            failure_message=f"inclusion '{inc.name}' sets {child}.{c0} NULL on the rows that refer to a deleted "
                            f"'{parent}' row, but role '{role}' can delete a '{parent}' row while some row of "
                            f"'{child}' referring to it is one it could not make that change to itself (its "
                            f"update policies, column privileges or column rules on '{child}'), so the key "
                            f"would change it past them",
            fix=f"let role '{role}' set {c0} NULL on every row of '{child}' that refers to a '{parent}' row it "
                f"can delete, narrow its delete on '{parent}', or use on_delete restrict").finish())
    return out


def obligations_for(spec: Spec, prop: Property) -> list[Obligation]:
    if isinstance(prop, RoleSeparation):
        return role_separation(spec, prop)
    if isinstance(prop, TenantIsolation):
        return tenant_isolation(spec, prop)
    if isinstance(prop, ColumnImmutable):
        return column_immutable(spec, prop)
    if isinstance(prop, MonotoneIn):
        return monotone_in(spec, prop)
    if isinstance(prop, WriteSubsetRead):
        return write_subset_read(spec, prop)
    if isinstance(prop, LeastPrivilege):
        return least_privilege(spec, prop)
    if isinstance(prop, InvariantPreserved):
        return invariant_preserved(spec, prop)
    if isinstance(prop, AlwaysOnUpdate):
        return always_on_update(spec, prop)
    if isinstance(prop, ChangesOnly):
        return changes_only(spec, prop)
    if isinstance(prop, Custom):
        return custom(spec, prop)
    if isinstance(prop, MustAllow):
        return must_allow(spec, prop)
    raise TypeError(prop)
