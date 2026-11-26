"""The lifter (D46): the deparsed text of a policy's USING / WITH CHECK (pg_get_expr) or of a CHECK
constraint (pg_get_constraintdef) -> a verified-fragment predicate, else an opaque block.

The lifter reads the shapes the compiler itself emits (`compile/sql.py`): `col op (select <ctx>)`,
`col = any ((select mls_reach_<h>(<ctx>))::t[])`, `col = any (array(select value from rel where
key = <ctx>))` (also when a lookup helper holds the subquery: `inline_lookups`), `col = any (array[c1, ...])`, `col is null`, `(p) is true` at the top of a CHECK,
`and` / `or` / `not`; and a fixed list of hand-written idioms: a bare `auth.uid()`,
`current_setting('app.x')` or `current_user` without the InitPlan wrapper (lifted; a hint names
the index-friendly form), `col in (c1, ...)`, `col in (select value from rel where key = <ctx>)`,
the correlated `exists (select 1 from rel where rel.key = <ctx> and rel.value = t.col)` (lifted
to `member`; a hint names it as the slow shape of FINDINGS), a bare boolean column, and
`col like 'const'` (never in the fragment: it becomes an opaque block over the column alone, which
the leakproof lint reports).

The lifter is total.  It works at the granularity of the boolean connectives: a conjunct,
disjunct or negand it cannot read becomes an opaque block whose signature is the columns, context
sources and relations its text names (a conservative scan); an expression it cannot parse at all
is one opaque block.  Every lifted atom is validated with the spec checker before it is kept, so
the lifted spec always checks.  A user function is unreadable (D34) unless it is one of the
identity sources, a compiler helper, or (#52, `inline_functions`, applied by the import before
lifting) a stable one-statement SQL helper returning a boolean, read as its body.  Deparsing differs across versions (D30): the parser reads the deparsed text
of every version in the matrix, and the tests pin shapes, not strings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields, replace
from typing import Any, Callable

from pydantic import TypeAdapter

from mls.spec.model import ARRAY_TYPES, CONTEXT_NOW, INT_RANGE, MAX_HOPS, ColType, Pred, Spec, pair_unique

PG_TO_MLS: dict[str, ColType] = {"integer": "int", "bigint": "bigint", "text": "text", "boolean": "bool",
                                 "timestamp with time zone": "timestamp", "uuid": "uuid", "citext": "citext"}
CAST_TO_MLS: dict[str, ColType] = {"uuid": "uuid", "integer": "int", "int": "int", "int4": "int", "bigint": "bigint",
                                   "int8": "bigint", "text": "text", "character varying": "text", "varchar": "text",
                                   "boolean": "bool", "bool": "bool", "timestamptz": "timestamp",
                                   "timestamp with time zone": "timestamp", "citext": "citext"}
SQL_TYPE_OF: dict[ColType, str] = {"int": "integer", "bigint": "bigint", "text": "text", "bool": "boolean",
                                   "timestamp": "timestamptz", "uuid": "uuid", "citext": "citext"}


def mls_type(pg_type: str) -> ColType | None:
    """The MLS type of a catalog column type (format_type), or None when MLS does not model it.
    `character varying(n)` compares as text (D53); the length limit is the table's, not a rule's."""
    if pg_type.endswith("[]"):  # D88: an array of text (varchar too); an enum array is read apart
        return "text[]" if mls_type(pg_type[:-2]) == "text" else None
    if pg_type == "character varying" or pg_type.startswith("character varying("):
        return "text"
    if pg_type.endswith(".citext"):  # #73: the extension's type, qualified when its schema is not on the path
        return "citext"
    return PG_TO_MLS.get(pg_type)
FLIP = {"=": "=", "<>": "<>", "<": ">", "<=": ">=", ">": "<", ">=": "<="}
REACH_FN = re.compile(r"^mls_reach_([a-z_][a-z0-9_]*)$")
_PRED = TypeAdapter(Pred)


class Unreadable(Exception):
    """An expression the lifter does not read; the message says why, for the import notes."""


# ----------------------------------------------------------------------------- tokens
@dataclass(frozen=True)
class Tok:
    kind: str  # ident | qident | str | num | op | end
    text: str
    pos: int


_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<qident>"(?:[^"]|"")*")
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_$]*)
  | (?P<op>->>|->|::|@>|<@|&&|<>|!=|<=|>=|!~~\*|!~~|~~\*|~~|\|\||[=<>()\[\],.+\-*/~])
""", re.VERBOSE)


_SPECIAL_FORMS = frozenset({"trim", "position", "substring", "extract", "overlay"})


def tokenize(text: str) -> list[Tok]:
    out: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None:
            raise Unreadable(f"unexpected character {text[pos]!r} at {pos}")
        kind = m.lastgroup
        if kind != "ws":
            out.append(Tok(kind, m.group(0), pos))
        pos = m.end()
    out.append(Tok("end", "", len(text)))
    return out


# ----------------------------------------------------------------------------- syntax tree
@dataclass
class Node:
    start: int = field(default=0, kw_only=True)
    end: int = field(default=0, kw_only=True)


@dataclass
class And(Node):
    items: list[Node]


@dataclass
class Or(Node):
    items: list[Node]


@dataclass
class Not(Node):
    x: Node


@dataclass
class IsNull(Node):
    x: Node
    negated: bool


@dataclass
class IsTrue(Node):
    x: Node
    value: bool  # IS TRUE / IS FALSE
    negated: bool


@dataclass
class Cmp(Node):
    l: Node
    op: str
    r: Node


@dataclass
class AnyOf(Node):
    l: Node
    op: str
    arr: Node
    quant: str = "any"  # `= ANY (...)`; `<> ALL (...)` is how NOT IN deparses


@dataclass
class InList(Node):
    l: Node
    items: list[Node]
    negated: bool


@dataclass
class InSelect(Node):
    l: Node
    select: "Select"
    negated: bool


@dataclass
class Like(Node):
    l: Node
    op: str
    r: Node


@dataclass
class BinOp(Node):
    l: Node
    op: str
    r: Node


@dataclass
class Exists(Node):
    select: "Select"


@dataclass
class Col(Node):
    qual: str | None
    name: str


@dataclass
class Func(Node):
    name: str  # possibly schema-qualified, lower-case
    args: list[Node]


@dataclass
class Str(Node):
    value: str


@dataclass
class Num(Node):
    text: str


@dataclass
class Bool(Node):
    value: bool


@dataclass
class Null(Node):
    pass


@dataclass
class Keyword(Node):
    name: str  # current_user, session_user, current_timestamp, ...


@dataclass
class Cast(Node):
    x: Node
    type: str  # lower-case, single-spaced


@dataclass
class Select(Node):
    target: Node
    alias: str | None
    table: str | None
    table_alias: str | None
    where: Node | None
    joins: list[tuple[str, str | None, Node]] = field(default_factory=list)  # inner joins: (table, alias, on)


@dataclass
class ArrayLit(Node):
    items: list[Node]


@dataclass
class ArrayQuery(Node):
    select: Select


_KW_CONST = {"current_user", "session_user", "current_role", "current_timestamp", "current_date", "localtimestamp"}


class Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = tokenize(text)
        self.i = 0

    # --- helpers
    def peek(self, k: int = 0) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def is_kw(self, *words: str, k: int = 0) -> bool:
        t = self.peek(k)
        return t.kind == "ident" and t.text.lower() in words

    def is_op(self, *ops: str, k: int = 0) -> bool:
        t = self.peek(k)
        return t.kind == "op" and t.text in ops

    def take(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect_op(self, op: str) -> Tok:
        if not self.is_op(op):
            raise Unreadable(f"expected '{op}' at {self.peek().pos}, found {self.peek().text!r}")
        return self.take()

    def expect_kw(self, word: str) -> Tok:
        if not self.is_kw(word):
            raise Unreadable(f"expected {word.upper()} at {self.peek().pos}, found {self.peek().text!r}")
        return self.take()

    def name(self) -> str:
        t = self.take()
        if t.kind == "ident":
            return t.text.lower()
        if t.kind == "qident":
            return t.text[1:-1].replace('""', '"')
        raise Unreadable(f"expected a name at {t.pos}, found {t.text!r}")

    def span(self, node: Node, start: int) -> Node:
        node.start = start
        node.end = self.toks[self.i - 1].pos + len(self.toks[self.i - 1].text)
        return node

    # --- grammar
    def parse(self) -> Node:
        e = self.expr()
        if self.peek().kind != "end":
            raise Unreadable(f"unexpected {self.peek().text!r} at {self.peek().pos}")
        return e

    def expr(self) -> Node:
        start = self.peek().pos
        items = [self.and_expr()]
        while self.is_kw("or"):
            self.take()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else self.span(Or(items), start)

    def and_expr(self) -> Node:
        start = self.peek().pos
        items = [self.not_expr()]
        while self.is_kw("and"):
            self.take()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else self.span(And(items), start)

    def not_expr(self) -> Node:
        start = self.peek().pos
        if self.is_kw("not"):
            self.take()
            return self.span(Not(self.not_expr()), start)
        return self.is_expr()

    def is_expr(self) -> Node:
        start = self.peek().pos
        e = self.cmp_expr()
        while self.is_kw("is"):
            self.take()
            neg = False
            if self.is_kw("not"):
                self.take()
                neg = True
            if self.is_kw("null"):
                self.take()
                e = self.span(IsNull(e, neg), start)
            elif self.is_kw("true", "false"):
                e = self.span(IsTrue(e, self.take().text.lower() == "true", neg), start)
            elif self.is_kw("distinct"):
                raise Unreadable("IS DISTINCT FROM is not in the fragment")
            else:
                raise Unreadable(f"unexpected IS at {start}")
        return e

    def cmp_expr(self) -> Node:
        start = self.peek().pos
        l = self.add_expr()
        if self.is_op("=", "<>", "!=", "<", "<=", ">", ">=", "@>", "<@", "&&"):
            op = self.take().text
            op = "<>" if op == "!=" else op
            if self.is_kw("any", "all"):
                which = self.take().text.lower()
                self.expect_op("(")
                arr = self.expr()
                self.expect_op(")")
                return self.span(AnyOf(l, op, arr, which), start)
            r = self.add_expr()
            return self.span(Cmp(l, op, r), start)
        neg = False
        if self.is_kw("not") and self.is_kw("in", "like", "ilike", k=1):
            self.take()
            neg = True
        if self.is_kw("in"):
            self.take()
            self.expect_op("(")
            if self.is_kw("select"):
                sel = self.select()
                self.expect_op(")")
                return self.span(InSelect(l, sel, neg), start)
            items = self.expr_list()
            self.expect_op(")")
            return self.span(InList(l, items, neg), start)
        if self.is_kw("like", "ilike") or self.is_op("~~", "~~*", "!~~", "!~~*"):
            t = self.take().text.lower()
            op = {"like": "~~", "ilike": "~~*"}.get(t, t)
            if neg:
                op = "!" + op
            r = self.add_expr()
            return self.span(Like(l, op, r), start)
        if neg:
            raise Unreadable(f"unexpected NOT at {start}")
        return l

    def add_expr(self) -> Node:
        start = self.peek().pos
        l = self.unary()
        while self.is_op("+", "-", "*", "/", "||", "->>", "->", "~"):
            op = self.take().text
            r = self.unary()
            l = self.span(BinOp(l, op, r), start)
        return l

    def unary(self) -> Node:
        start = self.peek().pos
        if self.is_op("-"):
            self.take()
            x = self.unary()
            if isinstance(x, Num):
                return self.span(Num("-" + x.text), start)
            return self.span(BinOp(Num("0"), "-", x), start)
        return self.postfix()

    def postfix(self) -> Node:
        start = self.peek().pos
        e = self.primary()
        while True:
            if self.is_op("::"):
                self.take()
                e = self.span(Cast(e, self.typename()), start)
            elif self.is_op(".") and self.peek(1).kind in ("ident", "qident"):
                # #94: `(c).f`, a field of a composite column, is the field column `c.f`
                dot = self.take().pos
                f = self.name()
                if not isinstance(e, Col) or "." in e.name:
                    raise Unreadable(f"reads field {f} of `{self.text[start:dot].strip()}`, which is not "
                                     f"a column: MLS reads a field of a composite column only")
                e = self.span(Col(e.qual, f"{e.name}.{f}"), start)
            else:
                return e

    def typename(self) -> str:
        words = [self.name()]
        while self.peek().kind == "ident" and not self.is_kw("and", "or", "is", "in", "like", "ilike", "not", "as",
                                                              "from", "where", "any", "all"):
            words.append(self.take().text.lower())
        if self.is_op("("):
            self.take()
            while not self.is_op(")"):
                self.take()
            self.take()
        t = " ".join(words)
        while self.is_op("["):
            self.take()
            self.expect_op("]")
            t += "[]"
        return t

    def expr_list(self) -> list[Node]:
        items = [self.expr()]
        while self.is_op(","):
            self.take()
            items.append(self.expr())
        return items

    def primary(self) -> Node:
        start = self.peek().pos
        t = self.peek()
        if t.kind == "op" and t.text == "(":
            self.take()
            if self.is_kw("select"):
                sel = self.select()
                self.expect_op(")")
                sel.start, sel.end = start, self.toks[self.i - 1].pos + 1
                return sel
            e = self.expr()
            self.expect_op(")")
            e.start, e.end = start, self.toks[self.i - 1].pos + 1
            return e
        if t.kind == "str":
            self.take()
            return self.span(Str(t.text[1:-1].replace("''", "'")), start)
        if t.kind == "num":
            self.take()
            return self.span(Num(t.text), start)
        if t.kind == "ident":
            w = t.text.lower()
            if w in ("true", "false"):
                self.take()
                return self.span(Bool(w == "true"), start)
            if w == "null":
                self.take()
                return self.span(Null(), start)
            if w in _KW_CONST:
                self.take()
                return self.span(Keyword(w), start)
            if w == "array":
                self.take()
                if self.is_op("["):
                    self.take()
                    items = [] if self.is_op("]") else self.expr_list()
                    self.expect_op("]")
                    return self.span(ArrayLit(items), start)
                self.expect_op("(")
                sel = self.select()
                self.expect_op(")")
                return self.span(ArrayQuery(sel), start)
            if w == "exists":
                self.take()
                self.expect_op("(")
                sel = self.select()
                self.expect_op(")")
                return self.span(Exists(sel), start)
            if w in ("select", "case", "cast"):
                raise Unreadable(f"{w.upper()} is not in the fragment")
        if t.kind in ("ident", "qident"):
            parts = [self.name()]
            while self.is_op(".") and self.peek(1).kind in ("ident", "qident"):
                self.take()
                parts.append(self.name())
            if self.is_op("("):
                self.take()
                if len(parts) == 1 and parts[0].lower() in _SPECIAL_FORMS:
                    args = self.special_form(parts[0].lower())
                else:
                    args = [] if self.is_op(")") else self.expr_list()
                self.expect_op(")")
                return self.span(Func(".".join(parts), args), start)
            if len(parts) > 2:
                raise Unreadable(f"a three-part name at {start}")
            if len(parts) == 2:
                return self.span(Col(parts[0], parts[1]), start)
            return self.span(Col(None, parts[0]), start)
        raise Unreadable(f"unexpected {t.text!r} at {t.pos}")

    def special_form(self, name: str) -> list[Node]:
        """The arguments of a SQL-standard special form as the deparser prints it (#45): `TRIM(BOTH
        [chars] FROM x)`, `POSITION(a IN b)`, `SUBSTRING(x FROM i FOR n)`, `EXTRACT(field FROM x)`,
        `OVERLAY(x PLACING y FROM i FOR n)`.  The keywords separate the arguments, so each argument is
        read below the comparisons (where IN would start a list)."""
        args: list[Node] = []
        if name == "trim":
            if self.is_kw("both", "leading", "trailing"):
                self.take()
            if not self.is_kw("from"):
                args.append(self.add_expr())
            self.expect_kw("from")
            return [self.add_expr(), *args]
        if name == "extract":
            if self.peek().kind in ("ident", "qident", "str"):
                self.take()
            else:
                raise Unreadable(f"unexpected {self.peek().text!r} at {self.peek().pos}")
            self.expect_kw("from")
            return [self.add_expr()]
        args.append(self.add_expr())
        seps = {"position": ("in",), "substring": ("from", "for"), "overlay": ("placing", "from", "for")}[name]
        if name == "position":
            self.expect_kw("in")
            return [*args, self.add_expr()]
        if not any(self.is_kw(w) for w in seps):  # `substring(x, i, n)`: the plain call
            while self.is_op(","):
                self.take()
                args.append(self.add_expr())
            return args
        while any(self.is_kw(w) for w in seps):
            self.take()
            args.append(self.add_expr())
        return args

    def select(self) -> Select:
        start = self.peek().pos
        self.expect_kw("select")
        if self.is_op("*"):
            self.take()
            target: Node = Num("*")
        else:
            target = self.expr()
        alias = None
        if self.is_kw("as"):
            self.take()
            alias = self.name()
        table = table_alias = None
        where = None
        joins: list[tuple[str, str | None, Node]] = []
        if self.is_kw("from"):
            self.take()
            table, table_alias = self.from_item(joins)
            if self.is_kw("join", "inner", "left", "right", "full", "cross", "natural") or self.is_op(","):
                raise Unreadable("a subquery over more than one table, other than an inner join")
            if self.is_kw("where"):
                self.take()
                where = self.expr()
            if self.is_kw("group", "order", "limit", "having", "union", "intersect", "except"):
                raise Unreadable(f"{self.peek().text.upper()} in a subquery")
        return self.span(Select(target, alias, table, table_alias, where, joins), start)

    def table_ref(self) -> tuple[str, str | None]:
        parts = [self.name()]
        while self.is_op("."):
            self.take()
            parts.append(self.name())
        alias = None
        if self.is_kw("as"):
            self.take()
            alias = self.name()
        elif self.peek().kind in ("ident", "qident") and not self.is_kw(
                "where", "join", "inner", "on", "left", "right", "full", "cross", "natural", "group", "order",
                "limit", "having", "union", "intersect", "except"):
            alias = self.name()
        return parts[-1], alias

    def from_item(self, joins: list[tuple[str, str | None, Node]]) -> tuple[str, str | None]:
        """`t [alias]`, `(from_item)`, then any `[inner] join t [alias] on cond` (the deparser
        parenthesizes a join list): the first table, with each joined one appended to `joins`."""
        if self.is_op("("):
            self.take()
            if self.is_kw("select"):
                raise Unreadable("a subquery in FROM")
            first = self.from_item(joins)
            self.expect_op(")")
        else:
            first = self.table_ref()
        while self.is_kw("join", "inner"):
            if self.is_kw("inner"):
                self.take()
            self.expect_kw("join")
            if self.is_op("("):
                raise Unreadable("a parenthesized join on the right of JOIN")
            t, a = self.table_ref()
            self.expect_kw("on")
            joins.append((t, a, self.expr()))
        if self.is_kw("left", "right", "full", "cross", "natural") or self.is_op(","):
            raise Unreadable("a subquery over more than one table, other than an inner join")
        return first


def parse(text: str) -> Node:
    return Parser(text).parse()


def strip_check(constraint_def: str) -> str:
    """The expression of a `CHECK (...)` definition from pg_get_constraintdef."""
    s = constraint_def.strip()
    if not s.upper().startswith("CHECK"):
        raise Unreadable("not a CHECK constraint")
    s = s[5:].strip()
    if not (s.startswith("(") and s.endswith(")")):
        raise Unreadable("a CHECK definition without parentheses")
    return s[1:-1]


# ----------------------------------------------------------------------------- environment

def member_body(relation: str, key: dict | None, value: dict) -> dict:
    """A membership atom's body; a set relation's (#63) has no key."""
    return {"relation": relation, "value": value} if key is None else {"relation": relation, "key": key, "value": value}


@dataclass
class Env:
    """What the lifter reads an expression against: the spec so far.  `tables` maps a table to
    its modelled columns (type, nullable); `context` a context name to (source, type);
    `relations` a name to (table, key, value); `hierarchies` a name to its declaration; `keys`
    a table to its primary key and unique column sets (a relation must be one of them)."""
    adapter: str
    context: dict[str, tuple[str, ColType]]
    tables: dict[str, dict[str, tuple[ColType, bool]]]
    governed: set[str]
    keys: dict[str, list[frozenset[str]]] = field(default_factory=dict)  # table -> its PK and unique column sets
    roles: list[str] = field(default_factory=list)
    # #86: the role of the rule being lifted, when a policy reads Supabase's auth.role()
    role: str | None = None
    relations: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    # D56: composed relations, name -> (base relation, ((table, key, value), ...)), and the name a
    # chain of n hops ending on a table should get (the compiler's hop policies carry it)
    composed: dict[str, tuple[str, tuple[tuple[str, str, str], ...]]] = field(default_factory=dict)
    # (last hop table, hops) -> name, and (last hop table, hops, base) -> name with the base relation's
    # (table, key, value, condition) read from the policy (D61: two chains may end alike)
    composed_names: dict[tuple, str] = field(default_factory=dict)
    hierarchies: dict[str, dict] = field(default_factory=dict)
    opaques: dict[str, dict] = field(default_factory=dict)
    # D59: the enum types (name -> labels) and each enum column's type (table -> column -> name)
    enums: dict[str, list[str]] = field(default_factory=dict)
    enum_cols: dict[str, dict[str, str]] = field(default_factory=dict)
    # #94: each field column's composite type (table -> `c.f` -> type name)
    composite_cols: dict[str, dict[str, str]] = field(default_factory=dict)
    # D61: the condition of each relation that has one (name -> its JSON predicate)
    conditions: dict[str, dict] = field(default_factory=dict)
    # #41: the memberships read from a subquery that runs as the caller (under the relation
    # table's own policies), in reading order; and the relations the import found those policies
    # hide rows of, which the lifter then leaves to an opaque block
    caller_reads: list[str] = field(default_factory=list)
    hidden: set[str] = field(default_factory=set)
    # #75: the context values a caller may lack (NULL): their IS [NOT] NULL is kept, not folded
    optional: set[str] = field(default_factory=set)
    # #89: the enum type of each enum context value
    context_enums: dict[str, str] = field(default_factory=dict)
    # #95: while a text is read again with its helper calls as written, each inlined helper whose
    # body held a part the lifter could not read, with that part (the note on its call quotes it)
    unread_bodies: dict[str, str] = field(default_factory=dict)
    # #45: the names of the functions in pg_catalog, so a note on a call says built-in or user function
    builtins: frozenset[str] = frozenset()
    _spec: Spec | None = field(default=None, repr=False)

    @classmethod
    def of_spec(cls, spec: Spec) -> "Env":
        return cls(adapter=spec.identity.adapter,
                   context={n: (cv.source, cv.type) for n, cv in spec.identity.context.items()},
                   optional={n for n, cv in spec.identity.context.items() if cv.optional},
                   context_enums={n: cv.enum for n, cv in spec.identity.context.items() if cv.enum},
                   tables={t: {c: (col.type, col.nullable) for c, col in tb.columns.items()}
                           for t, tb in spec.tables.items()},
                   governed=set(spec.governed()), roles=list(spec.roles),
                   keys={t: [frozenset(k) for k in ([tb.primary_key] if tb.primary_key else []) + list(tb.unique)]
                         for t, tb in spec.tables.items()},
                   relations={n: (r.table, r.key, r.value) for n, r in spec.base_relations().items()},
                   composed={n: (r.of, tuple((h.table, h.key, h.value) for h in r.through))
                             for n, r in spec.relations.items() if n not in spec.base_relations()},
                   hierarchies={n: h.model_dump() for n, h in spec.hierarchies.items()},
                   opaques={n: o.model_dump() for n, o in spec.opaques.items()},
                   enums={n: list(x) for n, x in spec.enums.items()},
                   enum_cols={t: {c: col.enum for c, col in tb.columns.items() if col.enum is not None}
                              for t, tb in spec.tables.items()},
                   composite_cols={t: {c: col.composite for c, col in tb.columns.items() if col.composite}
                                   for t, tb in spec.tables.items()},
                   conditions={n: r.where.model_dump(mode="json", by_alias=True, exclude_none=True)
                               for n, r in spec.base_relations().items() if r.where is not None})

    def ctx_by_source(self, source: str) -> str | None:
        for n, (s, _) in self.context.items():
            if s == source:
                return n
        return None

    def invalidate(self) -> None:
        self._spec = None

    def spec(self) -> Spec:
        """A minimal spec for the checker: the declarations, no rules."""
        if self._spec is None:
            d = {"mls_version": "0.1", "identity": {"adapter": self.adapter,
                                                    "context": {n: {"source": s, "type": t,
                                                                    **({"enum": self.context_enums[n]}
                                                                       if n in self.context_enums else {}),
                                                                    **({"optional": True} if n in self.optional else {})}
                                                                for n, (s, t) in self.context.items()}},
                 "roles": self.roles or ["r"], "enums": self.enums,
                 "tables": {t: {"columns": {c: {"type": ty, "nullable": nu,
                                                **({"enum": self.enum_cols[t][c]} if ty in ("enum", "enum[]") else {}),
                                                **({"composite": self.composite_cols[t][c]}
                                                   if c in self.composite_cols.get(t, {}) else {})}
                                            for c, (ty, nu) in cols.items()},
                                "mode": "adopted" if t in self.governed else "observed"}
                            for t, cols in self.tables.items()},
                 "relations": {**{n: {"table": t, **({"key": k} if k is not None else {}), "value": v,
                                      **({"where": self.conditions[n]} if n in self.conditions else {})}
                                  for n, (t, k, v) in self.relations.items()},
                               **{n: {"of": of, "through": [{"table": t, "key": k, "value": v} for t, k, v in hops]}
                                  for n, (of, hops) in self.composed.items()}},
                 "hierarchies": self.hierarchies,
                 "opaques": self.opaques, "rules": [], "properties": []}
            self._spec = Spec.model_validate(d)
        return self._spec

    def validate(self, pred: dict, table: str, scope: str, negated: bool) -> None:
        """Raise Unreadable with the checker's message when `pred` is outside the fragment."""
        from mls.spec.check import (
            Checker, check_scope, guard_scope, policy_scope, relation_scope, transition_scope,
        )

        ck = Checker(self.spec())
        sc = {"policy": policy_scope, "check": check_scope, "transition": transition_scope,
              "relation": relation_scope, "guard": guard_scope}[scope](table)
        ck.pred(_PRED.validate_python(pred), sc, "$", negated)
        if ck.sink.errors:
            e = ck.sink.errors[0]
            raise Unreadable(e.message + (f" ({e.fix})" if e.fix else ""))


# ----------------------------------------------------------------------------- the lifter
@dataclass
class LiftResult:
    pred: dict | None  # None when the text could not be parsed and no opaque was made
    kind: str  # lifted | partial | opaque
    reasons: list[str] = field(default_factory=list)  # why a part is opaque: "<sql>: <reason>"
    hints: list[str] = field(default_factory=list)  # index-friendly forms, slow shapes, LIKE
    opaques: list[str] = field(default_factory=list)  # names of the blocks made
    columns: set[str] = field(default_factory=set)  # columns the text names (conservative)


MakeOpaque = Callable[[str, list[str], list[str], list[str]], str]  # (sql, columns, context, relations) -> name
# (table, key, value, condition or None) -> name, None if refused
MakeRelation = Callable[[str, str, str, "dict | None"], "str | None"]


_PREDICATES = (And, Or, Not, IsNull, Cmp, AnyOf, InList, InSelect, Exists, Like)


def _const(node: Node) -> Node | None:
    """A constant's value node (a cast of one is the constant), or None for anything else."""
    while isinstance(node, Cast):
        node = node.x
    return node if isinstance(node, (Str, Num, Bool, Null)) else None


def _role_call(node: Node) -> bool:
    """#86: Supabase's `auth.role()`, bare, cast, or in an InitPlan `(select auth.role())`."""
    while isinstance(node, Cast) or (isinstance(node, Select) and node.table is None):
        node = node.x if isinstance(node, Cast) else node.target
    return isinstance(node, Func) and node.name == "auth.role" and not node.args


def _role_test(node: Node, role: str) -> Bool | None:
    """#86: `auth.role() = 'x'` (`<>`, `= ANY (ARRAY[..])`, `<> ALL`) for a caller of `role`, or None."""
    if isinstance(node, Cmp) and node.op in ("=", "<>"):
        for a, b in ((node.l, node.r), (node.r, node.l)):
            c = _const(b)
            if _role_call(a) and isinstance(c, Str):
                return Bool((c.value == role) == (node.op == "="), start=node.start, end=node.end)
    if isinstance(node, AnyOf) and _role_call(node.l) and (node.quant, node.op) in (("any", "="), ("all", "<>")):
        arr = node.arr.x if isinstance(node.arr, Cast) else node.arr
        if isinstance(arr, ArrayLit) and all(isinstance(_const(x), Str) for x in arr.items):
            hit = any(_const(x).value == role for x in arr.items)
            return Bool(hit == (node.quant == "any"), start=node.start, end=node.end)
    return None


def fold(node: Node, never_null: Callable[[Node], bool] = lambda _: False, role: str | None = None) -> Node:
    """#64: what an inlined helper's body leaves constant once the call's arguments are in place:
    `<constant> IS [NOT] NULL` is TRUE or FALSE, and `and` / `or` drop their TRUE / FALSE parts (a
    FALSE part makes an `and` FALSE, a TRUE one an `or` TRUE, whatever the others are, UNKNOWN
    included).  basejump's `(role = r or r is null)` is `role = 'owner'` for r = 'owner' and TRUE for
    r = NULL.  #66: so is the test of a term `never_null` says is never NULL (a context value: the
    model's assumption, the adapter's).  Anything else is returned as it is."""
    if role is not None and (test := _role_test(node, role)) is not None:
        return test  # #86: the caller's role, a constant in a rule of one role
    if isinstance(node, Not):
        x = fold(node.x, never_null, role)
        return Bool(not x.value, start=node.start, end=node.end) if isinstance(x, Bool) else node
    if isinstance(node, IsNull):
        c = _const(node.x)
        if c is not None:
            return Bool((isinstance(c, Null)) != node.negated, start=node.start, end=node.end)
        if never_null(node.x):
            return Bool(node.negated, start=node.start, end=node.end)
        return node
    if isinstance(node, IsTrue):  # #95: a guard `(c) is not true` whose condition folds to a constant
        x = fold(node.x, never_null, role)
        if isinstance(x, Bool):
            return Bool((x.value == node.value) != node.negated, start=node.start, end=node.end)
        return IsTrue(x, node.value, node.negated, start=node.start, end=node.end) if x is not node.x else node
    if isinstance(node, (And, Or)):
        items = [fold(x, never_null, role) for x in node.items]
        absorb = isinstance(node, Or)  # TRUE absorbs an or, FALSE an and
        if any(isinstance(x, Bool) and x.value == absorb for x in items):
            return Bool(absorb, start=node.start, end=node.end)
        items = [x for x in items if not isinstance(x, Bool)]
        if not items:
            return Bool(not absorb, start=node.start, end=node.end)
        if len(items) == 1:
            return items[0]
        return type(node)(items, start=node.start, end=node.end)
    return node


class Lifter:
    def __init__(self, env: Env, table: str, scope: str, make_opaque: MakeOpaque, make_relation: MakeRelation):
        self.env = env
        self.table = table
        self.scope = scope
        self.make_opaque = make_opaque
        self.make_relation = make_relation
        self.markers = context_markers(env)
        self.result = LiftResult(None, "opaque")
        self.hinted: set[str] = set()
        self._text = ""

    # --- entry points
    def lift(self, text: str, top_is_true: bool = False) -> LiftResult:
        self._text = text
        self.result.columns = scan_columns(text, self.env.tables[self.table])
        try:
            tree = parse(text)
        except Unreadable as e:
            self.result.reasons.append(f"{text.strip()}: {e}")
            self.result.pred = {"opaque": self.opaque(text, 0, len(text))}
            return self.result
        if top_is_true and isinstance(tree, IsTrue) and tree.value and not tree.negated:
            tree = tree.x
        try:
            self.result.pred = self.pred(tree, False)
        except Unreadable as e:
            self.result.reasons.append(f"{text.strip()}: {e}")
            self.result.pred = {"opaque": self.opaque(text, 0, len(text))}
            self.result.kind = "opaque"
            return self.result
        self.result.kind = "partial" if self.result.opaques else "lifted"
        self.result.pred = now_between_shape(self.result.pred)
        return self.result

    def opaque(self, text: str, start: int, end: int) -> str:
        sql = text[start:end].strip()
        cols = sorted(scan_columns(sql, self.env.tables[self.table]))
        ctx = [n for n, m in self.markers.items() if m.search(sql)]
        rels = [rn for rn, (t, _, _) in self.env.relations.items()
                if re.search(r'(?<![\w."])"?' + re.escape(t) + r'"?(?![\w"])', sql)]
        name = self.make_opaque(sql, cols, ctx, rels)
        self.result.opaques.append(name)
        self.env.invalidate()
        return name

    def never_null(self, node: Node) -> bool:
        """#66: a context value is never NULL in the model (the identity adapter's assumption), so its
        `IS [NOT] NULL` is TRUE or FALSE; the import says so."""
        from mls.identity.base import adapter_anonymous_roles

        found = self.context(node)
        if found is None or found[0] in self.env.optional:  # #75: an optional value's test is kept
            return False
        if found[0] != CONTEXT_NOW and adapter_anonymous_roles(self.env.adapter, self.env.roles):
            return False  # #85: anon (no claims) lacks it, a signed-in caller has it: the test is kept
        self.hint(f"`{self.src(node)} IS [NOT] NULL` is read as constant: the identity adapter's "
                  "assumption is that a context value is always set")
        return True

    def hint(self, text: str) -> None:
        if text not in self.hinted:
            self.hinted.add(text)
            self.result.hints.append(text)

    # --- predicates
    def part(self, node: Node, negated: bool) -> dict:
        """A conjunct / disjunct / negand: lifted, or an opaque block of its own text."""
        try:
            return self.pred(node, negated)
        except Unreadable as e:
            self.result.reasons.append(f"{self.src(node)}: {e}")
            return {"opaque": self.opaque(self.src_text, node.start, node.end)}

    def pred(self, node: Node, negated: bool) -> dict:
        node = fold(node, self.never_null, self.env.role)
        if isinstance(node, Bool):
            return {"lit": node.value}
        if isinstance(node, And):
            return {"and": [self.part(x, negated) for x in node.items]}
        if isinstance(node, Or):
            return {"or": [self.part(x, negated) for x in node.items]}
        if isinstance(node, Cmp) and node.op in ("=", "<>") and (isinstance(node.l, Bool) or isinstance(node.r, Bool)):
            # #64: `p = true` is p and `p = false` is not p, also in three values (UNKNOWN stays
            # UNKNOWN): a helper's call compared with true, its body inlined
            b, other = (node.l, node.r) if isinstance(node.l, Bool) else (node.r, node.l)
            if isinstance(other, _PREDICATES):
                if b.value == (node.op == "="):
                    return self.part(other, negated)
                return {"not": self.part(other, not negated)}
        if isinstance(node, Not):
            return {"not": self.part(node.x, not negated)}
        if isinstance(node, IsNull):
            p = {"is_null": self.term(node.x)[0]}
            self.check(p, negated)
            return {"not": p} if node.negated else p
        if isinstance(node, IsTrue) and isinstance(node.x, Col) and node.x.qual in (None, self.table) \
                and self.env.tables.get(self.table, {}).get(node.x.name) == ("bool", False):
            # #71: a NOT NULL boolean is never UNKNOWN, so `b IS FALSE` is `b = false`
            p = self.part(Cmp(node.x, "=", Bool(node.value)), negated)
            return {"not": p} if node.negated else p
        if isinstance(node, IsTrue) and isinstance(node.x, (IsNull, IsTrue)):
            # #95: an IS [NOT] NULL, or an IS [NOT] TRUE, is never UNKNOWN, so testing it for TRUE or
            # FALSE is the test itself or its negation (a plpgsql guard's `(c) is not true`)
            if node.value != node.negated:
                return self.part(node.x, negated)
            return {"not": self.part(node.x, not negated)}
        if isinstance(node, IsTrue):
            raise Unreadable("IS TRUE / IS FALSE inside an expression (the fragment is three-valued; only a CHECK's "
                             "outer `(p) IS TRUE` is read)")
        if isinstance(node, Cmp):
            return self.cmp(node, negated)
        if isinstance(node, AnyOf):
            return self.any_of(node, negated)
        if isinstance(node, InList):
            if node.negated:
                return {"not": self.in_list(node, not negated)}
            return self.in_list(node, negated)
        if isinstance(node, InSelect):
            if node.negated:
                raise Unreadable("NOT IN (subquery) is an anti-join (restate positively, or it stays opaque)")
            p = self.member(node.l, node.select, correlated=False)
            self.check(p, negated)
            self.hint(f"`{self.src(node)}` is lifted to a membership; the compiler writes it as "
                      f"`col = any (array(select ...))`, the index-driven shape")
            return p
        if isinstance(node, Exists):
            p = self.exists(node)
            self.check(p, negated)
            self.hint(f"`{self.src(node)}` is a correlated EXISTS, the per-row shape FINDINGS measures as the slow "
                      f"one; it is lifted to a membership and the compiler writes the array shape")
            return p
        if isinstance(node, Like):
            self.term(node.l)  # must be a readable term, so the block's signature is exact
            raise Unreadable("LIKE is not in the fragment (its operator is not leakproof: the leakproof lint "
                             "reports it); the comparison stays an opaque block over the column")
        if isinstance(node, Col):
            t, ty = self.term(node)
            if ty != "bool":
                raise Unreadable(f"a bare column of type {ty} is not a predicate")
            p = {"cmp": [t, "=", {"const": True}]}
            self.check(p, negated)
            return p
        if isinstance(node, Func):
            raise Unreadable(self.func_reason(node))
        if isinstance(node, (Cast, Select, BinOp, Keyword, Str, Num, Null, ArrayLit, ArrayQuery)):
            raise Unreadable(f"`{self.src(node)}` is not a predicate the fragment has")
        raise Unreadable(f"unknown node {type(node).__name__}")

    def check(self, pred: dict, negated: bool) -> None:
        self.env.validate(pred, self.table, self.scope, negated)

    def cmp(self, node: Cmp, negated: bool) -> dict:
        if node.op in ("@>", "<@", "&&"):  # D88
            raise Unreadable(f"operator {node.op} (containment or overlap) is not in the fragment; over an array it "
                             f"reads a NULL element as no match (FALSE where `'x' = ANY (col)` is UNKNOWN), so "
                             f"a label test on an array is read only as `'x' = ANY (col)`")
        (l, lt), (r, rt) = self.term(node.l), self.term(node.r)
        op = node.op
        if not _is_col(l) and _is_col(r):  # the fragment puts the column on the left
            l, r, op = r, l, FLIP[op]
        p = {"cmp": [l, op, r]}
        self.check(p, negated)
        return p

    def any_of(self, node: AnyOf, negated: bool) -> dict:
        arr = node.arr
        col = arr.x if isinstance(arr, Cast) and isinstance(arr.x, Col) and arr.type == "text[]" else arr
        if isinstance(col, Col):  # D88: `'x' = ANY (col)`, and `'x' <> ALL (col)` its negation
            c, ty = self.term(col)
            if ty in ARRAY_TYPES and (node.quant, node.op) in (("any", "="), ("all", "<>")):
                try:
                    label, _ = self.const(node.l)
                except Unreadable:
                    label = None
                if label is None or not isinstance(label["const"], str):
                    raise Unreadable(f"`{self.src(node)}`: the label tested among an array's elements must be a "
                                     f"text constant")
                p = {"has": [c, label]}
                if node.quant == "all":
                    self.check(p, not negated)
                    return {"not": p}
                self.check(p, negated)
                return p
        if node.quant == "all":
            if node.op == "<>" and isinstance(arr, ArrayLit):  # NOT IN (c1, ...) deparses as <> ALL (ARRAY[...])
                l, _ = self.term(node.l)
                p = {"in": [l, [self.const(x)[0] for x in arr.items]]}
                self.check(p, not negated)
                return {"not": p}
            raise Unreadable(f"{node.op} ALL is not in the fragment")
        if node.op != "=":
            raise Unreadable(f"{node.op} ANY is not in the fragment")
        if isinstance(arr, Cast) and isinstance(arr.x, ArrayLit) and CAST_TO_MLS.get(arr.type.removesuffix("[]")) \
                and arr.type.endswith("[]"):
            arr = arr.x  # (ARRAY['a'::character varying, ...])::text[], an IN list over a varchar column (D53)
        if isinstance(arr, ArrayLit):
            l, _ = self.term(node.l)
            p = {"in": [l, [self.const(x)[0] for x in arr.items]]}
            self.check(p, negated)
            return p
        if isinstance(arr, ArrayQuery):
            p = self.member(node.l, arr.select, correlated=False)
            self.check(p, negated)
            return p
        if isinstance(arr, Cast) and isinstance(arr.x, Select) and arr.x.table is None:
            # col = any ((select mls_reach_<h>(<ctx>))::t[]): the compiled in_group
            sel = arr.x
            if isinstance(sel.target, Func):
                m = REACH_FN.match(sel.target.name)
                if m and m.group(1) in self.env.hierarchies and len(sel.target.args) == 1:
                    key, _ = self.term(sel.target.args[0])
                    value, _ = self.term(node.l)
                    p = {"in_group": {"hierarchy": m.group(1), "key": key, "value": value}}
                    self.check(p, negated)
                    return p
                if m:
                    raise Unreadable(f"calls {sel.target.name}(), a hierarchy helper of a hierarchy the spec does not "
                                     f"declare (declare it to lift the policy)")
                raise Unreadable(self.func_reason(sel.target))
        raise Unreadable(f"`{self.src(node)}`: = ANY over something that is not a constant array, a membership "
                         f"subquery or a hierarchy helper")

    def in_list(self, node: InList, negated: bool) -> dict:
        l, _ = self.term(node.l)
        p = {"in": [l, [self.const(x)[0] for x in node.items]]}
        self.check(p, negated)
        return p

    # --- memberships
    def member(self, value_node: Node, sel: Select, correlated: bool, outer_value: Node | None = None) -> dict:
        """A membership subquery as its member atom.  A subquery from a SECURITY DEFINER helper's
        body (`inline_functions` aliases its FROM `mls_definer`) reads every row, as a relation
        does; any other runs as the caller, under the relation table's policies (#41), so it is
        recorded, and refused when the import found those policies hide rows of the relation."""
        atom = self._member(value_node, sel, correlated, outer_value)
        if not {DEFINER_ALIAS, SET_ALIAS} & {sel.table_alias, *(a for _, a, _ in sel.joins)}:
            rel = atom["member"]["relation"]
            if rel in self.env.hidden:
                raise Unreadable(f"the subquery runs as the caller, and the policies on {sel.table} hide some of "
                                 f"the rows of {rel} it reads, so the membership would claim more than the "
                                 f"policy allows")
            self.env.caller_reads.append(rel)
        return atom

    def _member(self, value_node: Node, sel: Select, correlated: bool, outer_value: Node | None = None) -> dict:
        """`select V from R where R.K = <key>`: a relation (R, K, V) and a member atom."""
        if sel.table is None:
            raise Unreadable("a membership subquery needs a FROM table")
        rel_table = sel.table
        if correlated and sel.joins:
            return self.exists_join(sel)
        if sel.joins:
            raise Unreadable("a membership subquery over a join (only an EXISTS may join)")
        if rel_table not in self.env.tables:
            raise Unreadable(f"subquery reads table {rel_table}, which is not in the spec")
        inner = InnerScope(self, rel_table, sel.table_alias)
        if correlated:
            if sel.where is None:
                raise Unreadable("EXISTS without a WHERE clause")
            conds = sel.where.items if isinstance(sel.where, And) else [sel.where]
            val_col = outer_col = None
            keys: list[tuple[str, dict, Node]] = []
            rest: list[Node] = []
            for c in conds:
                sides = None
                if isinstance(c, Cmp) and c.op == "=":
                    try:
                        sides = [inner.classify(c.l), inner.classify(c.r)]
                    except Unreadable:
                        sides = None
                kinds = sorted(k for k, _ in sides) if sides else None
                if kinds == ["inner", "outer"]:
                    i = sides[0][1] if sides[0][0] == "inner" else sides[1][1]
                    o = sides[0][1] if sides[0][0] == "outer" else sides[1][1]
                    if val_col is not None:
                        raise Unreadable("EXISTS correlates on two columns")
                    val_col, outer_col = i, o
                elif kinds == ["inner", "key"]:
                    i = sides[0][1] if sides[0][0] == "inner" else sides[1][1]
                    k = sides[0][1] if sides[0][0] == "key" else sides[1][1]
                    keys.append((i, k, c))
                else:
                    rest.append(c)  # D61: a condition on the relation's own rows, or unreadable
            ctx_keys = [k for k in keys if "ctx" in k[1]]
            const_keys = [k for k in keys if "const" in k[1]]
            if val_col is None and len(ctx_keys) == 1 and len(const_keys) == 1 and len(keys) == 2:
                # #90: no correlation, a context value and a constant: a fact of the caller alone
                # (`authorize('channels.delete')`: the caller's role holds that permission)
                (key_col, key_term, _), (val_col, value_json, _) = ctx_keys[0], const_keys[0]
                where = self.condition(rest, rel_table, sel.table_alias)
            else:
                (key_col, key_term), more = self.pick_key(keys)
                # #63: no key filter: the parent rows that meet a condition, correlated on a key of their own
                is_set = key_col is None and val_col is not None and \
                    frozenset((val_col,)) in self.env.keys.get(rel_table, [])
                if (key_col is None and not is_set) or val_col is None:
                    raise Unreadable("EXISTS without both a key filter and a correlation on the row")
                where = self.condition(more + rest, rel_table, sel.table_alias)
                value_json = {"col": outer_col}
        else:
            (rel_table, key_col, val_col), key_term, hops, where = self.chain(sel)
            value_json, _ = self.term(value_node)
            if hops:
                name = self.composed_relation((rel_table, key_col, val_col), hops, where)
                return {"member": member_body(name, key_term, value_json)}
        if rel_table not in self.env.governed:
            raise Unreadable(f"the relation table {rel_table} is observed (not governed): no relation can be declared "
                             f"on it")
        if key_col is not None and not pair_unique(self.env.keys.get(rel_table, []), key_col, val_col):
            raise Unreadable(f"({key_col}, {val_col}) is not unique in {rel_table} (neither the pair nor one of its "
                             f"columns is a key); a relation is a set of pairs (add a unique constraint on the pair "
                             f"to lift this)")
        name = self.declare(rel_table, key_col, val_col, where)
        return {"member": member_body(name, key_term, value_json)}

    def declare(self, table: str, key: str, value: str, where: dict | None) -> str:
        """The relation (table, key, value) with this condition, proposed or reused."""
        name = self.make_relation(table, key, value, where)
        if name is None:
            raise Unreadable(f"no relation ({key}, {value}) of {table} can be declared")
        if self.env.relations.get(name) != (table, key, value) or self.env.conditions.get(name) != where:
            self.env.relations[name] = (table, key, value)
            if where is not None:
                self.env.conditions[name] = where
            else:
                self.env.conditions.pop(name, None)
        self.env.invalidate()
        return name

    def pick_key(self, keys: list[tuple[str, dict, Node]]) -> tuple[tuple[str | None, dict | None], list[Node]]:
        """The relation's key among the `inner col = <ctx or constant>` comparisons: the one with
        a context value, else the only constant one (D60: the sessions in a state); the others are
        conditions on the relation's rows (D61)."""
        ctx = [k for k in keys if "ctx" in k[1]]
        if len(ctx) > 1:
            raise Unreadable("the subquery filters the relation on two context values")
        pick = ctx[0] if ctx else keys[0] if len(keys) == 1 else None
        if pick is None and keys:
            raise Unreadable("the subquery filters the relation on several constants and no context value: "
                             "which one is the key is not determined")
        if pick is None:
            return (None, None), []
        return (pick[0], pick[1]), [c for k in keys if k is not pick for c in [k[2]]]

    def condition(self, nodes: list[Node], table: str, alias: str | None) -> dict | None:
        """The rest of a membership subquery's WHERE as the relation's condition (D61): a
        predicate on the relation's own columns and constants, read completely or not at all."""
        if not nodes:
            return None
        sub = _ConditionLifter(self.env, table, "relation", self.make_opaque, self.make_relation)
        sub._text = self._text
        quals = {table} | ({alias} if alias else set())
        parts = [sub.pred(_unqualify(n, quals), False) for n in nodes]
        if {"lit": False} in parts:  # #64: a part folded FALSE: the subquery keeps no row
            raise Unreadable("the subquery's condition is always false: it reads no row")
        parts = [x for x in parts if x != {"lit": True}]  # a part folded TRUE keeps every row
        if not parts:
            return None
        p = parts[0] if len(parts) == 1 else {"and": parts}
        self.env.validate(p, table, "relation", False)
        return p

    def exists(self, node: Exists) -> dict:
        return self.member(node, node.select, correlated=True)

    def join_table(self, node: Node, tables: list[tuple[str, str | None]]) -> int:
        """The one joined table whose columns `node` reads (a condition on it), else Unreadable."""
        seen: set[int] = set()

        def walk(n) -> None:
            if isinstance(n, Col):
                hits = [i for i, (t, a) in enumerate(tables)
                        if (n.qual in (t, a) if n.qual is not None else n.name in self.env.tables[t])]
                if len(hits) != 1:
                    raise Unreadable(f"`{self.src(node)}`: column {n.name} is not of exactly one joined table")
                seen.add(hits[0])
            elif isinstance(n, (Select, Exists, ArrayQuery)):
                raise Unreadable(f"`{self.src(node)}`: a subquery in a joined EXISTS's condition")
            elif isinstance(n, Node):
                for f in fields(n):
                    if f.name not in ("start", "end"):
                        walk(getattr(n, f.name))
            elif isinstance(n, (list, tuple)):
                for x in n:
                    walk(x)

        walk(node)
        if len(seen) != 1:
            raise Unreadable(f"`{self.src(node)}`: a condition in a joined EXISTS must read one table")
        return seen.pop()

    def exists_join(self, sel: Select) -> dict:
        """`exists (select 1 from A join B on A.v = B.k ... where A.k = <key> and Z.v = t.col)`: a
        chain of key lookups from the table the key filters to the table the row correlates with,
        read as a composed relation (D60): A is the base (k, v), every other table a hop whose key
        is the column joined to the previous table and whose value the column joined to the next
        (the last one's, the correlated column).  Every condition is one of those equalities.  A
        table may occur twice under two aliases (#33: the self-join of a membership table, users who
        share a team, is the base relation and a hop back through the same table)."""
        tables = [(sel.table, sel.table_alias)] + [(t, a) for t, a, _ in sel.joins]
        names = [t for t, _ in tables]
        for t in names:
            if t not in self.env.tables:
                raise Unreadable(f"subquery reads table {t}, which is not in the spec")
        conds: list[Node] = []
        for c in [on for _, _, on in sel.joins] + ([sel.where] if sel.where is not None else []):
            conds.extend(c.items if isinstance(c, And) else [c])

        def side(node: Node) -> tuple[str, Any]:
            if isinstance(node, Col):
                if node.qual is not None:
                    hits = ([i for i, (_, a) in enumerate(tables) if a == node.qual]
                            or [i for i, (t, a) in enumerate(tables) if a is None and t == node.qual])
                    if len(hits) > 1:
                        raise Unreadable(f"{node.qual}.{node.name} names more than one table of the join")
                    if hits:
                        t = tables[hits[0]][0]
                        if node.name not in self.env.tables[t]:
                            raise Unreadable(f"column {t}.{node.name} is not modelled")
                        return "inner", (hits[0], node.name)
                    if node.qual == self.table:
                        return "outer", self.term(Col(None, node.name))[0]["col"]
                    raise Unreadable(f"column {node.qual}.{node.name} is of none of the tables")
                owners = [i for i, (t, _) in enumerate(tables) if node.name in self.env.tables[t]]
                if len(owners) > 1:
                    raise Unreadable(f"column {node.name} is ambiguous in the join")
                if owners:
                    return "inner", (owners[0], node.name)
                return "outer", self.term(node)[0]["col"]
            ctx = self.context(node)
            if ctx is not None:
                return "key", {"ctx": ctx[0]}
            return "key", self.const(node)[0]

        edges: dict[int, list[tuple[str, int, str]]] = {i: [] for i in range(len(tables))}
        corr = None
        keys: list[tuple[tuple[int, str], dict, Node]] = []
        rest: list[tuple[int, Node]] = []  # D61: conditions on one table's own columns
        for c in conds:
            sides = None
            if isinstance(c, Cmp) and c.op == "=":
                try:
                    sides = (side(c.l), side(c.r))
                except Unreadable:
                    sides = None
            if sides is None:
                rest.append((self.join_table(c, tables), c))
                continue
            (ka, a), (kb, b) = sides
            kinds = sorted((ka, kb))
            if kinds == ["inner", "inner"] and a[0] != b[0]:
                edges[a[0]].append((a[1], b[0], b[1]))
                edges[b[0]].append((b[1], a[0], a[1]))
            elif kinds == ["inner", "outer"] and corr is None:
                corr = (a, b) if ka == "inner" else (b, a)
            elif kinds == ["inner", "key"]:
                keys.append(((a, b, c) if ka == "inner" else (b, a, c)))
            else:
                raise Unreadable(f"`{self.src(c)}`: a joined EXISTS reads more than key lookups, `key = <ctx>`, "
                                 f"a condition on the key's table and the correlation on the row")
        (picked, key_term), more = self.pick_key(keys)
        if picked is None or corr is None:
            raise Unreadable("a joined EXISTS without both a key filter and a correlation on the row")
        ki, kcol = picked
        rest += [(next(k[0][0] for k in keys if k[2] is c), c) for c in more]
        if any(i != ki for i, _ in rest):
            raise Unreadable("a joined EXISTS filters a table other than the key's: only the base relation "
                             "has a condition")
        where = self.condition([c for _, c in rest], names[ki], tables[ki][1])
        (ci, ccol), outer_col = corr
        # walk the join from the key's table to the correlated one: a simple path through every table
        path, ins, outs, prev = [ki], [kcol], [], None
        while path[-1] != ci:
            nxt = [e for e in edges[path[-1]] if e[1] != prev]
            if len(nxt) != 1 or nxt[0][1] in path:
                raise Unreadable("the joined tables are not one chain from the key's table to the row's")
            out_col, j, in_col = nxt[0]
            outs.append(out_col)
            prev = path[-1]
            path.append(j)
            ins.append(in_col)
        outs.append(ccol)
        if len(path) != len(tables) or any(len(edges[i]) != (1 if i in (ki, ci) else 2) for i in path):
            raise Unreadable("the joined tables are not one chain from the key's table to the row's")
        base = (names[ki], ins[0], outs[0])
        hops = [(names[i], ins[n], outs[n]) for n, i in enumerate(path) if n > 0]
        name = self.composed_relation(base, hops, where)
        return {"member": {"relation": name, "key": key_term, "value": {"col": outer_col}}}

    def chain(self, sel: Select) -> tuple[tuple[str, str, str], dict, list[tuple[str, str, str]], dict | None]:
        """`select V from R where K = <key> [and <condition>]` is a base level (`select V from R where
        <condition>` with V a key of R: a set, #63, key None); `select V from T
        where K = any (array(<chain>))` or `... where K in (<chain>)` a hop over a chain (D56).
        Returns the base level (table, key, value), the key term, the hops (table, key, value) in
        order, and the base level's condition (D61)."""
        if sel.table is None:
            raise Unreadable("a membership subquery needs a FROM table")
        if sel.joins:
            raise Unreadable("a membership subquery over a join (only an EXISTS may join)")
        if sel.table not in self.env.tables:
            raise Unreadable(f"subquery reads table {sel.table}, which is not in the spec")
        inner = InnerScope(self, sel.table, sel.table_alias)
        if not isinstance(sel.target, Col):
            raise Unreadable("the membership subquery must select one column")
        kind, val_col = inner.classify(sel.target)
        if kind != "inner":
            raise Unreadable("the membership subquery must select a column of its table")
        w = sel.where
        if w is None:
            raise Unreadable("a membership subquery without a WHERE clause is not a relation lookup")
        nested = None
        if isinstance(w, AnyOf) and w.op == "=" and w.quant == "any" and isinstance(w.arr, ArrayQuery):
            nested = (w.l, w.arr.select)
        elif isinstance(w, InSelect) and not w.negated:
            nested = (w.l, w.select)
        if nested is not None:
            kind, key_col = inner.classify(nested[0])
            if kind != "inner":
                raise Unreadable(f"`{self.src(w)}`: a nested membership must filter a column of {sel.table}")
            base, key_term, hops, where = self.chain(nested[1])
            return base, key_term, hops + [(sel.table, key_col, val_col)], where
        keys: list[tuple[str, dict, Node]] = []
        rest: list[Node] = []
        for c in (w.items if isinstance(w, And) else [w]):
            sides = None
            if isinstance(c, Cmp) and c.op == "=":
                try:
                    sides = [inner.classify(c.l), inner.classify(c.r)]
                except Unreadable:
                    sides = None
            if sides and sorted(k for k, _ in sides) == ["inner", "key"]:
                keys.append((sides[0][1] if sides[0][0] == "inner" else sides[1][1],
                             sides[0][1] if sides[0][0] == "key" else sides[1][1], c))
            else:
                rest.append(c)
        if sel.table_alias == SET_ALIAS:  # #63: the compiler's set helper: every `=` is condition
            (key_col, key_term), more = (None, None), [k[2] for k in keys]
        else:
            (key_col, key_term), more = self.pick_key(keys)
        if key_col is None:
            # #63: no key: the rows of a parent that meet a condition, a set of its keys
            if frozenset((val_col,)) not in self.env.keys.get(sel.table, []):
                raise Unreadable(f"`{self.src(w)}`: the membership WHERE is not `key = <ctx>`, and "
                                 f"{sel.table}.{val_col} is no key of its own, so it is no set of rows either")
            where = self.condition(more + rest, sel.table, sel.table_alias)
            return (sel.table, None, val_col), None, [], where
        where = self.condition(more + rest, sel.table, sel.table_alias)
        return (sel.table, key_col, val_col), key_term, [], where

    def composed_relation(self, base: tuple[str, str, str], hops: list[tuple[str, str, str]],
                          where: dict | None = None) -> str:
        """Declare (or reuse) the composed relation base . hops (D56); every hop's pair must be unique
        in its table (a key of it lies within the pair), else the nesting stays opaque."""
        rel_table, key_col, val_col = base
        if rel_table not in self.env.governed:
            raise Unreadable(f"the relation table {rel_table} is observed (not governed): no relation can be declared "
                             f"on it")
        if key_col is not None and not pair_unique(self.env.keys.get(rel_table, []), key_col, val_col):
            raise Unreadable(f"({key_col}, {val_col}) is not unique in {rel_table} (neither the pair nor one of its "
                             f"columns is a key); a relation is a set of pairs (add a unique constraint on the pair "
                             f"to lift this)")
        if len(hops) > MAX_HOPS:
            raise Unreadable(f"{len(hops)} nested levels; a composed relation has at most {MAX_HOPS} hops")
        for t, k, v in hops:
            if t not in self.env.governed:
                raise Unreadable(f"the nested subquery reads {t}, which is observed (not governed)")
            if not pair_unique(self.env.keys.get(t, []), k, v):  # #43 up a foreign key, #33 a membership table
                raise Unreadable(f"the nested subquery selects {t}.{v} by {t}.{k}, and no primary key or unique "
                                 f"constraint of {t} lies within the pair: a pair may occur in many rows")
            if self.env.tables[t][k][1] or self.env.tables[t][v][1]:
                raise Unreadable(f"the nested subquery steps through {t}({k}, {v}), and a hop's columns must be "
                                 f"NOT NULL")
        of = self.declare(rel_table, key_col, val_col, where)
        sig = (of, tuple(hops))
        for n, c in self.env.composed.items():
            if c == sig:
                return n
        base_sig = (rel_table, key_col, val_col, None if where is None else json.dumps(where, sort_keys=True))
        name = (self.env.composed_names.get((hops[-1][0], len(hops), base_sig))
                or self.env.composed_names.get((hops[-1][0], len(hops)))
                or f"{of}_{hops[-1][0]}".lower()[:63])  # an MLS name
        taken = set(self.env.relations) | set(self.env.composed)
        base_n, i = name, 2
        while name in taken:
            name, i = f"{base_n}_{i}", i + 1
        self.env.composed[name] = sig
        self.env.invalidate()
        return name

    def unmodelled(self, name: str) -> str:
        """#96: why a column the text reads is not in the spec, a field of a composite named as one."""
        c, dot, f = name.partition(".")
        cols = self.env.tables[self.table]
        if dot:
            return (f"field {f} of composite column {c} is not modelled on {self.table} (a field is read only when "
                    f"its type is an MLS type and its column's composite type is the schema's)")
        if any(x.partition(".")[0] == c for x in cols if "." in x):
            return (f"column {c} is a composite column of {self.table}: MLS reads its fields, `({c}).field`, "
                    f"not the whole value")
        return f"column {name} is not modelled on {self.table}"

    # --- terms
    def term(self, node: Node) -> tuple[dict, ColType | None]:
        """A term of the fragment: a column of the table, a context value or a constant."""
        if isinstance(node, Col):
            cols = self.env.tables[self.table]
            if self.scope == "transition" and node.qual in ("old", "new"):
                if node.name not in cols:
                    raise Unreadable(self.unmodelled(node.name))
                return {node.qual: node.name}, cols[node.name][0]
            if node.qual is not None and node.qual != self.table:
                raise Unreadable(f"column {node.qual}.{node.name} is not of table {self.table}")
            if node.name not in cols:
                raise Unreadable(self.unmodelled(node.name))
            return {"col": node.name}, cols[node.name][0]
        if isinstance(node, Cast) and isinstance(node.x, Col) and CAST_TO_MLS.get(node.type) == "text":
            # a varchar column compared as text deparses as (col)::text (D53): the column itself
            t, ty = self.term(node.x)
            if ty == "text":
                return t, ty
        ctx = self.context(node)
        if ctx is not None:
            name, ty = ctx
            return {"ctx": name}, ty
        try:
            return self.const(node)
        except Unreadable:
            pass
        if isinstance(node, Func):
            raise Unreadable(self.func_reason(node))
        if isinstance(node, Select):
            raise Unreadable(f"`{self.src(node)}` is a subquery the fragment has no term for")
        raise Unreadable(f"`{self.src(node)}` is not a term of the fragment")

    def const(self, node: Node) -> tuple[dict, ColType | None]:
        if isinstance(node, Cast):
            ty = CAST_TO_MLS.get(node.type)
            if ty is None and node.type in self.env.enums:  # 'OWNER'::"MemberRole", a label (D59)
                inner, _ = self.const(node.x)
                if not isinstance(inner["const"], str):
                    raise Unreadable(f"`{self.src(node)}` is not a label of {node.type}")
                return inner, "enum"
            if ty is None:
                raise Unreadable(f"a cast to {node.type}, not an MLS type")
            inner, _ = self.const(node.x)
            v = inner["const"]
            if ty in INT_RANGE:
                if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str)
                                                                            and not re.fullmatch(r"-?\d+", v)):
                    raise Unreadable(f"`{self.src(node)}` is not an integer constant")
                return {"const": int(v)}, ty
            if ty == "bool":
                if isinstance(v, bool):
                    return {"const": v}, "bool"
                raise Unreadable(f"`{self.src(node)}` is not a boolean constant")
            if ty == "timestamp":
                raise Unreadable("timestamp constants are not supported (compare with now)")
            if not isinstance(v, str):
                raise Unreadable(f"`{self.src(node)}` is not a {ty} constant")
            return {"const": v}, ty
        if isinstance(node, Str):
            return {"const": node.value}, "text"
        if isinstance(node, Num):
            if not re.fullmatch(r"-?\d+", node.text):
                raise Unreadable(f"{node.text} is not an integer")
            return {"const": int(node.text)}, "int"
        if isinstance(node, Bool):
            return {"const": node.value}, "bool"
        if isinstance(node, Null):
            raise Unreadable("a NULL constant (use IS NULL)")
        raise Unreadable(f"`{self.src(node)}` is not a constant")

    def context(self, node: Node) -> tuple[str, ColType] | None:
        """The context value an expression reads, with the InitPlan wrapper stripped."""
        wrapped = False
        if isinstance(node, Cast) and isinstance(node.x, Select) and node.x.table is None:
            node = Select(**{**vars(node.x), "target": Cast(node.x.target, node.type)})  # #82: `(select ..)::T`
        if isinstance(node, Select) and node.table is None:
            node = node.target
            wrapped = True
        enum_cast = node.type if isinstance(node, Cast) and node.type in self.env.enums else None  # #89
        found = self._context_source(node)
        if found is None:
            return None
        source, cast = found
        if source == CONTEXT_NOW:
            name, ty = CONTEXT_NOW, "timestamp"
        else:
            name = self.env.ctx_by_source(source)
            if name is None:
                raise Unreadable(f"reads {source}, which is not a declared context value (declare it under "
                                 f"identity.context)")
            ty = self.env.context[name][1]
            if enum_cast is not None and self.env.context_enums.get(name) != enum_cast:
                raise Unreadable(f"reads {source} as the enum {enum_cast}, but context value {name} is declared "
                                 + (f"enum {self.env.context_enums[name]}" if name in self.env.context_enums else ty))
            if cast is not None and cast != ty:
                raise Unreadable(f"reads {source} as {SQL_TYPE_OF.get(cast, cast)}, but context value {name} is declared "
                                 f"{ty}")
            if cast is None and ty != "text" and source != "auth.uid":
                raise Unreadable(f"reads {source} as text, but context value {name} is declared {ty}")
        if not wrapped and name != CONTEXT_NOW:
            self.hint(f"`{self.src(node)}` is evaluated per row; the index-friendly form is `(select ...)`, "
                      f"an InitPlan the compiler writes on deploy")
        return name, ty

    def _context_source(self, node: Node) -> tuple[str, ColType | None] | None:
        """(source, cast type) of an identity expression, or None when it is not one."""
        cast: ColType | None = None
        if isinstance(node, Cast):
            if node.type == "text" and isinstance(node.x, (Keyword, Func, BinOp, Cast)):
                cast = "text"
            else:
                cast = CAST_TO_MLS.get(node.type) or ("enum" if node.type in self.env.enums else None)  # #89
                if cast is None:
                    return None
            node = node.x
        if isinstance(node, Func) and not node.args and node.name in ("now", "transaction_timestamp"):
            return CONTEXT_NOW, None
        if isinstance(node, Keyword) and node.name in ("current_timestamp", "localtimestamp"):
            return CONTEXT_NOW, None
        a = self.env.adapter
        if a == "supabase":
            if isinstance(node, Func) and node.name == "auth.uid" and not node.args:
                return "auth.uid", cast or "uuid"
            if isinstance(node, BinOp) and node.op == "->>" and isinstance(node.l, Func) and node.l.name == "auth.jwt" \
                    and not node.l.args:
                claim = node.r.x if isinstance(node.r, Cast) and node.r.type == "text" else node.r
                if isinstance(claim, Str):
                    return f"jwt.claims.{claim.value}", cast
            return None
        if a == "session_setting":
            inner = node
            if isinstance(inner, Func) and inner.name == "nullif" and len(inner.args) == 2 \
                    and self._is_empty_string(inner.args[1]):
                inner = inner.args[0]
            if isinstance(inner, Func) and inner.name == "current_setting" and inner.args:
                arg = inner.args[0]
                if isinstance(arg, Cast) and arg.type == "text":
                    arg = arg.x
                if isinstance(arg, Str) and arg.value.startswith("app."):
                    return arg.value, cast
            return None
        if a == "trusted_function":  # #72: the call, qualified or with its schema on the search path
            if isinstance(node, Func) and not node.args:
                for source, ty in self.env.context.values():
                    if node.name in (source, source.split(".", 1)[-1]):
                        return source, cast or ty
            return None
        if a == "pg_roles":
            if isinstance(node, Keyword) and node.name in ("current_user", "current_role"):
                return "current_user", cast or "text"
            return None
        return None

    @staticmethod
    def _is_empty_string(node: Node) -> bool:
        if isinstance(node, Cast) and node.type == "text":
            node = node.x
        return isinstance(node, Str) and node.value == ""

    def func_reason(self, node: Func) -> str:
        schema, _, base = node.name.rpartition(".")
        if base in self.env.builtins and schema in ("", "pg_catalog"):
            return (f"calls {base}(), a Postgres built-in function: MLS predicates compare columns with constants "
                    f"and context values and call no functions such as string, date or arithmetic ones")
        part = self.env.unread_bodies.get(node.name) or self.env.unread_bodies.get(base)
        if part is not None:
            part = " ".join(part.split())
            return (f"calls {node.name}(), whose body is read inline but holds `"
                    f"{part if len(part) <= 160 else part[:157] + '...'}`, which is not in the fragment")
        return (f"calls {node.name}(), a function the lifter does not read: only a "
                f"one-statement SQL function returning boolean, or a plpgsql one made of `if c then return "
                f"true|false; end if;` guards and one `return`, is read as its body (a SECURITY DEFINER one only "
                f"when its owner bypasses the policies of the tables it reads), with arguments that are the "
                f"row's columns or constants")

    # --- source text
    @property
    def src_text(self) -> str:
        return self._text

    def src(self, node: Node) -> str:
        return self._text[node.start:node.end].strip()


class _ConditionLifter(Lifter):
    """Reads a relation's condition (D61): every part lifts, or the whole membership stays
    opaque; no part becomes an opaque block of its own."""

    def part(self, node: Node, negated: bool) -> dict:
        return self.pred(node, negated)


def _unqualify(node, quals: set[str]):
    """`node` with the columns qualified by the relation table (or its alias) unqualified, so that
    the condition reads as a predicate of that table's rows."""
    if isinstance(node, Col):
        return replace(node, qual=None) if node.qual in quals else node
    if isinstance(node, Node):
        return replace(node, **{f.name: _unqualify(getattr(node, f.name), quals)
                                for f in fields(node) if f.name not in ("start", "end")})
    if isinstance(node, list):
        return [_unqualify(x, quals) for x in node]
    if isinstance(node, tuple):
        return tuple(_unqualify(x, quals) for x in node)
    return node


class InnerScope:
    """Name resolution inside a one-table subquery: a column of the subquery's table, a column
    of the outer row, or a key (context value / constant)."""

    def __init__(self, lifter: Lifter, table: str, alias: str | None):
        self.lifter = lifter
        self.table = table
        self.alias = alias
        self.cols = lifter.env.tables[table]

    def classify(self, node: Node) -> tuple[str, Any]:
        if isinstance(node, Col):
            # an aliased table answers only to its alias (SQL's scoping), so `t.c` inside an
            # aliased subquery over t is the outer row's (an inlined helper's argument, #52)
            if node.qual is not None and node.qual == (self.alias or self.table):
                if node.name not in self.cols:
                    raise Unreadable(f"column {self.table}.{node.name} is not modelled")
                return "inner", node.name
            if node.qual == self.lifter.table:
                return "outer", self.lifter.term(Col(None, node.name))[0]["col"]
            if node.qual is None:
                if node.name in self.cols:
                    return "inner", node.name
                return "outer", self.lifter.term(node)[0]["col"]
            raise Unreadable(f"column {node.qual}.{node.name} is of neither table")
        ctx = self.lifter.context(node)
        if ctx is not None:
            return "key", {"ctx": ctx[0]}
        return "key", self.lifter.const(node)[0]


def lift(text: str, table: str, env: Env, scope: str, make_opaque: MakeOpaque, make_relation: MakeRelation,
         top_is_true: bool = False) -> LiftResult:
    """Lift one expression.  `scope` is "policy" or "check"; `top_is_true` strips the CHECK
    template's outer `IS TRUE`."""
    return Lifter(env, table, scope, make_opaque, make_relation).lift(text, top_is_true)


# ----------------------------------------------------------------------------- helpers
def _is_col(term: dict) -> bool:
    return "col" in term or "old" in term or "new" in term


TRANSITION_BODY = re.compile(
    r"^\s*begin\s+if not \((.*) is true\) then\s+raise exception 'MLS transition \w+ on \w+ violated' "
    r"using errcode = 'check_violation';\s+end if;\s+return new;\s+end\s*$", re.DOTALL)
TRANSITION_TRIGGER = re.compile(r'^CREATE TRIGGER "?(\w+)"? BEFORE UPDATE ON "?(\w+)"? FOR EACH ROW EXECUTE '
                                r'(?:FUNCTION|PROCEDURE) "?(mls_tr_\w+)"?\(\)$')


_LOOKUP_CALL = re.compile(r"\( SELECT (mls_lookup_[a-z_][a-z0-9_]*)\(")
_LOOKUP_BODY = re.compile(r"^\s*select coalesce\(array\((.*)\), '\{\}'\)\s*$", re.S)
_LOOKUP_KEY = re.compile(r"= k(?=\)|\s|$)")


def lookup_calls(text: str, bodies: dict[str, str]) -> list[tuple[str, int, int, str]]:
    """D67: each call `( SELECT mls_lookup_r(<key>) AS mls_lookup_r)::t[]` of one of the compiler's
    lookup helpers (`compile/lookup.py`; `bodies` their name -> source) whose body is the
    template's, as (relation name, start, end, the subquery its body holds with the key in place
    of the parameter, `ARRAY(select value from rel where key = <key> ...)`)."""
    out, i = [], 0
    while (m := _LOOKUP_CALL.search(text, i)) is not None:
        i = m.end()
        name = m.group(1)
        body = _LOOKUP_BODY.match(bodies.get(name, ""))
        depth, j = 1, m.end()
        while j < len(text) and depth:  # the key argument: up to the call's closing parenthesis
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        tail = re.compile(r"\s+AS " + re.escape(name) + r"\)::[a-z ]+\[\]").match(text, j)
        if body is None or tail is None:
            continue
        key = text[m.end():j - 1]
        sub = _LOOKUP_KEY.sub(lambda _: "= " + key, body.group(1), count=1)
        sub = re.sub(r'(\bfrom "[^"]+")', r"\1 " + DEFINER_ALIAS, sub)  # #41: it reads every row
        if not key.strip():  # #63: a helper without a key is a set's: its base level says so
            i_ = sub.rindex(" " + DEFINER_ALIAS)
            sub = sub[:i_] + " " + SET_ALIAS + sub[i_ + len(DEFINER_ALIAS) + 1:]
        out.append((name[len("mls_lookup_"):], m.start(), tail.end(), "ARRAY(" + sub + ")"))
        i = tail.end()
    return out


DEFINER_ALIAS = "mls_definer"  # the FROM alias of an inlined SECURITY DEFINER body (#41)
SET_ALIAS = "mls_definer_set"  # #63: the base level of a set relation's helper, read as a set
_FUNC_SELECT = re.compile(r"^\s*select\s+(.*?)\s*;?\s*$", re.IGNORECASE | re.DOTALL)
_FUNC_FROM = re.compile(r'\b(from|join)\s+((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)(?=\s*(?:where\b|\)|$))',
                        re.IGNORECASE)
_ARG_COL = re.compile(r'^"?([a-z_][a-z0-9_]*)"?$')
_ARG_FIELD = re.compile(r'^\(\s*"?([a-z_][a-z0-9_]*)"?\s*\)\s*\.\s*"?([a-z_][a-z0-9_]*)"?$')
_ARG_INERT = re.compile(r"'(?:[^']|'')*'|::[a-z_ ]+(?:\[\])?|\bARRAY\b|\bauth\.[a-z_]+\(\)|\b(?:true|false|null)\b|"
                        r"\d+(?:\.\d+)?", re.IGNORECASE)


def function_body(src: str) -> str | None:
    """The expression a one-statement `language sql` function returns, `select <expr>`, or None."""
    m = _FUNC_SELECT.match(src)
    if m is None or ";" in m.group(1):
        return None
    return m.group(1)


_COUNT_INTO = re.compile(
    r"^\s*declare\s+(\w+)\s+(?:int|integer|bigint|int4|int8)\s*;\s*begin\s+select\s+count\s*\(\s*(?:\*|1)\s*\)\s+"
    r"(?:into\s+(?P<v1>\w+)\s+from\s+(?P<a>.+?)|from\s+(?P<b>.+?)\s+into\s+(?P<v2>\w+))\s*;\s*"
    r"return\s+(?P<r>\w+)\s*(?:>\s*0|>=\s*1|<>\s*0|!=\s*0)\s*;\s*end\s*;?\s*$", re.IGNORECASE | re.DOTALL)


def count_body(src: str) -> str | None:
    """#90: Supabase's documented RBAC helper, `authorize()`, is plpgsql: it counts the matching rows
    into a variable and returns whether the count is positive.  That body, and only that body, is
    the EXISTS it means: `exists (select 1 from <rest>)`; anything else is None."""
    src = re.sub(r"--[^\n]*", "", src)
    m = _COUNT_INTO.match(src)
    if m is None:
        return None
    var, into = m.group(1).lower(), (m.group("v1") or m.group("v2")).lower()
    rest = m.group("a") or m.group("b")
    if into != var or m.group("r").lower() != var or ";" in rest or re.search(r"\b(group|having|limit)\b", rest, re.I):
        return None
    return f"exists (select 1 from {rest.strip()})"


_PLPGSQL_GUARD = re.compile(r"\s*if\s+(?P<c>.+?)\s+then\s+return\s+(?P<v>true|false)\s*;\s*end\s+if\s*;",
                            re.IGNORECASE | re.DOTALL)
_PLPGSQL_RETURN = re.compile(r"\s*return\s+(?P<e>.+?)\s*;\s*end\s*;?\s*$", re.IGNORECASE | re.DOTALL)


def _balanced(text: str) -> bool:
    depth, quote = 0, False
    for ch in text:
        if ch == "'":
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not quote


def plpgsql_body(src: str) -> str | None:
    """#95: a plpgsql body made of guards `if c then return true|false; end if;` and one final
    `return e;` is the expression it returns: from the end, a guard returning false is
    `(c) is not true and (rest)`, one returning true `(c) is true or (rest)` (an IF whose condition is
    UNKNOWN is not taken, and a NULL `e` is returned as NULL, as the connectives keep it).  Anything
    else in the body (a declaration, an assignment, another statement) is None."""
    src = re.sub(r"--[^\n]*", "", src)
    m = re.match(r"\s*begin\b", src, re.IGNORECASE)
    if m is None:
        return None
    i, guards = m.end(), []
    while (g := _PLPGSQL_GUARD.match(src, i)) is not None:
        if not _balanced(g.group("c")) or re.search(r"\b(case|then|return)\b", g.group("c"), re.IGNORECASE):
            return None
        guards.append((g.group("c"), g.group("v").lower() == "true"))
        i = g.end()
    r = _PLPGSQL_RETURN.match(src, i)
    if r is None or ";" in r.group("e") or not _balanced(r.group("e")) \
            or re.search(r"\b(case|then|return)\b", r.group("e"), re.IGNORECASE):
        return None
    expr = r.group("e")
    for c, value in reversed(guards):
        expr = f"(({c}) is true or ({expr}))" if value else f"(({c}) is not true and ({expr}))"
    return expr


def split_args(text: str) -> list[str]:
    """A comma-separated list of SQL expressions (a function's argument defaults, as
    `pg_get_expr(proargdefaults)` prints them), split at its top-level commas."""
    out, depth, quote, start = [], 0, False, 0
    for j, ch in enumerate(text):
        if ch == "'":
            quote = not quote
        elif not quote and ch in "([":
            depth += 1
        elif not quote and ch in ")]":
            depth -= 1
        elif not quote and ch == "," and depth == 0:
            out.append(text[start:j].strip())
            start = j + 1
    out.append(text[start:].strip())
    return [x for x in out if x]


def inline_functions(text: str, table: str, columns: set[str], functions: dict[str, dict],
                     calls: list[tuple[str, str]] | None = None) -> str:
    """#52: every call of a one-statement SQL helper (`functions`: name -> {"params", "expr"},
    `adopt._read`) replaced by the expression its body returns, the arguments in place of the
    parameters, so that `has_org_role(org_id, ARRAY['owner'])` reads as the EXISTS it is.  An
    argument is the policy table's column (qualified with the table, the helper's own FROM
    aliased, so that it stays the outer row's) or holds no column at all (constants, an array of
    them, `auth.uid()`); a call with any other argument stays as it is, for the lifter to report.
    Helpers that call helpers are inlined to a depth of three.  `calls` collects (the inlined
    expression, the call it replaced), for `restore_calls`."""
    for _ in range(3):
        out, i, changed = [], 0, False
        pat = re.compile(r'(?<![\w."])(' + "|".join(map(re.escape, sorted(functions, key=len, reverse=True)))
                         + r')\s*\(') if functions else None
        while pat is not None and (m := pat.search(text, i)) is not None:
            f = functions[m.group(1)]
            args, j, depth, start, quote = [], m.end(), 1, m.end(), False
            while j < len(text) and depth:
                ch = text[j]
                if ch == "'":
                    quote = not quote
                elif not quote and ch in "([":
                    depth += 1
                elif not quote and ch in ")]":
                    depth -= 1
                elif not quote and ch == "," and depth == 1:
                    args.append(text[start:j])
                    start = j + 1
                j += 1
            args.append(text[start:j - 1])
            args = [a.strip() for a in args if a.strip() or f["params"]]
            # #64: a shorter call takes the defaults of the parameters it leaves out
            missing = (f.get("defaults") or [None] * len(f["params"]))[len(args):]
            if len(args) < len(f["params"]) and all(d is not None for d in missing):
                args = args + list(missing)
            subst = _function_args(args, table, columns) if len(args) == len(f["params"]) else None
            if subst is None:
                out.append(text[i:j])
                i = j
                continue
            start_at = m.start()
            if f.get("set"):  # #74: `select f(..) [as x]` is the body's select; a call elsewhere stays
                before = re.search(r"\bselect\s+$", text[:m.start()], re.IGNORECASE)
                after = re.match(r"\s+as\s+\w+", text[j:], re.IGNORECASE)
                if before is None or not re.match(r"\s*(?:as\s+\w+\s*)?\)", text[j:], re.IGNORECASE):
                    out.append(text[i:j])
                    i = j
                    continue
                start_at = before.start()
                j += after.end() if after else 0
            alias = DEFINER_ALIAS if f.get("definer") else "mls_inline"
            body = _FUNC_FROM.sub(lambda t: f"{t.group(1)} {t.group(2)} {alias}", _unalias(f["expr"], alias))
            for n, (param, arg) in enumerate(zip(f["params"], subst), start=1):
                body = re.sub(r'(?<![\w."$])(?:"' + re.escape(param) + '"|' + re.escape(param) + r')(?![\w"])|\$'
                              + str(n) + r'(?!\d)', lambda _: f"({arg})", body) if param else re.sub(
                                  r'\$' + str(n) + r'(?!\d)', lambda _: f"({arg})", body)
            if f.get("set"):
                body = "SELECT " + body
            out.append(text[i:start_at] + (body if f.get("set") else "(" + body + ")"))
            if calls is not None:
                calls.append((body, text[start_at:j]))
            i, changed = j, True
        text = "".join(out) + text[i:]
        if not changed:
            break
    return text


def restore_calls(sql: str, calls: list[tuple[str, str]]) -> str | None:
    """An opaque fragment of an inlined text with each whole inlined helper put back as its call
    (an opaque block must not run a SECURITY DEFINER body as the invoker), or None when the
    fragment holds only part of one: then the text is read again without inlining."""
    for body, call in reversed(calls):
        for form in (f"({body})", body):
            sql = sql.replace(form, call)
    if "mls_inline" in sql or DEFINER_ALIAS in sql or any(sql.strip() in body for body, _ in calls if sql.strip() != body):
        return None
    return sql


_FROM_ALIAS = re.compile(r'\b(from|join)\s+("?[a-z_][a-z0-9_]*"?)\s+(?:as\s+)?(?!(?:where|join|on|inner|left|right|'
                         r'full|cross|group|order|limit|union)\b)([a-z_][a-z0-9_]*)\b', re.IGNORECASE)


def _unalias(expr: str, alias: str) -> str:
    """#64: a helper body's own table alias (`from account_user wu where wu.user_id = ...`) taken
    out and its columns qualified with `alias`, the one the inlined FROM gets to say how it reads
    (`mls_definer`, `mls_inline`); #90: so are columns qualified with the bare table's name."""
    for m in list(_FROM_ALIAS.finditer(expr)):
        table, own = m.group(2), m.group(3)
        expr = re.sub(rf'(?<![\w."]){re.escape(own)}\.', f"{alias}.", expr)
        expr = expr.replace(m.group(0), f"{m.group(1)} {table}", 1)
    for m in list(_FUNC_FROM.finditer(expr)):  # #90: `from role_permissions where role_permissions.role = ..`
        table = m.group(2).rsplit(".", 1)[-1].strip('"')
        expr = re.sub(rf'(?<![\w."]){re.escape(table)}\.(?=[a-z_"])', f"{alias}.", expr)
    return expr


def _function_args(args: list[str], table: str, columns: set[str]) -> list[str] | None:
    """The arguments as they read inside the helper's body, or None when one cannot be placed."""
    out = []
    for a in args:
        c = _ARG_COL.match(a)
        fld = _ARG_FIELD.match(a)
        if c is not None and c.group(1) in columns:
            out.append(f'"{table}"."{c.group(1)}"')
        elif fld is not None and f"{fld.group(1)}.{fld.group(2)}" in columns:  # #94: `(c).f`
            out.append(f'("{table}"."{fld.group(1)}")."{fld.group(2)}"')
        elif re.search(r"[a-z_]", _ARG_INERT.sub(" ", a), re.IGNORECASE) is None:
            out.append(a)
        else:
            return None
    return out


def inline_lookups(text: str, bodies: dict[str, str]) -> str:
    """Every lookup helper call in `text` replaced by the subquery it stands for, which the lifter
    reads as the membership it is.  A call of a helper whose body is not the template's stays as it
    is (the lifter reports it as a function it does not read)."""
    for _, start, end, sub in reversed(lookup_calls(text, bodies)):
        text = text[:start] + sub + text[end:]
    return text


def transition_expr(trigger_def: str, function: str, body: str) -> str | None:
    """The predicate text of a trigger the transition template emitted (`compile/transition.py`):
    `BEFORE UPDATE ... FOR EACH ROW EXECUTE FUNCTION mls_tr_<table>_<name>()` whose body is the
    template's `if not ((p) is true) then raise`.  None for any other trigger: a hand-written
    trigger is never read (D34)."""
    m = TRANSITION_TRIGGER.match(trigger_def.strip())
    if m is None or m.group(3) != function or m.group(3) != f"mls_tr_{m.group(2)}_{m.group(1)}":
        return None
    b = TRANSITION_BODY.match(body)
    return b.group(1) if b else None



_ID = r'"?(\w+)"?'
INCLUSION_TRIGGER = re.compile(rf'^CREATE CONSTRAINT TRIGGER {_ID} AFTER INSERT OR UPDATE OF {_ID}, {_ID} ON {_ID} '
                               r'DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE (?:FUNCTION|PROCEDURE) '
                               rf'{_ID}\(\)$')
INCLUSION_TARGET_TRIGGER = re.compile(rf'^CREATE CONSTRAINT TRIGGER {_ID} AFTER UPDATE OR DELETE ON {_ID} '
                                      r'DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE (?:FUNCTION|PROCEDURE) '
                                      rf'{_ID}\(\)$')
INCLUSION_BODY = re.compile(
    rf'^\s*begin\s+if new\.{_ID} is null or new\.{_ID} is null then return null; end if;\s+'
    rf'if not exists \(select 1 from {_ID} where .*? then return null; end if;\s+'
    rf'perform 1 from {_ID} where {_ID} = new\."?\1"? and {_ID} = new\."?\2"? and \((.*)\) is true for share;\s+'
    r"if not found then\s+raise exception '[^']* is not in (\w+)'[^;]*;\s+end if;\s+return null;\s+end\s*$", re.DOTALL)


@dataclass
class InclusionText:
    name: str
    columns: tuple[str, str]
    target: str      # the relation's table
    key: str
    value: str
    condition: str   # the condition's text, read of the target's rows
    relation: str    # the relation's name, as its message gives it


def inclusion_parts(trigger_def: str, function: str, body: str) -> InclusionText | str | None:
    """#54: the inclusion the compiler's referencing-side trigger checks (`compile/fk.py`), or
    "target" for its trigger on the relation's table (part of the same rule), or None for any
    other trigger: a hand-written trigger is never read."""
    d = trigger_def.strip()
    m = INCLUSION_TARGET_TRIGGER.match(d)
    if m is not None:
        return "target" if m.group(3) == function == f"mls_incl_{m.group(1)}" and m.group(1).endswith("_target") \
            else None
    m = INCLUSION_TRIGGER.match(d)
    if m is None or m.group(5) != function or function != f"mls_incl_{m.group(4)}_{m.group(1)}":
        return None
    b = INCLUSION_BODY.match(body)
    if b is None or (b.group(1), b.group(2)) != (m.group(2), m.group(3)):
        return None
    return InclusionText(m.group(1), (m.group(2), m.group(3)), b.group(4), b.group(5), b.group(6), b.group(7),
                         b.group(8))


GUARD_BODY = re.compile(
    r"^\s*begin\s+if \((.*)\) is true and \(to_jsonb\(new\) - array\[(.*?)\]::text\[\]\) is distinct from "
    r"\(to_jsonb\(old\) - array\[\2\]::text\[\]\) then\s+raise exception 'MLS column rule \w+ on \w+ violated' "
    r"using errcode = 'insufficient_privilege';\s+end if;\s+return new;\s+end\s*$", re.DOTALL)
GUARD_TRIGGER = re.compile(r'^CREATE TRIGGER "?0_mls_cg_(\w+)"? BEFORE UPDATE ON "?(\w+)"? FOR EACH ROW '
                           r"WHEN \(+CURRENT_USER = '(\w+)'::name\)+ EXECUTE (?:FUNCTION|PROCEDURE) "
                           r'"?(mls_cg_\w+)"?\(\)$')
_OLD_QUAL = re.compile(r"""(?<![\w"'.])old\.(?=["\w])""")


@dataclass
class GuardText:
    name: str
    role: str
    kept: list[str]  # the columns the comparison leaves out (the rule's, and a hierarchy depth)
    condition: str   # the condition's text, read of the row (`old.` dropped)


def guard_parts(trigger_def: str, function: str, body: str) -> GuardText | None:
    """#57: the parts of a trigger the column guard template emitted (`compile/guard.py`):
    `0_mls_cg_<name>` BEFORE UPDATE ... WHEN (current_user = role) calling
    `mls_cg_<table>_<name>()`, whose body compares the row as jsonb without the listed columns
    when the condition, read of the old row, is true.  None for any other trigger (a hand-written
    one is never read)."""
    m = GUARD_TRIGGER.match(trigger_def.strip())
    if m is None or m.group(4) != function or function != f"mls_cg_{m.group(2)}_{m.group(1)}":
        return None
    b = GUARD_BODY.match(body)
    if b is None:
        return None
    kept = re.findall(r"'((?:[^']|'')*)'", b.group(2))
    return GuardText(m.group(1), m.group(3), [k.replace("''", "'") for k in kept], _OLD_QUAL.sub("", b.group(1)))


def scan_columns(sql: str, cols: dict[str, Any]) -> set[str]:
    """The modelled columns the text names (word boundaries; `table.col` and bare `col`)."""
    return {c for c in cols if re.search(r'(?<![\w."])"?' + re.escape(c) + r'"?(?![\w"])', sql)}


def context_markers(env: Env) -> dict[str, re.Pattern]:
    """What a text must contain to read each context value (the opaque signature scan)."""
    out: dict[str, re.Pattern] = {}
    for n, (source, _) in env.context.items():
        if source == "auth.uid":
            out[n] = re.compile(r"auth\.uid\(\)")
        elif source.startswith("jwt.claims."):
            out[n] = re.compile(r"auth\.jwt\(\)\s*->>\s*'" + re.escape(source[len("jwt.claims."):]) + "'")
        elif source.startswith("app."):
            out[n] = re.compile(r"current_setting\('" + re.escape(source) + "'")
        elif source == "current_user":
            out[n] = re.compile(r"\bcurrent_user\b|\bsession_user\b", re.IGNORECASE)
    return out


def columns_of(node: Node, out: set[str]) -> set[str]:
    """Every column name a parsed tree references (any qualification)."""
    if isinstance(node, Col):
        out.add(node.name)
    for f in getattr(node, "__dataclass_fields__", {}):
        v = getattr(node, f)
        if isinstance(v, Node):
            columns_of(v, out)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, Node):
                    columns_of(x, out)
    return out


def nullable_columns(text: str, cols: dict[str, tuple[ColType, bool]]) -> set[str] | None:
    """The nullable columns a bare CHECK expression references, or None when it does not parse."""
    try:
        tree = parse(text)
    except Unreadable:
        return None
    return {c for c in _unknown_columns(tree, set()) if c in cols and cols[c][1]}


def _unknown_columns(node: Node, out: set[str]) -> set[str]:
    """`columns_of` without the columns only tested by IS [NOT] NULL, which is never UNKNOWN (#71)."""
    if isinstance(node, IsNull) and isinstance(node.x, Col):
        return out
    if isinstance(node, Col):
        out.add(node.name)
    for f in getattr(node, "__dataclass_fields__", {}):
        v = getattr(node, f)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, Node):
                _unknown_columns(x, out)
    return out


def now_between_shape(p: dict) -> dict:
    """The compiled now_between is `(f is null or f <= now) and (u is null or now < u)`; fold the
    lifted `or`s back into the construct, anywhere in the predicate."""
    if "and" in p:
        out: list[dict] = []
        pending: dict | None = None  # a `from` half waiting for its `until`
        for x in p["and"]:
            f, u = _half(x)
            if f is None and u is None:
                if pending is not None:
                    out.append(pending)
                    pending = None
                out.append(now_between_shape(x))
            elif f is not None:
                if pending is not None:
                    out.append(pending)
                pending = {"now_between": {"from": f, "until": None}}
            else:
                if pending is not None:
                    pending["now_between"]["until"] = u
                    out.append(pending)
                    pending = None
                else:
                    out.append({"now_between": {"from": None, "until": u}})
        if pending is not None:
            out.append(pending)
        return out[0] if len(out) == 1 else {"and": out}
    if "or" in p:
        f, u = _half(p)
        if f is not None or u is not None:
            return {"now_between": {"from": f, "until": u}}
        return {"or": [now_between_shape(x) for x in p["or"]]}
    if "not" in p:
        return {"not": now_between_shape(p["not"])}
    return p


def _half(p: dict | None) -> tuple[dict | None, dict | None]:
    """(from, until) when `p` is `{or: [{is_null: c}, {cmp: [c, <=, now]}]}` / `{cmp: [c, >, now]}`."""
    if p is None or "or" not in p or len(p["or"]) != 2:
        return None, None
    a, b = p["or"]
    if "is_null" not in a or "cmp" not in b:
        return None, None
    c = a["is_null"]
    l, op, r = b["cmp"]
    if l != c or r != {"ctx": CONTEXT_NOW} or "col" not in c:
        return None, None
    if op == "<=":
        return c, None
    if op == ">":
        return None, c
    return None, None


_FRESH = re.compile(r"^\s*(?:(?:public\.|extensions\.)?(?:gen_random_uuid|uuid_generate_v1|uuid_generate_v1mc|"
                    r"uuid_generate_v4)\(\)|nextval\(.*\))\s*$", re.IGNORECASE)


def read_default(expr: str, table: str, column: str, env: Env) -> dict | str | None:
    """#76: a column default as the spec declares it: "fresh" for a generated value (a uuid
    generator, a sequence), else the term the lifter reads on the right of `column = <default>`
    (a constant, `now()`, a context value's SQL), or None."""
    if _FRESH.match(expr):
        return "fresh"
    try:
        r = lift(f'("{column}" = ({expr}))', table, env, "policy", lambda *a: "mls_default", lambda *a, **k: None)
    except Exception:  # an unreadable default is left out, never guessed
        return None
    p = r.pred if r.kind == "lifted" else None
    if p and "cmp" in p and p["cmp"][0] == {"col": column} and p["cmp"][1] == "=" \
            and isinstance(p["cmp"][2], dict) and set(p["cmp"][2]) <= {"ctx", "const"}:
        return p["cmp"][2]
    return None

