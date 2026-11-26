"""SQL text helpers shared by the compiler, the identity adapters and the Postgres tools."""
from __future__ import annotations


def q(ident: str) -> str:
    """Quote an identifier: a spec name is the catalog name exactly, whatever its case (the checker
    restricts catalog names to ASCII letters, digits and underscores)."""
    return '"' + ident.replace('"', '""') + '"'


def col(name: str, row: str | None = None) -> str:
    """#94: a column read in an expression, of `row` (`old`, `new`) when given.  A field column's
    name is `c.f` (a catalog name has no dot) and reads as `("c")."f"`."""
    c, dot, f = name.partition(".")
    base = q(c) if row is None else f"{row}.{q(c)}"
    return f"({base}).{q(f)}" if dot else base


def target(name: str) -> str:
    """#94: a column as an INSERT's column list and an UPDATE's SET name it: a field is `"c"."f"`."""
    c, dot, f = name.partition(".")
    return f"{q(c)}.{q(f)}" if dot else q(c)
