"""The leakproof lint reads pg_proc.proleakproof: text LIKE is reported, integer equality is not."""
from __future__ import annotations

import psycopg
import pytest

from mls.pg.lint import lint_catalog, lint_static

pytestmark = pytest.mark.pg


def test_lint_catalog_matches_static_expectations(pg_dsn, example_spec):
    with psycopg.connect(pg_dsn) as conn:
        warnings = lint_catalog(example_spec, conn)
    # the example's protected table (docs) has no text column, so nothing to warn about
    assert warnings == [] and lint_static(example_spec) == []
    from tests.templates.specs import base, make

    d = base()
    d["tables"]["docs"]["columns"]["slug"] = {"type": "text", "nullable": True}
    spec = make(d)
    with psycopg.connect(pg_dsn) as conn:
        warnings = lint_catalog(spec, conn)
    w = next(w for w in warnings if w.column == "slug")
    assert "~~" in w.operators and "=" not in w.operators
    assert "not leakproof" in str(w)


def test_array_columns_warn_as_the_catalog_says(pg_dsn):
    """#65: an array column's operators are anyarray's; the static list is what the catalog reports."""
    from tests.templates.specs import array_spec

    spec = array_spec()
    with psycopg.connect(pg_dsn) as conn:
        live = {(w.table, w.column): sorted(w.operators) for w in lint_catalog(spec, conn)}
    static = {(w.table, w.column): sorted(w.operators) for w in lint_static(spec)}
    assert live[("team_members", "roles")] == static[("team_members", "roles")], live
    assert live[("team_members", "perms")] == static[("team_members", "perms")], live
