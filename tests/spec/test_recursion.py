"""D66/D67: which lookups would recurse in Postgres, and so go through a helper (fast, no Docker;
`tests/templates/test_recursion.py` replays the shapes on PG 15–18)."""
from __future__ import annotations

from mls.compile import compile_spec
from mls.spec import check_spec
from mls.spec.recursion import routed
from mls.spec.syntax import parse
from tests.templates.test_recursion import SCHEMA, SHAPES


def _spec(rules: list[str]):
    return check_spec(parse(SCHEMA % "\n".join(f"  {r}" for r in rules)))


def test_the_lookup_that_closes_a_cycle_is_routed():
    """Members read a through b's relation, and a delete on b reads a's: the delete's lookup reads
    a under its SELECT policy, which reads b again.  The delete's lookup is the one routed (the
    SELECT policy's alone closes no cycle), and only it calls the helper."""
    spec = _spec(["R1 policy p on a: authenticated select permissive using rel_b(@uid, b_id)",
                  "R2 policy q on b: authenticated delete permissive using rel_a(@uid, a_id)"])
    assert routed(spec) == {("b", "rel_a")}
    sql = compile_spec(spec).sql()
    assert '("a_id" = any ((select "mls_lookup_rel_a"((select auth.uid())))::uuid[]))' in sql
    assert '"b_id" = any (array(select "id" from "b"' in sql
    assert "mls_rel_rel_a" not in sql  # no visibility policy for a routed lookup


def test_every_shape_that_would_recurse_is_routed_and_no_other():
    for name, (recurses, rules) in SHAPES.items():
        assert bool(routed(_spec(rules))) == recurses, name


def test_a_lookup_on_its_own_table_is_routed_for_every_command():
    spec = _spec(["R1 policy p on a: authenticated select permissive using rel_a(@uid, b_id)",
                  "R2 policy q on a: authenticated delete permissive using rel_a(@uid, b_id)"])
    assert routed(spec) == {("a", "rel_a")}


def test_the_routing_does_not_depend_on_the_order_of_the_rules():
    """The import lists policies by table: the same policies in another order route the same
    lookups, so a deployed spec reads back to the same helpers."""
    from tests.templates import specs

    spec = specs.up_spec()
    d = spec.model_dump(mode="json", by_alias=True, exclude_none=True)
    d["rules"] = d["rules"][::-1]
    from mls.spec.model import Spec

    assert routed(check_spec(Spec.model_validate(d))) == routed(spec)


def test_a_lookup_keyed_by_a_constant_goes_through_a_helper_and_exposes_nothing(monkeypatch):
    """D70: `done_task(true, task_id)` would need the visibility policy `done = true` for anon, every
    finished task whoever asks; routed, anon reads no task and the least-privilege bound proves.
    Unrouted (the old rule), the same spec is refuted on that bound."""
    from mls.props.effective import implicit_policies
    from mls.props.runner import run_all
    from mls.spec import recursion
    from tests.templates import specs

    spec = specs.storefront_spec()
    assert ("comments", "done_task") in recursion.routed(spec)
    assert not [p for p in implicit_policies(spec) if p.role == "anon"]
    assert {r.id: r.verdict for r in run_all(spec)}["P7"] == "PROVED"

    plain = specs.storefront_spec()  # a fresh spec: the routing and implicit policies are cached per spec
    monkeypatch.setattr(recursion, "routed", lambda spec: frozenset())
    assert {r.id: r.verdict for r in run_all(plain)}["P7"] == "REFUTED"
