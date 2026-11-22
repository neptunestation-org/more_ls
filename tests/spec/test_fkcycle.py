"""#35: an inclusion closing a cycle of foreign keys checked after each statement is refused, and
a deferred one is accepted, rendered, read back, explained and left out of the proofs' assumptions."""
from __future__ import annotations

from mls.english import rule as rule_line
from mls.props.obligations import relation_axioms
from mls.logic.tvl import Encoder
from mls.spec import check_spec
from mls.spec.model import Spec
from mls.spec.syntax import parse
from mls.terse import render
from tests.spec.test_check import base, errors


def cyclic(deferred: str | None = None) -> dict:
    """memberships ⊆ admin_of (R10) next to the example's admins ⊆ member_of (R8): a cycle."""
    d = base()
    d["rules"].append({"id": "R10", "kind": "inclusion", "name": "member_is_admin", "table": "memberships",
                       "columns": ["user_id", "tenant_id"], "relation": "admin_of", "on_delete": "restrict"})
    if deferred:
        next(r for r in d["rules"] if r["id"] == deferred)["deferred"] = True
    return d


def test_an_inclusion_closing_an_immediate_cycle_is_refused_once_with_the_deferred_fix():
    errs = errors(cyclic())
    assert len(errs) == 1, errs
    e = errs[0]
    i = next(j for j, r in enumerate(cyclic()["rules"]) if r["id"] == "R8")
    assert e.path == f"$.rules[{i}]"
    assert "closes a cycle of foreign keys" in e.message and "admins -> memberships -> admins" in e.message
    assert "member_is_admin on memberships" in e.message and "deferred" in e.fix


def test_deferring_either_inclusion_breaks_the_cycle():
    assert errors(cyclic("R8")) == []
    assert errors(cyclic("R10")) == []


def test_deferred_renders_parses_and_reads_in_english():
    spec = check_spec(Spec.model_validate(cyclic("R10")))
    text = render(spec)
    assert "(user_id, tenant_id) in admin_of on_delete restrict deferred" in text
    assert parse(text) == spec
    line = rule_line(spec, spec.rule("R10"))
    assert "checked when the transaction commits" in line
    assert "commits" not in rule_line(spec, spec.rule("R8"))


def test_the_proofs_do_not_assume_a_deferred_inclusion():
    """A policy runs while a deferred inclusion may still be unmet, so it is no axiom."""
    immediate = check_spec(Spec.model_validate(base()))
    d = base()
    next(r for r in d["rules"] if r["id"] == "R8")["deferred"] = True
    deferred = check_spec(Spec.model_validate(d))
    n = len(relation_axioms(immediate, Encoder(immediate)))
    assert len(relation_axioms(deferred, Encoder(deferred))) == n - 1
