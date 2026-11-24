"""Expected PROVED / REFUTED verdicts and counterexample shapes (ROADMAP M1 acceptance)."""
from __future__ import annotations

import copy
import json

import pytest

from mls.compile import compile_spec
from mls.errors import CompileError
from mls.logic.solve import solve
from mls.logic.term import not_
from mls.logic.tvl import Encoder
from mls.props.runner import run_all, run_property
from mls.spec import check_spec
from mls.spec.model import Spec
from tests.conftest import EXAMPLE


def base() -> dict:
    return json.loads(EXAMPLE.read_text())


def make(d: dict) -> Spec:
    spec = Spec.model_validate(d)
    spec = check_spec(spec)
    return spec


def verdicts(spec: Spec) -> dict[str, str]:
    return {r.id: r.verdict for r in run_all(spec)}


def test_example_all_proved(example_spec):
    assert set(verdicts(example_spec).values()) == {"PROVED"}


def test_isolation_refuted_by_owner_read():
    """Only without the owner_in_tenant FK: with it, an owner is provably a member."""
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] != "R7"]
    d["properties"][3]["invariants"] = [{"rule": "R6"}, {"rule": "R8"}]
    d["rules"].append({"id": "R10", "kind": "policy", "name": "owner_read", "table": "docs",
                       "role": "authenticated", "command": "select", "mode": "permissive",
                       "using": {"cmp": [{"col": "owner_id"}, "=", {"ctx": "uid"}]}})
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    assert r.verdict == "REFUTED"
    bad = next(o for o in r.obligations if o.verdict == "REFUTED")
    sc = bad.scenario
    assert sc.rows["r"]["values"]["owner_id"] == sc.context["uid"]
    assert [sc.context["uid"], sc.rows["r"]["values"]["tenant_id"]] not in sc.relations["member_of"]
    d["rules"].append({"id": "R7", "kind": "inclusion", "name": "owner_in_tenant", "table": "docs",
                       "columns": ["owner_id", "tenant_id"], "relation": "member_of", "on_delete": "restrict"})
    assert run_property(make(d), spec.properties[0]).verdict == "PROVED"


def test_tenant_move_refuted_without_transition_proved_with_it(example_spec):
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] != "R9"]
    spec = make(d)
    r = run_property(spec, next(p for p in spec.properties if p.id == "P2"))
    assert r.verdict == "REFUTED"
    sc = r.obligations[0].scenario
    old, new = sc.rows["old"]["values"], sc.rows["new"]["values"]
    assert old["tenant_id"] != new["tenant_id"]
    uid = sc.context["uid"]
    assert [uid, old["tenant_id"]] in sc.relations["member_of"]
    assert [uid, new["tenant_id"]] in sc.relations["member_of"]
    assert verdicts(example_spec)["P2"] == "PROVED"


def inline_invariants() -> list[dict]:
    return [
        {"rule": "R6"},
        {"table": "docs", "predicate": {"or": [{"is_null": {"col": "owner_id"}},
                                               {"member": {"relation": "member_of", "key": {"col": "owner_id"},
                                                           "value": {"col": "tenant_id"}}}]}},
        {"table": "admins", "predicate": {"member": {"relation": "member_of", "key": {"col": "user_id"},
                                                     "value": {"col": "tenant_id"}}}},
    ]


@pytest.mark.parametrize("drop,expected,failing", [
    (["R7", "R8"], "REFUTED", {"docs", "admins"}),
    (["R8"], "REFUTED", {"admins"}),
    ([], "PROVED", set()),
])
def test_membership_delete_induction_needs_both_fks(drop, expected, failing):
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] not in drop]
    d["properties"] = [{"id": "P4", "template": "invariant_preserved", "invariants": inline_invariants()}]
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    assert r.verdict == expected
    refuted = [o for o in r.obligations if o.verdict == "REFUTED"]
    deletes = [o for o in refuted if "delete on memberships" in o.name]
    tables = {r["table"] for o in deletes for n, r in o.scenario.rows.items() if n.startswith("row_")}
    assert tables == failing
    # without the FK, writes to the invariant's own table can also break it
    assert {o.name.split(" preserves")[0] for o in refuted if o not in deletes} <= {
        "insert on docs", "update on docs", "insert on admins", "update on admins",
        "update on memberships"}
    for o in deletes:
        deleted = o.scenario.rows["old"]["values"]
        assert [deleted["user_id"], deleted["tenant_id"]] in o.scenario.relations["member_of@before"]
        assert [deleted["user_id"], deleted["tenant_id"]] not in o.scenario.relations["member_of@after"]


def test_naive_check_admits_null_rows(example_spec):
    """CHECK (p) admits rows where p is not FALSE; CHECK ((p) IS TRUE) admits iff p is TRUE."""
    from pydantic import TypeAdapter
    from mls.spec.model import Pred

    pred = TypeAdapter(Pred).validate_python(
        {"or": [{"cmp": [{"col": "archived"}, "=", {"const": 0}]}, {"cmp": [{"col": "archived"}, "=", {"const": 1}]}]})
    enc = Encoder(example_spec)
    t, f = enc.tf(pred, "r", "docs")
    naive = solve([not_(f)], t)
    assert naive.status == "refuted"
    assert naive.model.var("r.archived.null", "Bool") is True
    assert solve([t], t).proved


def test_write_subset_read_refuted_when_check_is_weaker():
    d = base()
    d["rules"][3]["check"] = {"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "tenant_id"}}}
    spec = make(d)
    r = run_property(spec, next(p for p in spec.properties if p.id == "P5"))
    assert r.verdict == "REFUTED"
    sc = next(o.scenario for o in r.obligations if o.verdict == "REFUTED")
    assert sc.rows["new"]["values"]["level"] > sc.context["clearance"]


def test_least_privilege_refuted_lists_extra_privilege():
    d = base()
    d["properties"] = [{"id": "P6", "template": "least_privilege",
                        "allowed": {"authenticated": {"docs": ["select"], "memberships": ["select"], "admins": ["select"]}}}]
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    assert r.verdict == "REFUTED"
    assert "authenticated may insert all columns of docs" in r.obligations[0].message


def test_monotonicity_refuted_by_opaque_reading_relation():
    d = base()
    d["opaques"] = {"outsider": {"table": "docs", "columns": ["tenant_id"], "context": ["uid"],
                                 "relations": ["member_of"],
                                 "sql": "not exists (select 1 from memberships m where m.user_id = {ctx:uid} and m.tenant_id = tenant_id)"}}
    d["rules"].append({"id": "R10", "kind": "policy", "name": "outsider_public", "table": "docs",
                       "role": "authenticated", "command": "select", "mode": "permissive",
                       "using": {"and": [{"opaque": "outsider"}, {"cmp": [{"col": "level"}, "=", {"const": 0}]}]}})
    spec = make(d)
    r = run_property(spec, next(p for p in spec.properties if p.id == "P3"))
    assert r.verdict == "REFUTED"
    assert r.conditional_on == ["outsider"]
    # full opaque reporting: the summary counts conditional proofs and the assumptions quote the SQL
    from mls.props.report import to_json, to_markdown
    member = {"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "tenant_id"}}}
    d["properties"].append({"id": "C1", "template": "custom", "table": "docs", "role": "authenticated",
                            "command": "select", "goal": {"or": [{"opaque": "outsider"}, member]}})
    spec = make(d)
    results = run_all(spec)
    by_id = {x.id: x for x in results}
    # conditional only where the proof needs the block (#27): C1 holds for the rows R10 admits
    # because the goal reads the same block on the same row; write ⊆ read and the lower bounds
    # hold through the other policies whatever the block returns
    assert by_id["C1"].verdict == "PROVED" and by_id["C1"].conditional_on == ["outsider"]
    for pid in ("P5", "P7", "P8"):
        assert by_id[pid].verdict == "PROVED" and by_id[pid].conditional_on == [], pid
    n_cond = sum(1 for x in results if x.verdict == "PROVED" and x.conditional_on)
    assert n_cond == 1
    md = to_markdown(spec, results)
    assert f"({n_cond} conditional on opaque blocks)" in md
    assert "opaque block 'outsider' on docs (columns tenant_id; context uid; relations member_of) is unverified SQL: `not exists" in md
    assert to_json(spec, results)["summary"]["CONDITIONAL"] == n_cond
    # and isolation is now conditional on the block: the block could admit any row
    p1 = run_property(spec, spec.properties[0])
    assert p1.verdict == "REFUTED" and p1.conditional_on == ["outsider"]


def test_custom_property():
    d = base()
    d["properties"] = [{"id": "C1", "template": "custom", "table": "docs", "role": "authenticated",
                        "command": "select", "goal": {"not": {"cmp": [{"col": "archived"}, "=", {"const": 1}]}}},
                       {"id": "C2", "template": "custom", "table": "docs", "role": "authenticated",
                        "command": "select", "goal": {"is_null": {"col": "archived"}}}]
    spec = make(d)
    v = verdicts(spec)
    assert v == {"C1": "PROVED", "C2": "REFUTED"}


def test_relation_visibility_obligation_blocks_compile():
    d = base()
    d["rules"].append({"id": "R10", "kind": "policy", "name": "positive_tenants", "table": "memberships",
                       "role": "authenticated", "command": "select", "mode": "restrictive",
                       "using": {"cmp": [{"col": "tenant_id"}, ">", {"const": 0}]}})
    spec = make(d)
    with pytest.raises(CompileError) as ei:
        compile_spec(spec)
    e = ei.value.errors[0]
    assert e.path == "$.rules[0]" and "membership subquery would be filtered" in e.message and e.fix
    # a restrictive policy that keeps the user's own rows visible is fine
    d["rules"][-1]["using"] = {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}
    compile_spec(make(d))


def test_report_formats(example_spec):
    from mls.props.report import dumps_json, to_markdown

    results = run_all(example_spec)
    md = to_markdown(example_spec, results)
    assert "## Assumptions" in md and "identity adapter 'supabase'" in md
    js = json.loads(dumps_json(example_spec, results))
    assert js["summary"]["PROVED"] == 10 and js["properties"][0]["obligations"]


def test_role_separation_proved_and_refuted():
    """D49: no row of docs is read by both authenticated and an auditor who reads archived rows
    (R5 keeps archived rows from authenticated); an auditor reading level-0 rows shares rows."""
    d = base()
    d["roles"].append("auditor")
    d["rules"].append({"id": "A1", "kind": "policy", "name": "auditor_read", "table": "docs", "role": "auditor",
                       "command": "select", "mode": "permissive",
                       "using": {"cmp": [{"col": "archived"}, "=", {"const": 1}]}})
    d["properties"] = [{"id": "S1", "template": "role_separation", "table": "docs",
                        "roles": ["authenticated", "auditor"], "command": "select"}]
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    assert r.verdict == "PROVED" and r.obligations[0].name == "select: no row is admitted to both authenticated and auditor"
    d["rules"][-1]["using"] = {"cmp": [{"col": "level"}, "<=", {"const": 0}]}
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    assert r.verdict == "REFUTED"
    sc = r.obligations[0].scenario
    row = sc.rows["r"]["values"]
    assert row["level"] <= 0 and row["archived"] != 1  # both roles admit it: a member's unarchived level-0 row
    assert [sc.context["uid"], row["tenant_id"]] in sc.relations["member_of"] or \
        [sc.context["uid"], row["tenant_id"]] in sc.relations["admin_of"] or row["owner_id"] == sc.context["uid"]
    # the same role twice, or an unknown role, is refused by the checker
    from mls.errors import SpecError
    d["properties"][0]["roles"] = ["authenticated", "nobody"]
    with pytest.raises(SpecError) as ei:
        make(d)
    assert ei.value.errors[0].path == "$.properties[0].roles[1]"


def test_a_stored_row_of_a_relation_table_is_in_the_relation(monkeypatch):
    """The takeover example's P8 is about the membership table itself (a user sees only
    memberships of their own teams, through `user_id = @uid`): it holds because the row read is
    in the relation.  Without the relation row axiom the solver picks a row the relation does
    not contain, a state no database can be in, and refutes it."""
    from mls.props import obligations
    from mls.props.runner import run_all
    from mls.spec import load_checked
    from tests.conftest import ROOT

    spec = load_checked(ROOT / "examples" / "starter_takeover.mls")
    assert {r.id: r.verdict for r in run_all(spec)} == {f"P{i}": "PROVED" for i in range(1, 10)}
    monkeypatch.setattr(obligations, "relation_row_axioms", lambda enc, rows: [])
    assert {r.id: r.verdict for r in run_all(spec) if r.id == "P8"} == {"P8": "REFUTED"}


RECIPE = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table projects adopted {
  id bigint not null,
  owner_id uuid not null,
  team_id bigint not null,
  deleted_at timestamp;
  primary_key (id)
}

table team_members adopted {
  team_id bigint not null,
  user_id uuid not null;
  primary_key (team_id, user_id)
}

relation team_members = team_members(user_id, team_id)

opaque is_admin on projects (@uid) relations () sql $$ public.is_admin() $$

rules {
  R1 policy owner_all on projects: authenticated all permissive using owner_id = @uid
  R4 policy admin_read on projects: authenticated select permissive using opaque(is_admin)
  R5 policy hide_deleted on projects: authenticated select restrictive using deleted_at is null
}

properties {
  P2 must_allow projects authenticated select: owner_id = @uid and deleted_at is null
  P3 custom projects authenticated select new: deleted_at is null
  P4 custom projects authenticated select new: owner_id = @uid or opaque(is_admin)
}
"""


def test_a_proof_is_conditional_only_on_the_blocks_it_needs():
    """GUIDE §7's `is_admin()` recipe (#27): the restrictive policy alone proves P3, whatever the
    block returns; P2's witness shares an encoder with the access layers, which read the block,
    but its own formula does not (its well-formedness axiom is not a use); P4 needs the block to
    be the same value in the policy and in the goal, so it stays conditional."""
    from mls.spec.syntax import parse

    results = {r.id: r for r in run_all(check_spec(parse(RECIPE)))}
    assert {k: (r.verdict, r.conditional_on) for k, r in results.items()} == {
        "P2": ("PROVED", []), "P3": ("PROVED", []), "P4": ("PROVED", ["is_admin"])}


def test_both_state_copies_intern_text_constants_alike():
    """The induction step encodes the old row with one encoder and the new row with another; they
    must number text constants alike, or 'x' before and 'z' after can become the same value.  An
    update that keeps the status or sets it to 'z' preserves `status <> 'x'`."""
    d = base()
    d["tables"]["docs"]["columns"]["status"] = {"type": "text", "nullable": False}
    d["rules"].append({"id": "T1", "kind": "transition", "name": "status_kept_or_z", "table": "docs",
                       "predicate": {"or": [{"cmp": [{"new": "status"}, "=", {"old": "status"}]},
                                            {"cmp": [{"new": "status"}, "=", {"const": "z"}]}]}})
    d["properties"] = [{"id": "P1", "template": "invariant_preserved",
                        "invariants": [{"table": "docs", "predicate": {"cmp": [{"col": "status"}, "<>",
                                                                               {"const": "x"}]}}]}]
    spec = make(d)
    r = run_property(spec, spec.properties[0])
    update = [o for o in r.obligations if o.name.startswith("update on docs preserves")]
    assert update and all(o.verdict == "PROVED" for o in update), [(o.name, o.verdict) for o in update]


def test_an_enum_column_holds_only_its_labels():
    """D59: Postgres refuses any other value, and the proofs assume it.  `status <> 'In review'`
    leaves exactly the three states the policy lists, so P11 holds; with a fourth label the
    policy does not list, the counterexample is a document in that state."""
    from tests.templates.specs import ENUM_LABELS, enum_spec

    spec = enum_spec()
    assert run_property(spec, next(p for p in spec.properties if p.id == "P11")).verdict == "PROVED"
    spec = enum_spec(ENUM_LABELS + ["Extra"])
    r = run_property(spec, next(p for p in spec.properties if p.id == "P11"))
    assert r.verdict == "REFUTED"
    assert {o.scenario.rows["r"]["values"]["status"] for o in r.obligations if o.verdict == "REFUTED"} == {"'Extra'"}


SUBSET = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table members adopted {
  id uuid not null,
  org_id uuid not null,
  user_id uuid not null,
  role text;
  primary_key (id);
  unique (org_id, user_id)
}

table projects adopted {
  id uuid not null,
  org_id uuid not null;
  primary_key (id)
}

table tasks adopted {
  id uuid not null,
  project_id uuid not null;
  primary_key (id)
}

relation member_of = members(user_id, org_id)
relation admin_of = members(user_id, org_id) where role = 'admin'
relation member_project = member_of . projects(org_id, id)
relation admin_project = admin_of . projects(org_id, id)

rules {
  R1 policy members_read on projects: authenticated select permissive using member_of(@uid, org_id)
  R2 policy admins_edit on projects: authenticated update permissive using admin_of(@uid, org_id) and member_of(@uid, org_id) check admin_of(@uid, org_id)
  R3 policy admins_delete_tasks on tasks: authenticated delete permissive using admin_project(@uid, project_id) and member_project(@uid, project_id)
}

properties {
  P1 must_allow projects authenticated update: old.org_id = new.org_id and admin_of(@uid, old.org_id)
  P2 must_allow tasks authenticated delete: admin_project(@uid, project_id)
  P3 custom projects authenticated update old: member_of(@uid, org_id)
}
"""


def test_a_filtered_relation_is_within_its_unfiltered_twin(monkeypatch):
    """#37: every fact of `admin_of` comes from a row that is also a fact of `member_of` (same
    table, key and value), so a policy that asks for both admits every admin (P1), through a hop
    too (P2).  Without the axiom the solver finds an admin who is not a member, a state no
    database can be in."""
    from mls.props import obligations
    from mls.spec.syntax import parse

    spec = check_spec(parse(SUBSET))
    assert verdicts(spec) == {"P1": "PROVED", "P2": "PROVED", "P3": "PROVED"}
    monkeypatch.setattr(obligations, "subset_axioms", lambda spec, enc: [])
    assert verdicts(spec) == {"P1": "REFUTED", "P2": "REFUTED", "P3": "PROVED"}


def test_a_relation_whose_condition_implies_another_lies_within_it(monkeypatch):
    """#51: `admin_of` (role 'admin') lies within `staff_of` (role 'admin' or 'staff') over the same
    table, key and value: the solver decides that the first condition implies the second.  The
    scarpar takeover's role ladder (owner within admin within manager ...) was refuted without it."""
    from mls.props import obligations
    from mls.spec.syntax import parse

    text = SUBSET.replace("relation member_of = members(user_id, org_id)\n",
                          "relation member_of = members(user_id, org_id) where role = 'admin' or role = 'staff'\n")
    spec = check_spec(parse(text))
    assert verdicts(spec)["P1"] == "PROVED"
    monkeypatch.setattr(obligations, "_implies_on_rows", lambda *a: False)
    obligations._implied_cache.clear()
    assert verdicts(check_spec(parse(text)))["P1"] == "REFUTED"


UNIQUE_VALUE = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table riders adopted {
  id uuid not null,
  user_id uuid;
  primary_key (id)
}

relation rider_of = riders(user_id, id)

rules {
  R1 policy rider_reads_own on riders: authenticated select permissive using rider_of(@uid, id)
}

properties {
  P1 custom riders authenticated select old: user_id = @uid description 'a rider reads only their own riders row'
}
"""


def test_a_fact_with_a_unique_value_is_the_one_row_that_has_it(monkeypatch):
    """#51: `riders.id` is the primary key, so a fact `rider_of(k, x.id)` is row x's own pair: k is
    x's user_id, and a row whose user_id is NULL is nobody's.  Without the axiom the solver gives
    the row an arbitrary rider."""
    from mls.props import obligations
    from mls.spec.syntax import parse

    assert verdicts(check_spec(parse(UNIQUE_VALUE))) == {"P1": "PROVED"}
    monkeypatch.setattr(obligations, "_key_sets", lambda spec, table: [])
    assert verdicts(check_spec(parse(UNIQUE_VALUE))) == {"P1": "REFUTED"}


def test_an_unwritable_column_is_immutable():
    """An update by a role leaves every column it may not write unchanged: Postgres refuses the
    statement otherwise.  The upper bounds assume it as the lower bounds and the diff do, so a
    column rule alone proves `column_immutable` (aural-oss: a user never changes their role)."""
    from mls.spec.syntax import parse

    text = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table profiles adopted {
  id uuid not null,
  name text,
  role text;
  primary_key (id)
}

rules {
  R1 policy own_profile on profiles: authenticated update permissive using id = @uid check id = @uid
  R2 column_rule no_role_write on profiles: authenticated write id, name
}

properties {
  P1 column_immutable profiles: role
  P2 column_immutable profiles: name
}
"""
    spec = check_spec(parse(text))
    assert verdicts(spec) == {"P1": "PROVED", "P2": "REFUTED"}


ALWAYS = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table profiles adopted {
  id uuid not null,
  name text,
  role text,
  status text;
  primary_key (id)
}

rules {
  R1 policy own_profile on profiles: authenticated update permissive using id = @uid check id = @uid
  R2 column_rule no_role_write on profiles: authenticated write id, name
  R3 check known_status on profiles: status in ('active', 'closed')
%s}

properties {
  P1 column_immutable profiles: role
  P2 always_on_update profiles: new.role = old.role description 'nobody, the server included, changes a role'
  P3 always_on_update profiles: new.status <> 'deleted'
  P4 always_on_update profiles: old.status <> 'closed' or new.status = 'closed'
}
"""


def test_an_update_by_every_writer_is_proved_from_the_triggers_and_checks_alone():
    """#40: always_on_update binds the trusted roles too, so the column rule that proves
    column_immutable for the app's role proves nothing for it; a transition rule does, and a
    check on the written row does for a predicate over the new row."""
    from mls.english import prop
    from mls.spec.syntax import parse
    from mls.terse import render

    spec = check_spec(parse(ALWAYS % ""))
    assert verdicts(spec) == {"P1": "PROVED", "P2": "REFUTED", "P3": "PROVED", "P4": "REFUTED"}
    sc = run_property(spec, spec.properties[1]).obligations[0].scenario
    assert sc.rows["old"]["values"]["role"] != sc.rows["new"]["values"]["role"]
    rules = ("  R4 transition role_kept on profiles: new.role = old.role\n"
             "  R5 transition closed_stays on profiles: old.status <> 'closed' or new.status = 'closed'\n")
    spec = check_spec(parse(ALWAYS % rules))
    assert set(verdicts(spec).values()) == {"PROVED"}
    assert prop(spec, spec.properties[1]) == (
        "Every change to a row of profiles, by anyone (the roles that bypass the policies included), "
        "keeps this true: the new role is the previous role.")
    assert parse(render(spec)) == spec


def test_a_column_guard_limits_the_edit_only_where_its_condition_holds():
    """#50: the owner of a document who is not one of its tenant's admins edits only its level and
    archived flag; anyone else (or the owner, once an admin) edits as the policies allow.  The
    guard reads the admins relation as the caller, so a restrictive policy hiding admins rows is
    refused at compile time like a policy's membership; its English and terse forms round-trip."""
    from mls.english import rule
    from mls.spec.syntax import parse
    from mls.terse import render
    from tests.templates.specs import guard_spec

    spec = guard_spec()
    assert set(verdicts(spec).values()) == {"PROVED"}
    d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
    p12 = next(p for p in d["properties"] if p["id"] == "P12")
    p12["when"]["and"] = [c for c in p12["when"]["and"] if c != {"cmp": [{"new": "owner_id"}, "=", {"old": "owner_id"}]}]
    p12["when"]["and"].append({"is_null": {"new": "owner_id"}})  # the owner gives the document away
    bad = make(d)
    r = run_property(bad, next(p for p in bad.properties if p.id == "P12"))
    assert r.verdict == "REFUTED"
    sc = next(o for o in r.obligations if o.verdict == "REFUTED").scenario
    assert sc.rows["old"]["values"]["owner_id"] == sc.context["uid"] and sc.rows["new"]["values"]["owner_id"] is None
    g = spec.column_guards()[0]
    assert rule(spec, g) == ("When the row's owner_id is the current user and not the row's tenant_id is among the "
                             "current user's admin_of, an edit of a row of docs by authenticated changes only the "
                             "columns level, archived.")
    assert parse(render(spec)) == spec
    d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
    d["relations"]["chief_of"] = {"table": "admins", "key": "user_id", "value": "tenant_id"}  # read by the guard only
    g1 = next(r for r in d["rules"] if r["id"] == "G1")
    g1["when"]["and"][1]["not"]["member"]["relation"] = "chief_of"
    assert compile_spec(make(d))
    d["rules"].append({"id": "R20", "kind": "policy", "name": "hide_admins", "table": "admins", "role": "authenticated",
                       "command": "select", "mode": "restrictive", "using": {"cmp": [{"col": "user_id"}, "<>", {"ctx": "uid"}]}})
    with pytest.raises(CompileError) as e:
        compile_spec(make(d))
    assert "column rule 'owner_edits' uses relation 'chief_of'" in str(e.value)


def test_a_cascade_deletes_only_rows_the_deleter_could_delete():
    """#60 (D79): a member deletes a document and its notes go with it; the proofs keep the
    inclusion, and the compiler refuses a cascade to notes the member could not delete
    themselves (here: a restrictive policy keeps a note's author as its only deleter).  Its
    English says the rows go, and the terse form round-trips."""
    from mls.english import rule
    from mls.spec.syntax import parse
    from mls.terse import render
    from tests.templates.specs import cascade_spec

    spec = cascade_spec()
    assert set(verdicts(spec).values()) == {"PROVED"}
    assert compile_spec(spec)
    n2 = next(r for r in spec.rules if r.id == "N2")
    assert rule(spec, n2).endswith("removing it deletes the rows of doc_notes that refer to it.")
    assert parse(render(spec)) == spec
    d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
    d["tables"]["doc_notes"]["columns"]["author_id"] = {"type": "uuid", "nullable": True}
    d["rules"].append({"id": "N3", "kind": "policy", "name": "author_deletes", "table": "doc_notes",
                       "role": "authenticated", "command": "delete", "mode": "restrictive",
                       "using": {"cmp": [{"col": "author_id"}, "=", {"ctx": "uid"}]}})
    with pytest.raises(CompileError) as e:
        compile_spec(make(d))
    assert "inclusion 'note_in_doc' deletes the rows of 'doc_notes'" in str(e.value)


def test_changes_only_is_the_upper_bound_a_column_guard_proves():
    """#56 (D80): the guard fixture's owner edits only level and archived (the guard proves it);
    without the guard, or with a column left off the list, it is refuted with the column that
    changed.  Its English and terse forms round-trip."""
    from mls.english import prop
    from mls.spec.syntax import parse
    from mls.terse import render
    from tests.templates.specs import guard_spec

    spec = guard_spec()
    d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
    g1 = next(r for r in d["rules"] if r["id"] == "G1")
    d["properties"].append({"id": "P13", "template": "changes_only", "table": "docs", "role": "authenticated",
                            "columns": ["level", "archived"], "when": g1["when"],
                            "description": "the owner of a document who is not an admin edits only its level"})
    with_guard = make(d)
    assert verdicts(with_guard)["P13"] == "PROVED"
    p13 = next(p for p in with_guard.properties if p.id == "P13")
    assert prop(with_guard, p13) == (
        "When the row's owner_id is the current user and not the row's tenant_id is among the current "
        "user's admin_of, an edit of a row of docs by authenticated changes only the columns level, archived.")
    assert parse(render(with_guard)) == with_guard
    narrower = copy.deepcopy(d)
    narrower["properties"][-1]["columns"] = ["level"]
    assert verdicts(make(narrower))["P13"] == "REFUTED"
    no_guard = copy.deepcopy(d)
    no_guard["rules"] = [r for r in no_guard["rules"] if r["id"] != "G1"]
    assert verdicts(make(no_guard))["P13"] == "REFUTED"


def test_a_set_null_inclusion_nulls_only_what_the_rules_allow():
    """#62: deleting a document keeps its notes with no document.  The compiler refuses the key
    when a transition forbids the nulling (every such delete would fail) or when the deleter could
    not make that edit itself (no update policy on notes); an invariant the nulled note breaks is
    refuted on that row."""
    from mls.english import rule
    from mls.spec.syntax import parse
    from mls.terse import render
    from tests.templates.specs import set_null_spec

    spec = set_null_spec()
    assert set(verdicts(spec).values()) == {"PROVED"}
    assert compile_spec(spec)
    n2 = next(r for r in spec.rules if r.id == "N2")
    assert rule(spec, n2).endswith("removing it sets doc_id to empty on the rows of doc_notes that refer to it.")
    assert parse(render(spec)) == spec
    d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
    fixed = copy.deepcopy(d)
    fixed["rules"].append({"id": "N5", "kind": "transition", "name": "note_doc_fixed", "table": "doc_notes",
                           "predicate": {"cmp": [{"new": "doc_id"}, "=", {"old": "doc_id"}]}})
    with pytest.raises(CompileError) as e:
        compile_spec(make(fixed))
    assert "a check or transition rule on 'doc_notes' refuses that change" in str(e.value)
    no_update = copy.deepcopy(d)
    n1 = next(r for r in no_update["rules"] if r["id"] == "N1")
    n1["command"] = "select"
    del n1["check"]
    no_update["rules"].append({**n1, "id": "N1d", "name": "member_notes_delete", "command": "delete"})
    with pytest.raises(CompileError) as e:
        compile_spec(make(no_update))
    assert "is one it could not make that change to itself" in str(e.value)
    kept = copy.deepcopy(d)
    next(p for p in kept["properties"] if p["id"] == "P4")["invariants"].append(
        {"table": "doc_notes", "predicate": {"not": {"is_null": {"col": "doc_id"}}}})
    assert verdicts(make(kept))["P4"] == "REFUTED"


def test_a_label_test_models_only_arrays_that_exist():
    """#65 (exact encoding): R6 shows a membership row whenever its test of 'x' is not UNKNOWN.  A
    FALSE test of 'y' means the array is set and has no NULL element, so the test of 'x' is TRUE or
    FALSE: P1 holds.  A per-label encoding would refute it with a row no array can be.  Any row
    at all (P2) is refuted: its array may be NULL."""
    from tests.templates.specs import array_dict

    d = array_dict()
    x = {"has": [{"col": "roles"}, {"const": "x"}]}
    # without C1, whose check (TRUE required) already rules out a NULL array and a NULL element
    d["rules"] = [r for r in d["rules"] if r["id"] not in ("R6", "C1")] + [
        {"id": "R6", "kind": "policy", "name": "known_x", "table": "team_members", "role": "authenticated",
         "command": "select", "mode": "permissive", "using": {"or": [x, {"not": x}]}}]
    d["properties"] = [
        {"id": "P1", "template": "must_allow", "table": "team_members", "role": "authenticated", "command": "select",
         "when": {"not": {"has": [{"col": "roles"}, {"const": "y"}]}}},
        {"id": "P2", "template": "must_allow", "table": "team_members", "role": "authenticated", "command": "select",
         "when": {"lit": True}},
    ]
    results = {r.id: r for r in run_all(make(d))}
    assert {k: r.verdict for k, r in results.items()} == {"P1": "PROVED", "P2": "REFUTED"}
    # the scenario shows an array as the tested labels it holds, NULL for a NULL element
    sc = next(o.scenario for o in results["P2"].obligations if o.verdict == "REFUTED")
    roles = sc.rows["r"]["values"]["roles"]
    assert roles is None or (roles.startswith("{") and "NULL" in roles), roles
    # perms, tested for no label here, is a value, not an empty array (nor roles' labels)
    perms = sc.rows["r"]["values"].get("perms")
    assert perms is None or perms.startswith("array#"), perms


def test_the_array_fixture_proves():
    from tests.templates.specs import array_spec

    assert set(verdicts(array_spec()).values()) == {"PROVED"}, verdicts(array_spec())
