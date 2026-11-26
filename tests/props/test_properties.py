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



INSERT_COLS = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table members adopted {
  id int not null,
  group_id int not null,
  user_id uuid not null,
  "roles" text[] not null;
  primary_key (id);
  unique (group_id, user_id)
}

relation owner_of = members(user_id, group_id) where 'owner' = any("roles")

rules {
  R1 policy add on members: authenticated insert permissive check owner_of(@uid, group_id)
  R2 policy edit on members: authenticated update permissive using owner_of(@uid, group_id) check owner_of(@uid, group_id)
%s}

properties {
  P1 must_allow members authenticated insert: owner_of(@uid, group_id)
}
"""


def test_an_insert_needs_every_column_the_row_is_written_with():
    """#67: a write column rule grants INSERT on its columns only, so a row the role would have to
    write in another column cannot be inserted (its value would be the column's default, which the
    proofs do not model).  The lower bound over every such row is refuted; a rule that lists every
    column, or a guard (`when`, updates only), leaves inserts alone (rbac takeover, run 4)."""
    from mls.spec.syntax import parse

    def verdict(extra: str) -> str:
        return verdicts(check_spec(parse(INSERT_COLS % extra)))["P1"]

    assert verdict('  R3 column_rule roles_only on members: authenticated write "roles"\n') == "REFUTED"
    assert verdict('  R3 column_rule all on members: authenticated write id, group_id, user_id, "roles"\n') == "PROVED"
    assert verdict('  R3 column_rule guard on members: authenticated write "roles" when owner_of(@uid, group_id)\n') == "PROVED"
    assert verdict("") == "PROVED"


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


SERVICE = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated, authenticator, supabase_auth_admin

table members adopted {
  user_id uuid not null,
  team_id int not null;
  primary_key (user_id, team_id);
  assume ('rls not_forced')
}

table claims adopted {
  user_id uuid not null,
  team_id int not null,
  secret text;
  primary_key (user_id);
  assume ('rls not_forced')
}

relation member_of = members(user_id, team_id)

rules {
  R0 policy own_rows on members: authenticated select permissive using user_id = @uid
  R1 policy own on claims: authenticated select permissive using member_of(@uid, team_id)
  R2 policy hook on claims: authenticator select permissive using true
  R3 policy auth_hook on claims: supabase_auth_admin select permissive using true
}

properties {
  P1 tenant_isolation claims: team_id in member_of(@uid) for select, insert, update, delete
  P2 write_subset_read claims
  P3 column_immutable claims: secret
  P4 least_privilege: authenticated claims[select]; authenticated members[select]
  P5 must_allow claims authenticator select: true
%s}
"""


def test_supabase_service_roles_are_trusted_but_keep_their_rules():
    """#68: authenticator can become service_role and supabase_auth_admin can create roles, so no
    upper bound holds for them: tenant isolation, write ⊆ read, immutable columns and the least
    privilege leave them out, an upper bound naming one is refused, and the report says they are
    trusted.  Their own rules still compile and their lower bounds still prove."""
    from mls.errors import SpecError
    from mls.props.report import assumptions
    from mls.spec.syntax import parse

    spec = check_spec(parse(SERVICE % ""))
    results = run_all(spec)
    assert {r.id: r.verdict for r in results} == {"P1": "PROVED", "P2": "PROVED", "P3": "PROVED",
                                                    "P4": "PROVED", "P5": "PROVED"}
    trust = " ".join(assumptions(spec, results))
    assert "authenticator" in trust and "supabase_auth_admin" in trust and "service_role" in trust
    assert any("authenticator" in s.sql for s in compile_spec(spec).statements if "create policy" in s.sql.lower())

    with pytest.raises(SpecError) as ei:
        check_spec(parse(SERVICE % "  P6 changes_only claims authenticator: user_id\n"))
    e = ei.value.errors[0]
    assert e.path == "$.properties[5].role" and "authenticator" in e.message and "must_allow" in e.fix
    # a service role the spec does not declare is only unknown (one error, one fix)
    text = (SERVICE % "").replace("roles authenticated, authenticator, supabase_auth_admin", "roles authenticated")
    text = text[:text.index("rules {")] + "rules {\n}\n\nproperties {\n  P1 least_privilege: authenticator claims[select]\n}\n"
    with pytest.raises(SpecError) as ei:
        check_spec(parse(text))
    assert [x.message for x in ei.value.errors] == ["unknown role 'authenticator'"]
    # a migration re-checks the roles it keeps: they may have gained a way to a bypassing role
    from mls.compile.migrate import migrate
    assert migrate(spec, spec).empty
    grown = check_spec(parse((SERVICE % "").replace("  secret text;", "  secret text,\n  note text;")))
    sql = migrate(spec, grown).sql()
    assert "app role authenticated can become" in sql and "app role authenticator can become" not in sql


CITEXT = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table orgs adopted {
  id uuid not null,
  slug citext not null,
  owner_id uuid not null;
  primary_key (id);
  unique (slug)
}

rules {
  R1 policy public_orgs on orgs: authenticated select permissive using slug = 'Public' or owner_id = @uid
  R2 check no_admin on orgs: slug <> 'ADMIN'
}

properties {
  P1 must_allow orgs authenticated select: slug = 'PUBLIC'
  P2 custom orgs authenticated select new: slug <> 'admin'
  P3 custom orgs authenticated select new: slug = 'public' or owner_id = @uid
}
"""


def test_citext_compares_with_constants_ignoring_case():
    """#73: a citext column equals a constant whatever the case of either, as Postgres compares
    them: 'Public' grants 'PUBLIC', and the check on 'ADMIN' keeps 'admin' out.  Without the
    folding both properties would be refuted (two constants, two values)."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(CITEXT)))
    assert v == {"P1": "PROVED", "P2": "PROVED", "P3": "PROVED"}, v


DEFAULTS = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table user_emails adopted {
  id uuid not null default fresh,
  user_id uuid not null%s,
  email text not null,
  is_verified bool not null default false,
  is_primary bool not null default false,
  created_at timestamp not null default @now;
  primary_key (id)
}

rules {
  R1 policy add_own on user_emails: authenticated insert permissive check user_id = @uid and is_verified = false
  R2 column_rule address_only on user_emails: authenticated write email
}

properties {
  P1 must_allow user_emails authenticated insert: user_id = @uid and is_verified = false and is_primary = false
  P2 custom user_emails authenticated insert new: is_primary = false
}
"""


def test_an_insert_lower_bound_counts_on_the_defaults_of_the_columns_the_role_cannot_write():
    """#76 (graphile/starter): the role writes only `email`; the database fills in the owner from
    the current user, the flags with false, the id fresh and the time now.  "A user adds an
    address" is then proved over the rows those defaults give.  With no default for `user_id`
    the insert is admitted for no row (D89), and a default the policy refuses (is_verified true)
    refutes it.  An upper bound gains the defaults too (P2: a new address is never primary)."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(DEFAULTS % " default @uid")))
    assert v == {"P1": "PROVED", "P2": "PROVED"}, v
    v = verdicts(check_spec(parse(DEFAULTS % "")))
    assert v["P1"] == "REFUTED", v
    assert v["P2"] == "PROVED", v  # the defaults still declared bound is_primary
    # a column with no declared default is unconstrained for an upper bound, never assumed away
    unknown = (DEFAULTS % "").replace("is_primary bool not null default false", "is_primary bool not null")
    assert verdicts(check_spec(parse(unknown)))["P2"] == "REFUTED"
    refused = DEFAULTS.replace("is_verified bool not null default false", "is_verified bool not null default true")
    assert verdicts(check_spec(parse(refused % " default @uid")))["P1"] == "REFUTED"


SIGNED_OUT = """mls 0.1
identity trusted_function { uid: app_public.current_user_id uuid md5 '0123456789abcdef0123456789abcdef'%s }
roles visitor

table users adopted {
  id uuid not null,
  username text not null;
  primary_key (id)
}

rules {
  R1 policy read_users on users: visitor select permissive using %s
}

properties {
  P1 custom users visitor select new: not @uid is null description 'a visitor who is not signed in reads no user'
  P2 must_allow users visitor select: not @uid is null
}
"""


def test_a_property_speaks_about_a_caller_with_no_current_user():
    """#75 (graphile/starter): one role serves signed-in users and signed-out visitors, whose
    current user is NULL.  With the user value declared `optional`, "a visitor who is not signed in
    reads no user" is a property: proved for a policy SQL's NULL rules deny (`id = @uid or id <>
    @uid` is UNKNOWN for no user), refuted for `true`; "every signed-in user reads every user" is
    the lower bound `not @uid is null`.  Without `optional` the value is never NULL, and the
    checker refuses the test and says how to declare it."""
    from mls.errors import SpecError
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(SIGNED_OUT % (" optional", "id = @uid or id <> @uid"))))
    assert v == {"P1": "PROVED", "P2": "PROVED"}, v
    v = verdicts(check_spec(parse(SIGNED_OUT % (" optional", "not @uid is null"))))
    assert v == {"P1": "PROVED", "P2": "PROVED"}, v
    v = verdicts(check_spec(parse(SIGNED_OUT % (" optional", "true"))))
    assert v == {"P1": "REFUTED", "P2": "PROVED"}, v
    with pytest.raises(SpecError) as e:
        check_spec(parse(SIGNED_OUT % ("", "true")))
    assert any("optional" in (x.fix or "") for x in e.value.errors), e.value.errors


def test_a_default_from_an_optional_context_value_is_null_for_a_caller_who_lacks_it():
    """#75 with #76: `user_id default @uid` writes NULL for a signed-out visitor.  On a NOT NULL
    column that insert fails, so "a new row is always the caller's" still holds; on a nullable one
    the row is written with no owner, and the same promise is refuted."""
    from mls.spec.syntax import parse

    text = """mls 0.1
identity trusted_function { uid: app_public.current_user_id uuid md5 '0123456789abcdef0123456789abcdef' optional }
roles visitor

table notes adopted {
  id uuid not null default fresh,
  user_id uuid%s default @uid,
  body text not null;
  primary_key (id)
}

rules {
  R1 policy add on notes: visitor insert permissive check true
  R2 column_rule body_only on notes: visitor write body
}

properties {
  P1 custom notes visitor insert new: user_id = @uid
}
"""
    assert verdicts(check_spec(parse(text % " not null")))["P1"] == "PROVED"
    assert verdicts(check_spec(parse(text % "")))["P1"] == "REFUTED"


ANON = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles anon, authenticated

table notes adopted {
  id uuid not null,
  owner_id uuid not null;
  primary_key (id)
}

rules {
  R1 policy own_notes on notes: anon select permissive using owner_id = @uid
  R2 policy own_notes_signed_in on notes: authenticated select permissive using owner_id = @uid
}

properties {
  P1 custom notes anon select new: false description 'a signed-out caller reads no note'
  P2 custom notes authenticated select new: false description 'a signed-in user reads no note'
}
"""


def test_a_signed_out_supabase_caller_has_no_user():
    """#83 (midday): Supabase's anon key carries no claims, so `auth.uid()` is NULL for anon and a
    policy comparing with it grants anon nothing.  The proofs take anon's context values as unset;
    a signed-in user still has one."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(ANON)))
    assert v == {"P1": "PROVED", "P2": "REFUTED"}, v


ENUM_MEMBER = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated
enum doc_status ('pending', 'done')

table members adopted {
  user_id uuid not null,
  team_id uuid not null;
  primary_key (user_id, team_id)
}

table docs adopted {
  id uuid not null,
  team_id uuid not null,
  status enum doc_status;
  primary_key (id)
}

relation member_of = members(user_id, team_id)

rules {
  R1 policy team_docs on docs: authenticated select permissive using member_of(@uid, team_id)
  R2 policy own_memberships on members: authenticated select permissive using user_id = @uid
}

properties {
  P1 custom docs authenticated select new: false description 'nobody reads a doc'
}
"""


def test_a_scenario_lists_a_relation_over_its_own_types_only():
    """#84 (midday): the labels of an enum column the obligation reads are interned like text
    constants; a scenario listed them as members of a uuid relation.  Each pair holds values of
    the relation's own column types."""
    from mls.spec.syntax import parse

    res = {r.id: r for r in run_all(check_spec(parse(ENUM_MEMBER)))}["P1"]
    assert res.verdict == "REFUTED"
    scenarios = [o.scenario for o in res.obligations if o.scenario is not None]
    pairs = [x for sc in scenarios for p in sc.relations.get("member_of", []) for x in p]
    assert pairs and not [x for x in pairs if x in ("'pending'", "'done'")], pairs


SIGNED_IN_ONLY = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles anon, authenticated

table items adopted {
  id uuid not null,
  owner_id uuid;
  primary_key (id)
}

rules {
  R1 policy add_items on items: anon insert permissive check not @uid is null
  R2 policy add_items_signed_in on items: authenticated insert permissive check not @uid is null
  R3 policy read_items on items: anon select permissive using @uid is null
  R4 policy read_items_signed_in on items: authenticated select permissive using true
}

properties {
  P1 custom items anon insert new: false description 'a signed-out caller adds no item'
  P2 must_allow items authenticated insert: true
  P3 role_separation items select: anon | authenticated
}
"""


def test_a_user_null_test_reads_anon_as_signed_out():
    """#85 (nextbase): `not @uid is null` (nextbase's `auth.uid() IS NOT NULL`) refuses anon, whose
    user id is NULL, and admits every signed-in user; the checker accepts the test when the spec
    names an anonymous role.  A role-less obligation (role_separation) covers the real anon state:
    anon reads with `@uid is null`, a signed-in user reads everything, so a row both read exists."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(SIGNED_IN_ONLY)))
    assert v == {"P1": "PROVED", "P2": "PROVED", "P3": "REFUTED"}, v


PUBLISHED = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles anon, authenticated

table posts adopted {
  id uuid not null,
  published bool not null;
  primary_key (id)
}

table comments adopted {
  id uuid not null,
  post_id uuid not null;
  primary_key (id)
}

relation published_post = posts(id) where published = true

rules {
  R1 policy read_comments on comments: anon select permissive using published_post(post_id)
}

properties {
  P1 custom comments anon select new: false description 'anon reads no comment'
}
"""


def test_a_report_prints_an_example_over_a_set():
    """#87 (nextbase): a relation with no key is a set; the report's example lists its members as
    single values (the renderer unpacked every entry as a pair and crashed)."""
    from mls.props.report import to_markdown
    from mls.spec.syntax import parse

    spec = check_spec(parse(PUBLISHED))
    results = run_all(spec)
    assert {r.id: r.verdict for r in results} == {"P1": "REFUTED"}
    md = to_markdown(spec, results)
    assert "- published_post = {" in md and "(" not in md.split("- published_post = {")[1].split("}")[0], md


ROLE_CLAIM = """mls 0.1
identity supabase { uid: auth.uid uuid; user_role: jwt.claims.user_role enum app_role optional }
roles authenticated
enum app_role ('admin', 'moderator')

table channels adopted {
  id bigint not null,
  created_by uuid not null;
  primary_key (id)
}

rules {
  R1 policy remove on channels: authenticated delete permissive using created_by = @uid or @user_role <> 'moderator'
}

properties {
  P1 custom channels authenticated delete new: created_by = @uid or @user_role = 'admin'
  P2 must_allow channels authenticated delete: @user_role = 'admin'
  P3 custom channels authenticated delete new: created_by = @uid
}
"""


def test_an_enum_claim_is_one_of_its_labels_or_unset():
    """#89 (Slack clone): the `user_role` claim is an `app_role` label or unset (the hook writes null
    for a user with no role).  `@user_role <> 'moderator'` admits an admin and denies a caller with
    no role (UNKNOWN), so it is `@user_role = 'admin'`: P1 needs the labels as the claim's domain."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(ROLE_CLAIM)))
    assert v == {"P1": "PROVED", "P2": "PROVED", "P3": "REFUTED"}, v


GRANTS = """mls 0.1
identity supabase { uid: auth.uid uuid; user_role: jwt.claims.user_role enum app_role optional }
roles authenticated
enum app_role ('admin', 'moderator')
enum app_permission ('channels.delete', 'messages.delete')

table role_permissions adopted {
  id bigint not null,
  role enum app_role not null,
  permission enum app_permission not null;
  primary_key (id);
  unique (role, permission)
}

table channels adopted {
  id bigint not null,
  created_by uuid not null;
  primary_key (id)
}

relation role_grants = role_permissions(role, permission)

rules {
  R1 policy remove on channels: authenticated delete permissive using created_by = @uid or role_grants(@user_role, 'channels.delete')
  R2 policy read_grants on role_permissions: authenticated select permissive using role = @user_role
}

properties {
  P1 custom channels authenticated delete new: created_by = @uid or not @user_role is null
  P2 must_allow channels authenticated delete: role_grants(@user_role, 'channels.delete')
  P3 custom channels authenticated delete new: created_by = @uid
}
"""


def test_a_permission_of_the_callers_role_is_a_membership_with_a_constant_value():
    """#90 (Slack clone): `authorize('channels.delete')` asks whether the caller's role (an enum
    claim) holds the permission in role_permissions: a membership whose key is the claim and whose
    value is a constant label, the same for every row.  A caller with no role holds none (P1)."""
    from mls.spec.syntax import parse

    v = verdicts(check_spec(parse(GRANTS)))
    assert v == {"P1": "PROVED", "P2": "PROVED", "P3": "REFUTED"}, v


def test_the_trusted_roles_line_does_not_claim_forced_rls_on_adopted_tables():
    """#93: the compiler forces row level security on the tables it creates, never on an adopted
    one; the report says so only when the spec adopts a table."""
    from mls.props.report import assumptions
    from tests.templates import specs

    owned = make(base())
    adopted = specs.adopted_spec([{"rls": "not_forced"}])
    line = lambda s: next(a for a in assumptions(s, []) if a.startswith("trusted roles:"))
    assert "the compiler forces RLS for owners" in line(owned)
    assert "forces RLS for owners" not in line(adopted)
    assert "never on an adopted table, whose owner is bound only if the table forces RLS itself" in line(adopted)


BOOLS = """mls 0.1
identity supabase { uid: auth.uid uuid; staff: jwt.claims.staff bool }
roles visitor

table notes owned {
  id int not null,
  owner_id uuid,
  is_public bool not null,
  pinned bool;
  primary_key (id)
}

rules {
  R1 policy own on notes: visitor select permissive using owner_id = @uid
}

properties {
  P1 custom notes visitor select new: is_public = true or is_public = false
  P2 custom notes visitor select new: is_public = true
  P3 must_allow notes visitor select: owner_id = @uid and not is_public = true and not is_public = false
  P4 custom notes visitor select new: pinned is null or pinned = true or pinned = false
  P5 custom notes visitor select new: @staff = true or @staff = false
}
"""


def test_a_boolean_holds_true_false_or_null_and_nothing_else():
    """#99: the proofs encode a bool as 1 or 0, and the axioms keep it there: a NOT NULL boolean is
    true or false (P1), a counterexample shows a value Postgres can hold (P2), no row meets a
    condition that is neither (P3's witness fails), and the same for a nullable column (P4) and a
    bool context value (P5)."""
    from mls.spec.syntax import parse

    spec = check_spec(parse(BOOLS))
    results = {r.id: r for r in run_all(spec)}
    assert {k: r.verdict for k, r in results.items()} == {
        "P1": "PROVED", "P2": "REFUTED", "P3": "REFUTED", "P4": "PROVED", "P5": "PROVED"}
    bad = next(o for o in results["P2"].obligations if o.verdict == "REFUTED")
    assert bad.scenario.rows["r"]["values"]["is_public"] is False
    assert [o.verdict for o in results["P3"].obligations if "some row meets the condition" in o.name] == ["REFUTED"]
