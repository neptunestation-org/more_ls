"""Composed relations (D56) without Postgres: the checker's refusals (each with the JSON path and,
for a non-unique hop, the two ways out), the encoding (the example proves; a stored row of a hop
table is what the hop's lookups read; a restrictive policy on a hop table fails the hop's
visibility obligation), and the compiled shape (one nested InitPlan per level, a visibility policy
and a column grant per hop, the hop key indexed, the mutation dropping the hop policies)."""
from __future__ import annotations

import json

from mls.compile import compile_spec
from mls.compile.mutations import Mutation
from mls.errors import CompileError
from mls.props.runner import run_all
from mls.spec import check_spec, load_spec
from mls.spec.model import Spec
from tests.conftest import ROOT
from tests.spec.test_check import errors, has

TEAM_TASKS = ROOT / "examples" / "team_tasks.mls.json"


def base() -> dict:
    return json.loads(TEAM_TASKS.read_text())


def test_the_example_proves():
    spec = load_spec(TEAM_TASKS)
    results = run_all(spec)
    assert {r.id: r.verdict for r in results} == dict.fromkeys(["P1", "P2", "P3", "P4", "P5"], "PROVED")


def test_a_hop_whose_pair_is_not_unique_is_refused_with_the_ways_out():
    """#33: a hop needs its pair unique: its value a key (down), its key a key (up), or the pair
    itself the key (a membership table)."""
    d = base()
    d["tables"]["projects"]["primary_key"] = ["id", "name"]
    errs = errors(d)
    e = next(e for e in errs if e.path == "$.relations.in_project.through[0].value")
    assert "no primary key or unique constraint of 'projects' lies within (team_id, id)" in e.message
    assert "the pair (team_id, id)" in e.fix
    d["tables"]["projects"]["primary_key"] = ["id", "team_id"]
    assert not any(e.path.startswith("$.relations.in_project") for e in errors(d))
    d["tables"]["projects"]["primary_key"] = ["id", "name"]
    d["tables"]["projects"]["unique"] = [["id"]]
    assert not any(e.path.startswith("$.relations.in_project") for e in errors(d))


def test_the_chain_is_checked():
    d = base()
    d["tables"]["projects"]["columns"]["team_id"]["nullable"] = True
    assert has(errors(d), "$.relations.in_project.through[0].key", "must be NOT NULL")
    d = base()
    hop = {"table": "projects", "key": "team_id", "value": "id"}
    d["relations"]["in_project"]["through"] = [hop] * 4
    assert has(errors(d), "$.relations.in_project.through", "a composed relation has at most 3")
    d = base()
    d["relations"]["in_task"]["of"] = "in_project"
    assert has(errors(d), "$.relations.in_task.of", "'in_project' is itself composed")
    d = base()
    d["relations"]["in_project"]["through"][0]["table"] = "nowhere"
    assert has(errors(d), "$.relations.in_project.through[0].table", "unknown table 'nowhere'")
    d = base()
    d["tables"]["projects"]["columns"]["team_id"]["type"] = "text"
    assert has(errors(d), "$.relations.in_project.through[0].key", "does not match the previous level's value")


def test_a_composed_relation_is_refused_where_one_table_is_meant():
    d = base()
    d["rules"].append({"id": "R9", "kind": "inclusion", "name": "task_in_project", "table": "comments",
                       "columns": ["task_id", "id"], "relation": "in_project", "on_delete": "restrict"})
    assert has(errors(d), "$.rules[4].relation", "'in_project' is a composed relation; an inclusion rule")
    d = base()
    d["properties"].append({"id": "P9", "template": "monotone_in", "relation": "in_project"})
    assert has(errors(d), "$.properties[5].relation", "monotone_in is about one table's facts")
    d = base()
    d["opaques"] = {"gate": {"table": "tasks", "columns": ["project_id"], "context": [], "relations": ["in_project"],
                             "sql": "true"}}
    assert has(errors(d), "$.opaques.gate.relations[0]", "'in_project' is a composed relation")


def test_a_policy_on_a_hop_table_reads_the_relation_through_a_helper():
    """Its plain subquery would apply the hop table's policies inside its own policy ('infinite
    recursion detected in policy', D66); the lookup goes through the relation's helper instead
    (D67), and the other lookups of the relation keep their subqueries."""
    from mls.compile import compile_spec
    from mls.spec import check_spec
    from mls.spec.model import Spec
    from mls.spec.recursion import routed

    d = base()
    d["rules"].append({"id": "R9", "kind": "policy", "name": "own_projects", "table": "projects",
                       "role": "authenticated", "command": "select", "mode": "permissive",
                       "using": {"member": {"relation": "in_project", "key": {"ctx": "uid"}, "value": {"col": "id"}}}})
    assert errors(d) == []
    spec = check_spec(Spec.model_validate(d))
    assert routed(spec) == {("projects", "in_project")}
    sql = compile_spec(spec).sql()
    assert '"mls_lookup_in_project"' in sql and "security definer" in sql


def _custom(goal: dict, table: str = "projects") -> dict:
    return {"id": "P9", "template": "custom", "table": table, "role": "authenticated", "command": "select",
            "goal": goal}


def test_a_stored_hop_row_is_what_the_lookups_read():
    """A project the role reads (its team is one of the user's) is in in_project for the user: true
    only because the row r of projects is the row the hop's lookup finds (hop_row_axioms)."""
    d = base()
    d["properties"] = [_custom({"member": {"relation": "in_project", "key": {"ctx": "uid"}, "value": {"col": "id"}}})]
    assert [r.verdict for r in run_all(check_spec(Spec.model_validate(d)))] == ["PROVED"]
    # and the converse direction is not free: a goal the policy does not imply is refuted
    d["properties"] = [_custom({"member": {"relation": "in_project", "key": {"ctx": "uid"},
                                           "value": {"col": "team_id"}}})]
    assert [r.verdict for r in run_all(check_spec(Spec.model_validate(d)))] == ["REFUTED"]


def test_a_restrictive_policy_on_a_hop_table_fails_the_hop_visibility_obligation():
    d = base()
    d["tables"]["projects"]["columns"]["archived"] = {"type": "bool", "nullable": False}
    d["rules"].append({"id": "R9", "kind": "policy", "name": "hide_archived", "table": "projects",
                       "role": "authenticated", "command": "select", "mode": "restrictive",
                       "using": {"cmp": [{"col": "archived"}, "=", {"const": False}]}})
    try:
        compile_spec(check_spec(Spec.model_validate(d)))
    except CompileError as e:
        msgs = [x.message for x in e.errors]
    else:
        raise AssertionError("compiled")
    assert any("uses relation 'in_project', but a restrictive policy on 'projects' can hide rows whose "
               "team_id the previous level reaches" in m for m in msgs), msgs


def test_the_compiled_shape():
    spec = load_spec(TEAM_TASKS)
    sql = compile_spec(spec).sql()
    assert ('using (("task_id" = any (array(select "id" from "tasks" where "project_id" = any (array(select "id" '
            'from "projects" where "team_id" = any (array(select "team_id" from "team_members" where "user_id" = '
            '(select auth.uid())))))))))') in sql
    assert 'create policy "mls_rel_in_project_h1_authenticated_1" on "projects"' in sql
    assert 'create policy "mls_rel_in_task_h2_authenticated_1" on "tasks"' in sql
    assert 'create policy "mls_rel_in_task_h1' not in sql  # the same hop as in_project's: one policy
    assert 'create index "mls_ix_projects_team_id_id" on "projects" ("team_id", "id")' in sql
    mutated = compile_spec(spec, {Mutation.HOP_VISIBILITY_DROPPED}).sql()
    assert "_h1_" not in mutated and "_h2_" not in mutated and "mls_rel_member_of_authenticated_1" in mutated


UP = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table organizations owned {
  id bigint not null;
  primary_key (id)
}

table projects owned {
  id bigint not null,
  organization_id bigint not null;
  primary_key (id)
}

table project_members owned {
  user_id uuid not null,
  project_id bigint not null;
  primary_key (user_id, project_id)
}

relation member_of = project_members(user_id, project_id)
relation org_of = member_of . projects(id, organization_id)

rules {
  R1 policy own_memberships on project_members: authenticated select permissive using user_id = @uid
  R2 policy org_reads_projects on projects: authenticated select permissive using org_of(@uid, organization_id)
%s}

properties {
  P1 must_allow projects authenticated select: member_of(@uid, id) description 'a project member reads the project'
%s}
"""


def test_a_hop_up_a_foreign_key_is_accepted_and_tied_to_the_rows():
    """#43: `projects(id, organization_id)` has a unique key and a non-unique value, so the chain
    is its own relation symbol; the row axiom puts a stored project's organization in it for every
    member of the project, which P1 needs (R2 reads the chain through `projects` itself, so it goes
    through a lookup helper and no visibility policy admits the members' rows)."""
    from mls.props import obligations
    from mls.spec.syntax import parse

    spec = check_spec(parse(UP % ("", "")))
    assert {r.id: r.verdict for r in run_all(spec)} == {"P1": "PROVED"}
    real = obligations.up_row_axioms
    try:
        obligations.up_row_axioms = lambda enc, rows: []
        assert {r.id: r.verdict for r in run_all(spec)} == {"P1": "REFUTED"}
    finally:
        obligations.up_row_axioms = real


def test_a_hop_up_a_foreign_key_proves_isolation_and_reach_of_the_parent():
    from mls.spec.syntax import parse

    spec = check_spec(parse(UP % (
        "  R3 policy member_reads_org on organizations: authenticated select permissive using org_of(@uid, id)\n",
        "  P2 tenant_isolation organizations: id in org_of(@uid) for select description 'a user only reads the organizations of their projects'\n"
        "  P3 must_allow organizations authenticated select: org_of(@uid, id) description 'a project member reads its organization'\n")))
    assert {r.id: r.verdict for r in run_all(spec)} == dict.fromkeys(["P1", "P2", "P3"], "PROVED")


def test_a_chain_up_a_foreign_key_grows_with_its_base_relation():
    """`monotone_in` compares two copies of the base relation; the upward chain is its own symbol in
    each, and the obligation reads no `projects` row that would tie them, so the chains need the
    copies' order stated (the collect takeover's "removing project memberships never grants")."""
    from mls.spec.syntax import parse

    spec = check_spec(parse(UP % (
        "  R3 policy member_reads_org on organizations: authenticated select permissive using org_of(@uid, id)\n",
        "  P2 monotone_in: member_of description 'removing project memberships never grants access'\n")))
    assert {r.id: r.verdict for r in run_all(spec)} == {"P1": "PROVED", "P2": "PROVED"}
