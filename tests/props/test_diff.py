"""Access diff (SEMANTICS §7): new grants and new denials with scenarios; constraint-aware;
opaque blocks flagged; integrity and privilege diffs."""
from __future__ import annotations

import json

from mls.props.diff import diff, to_json, to_markdown
from mls.spec import check_spec
from mls.spec.model import Spec
from tests.conftest import EXAMPLE
from tests.templates.specs import V2


def base() -> dict:
    return json.loads(EXAMPLE.read_text())


def make(d: dict) -> Spec:
    spec = Spec.model_validate(d)
    spec = check_spec(spec)
    return spec


def changes(d):
    return {(a.table, a.role, a.command, a.which, a.direction) for a in d.access_changes}


def test_same_spec_has_no_diff(example_spec):
    d = diff(example_spec, example_spec)
    assert not d.any_change and d.unknown == []


def test_added_policy_is_a_new_grant_with_scenario(example_spec):
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] != "R2"]  # no admin_read
    old = make(d)
    res = diff(old, example_spec)
    assert ("docs", "authenticated", "select", "using", "granted") in changes(res)
    assert ("docs", "authenticated", "select", "using", "denied") not in changes(res)
    a = next(a for a in res.access_changes if a.table == "docs" and a.command == "select")
    sc = a.scenario
    row, uid = sc.rows["r"]["values"], sc.context["uid"]
    assert [uid, row["tenant_id"]] in sc.relations["admin_of"]
    assert row["level"] > sc.context["clearance"]  # the only way admin_read adds anything
    # the implicit relation policy (D21) on admins is a new grant too, and a new privilege
    assert ("admins", "authenticated", "select", "using", "granted") in changes(res)
    assert any(g.table == "admins" and g.after for g in res.grants)
    # the reverse diff reports the same change as a denial
    back = diff(example_spec, old)
    assert ("docs", "authenticated", "select", "using", "denied") in changes(back)


def test_diff_respects_constraints(example_spec):
    """Restricting admin_read to level <= 3 changes nothing: the CHECK already bounds level."""
    d = base()
    for r in d["rules"]:
        if r["id"] == "R2":
            r["using"] = {"and": [r["using"], {"cmp": [{"col": "level"}, "<=", {"const": 3}]}]}
    assert not diff(example_spec, make(d)).access_changes


def test_example_v1_to_v2():
    old, new = make(base()), make(json.loads(V2.read_text()))
    res = diff(old, new)
    ch = changes(res)
    assert ("docs", "authenticated", "delete", "using", "granted") in ch
    assert ("tenant_settings", "authenticated", "select", "using", "granted") in ch
    assert ("docs", "authenticated", "select", "using", "granted") not in ch
    kinds = {(i.table, i.kind, i.direction) for i in res.integrity_changes}
    assert ("docs", "stored rows", "accepted") in kinds     # level 4 now allowed
    assert ("docs", "stored rows", "rejected") in kinds     # title '' now rejected
    assert ("docs", "changes", "rejected") in kinds         # owner now immutable
    assert any(g.command == "delete" and g.table == "docs" for g in res.grants)
    md = to_markdown(old, new, res)
    assert "can now delete rows of docs" in md and "for example:" in md
    assert "  - before: `false`\n  - after: `owner_id = @uid and not archived = 1`" in md
    j = to_json(old, new, res)
    assert j["summary"]["access_changes"] == 2 and all(a["scenario_english"] for a in j["access"])
    assert all(a["before"] and a["after"] for a in j["access"] + j["integrity"])
    assert "table 'tenant_settings' is new" in res.notes


def test_opaque_change_is_flagged(example_spec):
    d = base()
    d["opaques"] = {"gate": {"table": "docs", "columns": ["level"], "context": ["clearance"],
                             "sql": "level < 1 or {ctx:clearance} >= 3"}}
    d["rules"].append({"id": "OP", "kind": "policy", "name": "gate", "table": "docs", "role": "authenticated",
                       "command": "all", "mode": "restrictive", "using": {"opaque": "gate"}})
    with_gate = make(d)
    res = diff(example_spec, with_gate)
    a = next(a for a in res.access_changes if a.command == "select" and a.direction == "denied")
    assert a.opaque_deps == ["gate"]
    assert "conditional on unverified SQL: gate" in to_markdown(example_spec, with_gate, res)
    d2 = json.loads(json.dumps(d))
    d2["opaques"]["gate"]["sql"] = "level < 2"
    res2 = diff(with_gate, make(d2))
    assert any("different SQL" in n for n in res2.notes)
    assert {a.direction for a in res2.access_changes if a.command == "select"} == {"granted", "denied"}


def test_hierarchy_diff():
    """Replacing direct membership by in_group grants access (and denies nothing); lowering the
    depth bound denies access to the deepest groups and the diff names the changed hierarchy."""
    from tests.templates import specs

    flat, org = specs.org_flat_spec(), specs.org_base_spec()
    res = diff(flat, org)
    assert ("files", "authenticated", "select", "using", "granted") in changes(res)
    assert ("files", "authenticated", "select", "using", "denied") not in changes(res)
    a = next(a for a in res.access_changes if a.table == "files" and a.command == "select")
    assert a.scenario.hierarchies
    d = specs.org_base()
    d["hierarchies"]["org"]["max_depth"] = 2
    shallow = specs.make(d)
    res = diff(org, shallow)
    assert ("files", "authenticated", "select", "using", "denied") in changes(res)
    assert ("files", "authenticated", "select", "using", "granted") not in changes(res)
    assert any("depth bound changed from 3 to 2" in n for n in res.notes)
    assert not diff(org, org).any_change
    # a different members relation is a different tree: both directions change
    d = specs.org_base()
    d["relations"]["other"] = {"table": "group_members", "key": "user_id", "value": "group_id"}
    d["hierarchies"]["org"]["members"] = "other"
    d["properties"] = [p for p in d["properties"] if p["id"] != "P2"]
    res = diff(org, specs.make(d))
    assert any("defined differently" in n for n in res.notes)
    assert ("files", "authenticated", "select", "using", "denied") in changes(res)


def test_a_table_observed_in_either_version_is_not_compared():
    """Observed means no row-level security from the spec: what roles can do there is not
    modelled, so `before: false` would be a false report; the diff says so in a note instead."""
    from mls.spec.syntax import parse

    head = ("mls 0.1\nidentity supabase { uid: auth.uid uuid }\nroles authenticated\n"
            "table notes owned {\n  id int not null,\n  owner uuid not null;\n  primary_key (id)\n}\n")
    rule = "  R1 policy own on notes: authenticated select permissive using owner = @uid\n"
    old = parse(head + "table tags observed {\n  id int not null;\n  primary_key (id)\n}\n"
                + "rules {\n" + rule + "}\n")
    new = parse(head + "table tags owned {\n  id int not null;\n  primary_key (id)\n}\n"
                + "rules {\n" + rule + "  R2 policy all_tags on tags: authenticated select permissive using true\n}\n")
    d = diff(check_spec(old), check_spec(new))
    assert not d.any_change
    assert any("table 'tags' is observed in the old version" in n and "not compared" in n for n in d.notes)
    d = diff(check_spec(new), check_spec(old))
    assert not d.access_changes and any("observed in the new version" in n for n in d.notes)


def test_a_renamed_relation_is_no_change(monkeypatch):
    """The import names a relation after its table, the loop after its meaning: the same table,
    key, value and condition are the same pairs whatever they are called, and a composed relation
    over them follows.  A filtered relation in one version lies within the unfiltered one in the
    other (D62).  Without the cross-version axioms each rename is reported as a grant and a denial."""
    from mls.props import diff as diff_mod
    from mls.spec.syntax import parse
    from tests.props.test_properties import SUBSET

    old = check_spec(parse(SUBSET))
    renamed = SUBSET
    for a, b in (("member_of", "in_org"), ("admin_of", "org_admin"), ("member_project", "org_project"),
                 ("admin_project", "admin_project_of")):
        renamed = renamed.replace(a, b)
    new = check_spec(parse(renamed))
    assert not any(a.changed for a in diff(old, new).access_changes)
    # the admins' delete now asks only for the filtered relation: the unfiltered half was implied
    narrowed = check_spec(parse(renamed.replace(" and org_project(@uid, project_id)", "")))
    assert not any(a.changed for a in diff(old, narrowed).access_changes)
    monkeypatch.setattr(diff_mod, "both_axioms", lambda old, new, e_old, e_new: [
        *diff_mod.relation_axioms(old, e_old), *diff_mod.relation_axioms(new, e_new)])
    assert any(a.changed for a in diff(old, new).access_changes)


def test_a_count_rule_that_comes_or_goes_is_listed():
    """A cardinality rule is no row constraint the proofs compare, so the diff lists the ones only
    one version has (a minimum added, a maximum's condition changed) instead of saying that the same
    changes are accepted."""
    from mls.props.diff import to_markdown
    from tests.templates import specs

    old, new = specs.cardinality_spec(), specs.min_count_spec()
    d = diff(old, new)
    assert d.any_change
    assert {(c.rule.id, c.direction) for c in d.counts} == {("R5", "removed"), ("R5", "added"), ("M1", "added")}
    md = to_markdown(old, new, d)
    assert "None: the same rows and changes are accepted." not in md
    assert ("- a count on files is added (stated, not compared row by row): M1: No transaction leaves a tenants "
            "row with fewer than 2 rows of files where the row's size is at least 3") in md
    assert diff(new, new).counts == []


def test_a_deferred_inclusion_is_an_integrity_change():
    """#54: an inclusion checked at commit is left out of what a policy may assume, but it changes
    the data a database accepts, and the diff says so: a project whose lead is no lead (a member
    with another role) is rejected by the new version."""
    from mls.props.diff import integrity_diff
    from tests.templates import specs

    got = {(c.table, c.kind, c.direction, c.verdict)
           for c in integrity_diff(specs.filtered_inclusion_base_spec(), specs.filtered_inclusion_spec())}
    assert ("projects", "stored rows", "rejected", "REFUTED") in got, got
    assert ("projects", "stored rows", "accepted", "PROVED") in got, got


def test_a_value_optional_in_one_version_only_is_compared_for_callers_who_have_it():
    """#75: the old version takes the user as always set, the new one may lack it (an import of a
    trusted function).  The old version says nothing about a caller with no user, so the same rules
    are no change; the note says how the value was compared.  A change for signed-in callers
    still shows."""
    from tests.props.test_properties import SIGNED_OUT
    from mls.spec.syntax import parse

    old = check_spec(parse(SIGNED_OUT.split("properties")[0] % ("", "id = @uid or id <> @uid")))
    new = check_spec(parse(SIGNED_OUT.split("properties")[0] % (" optional", "id = @uid or id <> @uid")))
    res = diff(old, new)
    assert res.access_changes == [], res.access_changes
    assert any("may be unset in the new version only" in n for n in res.notes), res.notes
    narrowed = check_spec(parse(SIGNED_OUT.split("properties")[0] % (" optional", "id = @uid")))
    assert any(a.table == "users" and a.direction == "denied" for a in diff(old, narrowed).access_changes)


def test_an_example_says_when_the_caller_lacks_an_optional_value():
    """#78 (graphile/starter): reading users narrowed from everyone to signed-in callers.  The
    only caller who loses the read is one with no current user, and the example says so."""
    from tests.props.test_properties import SIGNED_OUT
    from mls.spec.syntax import parse

    old = check_spec(parse(SIGNED_OUT.split("properties")[0] % (" optional", "true")))
    new = check_spec(parse(SIGNED_OUT.split("properties")[0] % (" optional", "not @uid is null")))
    res = diff(old, new)
    denied = [a for a in res.access_changes if a.table == "users" and a.direction == "denied"]
    assert denied and denied[0].scenario.context.get("uid", "absent") is None, denied
    text = to_markdown(old, new, res)
    assert "is not set" in text, text
