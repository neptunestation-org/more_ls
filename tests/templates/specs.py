"""Per-template specs for the differential and mutation tests.  Each variant of the example spec
isolates one template and the data shape its mutation needs (NULLs, column lists, bounds...)."""
from __future__ import annotations

import hashlib
import json

from mls.spec import check_spec
from mls.spec.model import Spec
from tests.conftest import EXAMPLE


def base() -> dict:
    return json.loads(EXAMPLE.read_text())


def make(d: dict) -> Spec:
    spec = Spec.model_validate(d)
    spec = check_spec(spec)
    return spec


def policy_spec() -> Spec:
    return make(base())


def in_spec() -> Spec:
    """A policy with `in` (expanded to an IN list): members see levels 2 and 3 whatever their
    clearance.  The mutation drops the last constant, hiding level 3 from low-clearance members.
    The admin policy (R2) and its lower bound go: in the generated data every member pair is
    also an admin pair, so with R2 the `in` policy would never decide anything."""
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] != "R2"]
    d["properties"] = [p for p in d["properties"] if p["id"] != "P8"]
    d["rules"].append({"id": "R10", "kind": "policy", "name": "member_read_high", "table": "docs",
                       "role": "authenticated", "command": "select", "mode": "permissive",
                       "using": {"and": [{"member": {"relation": "member_of", "key": {"ctx": "uid"},
                                                     "value": {"col": "tenant_id"}}},
                                         {"in": [{"col": "level"}, [{"const": 2}, {"const": 3}]]}]}})
    return make(d)


def up_spec() -> Spec:
    """#43: team_tasks with task assignees, whose chains go up foreign keys: an assignee reads the
    projects of their tasks (`assigned . tasks(id, project_id)`, one hop up, R6) and every project
    of those projects' teams (`. projects(id, team_id)`, two hops up; its chain reads `projects`, so
    R7 goes through a lookup helper).  Projects are readable only through those and the team
    policies' hop visibility; R5 is the composed fixture's update policy (filtered updates).  The
    mutation drops the hop visibility policies: the team chains read no project as the member."""
    d = composed_spec().model_dump(mode="json", by_alias=True, exclude_none=True)
    d["tables"]["task_assignees"] = {"columns": {"user_id": {"type": "uuid", "nullable": False},
                                                 "task_id": {"type": "bigint", "nullable": False}},
                                     "primary_key": ["user_id", "task_id"]}
    d["relations"]["assigned"] = {"table": "task_assignees", "key": "user_id", "value": "task_id"}
    d["relations"]["assigned_project"] = {"of": "assigned", "through": [{"table": "tasks", "key": "id", "value": "project_id"}]}
    d["relations"]["assigned_team"] = {"of": "assigned", "through": [{"table": "tasks", "key": "id", "value": "project_id"},
                                                                     {"table": "projects", "key": "id", "value": "team_id"}]}
    by_task = {"member": {"relation": "assigned_project", "key": {"ctx": "uid"}, "value": {"col": "id"}}}
    by_team = {"member": {"relation": "assigned_team", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    d["rules"] += [
        {"id": "R6", "kind": "policy", "name": "assignee_reads_projects", "table": "projects",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": by_task},
        {"id": "R7", "kind": "policy", "name": "assignee_reads_team_projects", "table": "projects",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": by_team},
        {"id": "R8", "kind": "policy", "name": "own_assignments", "table": "task_assignees",
         "role": "authenticated", "command": "select", "mode": "permissive",
         "using": {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}},
    ]
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "projects", "role": "authenticated", "command": "select",
         "when": by_task, "description": "an assignee reads the projects of their tasks"},
        {"id": "P7", "template": "must_allow", "table": "projects", "role": "authenticated", "command": "select",
         "when": by_team, "description": "an assignee reads every project of the teams of their tasks' projects"},
    ]
    return make(d)


def comember_spec() -> Spec:
    """#33: hops through membership tables, whose pair alone is unique.  A user reads the profiles
    of their teammates (`member_of . team_members(team_id, user_id)`, the self-join, R9) and of
    everyone assigned to a task of their teams (`. projects . tasks . task_assignees(task_id,
    user_id)`, lookups down and then one membership hop, R10), and their own (R11).  Both chains end
    in a hop with no lookup back, read through its own symbol; the teammate chain's hop visibility
    policy is on its own base table, so it goes through a lookup helper.  The mutation drops the
    hop visibility policies: the task chain reads no assignment as the member."""
    d = composed_spec().model_dump(mode="json", by_alias=True, exclude_none=True)
    d["tables"]["task_assignees"] = {"columns": {"user_id": {"type": "uuid", "nullable": False},
                                                 "task_id": {"type": "bigint", "nullable": False}},
                                     "primary_key": ["user_id", "task_id"]}
    d["tables"]["profiles"] = {"columns": {"user_id": {"type": "uuid", "nullable": False},
                                           "name": {"type": "text", "nullable": False}},
                               "primary_key": ["user_id"]}
    d["relations"]["teammate"] = {"of": "member_of", "through": [{"table": "team_members", "key": "team_id",
                                                                  "value": "user_id"}]}
    d["relations"]["team_assignee"] = {"of": "member_of", "through": [
        {"table": "projects", "key": "team_id", "value": "id"}, {"table": "tasks", "key": "project_id", "value": "id"},
        {"table": "task_assignees", "key": "task_id", "value": "user_id"}]}
    mate = {"member": {"relation": "teammate", "key": {"ctx": "uid"}, "value": {"col": "user_id"}}}
    assignee = {"member": {"relation": "team_assignee", "key": {"ctx": "uid"}, "value": {"col": "user_id"}}}
    own = {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}
    d["rules"] += [
        {"id": "R9", "kind": "policy", "name": "teammates_profiles", "table": "profiles",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": mate},
        {"id": "R10", "kind": "policy", "name": "assignees_profiles", "table": "profiles",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": assignee},
        {"id": "R11", "kind": "policy", "name": "own_profile", "table": "profiles",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": own},
    ]
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "profiles", "role": "authenticated", "command": "select",
         "when": mate, "description": "a user reads the profile of everyone who shares a team with them"},
        {"id": "P7", "template": "must_allow", "table": "profiles", "role": "authenticated", "command": "select",
         "when": assignee, "description": "a user reads the profile of everyone assigned to a task of their teams"},
        {"id": "P8", "template": "custom", "table": "profiles", "role": "authenticated", "command": "select",
         "goal": {"or": [mate, assignee, own]}, "description": "a user reads no other profile"},
    ]
    return make(d)


def nullable_member_spec() -> Spec:
    """The example with `docs.tenant_id` nullable (#42): a document with no tenant is nobody's
    (the membership is UNKNOWN, so the policies hide it from every member), and its writes are
    refused.  The mutation compiles the membership as `tenant_id is null or ...`, which shows those
    rows to everyone."""
    d = base()
    d["tables"]["docs"]["columns"]["tenant_id"]["nullable"] = True
    return make(d)


def check_nullable_spec() -> Spec:
    d = base()
    d["tables"]["docs"]["columns"]["flag"] = {"type": "int", "nullable": True}
    d["rules"].append({"id": "C1", "kind": "check", "name": "flag_bit", "table": "docs",
                       "predicate": {"or": [{"cmp": [{"col": "flag"}, "=", {"const": 0}]},
                                            {"cmp": [{"col": "flag"}, "=", {"const": 1}]}]}})
    return make(d)


def transition_nullable_spec() -> Spec:
    d = base()
    d["rules"].append({"id": "T1", "kind": "transition", "name": "owner_immutable", "table": "docs",
                       "predicate": {"cmp": [{"new": "owner_id"}, "=", {"old": "owner_id"}]}})
    return make(d)


def guard_spec() -> Spec:
    """#50: the owner of a document who is not one of its tenant's admins edits only its level and
    whether it is archived (a column guard: a trigger that fires for `authenticated` only, reading
    the editor's id and the admins relation as the caller).  P10's edits (which may clear the
    owner) are of unowned documents; P12 is the owner's edit the guard allows."""
    d = base()
    d["rules"].append({"id": "G1", "kind": "column_rule", "name": "owner_edits", "table": "docs",
                       "role": "authenticated", "access": "write", "columns": ["level", "archived"],
                       "when": {"and": [{"cmp": [{"col": "owner_id"}, "=", {"ctx": "uid"}]},
                                        {"not": {"member": {"relation": "admin_of", "key": {"ctx": "uid"},
                                                            "value": {"col": "tenant_id"}}}}]}})
    p10 = next(p for p in d["properties"] if p["id"] == "P10")
    p10["when"]["and"].append({"is_null": {"old": "owner_id"}})
    same = [{"cmp": [{"new": c}, "=", {"old": c}]} for c in ("id", "tenant_id", "owner_id")]
    d["properties"].append(
        {"id": "P12", "template": "must_allow", "table": "docs", "role": "authenticated", "command": "update",
         "when": {"and": [{"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"old": "tenant_id"}}},
                          {"cmp": [{"old": "owner_id"}, "=", {"ctx": "uid"}]},
                          {"cmp": [{"old": "archived"}, "=", {"const": 0}]},
                          {"cmp": [{"new": "archived"}, "=", {"const": 0}]},
                          {"cmp": [{"new": "level"}, ">=", {"const": 0}]},
                          {"cmp": [{"new": "level"}, "<=", {"ctx": "clearance"}]}, *same]},
         "description": "the owner of a document changes its level within their clearance"})
    return make(d)


def fk_spec() -> Spec:
    return make(base())


def deferred_spec() -> Spec:
    """#35: admins ⊆ member_of checked at commit (DEFERRABLE INITIALLY DEFERRED)."""
    d = base()
    next(r for r in d["rules"] if r["id"] == "R8")["deferred"] = True
    return make(d)


def cascade_spec() -> Spec:
    """#60 (D79): a document's notes are in its tenant (an inclusion into docs' (id, tenant_id)) and
    go with it: a member deletes a document of their tenant, and its notes are deleted too, which a
    member could delete one by one (the cascade obligation)."""
    d = base()
    d["tables"]["docs"]["unique"] = [["id", "tenant_id"]]
    d["tables"]["doc_notes"] = {"mode": "owned", "primary_key": ["id"], "columns": {
        "id": {"type": "int", "nullable": False}, "doc_id": {"type": "int", "nullable": False},
        "tenant_id": {"type": "int", "nullable": False}, "body": {"type": "text", "nullable": True}}}
    d["relations"]["doc_tenant"] = {"table": "docs", "key": "id", "value": "tenant_id"}
    member = {"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "tenant_id"}}}
    d["rules"] += [
        {"id": "D1", "kind": "policy", "name": "member_delete", "table": "docs", "role": "authenticated",
         "command": "delete", "mode": "permissive", "using": member},
        {"id": "N1", "kind": "policy", "name": "member_notes", "table": "doc_notes", "role": "authenticated",
         "command": "all", "mode": "permissive", "using": member, "check": member},
        {"id": "N2", "kind": "inclusion", "name": "note_in_doc", "table": "doc_notes",
         "columns": ["doc_id", "tenant_id"], "relation": "doc_tenant", "on_delete": "cascade"}]
    d["properties"] = [p for p in d["properties"] if p["template"] != "least_privilege"]
    next(p for p in d["properties"] if p["id"] == "P4")["invariants"].append({"rule": "N2"})
    return make(d)


def implied_key_spec() -> Spec:
    """#59: the cascade fixture with docs' `unique (id, tenant_id)` taken away: `id` is the primary
    key, so the pair is unique anyway and the compiler adds `mls_key_docs_id_tenant_id` itself."""
    d = json.loads(cascade_spec().model_dump_json(by_alias=True, exclude_none=True))
    d["tables"]["docs"]["unique"] = [u for u in d["tables"]["docs"].get("unique", []) if set(u) != {"id", "tenant_id"}]
    return make(d)


def set_null_spec() -> Spec:
    """#62: a note's document is in the note's tenant, and deleting the document keeps the note,
    with no document (`on_delete set_null` nulls doc_id, the tenant stays); a member could make
    that edit themselves, and a note's tenant never changes (a transition the nulling keeps)."""
    d = json.loads(cascade_spec().model_dump_json(by_alias=True, exclude_none=True))
    d["tables"]["doc_notes"]["columns"]["doc_id"]["nullable"] = True
    n2 = next(r for r in d["rules"] if r["id"] == "N2")
    n2["on_delete"] = "set_null"
    d["rules"].append({"id": "N4", "kind": "transition", "name": "note_tenant_fixed", "table": "doc_notes",
                       "predicate": {"cmp": [{"new": "tenant_id"}, "=", {"old": "tenant_id"}]}})
    return make(d)


def column_rule_spec() -> Spec:
    d = base()
    d["rules"].append({"id": "C1", "kind": "column_rule", "role": "authenticated", "table": "docs",
                       "columns": ["id", "tenant_id", "level"], "access": "read"})
    d["rules"].append({"id": "C2", "kind": "column_rule", "role": "authenticated", "table": "docs",
                       "columns": ["id", "tenant_id", "level", "owner_id"], "access": "write"})
    d["properties"] = []
    return make(d)


def time_spec() -> Spec:
    d = base()
    d["tables"]["docs"]["columns"]["valid_from"] = {"type": "timestamp", "nullable": True}
    d["tables"]["docs"]["columns"]["valid_until"] = {"type": "timestamp", "nullable": True}
    d["rules"].append({"id": "TB", "kind": "policy", "name": "currently_valid", "table": "docs",
                       "role": "authenticated", "command": "all", "mode": "restrictive",
                       "using": {"now_between": {"from": {"col": "valid_from"}, "until": {"col": "valid_until"}}}})
    return make(d)


def opaque_spec() -> Spec:
    d = base()
    d["opaques"] = {"low_or_cleared": {"table": "docs", "columns": ["level"], "context": ["clearance"],
                                       "sql": "level < 1 or {ctx:clearance} >= 3"}}
    d["rules"].append({"id": "OP", "kind": "policy", "name": "opaque_gate", "table": "docs",
                       "role": "authenticated", "command": "all", "mode": "restrictive",
                       "using": {"opaque": "low_or_cleared"}})
    return make(d)


def opaque_impl():
    return {"low_or_cleared": lambda row, ctx: row["level"] < 1 or ctx["clearance"] >= 3}


PG_ROLES = EXAMPLE.parent / "pg_roles_docs.mls.json"
SESSION = EXAMPLE.parent / "session_docs.mls.json"


def session_spec() -> Spec:
    """The example on the session_setting adapter (D47): the harness sets app.uid and
    app.clearance with set_config inside the transaction."""
    return make(json.loads(SESSION.read_text()))


def function_spec() -> Spec:
    """The session example on the trusted_function adapter (#72): the context values are read
    from `mls_ident.current_uid()` and `mls_ident.current_clearance()`, pinned by the md5 of the
    harness's stand-in bodies (so drift on a harness database is clean)."""
    from mls.identity.base import SQL_TYPE
    from mls.identity.trusted_function import stand_in_body

    d = json.loads(SESSION.read_text())
    d["identity"] = {"adapter": "trusted_function", "context": {
        n: {"source": f"mls_ident.current_{n}", "type": t,
            "md5": hashlib.md5(stand_in_body(n, SQL_TYPE[t]).encode()).hexdigest()}
        for n, t in (("uid", "uuid"), ("clearance", "int"))}}
    return make(d)


def optional_spec() -> Spec:
    """#75: `function_spec` with the user value optional, so the differential also runs as callers
    with no current user (the stand-in function returns NULL), and a policy reads `@uid is null`:
    a signed-out caller reads the public documents (clearance 0), a signed-in one by clearance."""
    s = function_spec()
    d = s.model_dump(mode="json", by_alias=True, exclude_none=True)
    d["identity"]["context"]["uid"]["optional"] = True
    d["rules"].append({"id": "R_signed_out", "kind": "policy", "name": "signed_out_public", "table": "docs",
                       "role": d["roles"][0], "command": "select", "mode": "permissive",
                       "using": {"and": [{"is_null": {"ctx": "uid"}}, {"cmp": [{"col": "level"}, "=", {"const": 0}]}]}})
    return make(d)


CITEXT = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table orgs adopted {
  id uuid not null,
  slug citext not null,
  kind citext,
  owner_id uuid not null;
  primary_key (id);
  unique (slug)
}

rules {
  R1 policy public_orgs on orgs: authenticated select permissive using slug = 'Public' or owner_id = @uid
  R2 policy own_kinds on orgs: authenticated update permissive using owner_id = @uid and kind in ('Team', 'personal') check owner_id = @uid
  R3 check no_admin on orgs: slug <> 'ADMIN'
}

properties {
  P1 must_allow orgs authenticated select: slug = 'PUBLIC'
  P2 custom orgs authenticated select new: slug <> 'admin'
}
"""


ROLE_CLAIM = """mls 0.1
identity supabase { uid: auth.uid uuid; user_role: jwt.claims.user_role enum app_role optional }
roles authenticated
enum app_role ('admin', 'moderator', 'it''s')

table channels adopted {
  id bigint not null,
  created_by uuid not null,
  min_role enum app_role;
  primary_key (id)
}

rules {
  R1 policy read_channels on channels: authenticated select permissive using min_role is null or min_role = @user_role or @user_role = 'admin'
  R2 policy remove_channels on channels: authenticated delete permissive using created_by = @uid or @user_role in ('admin', 'moderator')
  R3 policy edit_channels on channels: authenticated update permissive using @user_role <> 'it''s' check created_by = @uid
  R4 policy add_channels on channels: authenticated insert permissive check created_by = @uid
}

properties {
  P1 custom channels authenticated delete new: created_by = @uid or not @user_role is null
  P2 must_allow channels authenticated delete: @user_role = 'moderator'
}
"""


def role_claim_spec() -> Spec:
    """#89 (Slack clone): an optional claim of an enum type, `(auth.jwt() ->> 'user_role')::app_role`,
    whose labels need quoting.  The harness gives a caller a label or no claim; reads compare an enum
    column with the claim, deletes list two labels (the mutation drops 'moderator')."""
    from mls.spec.syntax import parse

    return make(parse(ROLE_CLAIM).model_dump(mode="json", by_alias=True, exclude_none=True))


def citext_spec() -> Spec:
    """#73: `orgs` adopted with citext columns compared with constants in another case than the
    data has (the harness writes the spec's constants lower-, upper- and as-cased): 'Public'
    reads 'PUBLIC' and 'public', the check keeps every case of 'admin' out, a unique slug refuses a
    second row differing only in case.  The mutation compares the column as text (case-sensitive)."""
    from mls.spec.syntax import parse

    return make(parse(CITEXT).model_dump(mode="json", by_alias=True, exclude_none=True))


DEFAULTS = """mls 0.1
identity supabase { uid: auth.uid uuid }
roles authenticated

table user_emails adopted {
  id uuid not null default fresh,
  user_id uuid not null default @uid,
  email text not null,
  is_verified bool not null default false,
  is_primary bool not null default false,
  created_at timestamp not null default @now;
  primary_key (id);
  assume ('rls not_forced')
}

rules {
  R1 policy add_own on user_emails: authenticated insert permissive check user_id = @uid and is_verified = false
  R2 policy read_own on user_emails: authenticated select permissive using user_id = @uid
  R3 column_rule address_only on user_emails: authenticated write email
  R4 policy delete_own on user_emails: authenticated delete permissive using user_id = @uid
}

properties {
  P1 must_allow user_emails authenticated insert: user_id = @uid and is_verified = false and is_primary = false
}
"""


def defaults_spec() -> Spec:
    """#76: an adopted table whose role writes only `email` on insert; the harness's stand-in has
    the declared defaults (the owner from auth.uid(), the flags false, a generated id, now()), and
    the oracle fills the columns the insert leaves out with them."""
    from mls.spec.syntax import parse

    return make(parse(DEFAULTS).model_dump(mode="json", by_alias=True, exclude_none=True))


def bigint_spec() -> Spec:
    """The session example with every key `bigint` (D53): the user id, the tenant ids and the
    document id, and the clearance a bigint context value compared with an int column.  The
    harness draws bigint values beyond 2³¹ (and user ids above 2³²), so an `integer` anywhere in
    the compiled script fails."""
    d = json.loads(SESSION.read_text())
    d["identity"]["context"]["uid"]["type"] = "bigint"
    d["identity"]["context"]["clearance"]["type"] = "bigint"
    for t, cols in (("memberships", ("user_id", "tenant_id")), ("admins", ("user_id", "tenant_id")),
                    ("docs", ("id", "tenant_id", "owner_id"))):
        for c in cols:
            d["tables"][t]["columns"][c]["type"] = "bigint"
    return make(d)


def pg_roles_spec() -> Spec:
    """The pg_roles rendering of the example (`examples/pg_roles_docs.mls.json`): same tables and
    rule shape (two permissive SELECT policies on docs, so the all-restrictive mutation is
    detectable), identity from `current_user`, no clearance claim."""
    return make(json.loads(PG_ROLES.read_text()))


# ----------------------------------------------------------------------------- versions (M2)
V2 = EXAMPLE.parent / "tenant_docs_v2.mls.json"


def v_a() -> Spec:
    """The example without the transition rule (no trigger)."""
    d = base()
    d["rules"] = [r for r in d["rules"] if r["id"] != "R9"]
    d["properties"] = [p for p in d["properties"] if p["id"] != "P2"]
    return make(d)


def v_b() -> Spec:
    return make(base())


def v_c() -> Spec:
    return make(json.loads(V2.read_text()))


def v_c_level() -> Spec:
    """v2 plus a permissive policy on `level` alone: the migration from v1 creates an index
    (`mls_ix_docs_level`) concurrently, and the migration back drops it.  (v2's policy on
    `owner_id` needs no index of its own: v1's inclusion index (owner_id, tenant_id) covers it.)"""
    d = json.loads(V2.read_text())
    d["rules"].append({"id": "R16", "kind": "policy", "name": "low_level_read", "table": "docs",
                       "role": "authenticated", "command": "select", "mode": "permissive",
                       "using": {"cmp": [{"col": "level"}, "<=", {"const": 0}]}})
    return make(d)


def v_d() -> Spec:
    """v2 plus: archived becomes NOT NULL, level becomes nullable, a unique (tenant_id, id), an FK."""
    d = json.loads(V2.read_text())
    d["tables"]["docs"]["columns"]["archived"]["nullable"] = False
    d["tables"]["docs"]["columns"]["level"]["nullable"] = True
    d["tables"]["docs"]["unique"] = [["tenant_id", "id"]]
    d["rules"].append({"id": "R15", "kind": "inclusion", "name": "owner_is_admin", "table": "docs",
                       "columns": ["owner_id", "tenant_id"], "relation": "admin_of", "on_delete": "restrict"})
    return make(d)


def v_tight() -> Spec:
    """The example with a stricter level range and a NULL-sensitive check on archived."""
    d = base()
    for r in d["rules"]:
        if r["id"] == "R6":
            r["predicate"] = {"and": [{"cmp": [{"col": "level"}, ">=", {"const": 0}]},
                                      {"cmp": [{"col": "level"}, "<=", {"const": 2}]}]}
    d["rules"].append({"id": "R14", "kind": "check", "name": "archived_bit", "table": "docs",
                       "predicate": {"or": [{"cmp": [{"col": "archived"}, "=", {"const": 0}]},
                                            {"cmp": [{"col": "archived"}, "=", {"const": 1}]}]}})
    return make(d)


# ----------------------------------------------------------------------------- M3
ORG = EXAMPLE.parent / "org_tree.mls.json"


def org_base() -> dict:
    return json.loads(ORG.read_text())


def hierarchy_spec() -> Spec:
    """org_tree where authenticated may also insert and update groups (so the depth bound and the
    parent immutability are exercised by app roles)."""
    d = org_base()
    d["rules"] += [
        {"id": "G1", "kind": "policy", "name": "group_insert", "table": "groups", "role": "authenticated",
         "command": "insert", "mode": "permissive", "check": {"lit": True}},
        {"id": "G2", "kind": "policy", "name": "group_update", "table": "groups", "role": "authenticated",
         "command": "update", "mode": "permissive", "using": {"lit": True}},
        {"id": "G3", "kind": "policy", "name": "member_insert", "table": "group_members", "role": "authenticated",
         "command": "insert", "mode": "permissive", "check": {"lit": True}},
        {"id": "G4", "kind": "policy", "name": "member_delete", "table": "group_members", "role": "authenticated",
         "command": "delete", "mode": "permissive", "using": {"lit": True}}]
    d["properties"] = [p for p in d["properties"] if p["id"] != "P5"]
    return make(d)


def cardinality_spec() -> Spec:
    """org_tree with a tight limit (2 files per tenant) and file deletes."""
    d = org_base()
    for r in d["rules"]:
        if r["id"] == "R5":
            r["max"] = 2
    d["rules"].append({"id": "F1", "kind": "policy", "name": "file_delete", "table": "files",
                       "role": "authenticated", "command": "delete", "mode": "permissive",
                       "using": {"in_group": {"hierarchy": "org", "key": {"ctx": "uid"}, "value": {"col": "group_id"}}}})
    d["properties"] = [p for p in d["properties"] if p["id"] != "P5"]
    return make(d)


def min_count_spec() -> Spec:
    """#61: the cardinality fixture with a minimum: a tenant keeps at least two files of size 3 or
    more once it has them (deletes and updates of files are checked at commit; two, the maximum,
    so that the random statements often meet the bound); and the maximum counts only those files
    too, so it bounds the large files (2) while small ones are free."""
    d = json.loads(cardinality_spec().model_dump_json(by_alias=True, exclude_none=True))
    big = {"cmp": [{"col": "size"}, ">=", {"const": 3}]}  # the generator draws ints from -1 to 4
    for r in d["rules"]:
        if r["id"] == "R5":
            r["where"] = big
    d["rules"].append({"id": "M1", "kind": "cardinality", "name": "keep_a_big_file", "table": "files",
                       "group": "tenant_id", "parent": "tenants", "min": 2, "where": big})
    return make(d)


def org_base_spec() -> Spec:
    return make(org_base())


def org_flat_spec() -> Spec:
    """org_tree without the hierarchy and the cardinality limit: direct membership only, every
    group a root (so a migration to org_tree finds consistent depths)."""
    d = org_base()
    del d["hierarchies"]
    for r in d["rules"]:
        for k in ("using", "check"):
            if "in_group" in r.get(k, {}):
                ig = r[k]["in_group"]
                r[k] = {"member": {"relation": "group_member", "key": ig["key"], "value": ig["value"]}}
    d["rules"] = [r for r in d["rules"] if r["kind"] != "cardinality"]
    d["rules"].append({"id": "X1", "kind": "check", "name": "groups_are_roots", "table": "groups",
                       "predicate": {"and": [{"is_null": {"col": "parent_id"}},
                                             {"cmp": [{"col": "depth"}, "=", {"const": 0}]}]}})
    d["properties"] = [p for p in d["properties"] if p["id"] in ("P4", "P5")]
    return make(d)


# ----------------------------------------------------------------------------- M5 (brownfield, D45)
def adopted_spec(assume: list[dict] | None = None) -> Spec:
    """The example with `docs` adopted (the harness creates it as the pre-existing table) and the
    optional hardening assumptions."""
    d = base()
    d["tables"]["docs"]["mode"] = "adopted"
    if assume:
        d["tables"]["docs"]["assume"] = assume
    return make(d)


def observed_spec() -> Spec:
    """The example plus an observed table nothing names."""
    d = base()
    d["tables"]["audit"] = {"columns": {"id": {"type": "int", "nullable": False}}, "mode": "observed",
                            "tags": ["legacy"]}
    return make(d)


def composed_spec() -> Spec:
    """The team_tasks example (D56): in_project (one hop, member_of . projects) and in_task (two,
    . tasks), without R1, so that projects are readable only through the hop's visibility policy,
    and with an update policy on tasks (filtered updates, a nested WITH CHECK).  The mutation drops
    the hops' visibility policies: the nested subqueries read no project as the role and every
    task and comment disappears."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["rules"] = [r for r in d["rules"] if r["id"] != "R1"]
    member = {"member": {"relation": "in_project", "key": {"ctx": "uid"}, "value": {"col": "project_id"}}}
    d["rules"].append({"id": "R5", "kind": "policy", "name": "member_updates_tasks", "table": "tasks",
                       "role": "authenticated", "command": "update", "mode": "permissive",
                       "using": member, "check": member})
    return make(d)


def owner_spec() -> Spec:
    """D60: the composed fixture plus the owner of each project.  `owns = projects(owner_id, id)`
    is a relation because `id` is the primary key; the owner reads and edits the tasks of their
    projects (R6, R7) and reads the comments on them through `owns . tasks(project_id, id)` (R8),
    whether or not they are in the project's team.  The mutation makes every policy restrictive,
    so an owner outside the team reads nothing."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["rules"] = [r for r in d["rules"] if r["id"] != "R1"]
    d["tables"]["projects"]["columns"]["owner_id"] = {"type": "uuid", "nullable": False}
    d["relations"]["owns"] = {"table": "projects", "key": "owner_id", "value": "id"}
    d["relations"]["owns_task"] = {"of": "owns", "through": [{"table": "tasks", "key": "project_id", "value": "id"}]}
    owner = {"member": {"relation": "owns", "key": {"ctx": "uid"}, "value": {"col": "project_id"}}}
    d["rules"] += [
        {"id": "R6", "kind": "policy", "name": "owner_reads_tasks", "table": "tasks", "role": "authenticated",
         "command": "select", "mode": "permissive", "using": owner},
        {"id": "R7", "kind": "policy", "name": "owner_edits_tasks", "table": "tasks", "role": "authenticated",
         "command": "update", "mode": "permissive", "using": owner, "check": owner},
        {"id": "R8", "kind": "policy", "name": "owner_reads_comments", "table": "comments", "role": "authenticated",
         "command": "select", "mode": "permissive",
         "using": {"member": {"relation": "owns_task", "key": {"ctx": "uid"}, "value": {"col": "task_id"}}}},
    ]
    d["properties"] = [p for p in d["properties"] if p["template"] != "tenant_isolation"] + [
        {"id": "P6", "template": "must_allow", "table": "tasks", "role": "authenticated", "command": "select",
         "when": owner, "description": "the owner of a project reads its tasks"},
        {"id": "P7", "template": "must_allow", "table": "comments", "role": "authenticated", "command": "select",
         "when": {"member": {"relation": "owns_task", "key": {"ctx": "uid"}, "value": {"col": "task_id"}}},
         "description": "the owner of a project reads the comments on its tasks"},
    ]
    return make(d)


def condition_spec() -> Spec:
    """D61: the composed fixture with a nullable `team_members.role`.  `lead_of` keeps the rows
    whose role is 'a' or 'b' (an `in`, expanded inside the relations; a NULL role is UNKNOWN, so
    not a lead): a lead edits their
    teams' projects (R6, R7) and deletes the tasks of those projects through `lead_of .
    projects(team_id, id)` (R8).  The mutation drops the condition from the subquery, so every
    member, NULL role included, edits and deletes."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["tables"]["team_members"]["columns"]["role"] = {"type": "text", "nullable": True}
    d["relations"]["lead_of"] = {"table": "team_members", "key": "user_id", "value": "team_id",
                                 "where": {"in": [{"col": "role"}, [{"const": "a"}, {"const": "b"}]]}}
    d["relations"]["leads_project"] = {"of": "lead_of",
                                       "through": [{"table": "projects", "key": "team_id", "value": "id"}]}
    lead = {"member": {"relation": "lead_of", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    leads = {"member": {"relation": "leads_project", "key": {"ctx": "uid"}, "value": {"col": "project_id"}}}
    d["rules"] += [
        {"id": "R6", "kind": "policy", "name": "lead_updates_projects", "table": "projects", "role": "authenticated",
         "command": "update", "mode": "permissive", "using": lead, "check": lead},
        {"id": "R7", "kind": "policy", "name": "lead_deletes_projects", "table": "projects", "role": "authenticated",
         "command": "delete", "mode": "permissive", "using": lead},
        {"id": "R8", "kind": "policy", "name": "lead_deletes_tasks", "table": "tasks", "role": "authenticated",
         "command": "delete", "mode": "permissive", "using": leads},
    ]
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "tasks", "role": "authenticated", "command": "delete",
         "when": leads, "description": "a lead deletes every task of their teams' projects"},
    ]
    return make(d)


def filtered_inclusion_spec(with_rule: bool = True) -> Spec:
    """#54: team_tasks where every project names a lead, `projects(lead_id, team_id)`, who must be a
    member of its team with role 'a': an inclusion into `lead_of`, a relation with a condition,
    so constraint triggers checked at commit.  A member edits their own membership row (R5, R6: a
    demotion or a removal of a project's lead is refused) and adds and edits their teams' projects
    (R7, R8: a project naming someone who is no lead is refused).  The mutations drop the
    condition (any member leads), the trigger on `team_members` (a lead is demoted under their
    project) and the deferral (a project and its lead's row cannot be written in either order)."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["tables"]["team_members"]["columns"]["role"] = {"type": "text", "nullable": True}
    d["tables"]["projects"]["columns"]["lead_id"] = {"type": "uuid", "nullable": False}
    d["relations"]["lead_of"] = {"table": "team_members", "key": "user_id", "value": "team_id",
                                 "where": {"cmp": [{"col": "role"}, "=", {"const": "a"}]}}
    own = {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}
    member = {"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    d["rules"] += [
        {"id": "I1", "kind": "inclusion", "name": "project_lead_leads", "table": "projects",
         "columns": ["lead_id", "team_id"], "relation": "lead_of", "on_delete": "restrict", "deferred": True},
    ][:1 if with_rule else 0] + [
        {"id": "R5", "kind": "policy", "name": "member_edits_own_membership", "table": "team_members",
         "role": "authenticated", "command": "update", "mode": "permissive", "using": own, "check": own},
        {"id": "R6", "kind": "policy", "name": "member_leaves", "table": "team_members", "role": "authenticated",
         "command": "delete", "mode": "permissive", "using": own},
        {"id": "R7", "kind": "policy", "name": "member_adds_projects", "table": "projects", "role": "authenticated",
         "command": "insert", "mode": "permissive", "check": member},
        {"id": "R8", "kind": "policy", "name": "member_edits_projects", "table": "projects", "role": "authenticated",
         "command": "update", "mode": "permissive", "using": member, "check": member},
    ]
    return make(d)



def filtered_inclusion_base_spec() -> Spec:
    """#54: the same without the inclusion, the migration's starting point."""
    return filtered_inclusion_spec(with_rule=False)

def set_spec() -> Spec:
    """#63: team_tasks with a nullable `projects.public`.  `public_projects` is a set relation, the
    ids of the projects whose `public` is TRUE (NULL is UNKNOWN: not public), and `public_tasks`
    is composed from it through `tasks(project_id, id)`.  Anyone signed in reads the tasks of a
    public project (R5) and the comments on them (R6), though only members read the project rows
    themselves (R1), and edits them while they stay in a public project (R7, filtered updates and
    a WITH CHECK): the set's helper reads `projects` without the caller's policies.  Its
    mutation reads them as the caller, so a non-member sees no public task; the condition's
    mutation drops `public = true`.  P1 and P3 (members only) no longer hold, by design."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["tables"]["projects"]["columns"]["public"] = {"type": "bool", "nullable": True}
    d["relations"]["public_projects"] = {"table": "projects", "value": "id",
                                         "where": {"cmp": [{"col": "public"}, "=", {"const": True}]}}
    d["relations"]["public_tasks"] = {"of": "public_projects",
                                      "through": [{"table": "tasks", "key": "project_id", "value": "id"}]}
    pub = {"member": {"relation": "public_projects", "value": {"col": "project_id"}}}
    pub_task = {"member": {"relation": "public_tasks", "value": {"col": "task_id"}}}
    d["rules"] += [
        {"id": "R5", "kind": "policy", "name": "anyone_reads_public_tasks", "table": "tasks",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": pub},
        {"id": "R6", "kind": "policy", "name": "anyone_reads_public_comments", "table": "comments",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": pub_task},
        {"id": "R7", "kind": "policy", "name": "anyone_edits_public_tasks", "table": "tasks",
         "role": "authenticated", "command": "update", "mode": "permissive", "using": pub, "check": pub},
    ]
    d["properties"] = [p for p in d["properties"] if p["id"] not in ("P1", "P3")] + [
        {"id": "P6", "template": "must_allow", "table": "tasks", "role": "authenticated", "command": "select",
         "when": pub, "description": "anyone signed in reads every task of a public project"},
        {"id": "P7", "template": "must_allow", "table": "comments", "role": "authenticated", "command": "select",
         "when": pub_task, "description": "anyone signed in reads every comment on a task of a public project"},
    ]
    return make(d)

def lookup_spec() -> Spec:
    """D67: team_tasks where the membership table's own policies read its relations, whose plain
    subqueries Postgres would refuse as infinite recursion: a member reads every membership of
    their teams (R5, `member_of` on `team_members`), a lead adds and removes members of their
    teams (R6, R7, `lead_of`, with a condition on a nullable `role`), and projects are readable
    only through `in_project`, whose hop runs through `projects` itself (R8, a composed helper).
    Those lookups call `mls_lookup_<relation>`; the others keep their subqueries.  The mutation
    drops the helpers' key: every user reads every membership and every project."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["rules"] = [r for r in d["rules"] if r["id"] != "R1"]
    d["tables"]["team_members"]["columns"]["role"] = {"type": "text", "nullable": True}
    d["relations"]["lead_of"] = {"table": "team_members", "key": "user_id", "value": "team_id",
                                 "where": {"cmp": [{"col": "role"}, "=", {"const": "lead"}]}}
    member = {"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    lead = {"member": {"relation": "lead_of", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    d["rules"] += [
        {"id": "R5", "kind": "policy", "name": "member_reads_memberships", "table": "team_members",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": member},
        {"id": "R6", "kind": "policy", "name": "lead_adds_members", "table": "team_members",
         "role": "authenticated", "command": "insert", "mode": "permissive", "check": lead},
        {"id": "R7", "kind": "policy", "name": "lead_removes_members", "table": "team_members",
         "role": "authenticated", "command": "delete", "mode": "permissive", "using": lead},
        {"id": "R8", "kind": "policy", "name": "member_reads_projects", "table": "projects",
         "role": "authenticated", "command": "select", "mode": "permissive",
         "using": {"member": {"relation": "in_project", "key": {"ctx": "uid"}, "value": {"col": "id"}}}},
    ]
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "team_members", "role": "authenticated",
         "command": "select", "when": member, "description": "a member reads every membership of their teams"},
        {"id": "P7", "template": "must_allow", "table": "team_members", "role": "authenticated",
         "command": "delete", "when": lead, "description": "a lead removes any member of their teams"},
    ]
    return make(d)


def nullable_relation_spec() -> Spec:
    """#49: the composed fixture with tasks assigned to a user or to nobody (`tasks.assignee_id`
    nullable), and the comments on a task readable only by its assignee (R6, `assigned_to(@uid,
    task_id)` over `tasks(assignee_id, id)`, in place of the team's R4).  A task with no assignee is
    no pair: nobody reads its comments.  The mutation lets the subquery take rows with a NULL key,
    so a member reads the comments on the unassigned tasks of their projects."""
    d = composed_spec().model_dump(mode="json", by_alias=True, exclude_none=True)
    d["tables"]["tasks"]["columns"]["assignee_id"] = {"type": "uuid", "nullable": True}
    d["relations"]["assigned_to"] = {"table": "tasks", "key": "assignee_id", "value": "id"}
    d["rules"] = [r for r in d["rules"] if r["id"] != "R4"]
    del d["relations"]["in_task"]  # R4's, unused without it
    assigned = {"member": {"relation": "assigned_to", "key": {"ctx": "uid"}, "value": {"col": "task_id"}}}
    d["rules"].append({"id": "R6", "kind": "policy", "name": "assignee_reads_comments", "table": "comments",
                       "role": "authenticated", "command": "select", "mode": "permissive", "using": assigned})
    # P1 (tasks by team) goes too: the assignee lookup's visibility policy shows an assignee their
    # own tasks, in any team's project
    d["properties"] = [p for p in d["properties"] if p["id"] not in ("P1", "P3", "P4")] + [
        {"id": "P6", "template": "tenant_isolation", "table": "comments", "column": "task_id",
         "relation": "assigned_to", "key": {"ctx": "uid"}, "commands": ["select"],
         "description": "a user only reads the comments on tasks assigned to them"},
        {"id": "P7", "template": "must_allow", "table": "comments", "role": "authenticated", "command": "select",
         "when": assigned, "description": "an assignee reads every comment on their tasks"},
    ]
    return make(d)


def storefront_spec() -> Spec:
    """D70: the composed fixture with a public side, the shape of a shop's storefront: a signed-out
    caller reads the comments on finished tasks (R6), checked with `done_task(true, task_id)` over
    `tasks(done, id)`, a lookup keyed by a constant.  Its visibility policy would be `done = true`
    for anon, every finished task of every team (P7 would be refuted), so it goes through a helper
    and anon reads no task.  Without the example's comment isolation (P3), which anon now crosses.  The mutation drops the helper's key: anon reads every comment."""
    d = composed_spec().model_dump(mode="json", by_alias=True, exclude_none=True)
    d["roles"] = ["anon", *d["roles"]]
    d["properties"] = [p for p in d["properties"] if p["id"] != "P3"]  # isolation, which anon's reads now cross
    d["relations"]["done_task"] = {"table": "tasks", "key": "done", "value": "id"}
    done = {"member": {"relation": "done_task", "key": {"const": True}, "value": {"col": "task_id"}}}
    d["rules"].append({"id": "R6", "kind": "policy", "name": "anon_reads_done_comments", "table": "comments",
                       "role": "anon", "command": "select", "mode": "permissive", "using": done})
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "comments", "role": "anon", "command": "select",
         "when": done, "description": "a signed-out caller reads the comments on finished tasks"},
        {"id": "P7", "template": "least_privilege",
         "allowed": {"anon": {"comments": ["select"]},
                     "authenticated": {"team_members": ["select"], "projects": ["select"],
                                       "tasks": ["select", "insert", "update"], "comments": ["select"]}},
         "description": "a signed-out caller reads nothing but comments"},
    ]
    return make(d)


# ----------------------------------------------------------------------------- case-sensitive names (D58)
MIXED_CASE = {"memberships": "Membership", "admins": "Admin", "docs": "Doc", "user_id": "userId",
              "tenant_id": "tenantId", "owner_id": "ownerId", "archived": "isArchived",
              "authenticated": "DocReader"}


def mixed_case_spec() -> Spec:
    """The pg_roles example with the names a Prisma schema has: PascalCase tables, camelCase
    columns and a mixed-case role, all quoted wherever MLS emits them.  The tables also have
    lower-case `tenantid`, `isarchived` and `userid` holding other data, so a reference emitted unquoted
    (Postgres folds `tenantId` to `tenantid`) reads the wrong column rather than failing (mutation
    `IDENT_UNQUOTED`)."""
    import re

    from mls.spec.syntax import parse

    text = PG_ROLES.with_suffix("").read_text()
    for old, new in MIXED_CASE.items():
        text = re.sub(rf"\b{old}\b", new, text)
    text = text.replace("  tenantId int not null,\n  ownerId", "  tenantId int not null,\n  tenantid int,\n  ownerId", 1)
    text = text.replace("  isArchived int;", "  isArchived int,\n  isarchived int;", 1)
    text = text.replace("  userId text not null,\n", "  userId text not null,\n  userid text,\n")  # Membership, Admin
    assert "tenantid int," in text and "isarchived int;" in text and text.count("userid text,") == 2
    return check_spec(parse(text))


ENUM_LABELS = ["Draft", "In review", "it's", "Published"]


def enum_spec(labels: list[str] | None = None) -> Spec:
    return make(enum_dict(labels))


def enum_dict(labels: list[str] | None = None) -> dict:
    """D59: `docs` adopted with a column of a mixed-case enum type whose labels need quoting.
    Members read the documents in the listed states whatever their clearance (an `in` the
    mutation shortens, hiding 'Published' ones), nobody reads one in review, and a draft stays at
    level 0 or 1 (a check rule).  Only a draft changes state, and a document with no state is never
    edited (T1, comparing the old and new status, #39; its NULLs are what `TRANSITION_NAIVE` lets
    through), so P10's edit keeps the status.  P11 holds only because the column holds nothing but its labels:
    `status <> 'In review'` leaves exactly the states R10 lists.  R2 and P8 go as in `in_spec`; P5
    and P7 go because R11 hides documents in review from their writers and their members."""
    d = base()
    d["enums"] = {"DocStatus": labels or ENUM_LABELS}
    d["tables"]["docs"]["mode"] = "adopted"
    d["tables"]["docs"]["columns"]["status"] = {"type": "enum", "enum": "DocStatus", "nullable": True}
    d["rules"] = [r for r in d["rules"] if r["id"] != "R2"]
    d["properties"] = [p for p in d["properties"] if p["id"] not in ("P5", "P7", "P8")]
    st = {"col": "status"}
    d["rules"] += [
        {"id": "R10", "kind": "policy", "name": "member_read_states", "table": "docs", "role": "authenticated",
         "command": "select", "mode": "permissive",
         "using": {"and": [{"member": {"relation": "member_of", "key": {"ctx": "uid"}, "value": {"col": "tenant_id"}}},
                           {"in": [st, [{"const": "Draft"}, {"const": "it's"}, {"const": "Published"}]]}]}},
        {"id": "R11", "kind": "policy", "name": "hide_in_review", "table": "docs", "role": "authenticated",
         "command": "select", "mode": "restrictive",
         "using": {"or": [{"is_null": st}, {"cmp": [st, "<>", {"const": "In review"}]}]}},
        {"id": "C1", "kind": "check", "name": "drafts_low", "table": "docs",
         "predicate": {"or": [{"is_null": st}, {"cmp": [st, "<>", {"const": "Draft"}]},
                              {"cmp": [{"col": "level"}, "<=", {"const": 1}]}]}},
        {"id": "T1", "kind": "transition", "name": "only_drafts_move", "table": "docs",
         "predicate": {"or": [{"cmp": [{"new": "status"}, "=", {"old": "status"}]},
                              {"cmp": [{"old": "status"}, "=", {"const": "Draft"}]}]}},
    ]
    p10 = next(p for p in d["properties"] if p["id"] == "P10")
    p10["when"]["and"].append({"cmp": [{"new": "status"}, "=", {"old": "status"}]})
    d["properties"].append(
        {"id": "P11", "template": "must_allow", "table": "docs", "role": "authenticated", "command": "select",
         "when": {"and": [{"member": {"relation": "member_of", "key": {"ctx": "uid"},
                                           "value": {"col": "tenant_id"}}},
                               {"not": {"is_null": st}}, {"cmp": [st, "<>", {"const": "In review"}]},
                               {"not": {"is_null": {"col": "archived"}}},
                               {"cmp": [{"col": "archived"}, "<>", {"const": 1}]}]},
         "description": "a member reads every unarchived document of their tenant that is not in review"})
    return d


def array_dict() -> dict:
    """#65: team_tasks with `team_members` adopted, a member's roles as `roles text[]` and their
    permissions as `perms "Perm"[]` (an enum array), both nullable.  `lead_of` is the members whose
    roles include 'lead' (a relation with a condition): a lead edits their team's projects (R5).
    A member reads their own row, and anyone's whose roles do not include 'private' (R6: a NULL
    array, or a NULL element, makes that UNKNOWN, so the row is hidden; the mutation reads a NULL
    element as no match).  A member edits their own row while their perms include 'edit' (R7), a
    banned member's row is refused (C1), and an edit never makes someone a lead (T1)."""
    d = json.loads((EXAMPLE.parent / "team_tasks.mls.json").read_text())
    d["enums"] = {"Perm": ["edit", "view"]}
    tm = d["tables"]["team_members"]
    tm["mode"] = "adopted"
    tm["columns"]["roles"] = {"type": "text[]", "nullable": True}
    tm["columns"]["perms"] = {"type": "enum[]", "enum": "Perm", "nullable": True}
    d["relations"]["lead_of"] = {"table": "team_members", "key": "user_id", "value": "team_id",
                                 "where": {"has": [{"col": "roles"}, {"const": "lead"}]}}
    own = {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}
    lead = {"member": {"relation": "lead_of", "key": {"ctx": "uid"}, "value": {"col": "team_id"}}}
    not_private = {"not": {"has": [{"col": "roles"}, {"const": "private"}]}}
    d["rules"] += [
        {"id": "R5", "kind": "policy", "name": "lead_edits_projects", "table": "projects", "role": "authenticated",
         "command": "update", "mode": "permissive", "using": lead, "check": lead},
        {"id": "R6", "kind": "policy", "name": "members_read_public_rows", "table": "team_members",
         "role": "authenticated", "command": "select", "mode": "permissive", "using": {"or": [own, not_private]}},
        {"id": "R7", "kind": "policy", "name": "editor_edits_own_row", "table": "team_members",
         "role": "authenticated", "command": "update", "mode": "permissive",
         "using": {"and": [own, {"has": [{"col": "perms"}, {"const": "edit"}]}]}, "check": own},
        {"id": "C1", "kind": "check", "name": "no_banned_members", "table": "team_members",
         "predicate": {"not": {"has": [{"col": "roles"}, {"const": "banned"}]}}},
        {"id": "T1", "kind": "transition", "name": "nobody_made_lead", "table": "team_members",
         "predicate": {"or": [{"has": [{"old": "roles"}, {"const": "lead"}]},
                              {"not": {"has": [{"new": "roles"}, {"const": "lead"}]}}]}},
    ]
    d["properties"] += [
        {"id": "P6", "template": "must_allow", "table": "team_members", "role": "authenticated",
         "command": "select", "when": not_private,
         "description": "a member reads every membership row whose roles do not include private"},
    ]
    return d


def array_spec() -> Spec:
    return make(array_dict())
