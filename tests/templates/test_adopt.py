"""Milestone 5 (D45) on real Postgres: an adopted table owned by an app role proves and drifts with
the assumption stated; `check --dsn` verifies adopted tables against the catalog; `mls import` of
the deployed example round-trips to a spec with no opaque block, clean drift and an empty
behaviour diff (Milestone 5's first acceptance criterion); the hand-written Supabase-style
fixture imports to a spec that checks, its policies lifted where the lifter reads them and opaque
blocks carrying their signature where it does not."""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest

from mls.cli import main
from mls.compile import compile_spec
from mls.errors import SpecError
from mls.identity.base import get_adapter
from mls.pg.adopt import import_schema, verify_adopted
from mls.pg.drift import DriftError, drift
from mls.pg.harness import Harness, run_differential
from mls.props.diff import behaviour_diff
from mls.props.report import to_markdown
from mls.props.runner import run_all
from mls.spec import check_spec
from mls.spec.model import Spec
from tests.templates import specs

pytestmark = pytest.mark.pg

ASSUME = [{"owner": "authenticated"}, {"rls": "not_forced"}]
FIXTURE = Path(__file__).resolve().parent.parent / "brownfield" / "supabase_schema.sql"


@pytest.fixture(scope="module")
def adopted(pg_dsn):
    spec = specs.adopted_spec(ASSUME)
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_adopt")
    h.deploy()
    with h.conn.cursor() as cur:
        cur.execute('alter table "docs" owner to "authenticated"')  # the brownfield state the spec assumes
    yield spec, h
    h.close()


def test_assumed_hardening_is_reported_as_assumed(adopted):
    spec, h = adopted
    res = drift(h.conn, spec, compile_spec(spec))
    assert res.ok, [str(i) for i in res.items]
    kinds = {i.kind for i in res.items}
    assert kinds == {"assumed"}, [str(i) for i in res.items]
    assert any("owner authenticated is an app role and is trusted" in i.object for i in res.items)
    assert any("row level security is not forced" in i.object for i in res.items)
    assert "assumed: owner `authenticated` of adopted table `docs` is trusted" in to_markdown(spec, run_all(spec))


def test_without_the_assumption_it_is_hardening_drift(adopted):
    spec, h = adopted
    bare = specs.adopted_spec()
    res = drift(h.conn, bare, compile_spec(bare))
    assert not res.ok
    assert {i.kind for i in res.items} == {"hardening"}
    assert any("owned by app role authenticated" in i.object for i in res.items)


def test_stale_assumption_is_a_note(adopted):
    spec, h = adopted
    script = compile_spec(spec)
    with h.conn.transaction(force_rollback=True):
        with h.conn.cursor() as cur:
            cur.execute('alter table "docs" owner to current_user')
            cur.execute('alter table "docs" force row level security')
            for g in script.by_section("grants"):  # ownership transfer folds the old owner's grants into the new one
                cur.execute(g)
        res = drift(h.conn, spec, script)
    assert res.ok and res.items == [], [str(i) for i in res.items]
    assert any("no longer needed" in n and "owner" in n for n in res.notes)
    assert any("no longer needed" in n and "not_forced" in n for n in res.notes)


def test_adopted_differential_and_mutation(pg_dsn):
    spec = specs.adopted_spec()
    res = run_differential(spec, compile_spec(spec), pg_dsn, "mls_adopt_diff", seed=1, rows_per_table=30,
                           n_contexts=16, ops_per_context=25)
    assert res.ok, res.summary()
    from mls.compile import Mutation

    bad = run_differential(spec, compile_spec(spec, {Mutation.POLICY_ALL_RESTRICTIVE}), pg_dsn, "mls_adopt_mut",
                           seed=1, rows_per_table=30, n_contexts=16, ops_per_context=25)
    assert not bad.ok


def test_observed_table_must_exist(adopted):
    spec, h = adopted
    obs = specs.observed_spec()
    res = drift(h.conn, obs, compile_spec(obs))
    assert any(i.kind == "missing" and "table audit (observed)" in i.object for i in res.items)
    with h.conn.transaction(force_rollback=True):
        with h.conn.cursor() as cur:
            cur.execute('create table "audit" (id integer)')
        res = drift(h.conn, obs, compile_spec(obs))
    assert not any("audit" in i.object for i in res.items), [str(i) for i in res.items]


def test_check_dsn_verifies_adopted_tables(adopted, tmp_path, capsys):
    spec, h = adopted
    assert verify_adopted(h.conn, spec) == []
    wrong = spec.model_copy(deep=True)
    wrong.tables["docs"].columns["note"] = wrong.tables["docs"].columns["level"]  # declared int, text in the catalog
    with h.conn.transaction(force_rollback=True):
        with h.conn.cursor() as cur:
            cur.execute('alter table "docs" drop column "archived" cascade')
            cur.execute('alter table "docs" add column "note" text')
        errs = verify_adopted(h.conn, wrong)
    paths = {e.path: e for e in errs}
    assert "adopted table 'docs' has no column 'archived'" in paths["$.tables.docs.columns.archived"].message
    assert "text in the catalog, declared int" in paths["$.tables.docs.columns.note.type"].message
    # #68: an app role that can become a role bypassing the policies is refused, with the way out
    with h.conn.transaction(force_rollback=True):
        with h.conn.cursor() as cur:
            cur.execute('create role mls_chk_bypass bypassrls; grant mls_chk_bypass to "authenticated"')
        esc = [e for e in verify_adopted(h.conn, spec) if e.path.startswith("$.roles")]
    assert len(esc) == 1 and "can become 'mls_chk_bypass'" in esc[0].message and "revoke" in esc[0].fix, esc
    # the same table declared owned, while an app role owns it: refused with the fix
    owned = specs.policy_spec()
    errs = verify_adopted(h.conn, owned)
    assert len(errs) == 1 and errs[0].path == "$.tables.docs.mode"
    assert '{"owner": "authenticated"}' in errs[0].fix
    dsn = psycopg.conninfo.make_conninfo(h.dsn, dbname=h.dbname)
    p = tmp_path / "adopted.json"
    d = json.loads(specs.EXAMPLE.read_text())
    d["tables"]["docs"]["mode"] = "adopted"
    d["tables"]["docs"]["assume"] = ASSUME
    p.write_text(json.dumps(d))
    assert main(["check", str(p), "--dsn", dsn]) == 0
    assert "OK" in capsys.readouterr().out
    assert main(["check", str(specs.EXAMPLE), "--dsn", dsn, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["errors"][0]["path"] == "$.tables.docs.mode"


# ----------------------------------------------------------------------------- mls import
def test_import_of_the_deployed_example_round_trips(pg_dsn, example_spec, tmp_path, capsys):
    """Acceptance (ROADMAP M5): import the database `mls compile examples/tenant_docs.mls.json`
    deploys; the spec has 0 opaque blocks, its drift is clean and `behaviour_diff` against the
    source is empty."""
    h = Harness(example_spec, compile_spec(example_spec), pg_dsn, "mls_import_rt")
    h.deploy()
    try:
        res = import_schema(h.conn)
        imported = check_spec(Spec.model_validate(res.spec))
        assert imported.identity.adapter == "supabase"
        assert imported.identity.context["uid"].source == "auth.uid"
        assert imported.identity.context["clearance"].model_dump(exclude_defaults=True) == {"source": "jwt.claims.clearance", "type": "int"}
        assert imported.roles == ["authenticated"]
        assert {t: tb.mode for t, tb in imported.tables.items()} == {"docs": "adopted", "memberships": "adopted",
                                                                     "admins": "adopted"}
        assert imported.tables["docs"].columns == example_spec.tables["docs"].columns
        assert imported.tables["docs"].primary_key == ["id"]
        # the relations get their names back from the compiler's relation-visibility policies
        assert {n: (r.table, r.key, r.value) for n, r in imported.relations.items()} == {
            "member_of": ("memberships", "user_id", "tenant_id"), "admin_of": ("admins", "user_id", "tenant_id")}
        assert imported.opaques == {}, res.notes
        src = {(r.kind, r.name) for r in example_spec.rules}
        assert src == {(r.kind, r.name) for r in imported.rules}, res.notes
        by_name = {r.name: r for r in imported.rules}
        for r in example_spec.rules:
            assert by_name[r.name].model_dump(exclude={"id", "requirement"}) == r.model_dump(exclude={"id", "requirement"})
        assert any("relation-visibility policy" in n for n in res.notes)
        assert any("relation grant" in n for n in res.notes)
        d = drift(h.conn, imported, compile_spec(imported))
        assert d.ok and d.items == [], [str(i) for i in d.items]
        bad = [c for c in behaviour_diff(example_spec, imported) if c.verdict != "PROVED"]
        assert bad == [], [str(c) for c in bad]
        # the CLI: --out writes the spec, the notes go to stderr, and `check --dsn` accepts it
        dsn = psycopg.conninfo.make_conninfo(h.dsn, dbname=h.dbname)
        out = tmp_path / "imported.json"
        assert main(["import", "--dsn", dsn, "--out", str(out)]) == 0
        assert "note:" in capsys.readouterr().err
        assert main(["check", str(out), "--dsn", dsn]) == 0
        assert main(["drift", str(out), "--dsn", dsn]) == 0
        assert "drift: none" in capsys.readouterr().out
    finally:
        h.close()


@pytest.fixture(scope="module")
def brownfield(pg_dsn):
    dbname = "mls_brownfield"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(FIXTURE.read_text())
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def test_import_of_the_brownfield_fixture(brownfield):
    """Acceptance (ROADMAP M5): the hand-written Supabase-style schema imports to a spec that
    checks; the policies the lifter reads are in the fragment, every other one is an opaque
    block whose signature names the columns and context it reads; a proof over a block is
    conditional on it."""
    res = import_schema(brownfield)
    spec = check_spec(Spec.model_validate(res.spec))
    assert spec.identity.adapter == "supabase" and set(spec.identity.context) == {"uid", "role"}
    assert spec.identity.context["role"].model_dump(exclude_defaults=True) == {"source": "jwt.claims.role", "type": "text"}
    assert spec.roles == ["anon", "authenticated"]
    # #98: the anon key has no user, so uid is declared never set for anon, as an assumption the note
    # names; `role` is a claim the anon key carries
    assert spec.identity.context["uid"].unset_for == ["anon"]
    assert any("declared uid never set in sessions of anon" in n and "if it serves them as another role" in n
               for n in res.notes), res.notes
    modes = {t: tb.mode for t, tb in spec.tables.items()}
    assert modes == {"profiles": "adopted", "projects": "adopted", "project_members": "adopted",
                     "tasks": "adopted", "audit_log": "observed"}
    # bigint is modelled since D53 (the starter fixture of #20 keeps an unmodelled jsonb column)
    assert spec.tables["profiles"].columns["credits"].type == "bigint"
    assert spec.tables["tasks"].columns["id"].type == "bigint"
    assert spec.tables["profiles"].columns["created_at"].type == "timestamp"
    assert spec.tables["tasks"].primary_key == ["id"]
    # the lifted policies (bare auth.uid(), IN (subquery), EXISTS, a claim, a boolean column)
    by_name = {p.name: p for p in spec.policies()}
    pred = lambda p: p.model_dump(mode="json", by_alias=True, exclude_none=True)  # noqa: E731
    member = {"member": {"relation": "project_members", "key": {"ctx": "uid"}, "value": {"col": "project_id"}}}
    assert pred(by_name["tasks_of_my_projects"].using) == member
    assert pred(by_name["members_see_their_projects"].using) == {
        "member": {"relation": "project_members", "key": {"ctx": "uid"}, "value": {"col": "id"}}}
    assert pred(by_name["assignee_updates"].using) == {"and": [
        {"cmp": [{"col": "assignee"}, "=", {"ctx": "uid"}]}, {"cmp": [{"ctx": "role"}, "=", {"const": "editor"}]}]}
    assert pred(by_name["no_deletes_of_done_tasks"].using) == {"not": {"cmp": [{"col": "done"}, "=", {"const": True}]}}
    assert by_name["no_deletes_of_done_tasks"].mode == "restrictive"
    assert pred(by_name["users_update_own_profile"].using) == {"cmp": [{"col": "id"}, "=", {"ctx": "uid"}]}
    assert by_name["users_update_own_profile"].check is None  # equal to using: one predicate, not two
    two = [p for n, p in by_name.items() if n.startswith("members_see_memberships")]
    assert len(two) == 2 and {p.role for p in two} == {"anon", "authenticated"}
    assert pred(two[0].using) == pred(two[1].using) == {"cmp": [{"col": "user_id"}, "=", {"ctx": "uid"}]}
    assert spec.relations["project_members"].model_dump(exclude_none=True) == {"table": "project_members", "key": "user_id",
                                                               "value": "project_id"}
    # the owner of the parent row (D60): (owner, id) is unique in projects because id is its key
    assert by_name["insert_into_own_projects"].command == "insert" and by_name["insert_into_own_projects"].using is None
    own = pred(by_name["insert_into_own_projects"].check)
    rel = spec.relations[own["member"]["relation"]]
    assert (rel.table, rel.key, rel.value, rel.where) == ("projects", "owner", "id", None)
    assert own["member"]["key"] == {"ctx": "uid"} and own["member"]["value"] == {"col": "project_id"}
    # what stays opaque: a lookup with no key, whose filter is a LIKE
    o = spec.opaques[by_name["only_open_projects"].check.opaque]
    assert o.columns == ["project_id"] and o.context == [] and "projects" in o.sql
    assert list(spec.opaques) == [by_name["only_open_projects"].check.opaque]
    # #63: no key over a key of projects is a set; its condition, a LIKE, is what stays out
    assert any("only open projects" in n and "LIKE" in n for n in res.notes), [n for n in res.notes if "open" in n]
    assert any(n.startswith("lint:") and "auth.uid()" in n and "index-friendly" in n for n in res.notes)
    assert any(n.startswith("lint:") and "correlated EXISTS" in n for n in res.notes)
    # the CHECKs over NOT NULL columns are check rules; the trigger is listed
    checks = {r.name: pred(r.predicate) for r in spec.checks()}
    assert checks == {"projects_name_check": {"cmp": [{"col": "name"}, "<>", {"const": ""}]},
                      "tasks_priority_check": {"and": [{"cmp": [{"col": "priority"}, ">=", {"const": 0}]},
                                                       {"cmp": [{"col": "priority"}, "<=", {"const": 5}]}]}}
    assert any("tasks_priority_check" in n and "drift reports the definition as differs" in n for n in res.notes)
    # late binding (D48): a selector over the imported spec expands to every adopted table with the
    # column, the membership table included, whose expansion reads its own relation through a
    # helper (D67: its plain subquery would recurse); narrowed by name, the selector still filters
    # by the column
    from mls.spec.recursion import routed

    d = dict(res.spec)
    s1 = {"id": "S1", "kind": "policy", "name": "project_rows", "role": "authenticated",
          "command": "select", "mode": "permissive", "using": member,
          "applies_to": {"has_column": ["project_id", "uuid"]}}
    d["rules"] = d["rules"] + [s1]
    sel = check_spec(Spec.model_validate(d))
    rel = member["member"]["relation"]
    assert ("project_members", rel) in routed(sel) and ("tasks", rel) not in routed(sel)
    d["rules"][-1] = {**s1, "applies_to": {"and": [{"has_column": ["project_id", "uuid"]},
                                                   {"named": ["projects", "tasks"]}]}}
    sel = check_spec(Spec.model_validate(d))
    assert [r.table for r in sel.expansions("S1")] == ["tasks"]
    assert not any(r.kind == "inclusion" for r in spec.rules)  # single-column FKs are not inclusions
    cr = [r for r in spec.rules if r.kind == "column_rule"]
    assert [(r.table, r.role, r.access, r.columns) for r in cr] == [("profiles", "anon", "read", ["display_name", "id"])]
    assert any("is not an inclusion" in n for n in res.notes)
    assert any("has insert on project_members but no permissive insert policy" in n for n in res.notes)
    assert any("audit_log has row level security disabled: observed" in n for n in res.notes)
    assert any('"tasks of my projects" on tasks is imported as rule tasks_of_my_projects' in n for n in res.notes)
    assert any("trigger tasks_touch" in n and "never inlined" in n for n in res.notes)
    # proofs over the lifted policies are unconditional; one over the block is conditional on it
    d = dict(res.spec)
    d["properties"] = [
        {"id": "P1", "template": "write_subset_read", "table": "profiles"},
        {"id": "P2", "template": "tenant_isolation", "table": "tasks", "column": "project_id",
         "relation": "project_members", "key": {"ctx": "uid"}, "commands": ["select"]},
        # the restrictive insert policy is the opaque block: the written row is not shown readable
        {"id": "P3", "template": "write_subset_read", "table": "tasks"},
        {"id": "P4", "template": "custom", "table": "tasks", "role": "authenticated", "command": "insert",
         "goal": {"opaque": by_name["only_open_projects"].check.opaque}},
    ]
    proved = check_spec(Spec.model_validate(d))
    results = {r.id: r for r in run_all(proved)}
    assert results["P1"].verdict == "PROVED" and results["P1"].conditional_on == []
    assert results["P2"].verdict == "PROVED" and results["P2"].conditional_on == []
    assert results["P3"].verdict == "REFUTED"
    assert results["P4"].verdict == "PROVED" and results["P4"].conditional_on == ["only_open_projects_check"]
    md = to_markdown(proved, list(results.values()))
    assert "3 proved (1 conditional on opaque blocks), 1 refuted" in md
    for r in results.values():
        for name in r.conditional_on:
            assert f"opaque block '{name}' on" in md  # the assumptions list it with its SQL
        if r.conditional_on:
            assert f"conditional on opaque blocks: {', '.join(r.conditional_on)}" in md
    # the hardening state is recorded as assumptions, so drift reports it as assumed, not as hardening;
    # what fails is only what the notes announced: renamed policies and the grants without a policy
    assert all(tb.assume == [] or tb.mode == "adopted" for tb in spec.tables.values())
    assert [a.model_dump() for a in spec.tables["tasks"].assume] == [{"rls": "not_forced"}]
    assert any("table tasks: assumed row level security is not forced" in n for n in res.notes)
    dd = drift(brownfield, spec, compile_spec(spec))
    assert dd.by_kind("assumed") and not dd.by_kind("hardening"), [str(i) for i in dd.items]
    failing = [i for i in dd.items if i.kind not in ("foreign", "assumed")]
    assert failing
    for i in failing:  # renamed policies, the grants without a policy, the indexes and the CHECK form a deploy adds
        assert (i.kind in ("missing", "unexpected") and ("policy" in i.object or "privilege" in i.object)) \
            or (i.kind == "missing" and "index mls_ix_" in i.object) \
            or (i.kind == "differs" and "constraint" in i.object and "IS TRUE" in i.expected), str(i)
    assert any("privilege INSERT on project_members for authenticated" in i.object for i in failing)
    assert any("has delete on tasks but no permissive delete policy" in n for n in res.notes)


def test_import_needs_an_app_role(brownfield):
    with pytest.raises(SpecError) as ei:
        import_schema(brownfield, roles=[])
    assert ei.value.errors[0].path == "$.roles" and "--role" in ei.value.errors[0].fix


TYPES_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create table team_members (user_id bigint not null, team_id bigint not null, primary key (user_id, team_id));
create table tickets (
  id bigint generated by default as identity primary key,
  team_id bigint not null,
  status varchar(20) not null,
  title character varying,
  labels varchar(20)[],
  constraint tickets_team_ref_uq unique (team_id, id),
  check (status in ('open', 'closed')),
  foreign key (user_id, team_id) references team_members (user_id, team_id),
  user_id bigint not null
);
alter table team_members enable row level security;
alter table tickets enable row level security;
create policy own_memberships on team_members for select to app using (
  user_id = (select nullif(current_setting('app.uid', true), '')::bigint));
create policy member_read on tickets for select to app using (
  team_id = any (array(select team_id from team_members
                       where user_id = (select nullif(current_setting('app.uid', true), '')::bigint))));
create policy vip_read on tickets for select to app using ('vip' = any (labels));
"""
BIG = 2**40 + 7


@pytest.fixture
def typed(pg_dsn):
    dbname = "mls_types"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(TYPES_SQL)
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def test_bigint_keys_and_varchar_columns_import_deploy_and_drift(typed):
    """D53: `bigint` identity keys import as bigint, `varchar` columns as text on the adopted
    table; the imported spec deploys over the schema, drift is then clean (the CHECK over the
    varchar column included), and a key above 2³¹ passes through the compiled policy.  #65: a
    `varchar(n)[]` column is `text[]`, its label test (deparsed over a cast) is read, and drift's
    stand-in takes the live type.  #69: a unique key the table has under its own name matches the
    declared one by its columns, and a declared key the table lacks is still missing."""
    res = import_schema(typed)
    spec = check_spec(Spec.model_validate(res.spec))
    t = spec.tables["tickets"]
    assert t.mode == "adopted"
    assert {c: col.type for c, col in t.columns.items()} == {
        "id": "bigint", "team_id": "bigint", "status": "text", "title": "text", "labels": "text[]",
        "user_id": "bigint"}
    vip = next(r for r in spec.rules if r.kind == "policy" and r.name == "vip_read")
    assert vip.using.model_dump(by_alias=True) == {"has": ({"col": "labels"}, {"const": "vip"})}
    assert spec.identity.context["uid"].type == "bigint"
    assert res.spec["opaques"] == {}, res.notes
    check = next(r for r in spec.rules if r.kind == "check")  # the CHECK over the varchar column is read
    assert check.name == "tickets_status_check"
    verify_adopted(typed, spec)  # the catalog's varchar is the spec's text
    script = compile_spec(spec)
    with typed.transaction():
        with typed.cursor() as cur:
            # the deploy creates the CHECK it imported and does not replace the live one yet (#20)
            cur.execute("alter table tickets drop constraint tickets_status_check")
            for st in script.statements:
                cur.execute(st.sql)
    d = drift(typed, spec, script)
    assert d.ok, [str(i) for i in d.items]
    assert not [i for i in d.items if i.kind in ("differs", "missing")], [str(i) for i in d.items]
    assert ["team_id", "id"] in res.spec["tables"]["tickets"]["unique"]
    assert not any("named differently" in n for n in res.notes), res.notes
    other = spec.model_copy(deep=True)
    other.tables["tickets"].unique.append(["status", "user_id"])
    d = drift(typed, other, compile_spec(other))
    assert any(i.kind == "missing" and "tickets_status_user_id_key" in i.object for i in d.items), \
        [str(i) for i in d.items]
    with typed.transaction(force_rollback=True):
        with typed.cursor() as cur:
            cur.execute("insert into team_members values (%s, %s), (%s, 1)", (BIG, BIG + 1, BIG + 2))
            cur.execute("insert into tickets (id, team_id, status, user_id) values (%s, %s, 'open', %s), "
                        "(1, 1, 'open', %s)", (BIG + 3, BIG + 1, BIG, BIG + 2))
            cur.execute("select set_config('app.uid', %s, true)", (str(BIG),))
            cur.execute("set local role app")
            cur.execute("select id from tickets")
            assert [r[0] for r in cur.fetchall()] == [BIG + 3]


def test_discard_import_of_the_brownfield_fixture(brownfield):
    """D52 on plain Postgres: every table adopted (the one without RLS too), no policy, column rule
    or opaque block, each discarded policy listed with its text; `keep` stays the default."""
    res = import_schema(brownfield, policies="discard")
    spec = check_spec(Spec.model_validate(res.spec))
    assert all(t.mode == "adopted" for t in spec.tables.values())
    assert "audit_log" in spec.tables
    assert spec.policies() == [] and spec.column_rules() == [] and spec.opaques == {}
    discarded = [n for n in res.notes if " discarded (--policies discard" in n]
    assert len(discarded) == 10 and any("restrictive for delete to authenticated using ((NOT done))" in n
                                       for n in discarded), discarded
    assert spec.identity.adapter == "supabase"  # still read from the discarded policies' text
    assert import_schema(brownfield).spec["tables"]["audit_log"]["mode"] == "observed"


def test_import_notes_name_builtins_special_forms_and_the_user_column(brownfield):
    """#45: a CHECK calling a built-in (through a special form too) is kept with that reason, and
    a two-column key whose columns both have the user id's type but refer elsewhere says so."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table devices (id uuid primary key);
            create table boards (id uuid primary key, name text not null
                check (length(trim(both from name)) >= 1 and position('@' in name) = 0));
            create table device_boards (device_id uuid not null references devices,
                board_id uuid not null references boards, primary key (device_id, board_id));""")
        res = import_schema(brownfield, policies="discard")
    notes = [n for n in res.notes if "boards" in n]
    assert any("calls length(), a Postgres built-in function" in n for n in notes), notes
    assert not any("expected" in n for n in notes), notes
    assert any("table device_boards: the key (device_id, board_id) has a foreign key on each column "
               "(device_id to devices, board_id to boards), but neither refers to the user table "
               "(auth.users) and both have the user id's type (uuid), so either could be the user" in n
               for n in notes), notes


def test_enum_labels_are_the_catalogs(pg_dsn):
    """D59: drift's shadow creates its own copy of each enum type, so a deployed enum spec drifts
    clean; a label added to the live type (or a column the spec calls text) is drift and a
    `check --dsn` error naming the catalog's labels."""
    spec = specs.enum_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_enum")
    h.deploy()
    try:
        h.conn.execute('alter table "docs" force row level security')  # the owner's step (the compiler never forces it)
        script = compile_spec(spec)
        res = drift(h.conn, spec, script)
        assert res.ok and res.items == [], [str(i) for i in res.items]
        assert verify_adopted(h.conn, spec) == []
        with h.conn.transaction(force_rollback=True):
            h.conn.execute("""alter type "DocStatus" add value 'Gone'""")
            res = drift(h.conn, spec, script)
            assert [(i.kind, i.object) for i in res.items] == [("differs", "enum type DocStatus")]
            errs = verify_adopted(h.conn, spec)
            assert [e.path for e in errs] == ["$.enums.DocStatus"]
            assert "'Draft', 'In review', \"it's\", 'Published', 'Gone' in the catalog" in errs[0].message
        d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
        d["tables"]["docs"]["columns"]["status"] = {"type": "text", "nullable": True}
        d["enums"] = {}
        errs = verify_adopted(h.conn, Spec.model_validate(d))
        assert [(e.path, e.fix) for e in errs] == [("$.tables.docs.columns.status", "declare it as enum DocStatus")]
    finally:
        h.close()


HELPERS_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if;
             if not exists (select from pg_roles where rolname = 'mls_weak') then create role mls_weak; end if; end $$;
create table members (user_id bigint not null, team_id bigint not null, role text not null,
                      primary key (user_id, team_id));
create table tickets (id bigint primary key, team_id bigint not null, level int not null);
alter table members enable row level security;
alter table tickets enable row level security;
create function is_member(t bigint) returns boolean language sql stable security definer as $f$
  select exists (select 1 from members
                 where team_id = t and user_id = nullif(current_setting('app.uid', true), '')::bigint)
$f$;
create function has_role(t bigint, roles text[]) returns boolean language sql stable as $f$
  select exists (select 1 from members
                 where team_id = t and user_id = nullif(current_setting('app.uid', true), '')::bigint
                   and role = any(roles))
$f$;
create function is_member_v(t bigint) returns boolean language sql volatile security definer as $f$
  select exists (select 1 from members
                 where team_id = t and user_id = nullif(current_setting('app.uid', true), '')::bigint)
$f$;
create function is_member_w(t bigint) returns boolean language sql stable security definer as $f$
  select exists (select 1 from members
                 where team_id = t and user_id = nullif(current_setting('app.uid', true), '')::bigint)
$f$;
alter function is_member_w(bigint) owner to mls_weak;
create policy own_memberships on members for select to app using (
  user_id = nullif(current_setting('app.uid', true), '')::bigint);
create policy member_read on tickets for select to app using (is_member(team_id));
create policy admin_edit on tickets for update to app using (has_role(team_id, array['admin']));
create policy v_read on tickets for select to app using (level < 0 or is_member_v(team_id));
create policy w_read on tickets for select to app using (level < -1 or is_member_w(team_id));
"""


@pytest.fixture
def helpers(pg_dsn):
    dbname = "mls_helpers"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(HELPERS_SQL)
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def test_one_line_sql_helpers_are_read_inline_and_drift_checks_their_bodies(helpers):
    """#52: a stable one-statement SQL helper returning a boolean is read as its body: a SECURITY
    DEFINER one whose owner bypasses the table's policies (it reads every row, as a relation does)
    and an invoker one; #64: a volatile one too, with a note.  A definer one whose owner the policies
    bind stays an opaque call.  The table assumes each inlined helper with its body's md5, and drift
    reports a changed body as a difference."""
    res = import_schema(helpers)
    spec = check_spec(Spec.model_validate(res.spec))
    assert sorted(o["sql"].strip() for o in res.spec["opaques"].values()) == ["is_member_w(team_id)"], res.notes
    assert any("function is_member_v() is VOLATILE" in n for n in res.notes), res.notes
    rules = {r.name: r for r in spec.policies()}
    assert "member" in json.dumps(rules["member_read"].using.model_dump(by_alias=True, exclude_none=True))
    assert "member" in json.dumps(rules["admin_edit"].using.model_dump(by_alias=True, exclude_none=True))
    assumed = sorted(a.inlined.split(" md5 ")[0] for a in spec.tables["tickets"].assume if hasattr(a, "inlined"))
    assert assumed == ["function has_role(bigint, text[])", "function is_member(bigint)", "function is_member_v(bigint)"]
    helpers.execute("drop policy v_read on tickets; drop policy w_read on tickets")
    spec = check_spec(Spec.model_validate(import_schema(helpers).spec))
    script = compile_spec(spec)
    inline = [i for i in drift(helpers, spec, script).items if "body" in i.object]
    assert sorted(i.kind for i in inline) == ["assumed", "assumed"], [str(i) for i in inline]
    with helpers.transaction(force_rollback=True):
        helpers.execute("""create or replace function is_member(t bigint) returns boolean language sql stable
                           security definer as $f$ select true $f$""")
        changed = [i for i in drift(helpers, spec, script).items if "is_member(bigint)" in i.object]
        assert [i.kind for i in changed] == ["differs"] and "has a new body" in changed[0].object



ENUM_CALL_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create type member_role as enum ('owner', 'member');
create table members (user_id bigint not null, team_id bigint not null, role member_role not null,
                      primary key (user_id, team_id));
create table tickets (id bigint primary key, team_id bigint not null);
alter table tickets enable row level security;
create function has_role(t bigint, r member_role) returns boolean language plpgsql stable as $f$
  begin return exists (select 1 from members where team_id = t and role = r); end $f$;
create policy owner_read on tickets for select to app using (has_role(team_id, 'owner'::member_role));
"""


def test_drift_calls_a_function_over_a_live_enum_type(pg_dsn):
    """An opaque block that calls a function taking an enum must resolve that function in drift's
    shadow: the shadow uses the live type when its labels are the spec's, rather than a copy of the
    same name that no live function takes (basejump's `has_role_on_account(uuid, account_role)`)."""
    dbname = "mls_enum_call"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    try:
        with psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True) as conn:
            conn.execute(ENUM_CALL_SQL)
            res = import_schema(conn)
            spec = check_spec(Spec.model_validate(res.spec))
            assert [o["sql"].strip() for o in res.spec["opaques"].values()] == [
                "has_role(team_id, 'owner'::member_role)"], res.notes
            items = drift(conn, spec, compile_spec(spec)).items
            assert not any("owner_read" in i.object or "enum" in i.object for i in items), [str(i) for i in items]
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


BASEJUMP_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create schema bj;
create table bj.members (user_id bigint not null, team_id bigint not null, role text not null,
                         primary key (user_id, team_id));
create table bj.tickets (id bigint primary key, team_id bigint not null);
alter table bj.tickets enable row level security;
alter table bj.members enable row level security;
create function bj.has_role_on(team_id bigint, role text default null) returns boolean language sql
  security definer set search_path = public as $f$
select exists(select 1 from bj.members m
              where m.user_id = nullif(current_setting('app.uid', true), '')::bigint
                and m.team_id = has_role_on.team_id
                and (m.role = has_role_on.role or has_role_on.role is null))
$f$;
create policy member_read on bj.tickets for select to app using (bj.has_role_on(team_id) = true);
create policy owner_delete on bj.tickets for delete to app using (bj.has_role_on(team_id, 'owner') = true);
"""


def test_a_volatile_helper_with_a_defaulted_switch_reads_as_two_relations(pg_dsn):
    """#64, basejump's `has_role_on_account`: a VOLATILE definer helper in its own schema, whose
    body aliases its table and names its parameters by the function's name, called with and
    without its defaulted role, compared with true.  The default fills the short call, and the
    switch `(m.role = r or r is null)` folds per call: no role is the plain membership, 'owner' the
    owners among the members."""
    dbname = "mls_basejump"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    try:
        with psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True) as conn:
            conn.execute(BASEJUMP_SQL)
            res = import_schema(conn, schema="bj")
            spec = check_spec(Spec.model_validate(res.spec))
            assert res.spec["opaques"] == {}, res.notes
            rels = {(r.key, r.value, json.dumps(r.where.model_dump(by_alias=True, exclude_none=True)) if r.where else None)
                    for r in spec.base_relations().values()}
            assert rels == {("user_id", "team_id", None),
                            ("user_id", "team_id", '{"cmp": [{"col": "role"}, "=", {"const": "owner"}]}')}
            assert any("function has_role_on() is VOLATILE" in n for n in res.notes), res.notes
            items = drift(conn, spec, compile_spec(spec), schema="bj").items
            assert any(i.kind == "assumed" and "has_role_on(bigint, text)" in i.object for i in items), \
                [str(i) for i in items]
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')

HIDDEN_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create table members (user_id bigint not null, team_id bigint not null, role text not null,
                      primary key (user_id, team_id));
create table tickets (id bigint primary key, team_id bigint not null);
create table notes (id bigint primary key, team_id bigint not null);
create table pages (id bigint primary key, team_id bigint not null);
alter table members enable row level security;
alter table tickets enable row level security;
alter table notes enable row level security;
alter table pages enable row level security;
create policy not_viewers on members for select to app using (role <> 'viewer');
create function in_team(t bigint) returns boolean language sql stable security definer as $f$
  select exists (select 1 from members
                 where team_id = t and user_id = nullif(current_setting('app.uid', true), '')::bigint)
$f$;
create policy member_read on tickets for select to app using (
  exists (select 1 from members m
          where m.team_id = tickets.team_id and m.user_id = nullif(current_setting('app.uid', true), '')::bigint));
create policy helper_read on notes for select to app using (in_team(team_id));
create policy mixed_read on pages for select to app using (
  team_id < 0 or exists (select 1 from members m
                         where m.team_id = pages.team_id and m.user_id = nullif(current_setting('app.uid', true), '')::bigint));
create table profiles (user_id bigint primary key);
alter table profiles enable row level security;
create policy mates_read on profiles for select to app using (
  exists (select 1 from members a join members b on b.team_id = a.team_id
          where a.user_id = nullif(current_setting('app.uid', true), '')::bigint and b.user_id = profiles.user_id));
"""


@pytest.fixture
def hidden(pg_dsn):
    dbname = "mls_hidden"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(HIDDEN_SQL)
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def test_a_membership_whose_rows_the_inner_policies_hide_is_not_claimed(hidden):
    """#41: a hand-written subquery runs as the caller, under the membership table's own policies.
    Here a viewer's membership rows are hidden from the app, so `exists (select .. from members ..)`
    is narrower than the relation members(user_id, team_id): the import reads it as an opaque block
    (with a note), never as the membership.  The same subquery in a SECURITY DEFINER helper reads
    every row and lifts; in a disjunction only the subquery goes opaque.  Once the members' policy
    shows each user their own rows, the subquery lifts."""
    res = import_schema(hidden)
    spec = check_spec(Spec.model_validate(res.spec))
    rules = {r.name: r for r in spec.policies()}
    using = {n: json.dumps(r.using.model_dump(by_alias=True, exclude_none=True)) for n, r in rules.items()}
    assert '"opaque"' in using["member_read"] and '"member"' not in using["member_read"]
    assert '"member"' in using["helper_read"] and '"opaque"' not in using["helper_read"]
    assert '"cmp"' in using["mixed_read"] and '"opaque"' in using["mixed_read"] and '"member"' not in using["mixed_read"]
    flagged = [n for n in res.notes if "hide some of the rows it reads" in n]
    assert len(flagged) == 3 and any("member_read on tickets" in n for n in flagged), res.notes
    # #33: the co-members' chain is read, then left to an opaque block, and no longer proposed
    assert any("mates_read on profiles" in n for n in flagged), flagged
    assert '"opaque"' in using["mates_read"]
    assert not [r for r in res.spec["relations"].values() if "through" in r], res.spec["relations"]
    assert not [n for n in res.notes if " proposed: " in n and " . " in n], res.notes
    assert all("exists" in o["sql"].lower() or "EXISTS" in o["sql"] for o in res.spec["opaques"].values())

    hidden.execute("drop policy not_viewers on members; create policy own on members for select to app using ("
                   "user_id = nullif(current_setting('app.uid', true), '')::bigint)")
    res = import_schema(hidden)
    assert list(res.spec["opaques"]) == ["mates_read_using_rls"], res.notes  # teammates' rows stay hidden
    assert [n for n in res.notes if "hide some of the rows" in n and "mates_read" not in n] == []


UNDEPLOYED_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create table members (user_id bigint not null, team_id bigint not null, primary key (user_id, team_id));
create table docs (id bigint primary key, team_id bigint not null);
alter table members enable row level security;
alter table docs enable row level security;
create policy team_read on members for select to app using (
  team_id in (select m.team_id from members m where m.user_id = nullif(current_setting('app.uid', true), '')::bigint));
create function may_read(d bigint) returns boolean language plpgsql stable as $f$
  declare n bigint; begin n := d; return n > 0; end $f$;
create policy doc_read on docs for select to app using (may_read(id));
"""


@pytest.fixture
def undeployed(pg_dsn):
    dbname = "mls_undeployed"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    conn = psycopg.connect(psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname), autocommit=True)
    conn.execute(UNDEPLOYED_SQL)
    yield conn
    conn.close()
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')


def test_drift_of_an_import_mls_never_deployed(undeployed):
    """#53: drift on an imported spec before any deploy.  A role the spec needs and the server
    lacks (here an app role renamed to one that does not exist; on a real takeover the helpers'
    owner) is reported missing, not a crash: the shadow creates it inside its rolled-back
    transaction.  An opaque block's unqualified call of the schema's own function resolves in the
    shadow and deparses as the live policy does."""
    res = import_schema(undeployed)
    assert "may_read(id)" in json.dumps(res.spec["opaques"]), res.spec["opaques"]
    spec = check_spec(Spec.model_validate(res.spec))
    items = [str(i) for i in drift(undeployed, spec, compile_spec(spec)).items]
    assert not [i for i in items if "doc_read" in i], items

    absent = "mls_absent_role"
    spec = check_spec(Spec.model_validate(json.loads(json.dumps(res.spec).replace('"app"', f'"{absent}"'))))
    items = [str(i) for i in drift(undeployed, spec, compile_spec(spec)).items]
    assert f"missing: role {absent}" in items, items
    assert undeployed.execute("select count(*) from pg_roles where rolname = %s", (absent,)).fetchone()[0] == 0

    # a connection that may not create the role gets an error naming the fix
    undeployed.execute("do $$ begin if not exists (select from pg_roles where rolname = 'mls_no_createrole') then "
                       "create role mls_no_createrole; end if; end $$; "
                       "grant create on database mls_undeployed to mls_no_createrole; set role mls_no_createrole")
    try:
        with pytest.raises(DriftError, match=f"role {absent} does not exist .* CREATEROLE"):
            drift(undeployed, spec, compile_spec(spec))
    finally:
        undeployed.execute("reset role")


def test_drift_as_a_role_that_cannot_act_as_the_helpers_owner(pg_dsn):
    """#79 (graphile/starter): after a deploy, the helpers' owner exists, and the shadow transfers
    its helpers to it as the deploy did; a connection that may not act as that role (the tables'
    owner, say) gets an error naming the role and the fix, not a traceback."""
    dbname = "mls_drift_nonmember"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    try:
        spec = specs.lookup_spec()
        script = compile_spec(spec)
        with psycopg.connect(dsn) as conn:
            for st in get_adapter(spec).harness_setup_sql(spec)[:3]:  # auth.jwt(), auth.uid(); no grants yet
                conn.execute(st)
            conn.execute(script.sql())
            conn.commit()
            assert drift(conn, spec, script).ok
            conn.execute("do $$ begin if not exists (select from pg_roles where rolname = 'mls_not_internal') then "
                         "create role mls_not_internal; end if; end $$; "
                         f'grant create on database "{dbname}" to mls_not_internal; set role mls_not_internal')
            with pytest.raises(DriftError, match="mls_not_internal may not act as mls_internal.*fix: run drift as"):
                drift(conn, spec, script)
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


def test_a_cascading_key_imports_as_a_cascade_inclusion_and_a_clash_is_refused(brownfield):
    """#60 (D79): a two-column ON DELETE CASCADE key onto a key pair imports as an on_delete
    cascade inclusion, which the table's own single-column cascading key does not clash with;
    the same inclusion as restrict does (a parent delete would fire both, in an order the proofs
    cannot know), and `check --dsn` names the key."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table gadgets (id int primary key, shop int not null, unique (id, shop));
            create table gadget_parts (id int primary key,
                gadget_id int not null references gadgets on delete cascade, shop int not null,
                constraint part_in_shop foreign key (gadget_id, shop) references gadgets (id, shop)
                    on update restrict on delete cascade);""")
        res = import_schema(brownfield, policies="discard")
        spec = check_spec(Spec.model_validate(res.spec))
        inc = next(r for r in spec.inclusions() if r.name == "part_in_shop")
        assert inc.on_delete == "cascade" and inc.table == "gadget_parts"
        assert [e for e in verify_adopted(brownfield, spec) if "part_in_shop" in e.message] == []
        d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
        next(r for r in d["rules"] if r.get("name") == "part_in_shop")["on_delete"] = "restrict"
        errs = [e for e in verify_adopted(brownfield, Spec.model_validate(d)) if "part_in_shop" in e.message]
        assert len(errs) == 1 and errs[0].path.endswith(".on_delete"), errs
        assert ("the table's own foreign key 'gadget_parts_gadget_id_fkey' on (gadget_id) is ON DELETE CASCADE"
                in errs[0].message) and "use on_delete cascade" in errs[0].fix


def test_a_set_null_key_imports_as_a_set_null_inclusion_and_a_clash_is_refused(brownfield):
    """#62: a two-column key `ON DELETE SET NULL (its first column)` onto a key pair imports as an
    on_delete set_null inclusion, beside which the table's own single-column SET NULL key (scarpar's
    `deliveries.rider_id`) does not clash; the same inclusion as restrict does."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table couriers (id int primary key, shop int not null, unique (id, shop));
            create table drops (id int primary key,
                courier_id int references couriers on delete set null, shop int not null,
                constraint courier_in_shop foreign key (courier_id, shop) references couriers (id, shop)
                    on update restrict on delete set null (courier_id));""")
        res = import_schema(brownfield, policies="discard")
        spec = check_spec(Spec.model_validate(res.spec))
        inc = next(r for r in spec.inclusions() if r.name == "courier_in_shop")
        assert inc.on_delete == "set_null" and inc.columns == ["courier_id", "shop"]
        assert [e for e in verify_adopted(brownfield, spec) if "courier_in_shop" in e.message] == []
        d = json.loads(spec.model_dump_json(by_alias=True, exclude_none=True))
        next(r for r in d["rules"] if r.get("name") == "courier_in_shop")["on_delete"] = "restrict"
        errs = [e for e in verify_adopted(brownfield, Spec.model_validate(d)) if "courier_in_shop" in e.message]
        assert len(errs) == 1 and "is ON DELETE SET NULL" in errs[0].message, errs
        assert "use on_delete set_null" in errs[0].fix


SCHEMA_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create extension if not exists citext;
create schema app;
create table app.notes (id bigint primary key, owner_id bigint not null, body text, email citext);
alter table app.notes enable row level security;
create policy own_notes on app.notes for select to app using (
  owner_id = (select nullif(current_setting('app.uid', true), '')::bigint));
grant usage on schema app to app;
create function app.notes_by_email(e citext) returns setof bigint language sql security definer as $f$
  select id from app.notes where email = e $f$;
"""


def test_a_takeover_outside_public(pg_dsn, tmp_path, capsys):
    """#70: tables in another schema.  Every command with --dsn that finds none of the spec's
    tables in its schema says where they are and names --schema; with it, compile --schema writes
    a script that runs there, and drift is clean after it: with a type from an extension in public
    (citext, as graphile/starter has it), in a column and in a bypass path's signature."""
    dbname = "mls_other_schema"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SCHEMA_SQL)
        spec = tmp_path / "spec.mls.json"
        assert main(["import", "--dsn", dsn, "--schema", "app", "--out", str(spec)]) == 0
        assert "bypass path: function notes_by_email(citext)" in capsys.readouterr().err
        d = json.loads(spec.read_text())
        d["tables"]["notes"]["assume"].append({"bypass": "function notes_by_email(citext)"})
        spec.write_text(json.dumps(d))
        for cmd in (["check", str(spec)], ["drift", str(spec)], ["preflight", str(spec)], ["status", str(spec)]):
            assert main([*cmd, "--dsn", dsn]) != 0, cmd
            out = capsys.readouterr()
            assert "schema 'public'" in out.err + out.out and "--schema app" in out.err + out.out, (cmd, out)
        script = tmp_path / "deploy.sql"
        assert main(["compile", str(spec), "--schema", "app", "--out", str(script)]) == 0
        with psycopg.connect(dsn) as conn:  # as psql would run it: one transaction, the default search path
            conn.execute(script.read_text())
        capsys.readouterr()
        assert main(["drift", str(spec), "--dsn", dsn, "--schema", "app"]) == 0, capsys.readouterr()
        assert main(["check", str(spec), "--dsn", dsn, "--schema", "app"]) == 0
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


CLASH_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'app') then create role app; end if; end $$;
create function whoami() returns bigint language sql volatile as $f$ select 1::bigint $f$;
create table emails (id bigint primary key, user_id bigint not null, extra jsonb, label text);
create table logins (id bigint primary key, user_id bigint not null);
alter table emails enable row level security;
alter table logins enable row level security;
create policy select_own on emails for select to app using (user_id = whoami());
create policy select_own on logins for select to app using (user_id = whoami());
grant select on emails, logins to app;
grant update (extra, label) on emails to app;
create policy update_own on emails for update to app using (user_id = whoami());
grant insert (extra) on emails to app;
create policy insert_own on emails for insert to app with check (user_id = whoami());
"""


def test_an_import_names_each_tables_opaque_blocks_apart_and_drops_left_out_columns(pg_dsn, tmp_path, capsys):
    """#71 (graphile/starter): two tables with a policy of the same name get two opaque blocks, and
    a column grant over a column the import leaves out (jsonb) names only the modelled ones."""
    dbname = "mls_import_clash"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(CLASH_SQL)
        out = tmp_path / "before.json"
        assert main(["import", "--dsn", dsn, "--out", str(out)]) == 0, capsys.readouterr()
        err = capsys.readouterr().err
        d = json.loads(out.read_text())
        tables = {o["table"] for o in d["opaques"].values()}
        assert tables == {"emails", "logins"} and {"select_own_using", "logins_select_own_using"} <= set(d["opaques"]), d["opaques"]
        rule = next(r for r in d["rules"] if r["kind"] == "column_rule" and r["table"] == "emails")
        assert rule["columns"] == ["label"], rule
        assert "extra" in err and "not modelled" in err, err
        # insert only on the left-out column: no column rule could say so, so the policy goes (stricter)
        assert not any(r["kind"] == "policy" and r["command"] == "insert" for r in d["rules"]), d["rules"]
        assert "insert_own is not imported and the spec denies the insert" in err, err
        assert main(["check", str(out), "--dsn", dsn]) == 0, capsys.readouterr()
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


GRAPHILE_SQL = """
do $$ begin if not exists (select from pg_roles where rolname = 'visitor') then create role visitor; end if; end $$;
create schema app_public; create schema app_private;
create table app_public.users (id uuid primary key, name text);
create table app_public.orgs (id uuid primary key, name text);
create table app_public.org_members (org_id uuid not null references app_public.orgs,
  user_id uuid not null references app_public.users, primary key (org_id, user_id));
create table app_private.sessions (uuid uuid primary key, user_id uuid not null references app_public.users);
create function app_public.current_session_id() returns uuid as $f$
  select nullif(pg_catalog.current_setting('jwt.claims.session_id', true), '')::uuid;
$f$ language sql stable;
create function app_public.current_user_id() returns uuid as $f$
  select user_id from app_private.sessions where uuid = app_public.current_session_id();
$f$ language sql stable security definer set search_path to pg_catalog, public, pg_temp;
alter table app_public.users enable row level security;
alter table app_public.org_members enable row level security;
create policy select_self on app_public.users for select to visitor using (id = app_public.current_user_id());
create policy select_own on app_public.org_members for select to visitor using (user_id = app_public.current_user_id());
grant usage on schema app_public to visitor;
grant select on app_public.users, app_public.org_members to visitor;
"""


def test_an_identity_read_from_a_trusted_function(pg_dsn, tmp_path, capsys):
    """#72 (graphile/starter): the policies read the user from app_public.current_user_id(); the
    import takes it as the identity, pins its body, lifts the policies, and proposes the membership
    table keyed by the column that refers to the table the function's result refers to."""
    dbname = "mls_trusted_fn_import"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(GRAPHILE_SQL)
            digest = conn.execute("select md5(prosrc) from pg_proc where proname = 'current_user_id'").fetchone()[0]
        kept = tmp_path / "before.json"
        assert main(["import", "--dsn", dsn, "--schema", "app_public", "--out", str(kept)]) == 0, capsys.readouterr()
        err = capsys.readouterr().err
        d = json.loads(kept.read_text())
        assert d["identity"] == {"adapter": "trusted_function", "context": {"current_user_id": {
            "source": "app_public.current_user_id", "type": "uuid", "md5": digest, "optional": True}}}, d["identity"]
        assert "trusted_function" in err and "current_user_id()" in err, err
        assert not d.get("opaques"), d.get("opaques")
        own = next(r for r in d["rules"] if r["table"] == "org_members")
        assert own["using"] == {"cmp": [{"col": "user_id"}, "=", {"ctx": "current_user_id"}]}, own
        # deployed as imported, drift is clean: the pin matches the live body
        script = tmp_path / "deploy.sql"
        assert main(["compile", str(kept), "--schema", "app_public", "--out", str(script)]) == 0
        with psycopg.connect(dsn) as conn:
            conn.execute(script.read_text())
        capsys.readouterr()
        assert main(["drift", str(kept), "--dsn", dsn, "--schema", "app_public"]) == 0, capsys.readouterr()
        # the skeleton proposes the membership table: user_id refers to users, the sessions' user table
        skel = tmp_path / "skeleton.json"
        assert main(["import", "--dsn", dsn, "--schema", "app_public", "--policies", "discard",
                     "--out", str(skel)]) == 0, capsys.readouterr()
        s = json.loads(skel.read_text())
        assert {"table": "org_members", "key": "user_id", "value": "org_id"}.items() <= \
            next(iter(s["relations"].values())).items(), s.get("relations")
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


SET_HELPER_SQL = """
create function app_public.current_user_org_ids() returns setof uuid as $f$
  select org_id from app_public.org_members
    where user_id = app_public.current_user_id();
$f$ language sql stable security definer set search_path to pg_catalog, public, pg_temp;
alter table app_public.orgs enable row level security;
create policy select_member on app_public.orgs for select to visitor
  using (id in (select app_public.current_user_org_ids()));
create policy select_member_any on app_public.org_members for select to visitor
  using (org_id = any(array(select app_public.current_user_org_ids())));
grant select on app_public.orgs to visitor;
"""


def test_a_set_returning_helper_is_read_as_the_membership_its_body_is(pg_dsn, tmp_path, capsys):
    """#74 (graphile/starter): `id in (select current_user_org_ids())`, a one-statement SQL helper
    returning setof uuid, reads as the membership subquery its body is (the definer's owner
    bypasses the policies, so it reads every row, as a relation does), with its body pinned."""
    dbname = "mls_set_helper_import"
    with psycopg.connect(pg_dsn, autocommit=True) as admin:
        admin.execute(f'drop database if exists "{dbname}"')
        admin.execute(f'create database "{dbname}"')
    dsn = psycopg.conninfo.make_conninfo(pg_dsn, dbname=dbname)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(GRAPHILE_SQL + SET_HELPER_SQL)
        out = tmp_path / "before.json"
        assert main(["import", "--dsn", dsn, "--schema", "app_public", "--out", str(out)]) == 0, capsys.readouterr()
        err = capsys.readouterr().err
        d = json.loads(out.read_text())
        assert not d.get("opaques"), (d.get("opaques"), err)
        member = {"member": {"relation": next(iter(d["relations"])), "key": {"ctx": "current_user_id"},
                             "value": {"col": "id"}}}
        orgs = next(r for r in d["rules"] if r["table"] == "orgs")
        assert orgs["using"] == member, orgs
        rel = d["relations"][member["member"]["relation"]]
        assert (rel["table"], rel["key"], rel["value"]) == ("org_members", "user_id", "org_id"), rel
        assert any(a.get("inlined", "").startswith("function current_user_org_ids() md5 ")
                   for a in d["tables"]["orgs"]["assume"]), d["tables"]["orgs"]["assume"]
        any_rule = next(r for r in d["rules"] if r["table"] == "org_members" and r["name"] == "select_member_any")
        assert any_rule["using"]["member"]["value"] == {"col": "org_id"}, any_rule
        assert main(["check", str(out), "--dsn", dsn, "--schema", "app_public"]) == 0, capsys.readouterr()
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as admin:
            admin.execute(f'drop database if exists "{dbname}"')


def test_a_policy_with_no_expression_imports_as_granting_nothing(brownfield):
    """#81 (midday): Postgres grants nothing through a permissive policy whose USING is missing
    (select, update, delete; an update with only WITH CHECK too), or an insert policy whose WITH
    CHECK is missing.  Import reads each as `false`, with a note, never as `true`; a policy with
    USING and no WITH CHECK keeps USING as its check.  A restrictive one restricts nothing: `true`."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table bare (id int primary key, v int);
            alter table bare enable row level security;
            grant select, insert, update, delete on bare to authenticated;
            create policy bare_read on bare for select to authenticated;
            create policy bare_add on bare for insert to authenticated;
            create policy bare_edit on bare for update to authenticated with check (v > 0);
            create policy bare_drop on bare for delete to authenticated;
            create policy bare_bump on bare for update to authenticated using (v < 10);
            create policy bare_limit on bare as restrictive for select to authenticated;""")
        res = import_schema(brownfield)
    rules = {r["name"]: r for r in res.spec["rules"] if r.get("table") == "bare"}
    assert rules["bare_read"]["using"] == {"lit": False}, rules["bare_read"]
    assert rules["bare_add"]["check"] == {"lit": False}, rules["bare_add"]
    assert rules["bare_edit"]["using"] == {"lit": False}, rules["bare_edit"]
    assert rules["bare_drop"]["using"] == {"lit": False}, rules["bare_drop"]
    assert rules["bare_bump"]["using"] != {"lit": False} and "check" not in rules["bare_bump"], rules["bare_bump"]
    assert rules["bare_limit"]["using"] == {"lit": True}, rules["bare_limit"]  # restricts nothing
    for name, part in (("bare_read", "USING"), ("bare_add", "WITH CHECK"), ("bare_edit", "USING")):
        assert any(f"policy {name} on bare has no {part}" in n and "grants nothing" in n for n in res.notes), res.notes
    check_spec(Spec.model_validate(res.spec))


def test_a_policy_reading_auth_role_imports_per_role(brownfield):
    """#86 (nextbase): `author_id = auth.uid() or auth.role() = 'service_role'` to public.  Supabase's
    auth.role() is the caller's role, so each role's rule reads the test as a constant: the owner
    test for anon and authenticated (service_role is the trusted role, no app role)."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create function auth.role() returns text language sql stable as $f$
              select nullif(current_setting('request.jwt.claim.role', true), '')::text $f$;
            create table posts (id int primary key, author_id uuid, published boolean not null);
            alter table posts enable row level security;
            grant select on posts to authenticated, anon;
            create policy posts_read on posts for select using (
              published or (auth.uid() = author_id) or (auth.role() = 'service_role'::text));
            create policy posts_signed_in on posts for update using (auth.role() = 'authenticated');""")
        res = import_schema(brownfield)
    rules = {(r["name"], r["role"]): r for r in res.spec["rules"] if r.get("table") == "posts"}
    for name in ("posts_read", "posts_read_authenticated"):
        role = "authenticated" if name.endswith("authenticated") else "anon"
        assert "opaque" not in json.dumps(rules[(name, role)]), rules[(name, role)]
        assert "service_role" not in json.dumps(rules[(name, role)])
    assert rules[("posts_signed_in", "anon")]["using"] == {"lit": False}
    assert rules[("posts_signed_in_authenticated", "authenticated")]["using"] == {"lit": True}
    assert any("posts_read on posts reads auth.role()" in n for n in res.notes), res.notes
    check_spec(Spec.model_validate(res.spec))


def test_a_utc_wall_clock_default_is_not_now(brownfield):
    """#88 (nextbase): `timestamptz default timezone('utc', now())` stores now() only when the
    session's time zone is UTC; under another it is shifted by the offset, so import does not read
    it as now() and says why, with the fix."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table stamped (id int primary key, at timestamptz not null default timezone('utc', now()),
                                  plain timestamptz not null default now());
            alter table stamped enable row level security;""")
        brownfield.execute("set local time zone 'America/New_York'")
        shifted, same = brownfield.execute(
            "insert into stamped (id) values (1) returning at <> now(), plain = now()").fetchone()
        brownfield.execute("set local time zone 'UTC'")
        utc = brownfield.execute("insert into stamped (id) values (2) returning at = now()").fetchone()[0]
        res = import_schema(brownfield)
    assert shifted and same and utc
    cols = res.spec["tables"]["stamped"]["columns"]
    assert "default" not in cols["at"] and cols["plain"]["default"] == {"ctx": "now"}, cols
    assert any("stamped.at" in n and "only when the session's time zone is UTC" in n and "set default now()" in n
               for n in res.notes), res.notes


def test_supabases_authorize_helper_reads_as_a_role_grant(brownfield):
    """#90 (Slack clone): Supabase's documented RBAC.  The `user_role` claim is cast to the enum
    `app_role`, and `authorize(permission)` (plpgsql, SECURITY DEFINER) counts the caller's
    role_permissions rows.  Import reads the claim as an optional enum value and each call as a
    membership with a constant value, the table assuming the function by its md5."""
    from tests.pg.test_lift import AUTHORIZE

    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create type app_permission as enum ('channels.delete', 'messages.delete');
            create type app_role as enum ('admin', 'moderator');
            create table role_permissions (id bigint generated by default as identity primary key,
              role app_role not null, permission app_permission not null, unique (role, permission));
            create table channels (id bigint generated by default as identity primary key,
              created_by uuid not null);
            alter table role_permissions enable row level security;
            alter table channels enable row level security;
            grant select, delete on channels to authenticated;
            create function authorize(requested_permission app_permission) returns boolean
              language plpgsql security definer set search_path = public as $f$""" + AUTHORIZE + """$f$;
            create policy own_delete on channels for delete to authenticated using (auth.uid() = created_by);
            create policy authorized_delete on channels for delete to authenticated
              using (authorize('channels.delete'));""")
        res = import_schema(brownfield)
    assert res.spec["identity"]["context"]["user_role"] == {
        "source": "jwt.claims.user_role", "type": "enum", "enum": "app_role", "optional": True, "unset_for": ["anon"]}
    rule = next(r for r in res.spec["rules"] if r.get("name") == "authorized_delete")
    member = rule["using"]["member"]
    assert member["key"] == {"ctx": "user_role"} and member["value"] == {"const": "channels.delete"}, rule
    rel = res.spec["relations"][member["relation"]]
    assert (rel["table"], rel["key"], rel["value"]) == ("role_permissions", "role", "permission"), rel
    assert any("authorize(app_permission)" in a.get("inlined", "")
               for a in res.spec["tables"]["channels"].get("assume", [])), res.spec["tables"]["channels"]
    assert not [o for o in res.spec.get("opaques", {}).values() if o["table"] == "channels"], res.spec["opaques"]
    check_spec(Spec.model_validate(res.spec))


def test_a_helper_in_another_schema_is_read_inline(helpers):
    """#80 (midday): `team_id in (select private.my_teams() as my_teams)`, a set-returning definer
    helper in a schema of its own.  Import reads it as the membership it selects, the table
    assumes it under its qualified name, and drift checks that body."""
    with helpers.transaction(force_rollback=True):
        helpers.execute("""
            create schema private;
            create function private.my_teams() returns setof bigint language sql stable security definer as $f$
              select team_id from members where user_id = nullif(current_setting('app.uid', true), '')::bigint
            $f$;
            drop policy v_read on tickets; drop policy w_read on tickets; drop policy member_read on tickets;
            create policy team_read on tickets for select to app using (
              team_id in (select private.my_teams() as my_teams));""")
        res = import_schema(helpers)
        spec = check_spec(Spec.model_validate(res.spec))
        rules = {r.name: r for r in spec.policies()}
        assert "member" in json.dumps(rules["team_read"].using.model_dump(by_alias=True, exclude_none=True)), res.notes
        assert not [o for o in res.spec["opaques"].values() if "my_teams" in o["sql"]], res.spec["opaques"]
        assumed = [a.inlined.split(" md5 ")[0] for a in spec.tables["tickets"].assume if hasattr(a, "inlined")]
        assert "function private.my_teams()" in assumed, assumed
        items = [str(i) for i in drift(helpers, spec, compile_spec(spec)).items if "my_teams" in i.object]
        assert items == ["assumed: function private.my_teams() keeps the body the policies on tickets are read as"], items


def test_check_dsn_looks_a_field_up_in_its_composite_type(pg_dsn):
    """#94: `check --dsn` finds a declared field in its composite column's type, of its type."""
    spec = specs.composite_spec()
    h = Harness(spec, compile_spec(spec), pg_dsn, "mls_adopt_composite")
    h.deploy()
    try:
        assert verify_adopted(h.conn, spec) == []
        wrong = spec.model_copy(deep=True)
        cols = wrong.tables["endpoints"].columns
        cols["metadata.name"] = cols["metadata.workspace"]  # no such field
        cols["metadata.workspace"] = cols["metadata.workspace"].model_copy(update={"type": "int"})
        cols["status.phase"] = cols["metadata.workspace"]  # no such composite column
        paths = {e.path: e for e in verify_adopted(h.conn, wrong)}
        assert "composite type resource_meta has no field 'name'" in paths["$.tables.endpoints.columns.metadata.name"].message
        assert "is text in the catalog, declared int" in paths["$.tables.endpoints.columns.metadata.workspace.type"].message
        assert "has no composite column 'status'" in paths["$.tables.endpoints.columns.status.phase"].message
    finally:
        h.close()


def test_a_plpgsql_helper_of_guards_and_one_return_reads_inline(brownfield):
    """#95 (neutree): a plpgsql SECURITY DEFINER helper whose body is guards (`if c then return
    false; end if;`) and one `return e` reads as `(c) is not true and (e)`: here the membership its
    EXISTS selects, the table assuming the function by md5."""
    with brownfield.transaction(force_rollback=True):
        brownfield.execute("""
            create table crew (user_id uuid not null, team_id bigint not null, primary key (user_id, team_id));
            create table team_docs (id bigint primary key, team_id bigint not null);
            alter table crew enable row level security;
            alter table team_docs enable row level security;
            grant select on team_docs to authenticated;
            create function can_read_team(user_uuid uuid, t bigint) returns boolean
              language plpgsql stable security definer as $f$
            begin
                if user_uuid is null then
                    return false;
                end if;
                -- a member of the team
                return exists (select 1 from crew m where m.user_id = user_uuid and m.team_id = t);
            end;
            $f$;
            create policy team_read on team_docs for select to authenticated
              using (can_read_team(auth.uid(), team_id));""")
        res = import_schema(brownfield)
    rule = next(r for r in res.spec["rules"] if r.get("name") == "team_read" and r.get("role") == "authenticated")
    assert "member" in json.dumps(rule["using"]) and "opaque" not in json.dumps(rule["using"]), "\n".join(n for n in res.notes if "team_read" in n)
    assert any("can_read_team(uuid, bigint)" in a.get("inlined", "")
               for a in res.spec["tables"]["team_docs"].get("assume", [])), res.spec["tables"]["team_docs"]
    check_spec(Spec.model_validate(res.spec))
