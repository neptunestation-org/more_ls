"""Drift detection (D7, D8, D13, D45): compile the spec into a shadow schema on the same server, take
normalized catalog snapshots of the shadow and of the live schema, and compare them.  Everything
runs in one transaction that is rolled back, so the server is left untouched.

Reported: missing objects, objects that differ (expression, validation state, roles, privileges),
foreign objects on MLS-owned tables (policies, triggers, constraints, indexes the spec does not
own), hardening (RLS enabled and forced, app roles without BYPASSRLS/superuser, no SET on
session_replication_role, app role not the owner).  Tables in the schema that the spec does not
mention are listed as notes, not drift.

Table modes (D45): on an `adopted` table a constraint, trigger, index or column the spec does not
declare is `foreign` (listed, not drift: the table was not created by MLS), while an undeclared
policy or privilege is still `unexpected` (it changes what a role can do).  Hardening the spec
states under `assume` is reported as `assumed`, not as `hardening`; an assumption the catalog no
longer needs is a note.  An `observed` table is only checked to exist.

Bypass paths (D54): a view that is not `security_invoker` (or a materialized view) over a governed
table that an app role may use, and a SECURITY DEFINER function an app role may execute whose
owner bypasses the table's policies and whose body names it, are `hardening` with their fix, or
`assumed` when the table assumes `{"bypass": "<path>"}`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

import psycopg
from psycopg import sql as psql

from mls.compile.internal import INTERNAL_ROLE, needs_internal_role
from mls.compile.plan import Script
from mls.compile.sql import enum_ddl, q
from mls.compile.table import table_ddl
from mls.identity import get_adapter
from mls.pg.catalog import Snapshot, bypass_paths, snapshot
from mls.pg.lift import mls_type
from mls.spec.model import BypassAssumed, InlinedAssumed, OwnerAssumed, PathAssumed, RlsAssumed, Spec

FAILING = ("missing", "unexpected", "differs", "hardening")


class DriftError(Exception):
    """The shadow deploy could not run on this connection."""


@dataclass
class DriftItem:
    kind: str        # missing | unexpected | differs | hardening | assumed | foreign
    object: str
    expected: str | None = None
    actual: str | None = None

    def __str__(self) -> str:
        s = f"{self.kind}: {self.object}"
        if self.expected is not None or self.actual is not None:
            s += f" (expected {self.expected!r}, found {self.actual!r})"
        return s


@dataclass
class DriftResult:
    items: list[DriftItem]
    notes: list[str]

    @property
    def ok(self) -> bool:
        """No drift: `assumed` and `foreign` items are the expected state of an adopted table."""
        return not any(i.kind in FAILING for i in self.items)

    def by_kind(self, kind: str) -> list[DriftItem]:
        return [i for i in self.items if i.kind == kind]


def shadow_snapshot(conn: psycopg.Connection, spec: Spec, script: Script,
                    live_types: dict[str, dict[str, str]] | None = None, live: str = "public",
                    missing_roles: list[str] = ()) -> Snapshot:
    """Deploy the script into a throwaway schema inside the current transaction and snapshot it.
    `live_types` are the catalog types an adopted table's stand-in takes in place of the spec's
    (a `character varying(n)` column the spec reads as text, D53), so that its constraints and
    indexes deparse as the live ones do.  The live schema follows the shadow on the search path, so
    an opaque block's unqualified call of one of its functions resolves (#53).  `missing_roles` are
    the spec's roles the server lacks (the deploy creates them; drift reports them missing): the
    shadow creates them for its own statements, and the rollback drops them again."""
    shadow = "mls_shadow_" + secrets.token_hex(4)
    with conn.cursor() as cur:
        cur.execute(psql.SQL("create schema {}").format(psql.Identifier(shadow)))
        # the deploy's path (`<schema>, public`): a type an extension put in public, such as citext, resolves
        cur.execute(psql.SQL("set local search_path to {}, {}, public, pg_catalog").format(
            psql.Identifier(shadow), psql.Identifier(live)))
        for r in missing_roles:
            try:
                cur.execute(psql.SQL("create role {} nologin").format(psql.Identifier(r)))
            except psycopg.errors.InsufficientPrivilege:
                raise DriftError(f"role {r} does not exist and this connection may not create it, so the spec "
                                 f"cannot be deployed into the shadow schema (fix: run drift as a role with "
                                 f"CREATEROLE, or create the role {r} first; the deploy creates it too)") from None
            if r == INTERNAL_ROLE:  # the helpers' owner: transferring them needs the membership
                cur.execute(psql.SQL("grant {} to {}").format(psql.Identifier(r), psql.Identifier(
                    cur.execute("select current_user").fetchone()[0])))
        for name, labels in spec.enums.items():  # the stand-ins' types, named as the live ones print
            live_labels = cur.execute(
                """select array(select e.enumlabel from pg_enum e where e.enumtypid = t.oid order by e.enumsortorder)
                   from pg_type t join pg_namespace n on n.oid = t.typnamespace
                   where n.nspname = %s and t.typname = %s and t.typtype = 'e'""", (live, name)).fetchone()
            if live_labels is not None and list(live_labels[0]) == list(labels):
                continue  # the live type itself: an opaque block's call of a function over it must still resolve
            cur.execute(enum_ddl(name, labels))
        for name, t in spec.tables.items():
            if t.mode == "adopted":  # the script does not create it: stand in for the existing table
                for s in table_ddl(name, t):
                    cur.execute(s)
                for c, ty in (live_types or {}).get(name, {}).items():
                    cur.execute(f"alter table {q(name)} alter column {q(c)} type {ty}")
        for st in script.statements:
            if st.section == "roles":
                continue  # roles are global; their attributes are compared directly
            cur.execute(st.sql)
    return snapshot(conn, shadow, list(spec.governed()), _roles(spec), _observed(spec), also=live)


def _live_types(spec: Spec, actual: Snapshot) -> dict[str, dict[str, str]]:
    """The adopted columns declared text (or text[], D88) whose live type is another that MLS reads
    as that: `varchar(n)`, `varchar(n)[]`."""
    out: dict[str, dict[str, str]] = {}
    for name, t in spec.tables.items():
        live = actual["tables"].get(name)
        if t.mode != "adopted" or live is None:
            continue
        for c, col in t.columns.items():
            lc = live["columns"].get(c)
            if col.type in ("text", "text[]", "citext") and lc is not None and lc["type"] != col.type \
                    and mls_type(lc["type"]) == col.type:
                out.setdefault(name, {})[c] = lc["type"]
    return out


def _roles(spec: Spec) -> list[str]:
    return list(spec.roles) + ([INTERNAL_ROLE] if needs_internal_role(spec) else [])


def _observed(spec: Spec) -> list[str]:
    return [t for t, tb in spec.tables.items() if tb.mode == "observed"]


def _assumed(spec: Spec, table: str, cls, value: str) -> bool:
    """Whether `table` assumes `cls` with the given value (owner / bypassrls role, or rls mode)."""
    field = next(iter(cls.model_fields))
    return any(isinstance(a, cls) and getattr(a, field) == value for a in spec.tables[table].assume)


def path_key(path: str) -> str:
    return " ".join(path.split()).replace("( ", "(").replace(" )", ")").replace(" ,", ",")


def bypass_report(spec: Spec, paths: dict[str, list[dict]]) -> tuple[list[DriftItem], list[str]]:
    """The bypass paths (D54, `catalog.bypass_paths`) of the governed tables as drift items:
    `hardening` with the fix, or `assumed` when the table assumes the path; an assumed path the
    catalog no longer shows is a note.  `drift` and `mls status --dsn` both read this."""
    items: list[DriftItem] = []
    notes: list[str] = []
    for t, found in paths.items():
        assumed = {path_key(a.bypass): a.bypass for a in spec.tables[t].assume if isinstance(a, PathAssumed)}
        seen: set[str] = set()
        for f in found:
            key = path_key(f["path"])
            seen.add(key)
            who = ", ".join(f["roles"])
            if key in assumed:
                items.append(DriftItem("assumed", f"{f['path']} reaches table {t} without its policies "
                                                  f"(used by {who}) and is trusted"))
                continue
            name = f["path"].split(" ", 1)[1]
            if f["kind"] == "view":
                what = "runs as its owner (it is not security_invoker)"
                fix = f"alter view {name} set (security_invoker = true), or revoke its privileges from {who}"
            elif f["kind"] == "materialized view":
                what = "holds rows its owner read"
                fix = f"revoke its privileges from {who}"
            else:
                what = f"is SECURITY DEFINER, owned by {f['owner']}, who bypasses the policies"
                fix = f"revoke execute on function {name} from public, {who}"
            trust = (f"; or assume {{\"bypass\": \"{f['path']}\"}} on {t}" if spec.tables[t].mode == "adopted"
                     else "")
            items.append(DriftItem("hardening", f"{f['path']} reaches table {t} without its policies: it {what}, "
                                                f"and {who} may use it (fix: {fix}{trust})"))
        for key, written in assumed.items():
            if key not in seen:
                notes.append(f"table '{t}': {written} is not a bypass path now; the assumption "
                             f"{{\"bypass\": \"{written}\"}} is no longer needed"
                             + (f" (found: {', '.join(f['path'] for f in found)})" if found else ""))
    return items, notes


def _own_key_names(exp: dict, act: dict) -> tuple[dict, dict]:
    """#69: an adopted table's keys are the database's, names included.  A declared unique or
    primary key the table has under another name (same definition) is that key, and so is its
    index: the expected entries are renamed to the live names before the comparison."""
    exp = {**exp, "constraints": dict(exp["constraints"]), "indexes": dict(exp["indexes"])}
    for name, e in list(exp["constraints"].items()):
        if e.get("type") not in ("u", "p") or name in act["constraints"]:
            continue
        live = next((n for n, a in act["constraints"].items()
                     if a == e and n not in exp["constraints"]), None)
        if live is None:
            continue
        exp["constraints"][live] = exp["constraints"].pop(name)
        idx = exp["indexes"].pop(name, None)
        if idx is not None:  # its definition names it: compare under the live name
            exp["indexes"][live] = idx.replace(f"INDEX {name} ON", f"INDEX {live} ON", 1)
    return exp, act


def compare(spec: Spec, expected: Snapshot, actual: Snapshot) -> tuple[list[DriftItem], list[str]]:
    items: list[DriftItem] = []
    notes: list[str] = []
    trusted = get_adapter(spec).trusted_roles
    service = get_adapter(spec).service_roles
    for name, labels in spec.enums.items():  # D59: the database owns the type; the spec states its labels
        live = actual.get("enums", {}).get(name)
        if live is None:
            items.append(DriftItem("missing", f"enum type {name}"))
        elif live != labels:
            items.append(DriftItem("differs", f"enum type {name}", ", ".join(labels), ", ".join(live)))
    for t, exp in expected["tables"].items():
        mode = spec.tables[t].mode
        extra = "unexpected" if mode == "owned" else "foreign"
        act = actual["tables"].get(t)
        if act is None:
            items.append(DriftItem("missing", f"table {t}" + (" (adopted: it must exist)" if mode == "adopted" else "")))
            continue
        for c, e in exp["columns"].items():
            a = act["columns"].get(c)
            if a is None:
                items.append(DriftItem("missing", f"column {t}.{c}"))
            elif a != e:
                items.append(DriftItem("differs", f"column {t}.{c}", str(e), str(a)))
        for c in act["columns"]:
            if c not in exp["columns"]:
                items.append(DriftItem(extra, f"column {t}.{c}"))
        if mode == "adopted":
            exp, act = _own_key_names(exp, act)
        for group, label in (("constraints", "constraint"), ("policies", "policy"),
                             ("triggers", "trigger"), ("indexes", "index")):
            for name, e in exp[group].items():
                a = act[group].get(name)
                if a is None:
                    items.append(DriftItem("missing", f"{label} {name} on {t}"))
                elif a != e:
                    items.append(DriftItem("differs", f"{label} {name} on {t}", str(e), str(a)))
            for name in act[group]:
                if name not in exp[group]:
                    items.append(DriftItem("unexpected" if group == "policies" else extra, f"{label} {name} on {t}"))
        # a trusted platform role (D55) bypasses the policies whatever it holds: not compared
        exp_acl = {g for g in exp["acl"] if g[0] not in trusted}
        act_acl = {g for g in act["acl"] if g[0] not in trusted}
        if act["owner"] in spec.roles:  # an owner holds every privilege: its grants are not comparable
            exp_acl = {g for g in exp_acl if g[0] != act["owner"]}
            act_acl = {g for g in act_acl if g[0] != act["owner"]}
        if exp_acl != act_acl:
            missing = sorted(exp_acl - act_acl)
            extra_acl = sorted(act_acl - exp_acl)
            for g in missing:
                items.append(DriftItem("missing", f"privilege {g[1]} on {t}{'.' + g[2] if g[2] else ''} for {g[0]}"))
            for g in extra_acl:
                items.append(DriftItem("unexpected", f"privilege {g[1]} on {t}{'.' + g[2] if g[2] else ''} for {g[0]}"))
        if not act["rls"]:
            items.append(DriftItem("hardening", f"table {t}: row level security is not enabled"))
        if not act["force"]:
            if mode == "adopted" and _assumed(spec, t, RlsAssumed, "not_forced"):
                items.append(DriftItem("assumed", f"table {t}: row level security is not forced; the owner "
                                                  f"{act['owner']} bypasses the policies and is trusted"))
            else:
                items.append(DriftItem("hardening", f"table {t}: row level security is not forced"))
        elif mode == "adopted" and _assumed(spec, t, RlsAssumed, "not_forced"):
            notes.append(f"table '{t}': row level security is forced now; the assumption {{\"rls\": \"not_forced\"}} "
                         f"is no longer needed")
        if act["owner"] in spec.roles:
            if mode == "adopted" and _assumed(spec, t, OwnerAssumed, act["owner"]):
                items.append(DriftItem("assumed", f"table {t}: owner {act['owner']} is an app role and is trusted "
                                                  f"(it holds every privilege; its grants are not compared)"))
            else:
                items.append(DriftItem("hardening", f"table {t}: owned by app role {act['owner']}"))
        for a in spec.tables[t].assume:
            if isinstance(a, OwnerAssumed) and a.owner != act["owner"]:
                notes.append(f"table '{t}': the owner is {act['owner']} now, not {a.owner}; the assumption "
                             f"{{\"owner\": \"{a.owner}\"}} is no longer needed")
    for t, present in actual.get("observed", {}).items():
        if not present:
            items.append(DriftItem("missing", f"table {t} (observed)"))
    def _untrusted(f):
        return f if f is None else {**f, "execute": [r for r in f["execute"] if r not in trusted]}

    for name, e in expected["functions"].items():
        e, a = _untrusted(e), _untrusted(actual["functions"].get(name))
        if a is None:
            items.append(DriftItem("missing", f"function {name}"))
        elif a != e:
            items.append(DriftItem("differs", f"function {name}", str(e), str(a)))
    adopted = [t for t, tb in spec.governed().items() if tb.mode == "adopted"]
    for r in _roles(spec):
        a = actual["roles"].get(r)
        if a is None:
            items.append(DriftItem("missing", f"role {r}"))
            continue
        if a["bypassrls"]:
            assuming = [t for t in adopted if _assumed(spec, t, BypassAssumed, r)]
            if r in spec.roles and assuming and len(assuming) == len(spec.governed()):
                for t in assuming:
                    items.append(DriftItem("assumed", f"role {r} has BYPASSRLS and is trusted on {t}"))
            else:
                items.append(DriftItem("hardening", f"role {r} has BYPASSRLS"))
        else:
            for t in adopted:
                if _assumed(spec, t, BypassAssumed, r):
                    notes.append(f"role '{r}' has no BYPASSRLS now; the assumption {{\"bypassrls\": \"{r}\"}} on "
                                 f"table '{t}' is no longer needed")
        if r in service:  # #68: the platform's own role; the deploy never alters it
            continue
        if a["super"]:
            items.append(DriftItem("hardening", f"role {r} is a superuser"))
        if a["can_set_replication_role"]:
            items.append(DriftItem("hardening", f"role {r} may SET session_replication_role"))
        if r in spec.roles:  # #68: an app role that can act as a trusted one
            for x in a.get("escalates_to", []):
                items.append(DriftItem("hardening", f"role {r} can become {x}, which bypasses the policies "
                                                    f"(fix: revoke {x} from {r}, through every role between)"))
            if a.get("createrole"):
                items.append(DriftItem("hardening", f"role {r} has CREATEROLE"))
        if spec.identity.adapter == "session_setting" and r in spec.roles:  # D47
            for fn in a["app_setters"]:
                items.append(DriftItem("hardening", f"role {r} may execute {fn}, which sets app.*"))
            for d in a["app_defaults"]:
                items.append(DriftItem("hardening", f"role {r} has a default for {d.split('=')[0]} (ALTER ROLE ... SET)"))
        if r == INTERNAL_ROLE:
            if a["login"]:
                items.append(DriftItem("hardening", f"role {r} can log in"))
            for mbr in a["members"]:
                if mbr in spec.roles:
                    items.append(DriftItem("hardening", f"app role {mbr} is a member of {r}"))
    if "bypass" in actual:
        b_items, b_notes = bypass_report(spec, actual["bypass"])
        items += b_items
        notes += b_notes
    for t, tb in spec.tables.items():  # #52: the helpers the import read inline keep their bodies
        for a in tb.assume:
            if isinstance(a, InlinedAssumed):
                fn, _, digest = a.inlined.rpartition(" md5 ")
                now = actual.get("bodies", {}).get(path_key(fn))
                if now == digest:
                    items.append(DriftItem("assumed", f"{fn} keeps the body the policies on {t} are read as"))
                else:
                    items.append(DriftItem("differs", f"{fn} " + ("is gone" if now is None else "has a new body")
                                           + f" since the import, which read its calls in the policies on {t} "
                                             f"as its old body (fix: import again, or restore the function)"))
    items += _identity_function_items(spec, actual.get("identity_functions", {}))
    for (t, c), (declared, live) in sorted(actual.get("defaults", {}).items()):  # #76
        if live != declared:
            items.append(DriftItem("differs", f"column {t}.{c}: the spec declares default {declared}, the database "
                                              f"has {live or 'none'}; the insert proofs count on the spec's "
                                              f"(fix: import again, or restore the default)"))
    return items, notes


def live_defaults(conn: psycopg.Connection, spec: Spec, schema: str) -> dict[tuple[str, str], tuple[str, str | None]]:
    """#76: each declared default of an adopted table, with the live one read as the import does."""
    from mls.pg.lift import Env, read_default

    env = Env.of_spec(spec)
    out = {}
    for t, tb in spec.tables.items():
        for c, col in tb.columns.items():
            if col.default is None or tb.mode != "adopted":
                continue
            row = conn.execute("""select case when a.attidentity <> '' then 'fresh'
                                              when a.attgenerated = '' then pg_get_expr(d.adbin, d.adrelid) end
                                  from pg_attribute a left join pg_attrdef d
                                       on d.adrelid = a.attrelid and d.adnum = a.attnum
                                  where a.attrelid = to_regclass(%s) and a.attname = %s""",
                               (f'"{schema}"."{t}"', c)).fetchone()
            live = ("fresh" if row[0] == "fresh" else read_default(row[0], t, c, env)) if row and row[0] else None
            declared = col.default if col.default == "fresh" else col.default.model_dump(by_alias=True)
            out[(t, c)] = (_show_default(declared), _show_default(live))
    return out


def _show_default(d) -> str | None:
    if d is None or d == "fresh":
        return d
    if "ctx" in d:
        return f"@{d['ctx']}"
    return repr(d["const"])


def identity_functions(conn: psycopg.Connection, spec: Spec) -> dict[str, dict]:
    """#72: the catalog state of each trusted_function source (missing ones are left out)."""
    from mls.identity.base import SQL_TYPE

    out: dict[str, dict] = {}
    if spec.identity.adapter != "trusted_function":
        return out
    for cv in spec.identity.context.values():
        schema, fn = cv.source.split(".", 1)
        row = conn.execute("""select p.prorettype = %s::regtype, p.provolatile = 'v', md5(p.prosrc),
                                     pg_get_userbyid(p.proowner)
                              from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                              where n.nspname = %s and p.proname = %s and p.pronargs = 0""",
                           (SQL_TYPE[cv.type], schema, fn)).fetchone()
        if row is not None:
            out[cv.source] = {"type_ok": row[0], "volatile": row[1], "md5": row[2], "owner": row[3]}
    return out


def _identity_function_items(spec: Spec, live: dict[str, dict]) -> list[DriftItem]:
    """The function a context value comes from is trusted as the spec pins it (#72)."""
    items = []
    if spec.identity.adapter != "trusted_function":
        return items
    for n, cv in spec.identity.context.items():
        f, what = live.get(cv.source), f"{cv.source}()"
        if f is None:
            continue  # drift stopped before the shadow (DriftError)
        if f["md5"] != cv.md5:
            items.append(DriftItem("hardening", f"{what} has a new body since the spec pinned it (md5 {f['md5']}): "
                                                f"check that it still returns {n}, then set its md5 in the spec"))
        if not f["type_ok"]:
            items.append(DriftItem("hardening", f"{what} no longer returns {cv.type}"))
        if f["volatile"]:
            items.append(DriftItem("hardening", f"{what} is VOLATILE: it may return another value for each row "
                                                f"(fix: alter function {cv.source}() stable)"))
        if f["owner"] in spec.roles:
            items.append(DriftItem("hardening", f"{what} is owned by app role {f['owner']}, which can replace it "
                                                f"(fix: alter function {cv.source}() owner to the tables' owner)"))
    return items


def drift(conn: psycopg.Connection, spec: Spec, script: Script, schema: str = "public") -> DriftResult:
    with conn.transaction(force_rollback=True):  # nests as a savepoint inside a caller's transaction
        actual = snapshot(conn, schema, list(spec.governed()), _roles(spec), _observed(spec))
        present = [t for t in spec.governed() if actual["tables"].get(t) is not None]
        actual["bypass"] = bypass_paths(conn, schema, present, list(spec.roles))
        actual["identity_functions"] = identity_functions(conn, spec)
        actual["defaults"] = live_defaults(conn, spec, schema)
        gone = [f"{cv.source}()" for cv in spec.identity.context.values()
                if spec.identity.adapter == "trusted_function" and cv.source not in actual["identity_functions"]]
        if gone:
            raise DriftError(f"{', '.join(gone)} {'is' if len(gone) == 1 else 'are'} gone (no such function without "
                             f"arguments): the spec's identity reads {'it' if len(gone) == 1 else 'them'} "
                             f"(fix: restore the function, or change the spec's identity)")
        actual["bodies"] = {path_key(f"function {n}({types})"): digest for n, types, digest in conn.execute(
            """select p.proname, oidvectortypes(p.proargtypes), md5(p.prosrc) from pg_proc p
               join pg_namespace n on n.oid = p.pronamespace where n.nspname = %s""", (schema,)).fetchall()}
        missing = [r for r in _roles(spec) if actual["roles"].get(r) is None]
        expected = shadow_snapshot(conn, spec, script, _live_types(spec, actual), schema, missing)
    items, notes = compare(spec, expected, actual)
    notes += [f"table '{t}' in schema '{schema}' is not in the spec" for t in actual["other_tables"]]
    return DriftResult(items, notes)
