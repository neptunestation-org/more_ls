"""Normalized catalog snapshots: what Postgres itself says the objects are (pg_get_expr,
pg_get_constraintdef, pg_get_triggerdef, pg_get_indexdef, aclexplode), never the strings we
generated.  Two snapshots taken on the same server (a shadow deploy and the live schema) are
comparable; the schema name is stripped from every definition.
"""
from __future__ import annotations

import re
from typing import Any

import psycopg
from psycopg import sql as psql

from mls.compile.hardening import CAN_BECOME  # #68

Snapshot = dict[str, Any]


def _strip_schema(s: str | None, schema: str) -> str | None:
    if s is None:
        return None
    return re.sub(rf'(?<![\w"])("?{re.escape(schema)}"?)\.', "", s)


def snapshot(conn: psycopg.Connection, schema: str, tables: list[str], roles: list[str],
             observed: list[str] = (), also: str | None = None) -> Snapshot:
    """`tables` are snapshotted in full; `observed` ones (D45) only for their existence.  `also` is a
    schema on the search path after `schema` (a shadow's live schema), so that a function of it
    deparses unqualified, as it does in the live snapshot."""
    out: Snapshot = {"tables": {}, "roles": {}, "other_tables": [], "observed": {}}
    with conn.cursor() as cur:
        cur.execute(psql.SQL("set local search_path to {}, pg_catalog").format(
            psql.SQL(", ").join(psql.Identifier(x) for x in [schema, also] if x)))
        cur.execute("""select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
                       where n.nspname = %s and c.relkind in ('r', 'p') order by 1""", (schema,))
        present = [r[0] for r in cur.fetchall()]
        out["other_tables"] = sorted(set(present) - set(tables) - set(observed))
        out["observed"] = {t: t in present for t in observed}
        # enum types (D59): the labels, in the type's order
        cur.execute("""select t.typname, array(select e.enumlabel from pg_enum e where e.enumtypid = t.oid
                                               order by e.enumsortorder)
                       from pg_type t join pg_namespace n on n.oid = t.typnamespace
                       where n.nspname = %s and t.typtype = 'e' order by 1""", (schema,))
        out["enums"] = {r[0]: list(r[1]) for r in cur.fetchall()}
        for t in tables:
            if t not in present:
                out["tables"][t] = None
                continue
            cur.execute("""select c.oid, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner)
                           from pg_class c join pg_namespace n on n.oid = c.relnamespace
                           where n.nspname = %s and c.relname = %s""", (schema, t))
            oid, rls, force, owner = cur.fetchone()
            tb: dict[str, Any] = {"rls": rls, "force": force, "owner": owner}
            cur.execute("""select a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
                           from pg_attribute a where a.attrelid = %s and a.attnum > 0 and not a.attisdropped
                           order by a.attnum""", (oid,))
            tb["columns"] = {r[0]: {"type": r[1], "notnull": r[2]} for r in cur.fetchall()}
            cur.execute("""select conname, contype, pg_get_constraintdef(oid), convalidated
                           from pg_constraint where conrelid = %s order by 1""", (oid,))
            tb["constraints"] = {r[0]: {"type": r[1], "def": _strip_schema(r[2], schema), "validated": r[3]}
                                 for r in cur.fetchall()}
            cur.execute("""select polname, polcmd, polpermissive,
                                  array(select rolname from pg_roles where oid = any (polroles) order by 1),
                                  pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)
                           from pg_policy where polrelid = %s order by 1""", (oid,))
            tb["policies"] = {r[0]: {"cmd": r[1], "permissive": r[2], "roles": list(r[3]),
                                     "using": _strip_schema(r[4], schema), "check": _strip_schema(r[5], schema)}
                              for r in cur.fetchall()}
            cur.execute("""select t.tgname, pg_get_triggerdef(t.oid), p.proname
                           from pg_trigger t join pg_proc p on p.oid = t.tgfoid
                           where t.tgrelid = %s and not t.tgisinternal order by 1""", (oid,))
            tb["triggers"] = {r[0]: {"def": _strip_schema(r[1], schema), "function": r[2]}
                              for r in cur.fetchall()}
            cur.execute("""select c2.relname, pg_get_indexdef(i.indexrelid)
                           from pg_index i join pg_class c2 on c2.oid = i.indexrelid
                           where i.indrelid = %s order by 1""", (oid,))
            tb["indexes"] = {r[0]: _strip_schema(r[1], schema) for r in cur.fetchall()}
            cur.execute("""select coalesce(nullif(x.grantee, 0)::regrole::text, 'public'), x.privilege_type
                           from pg_class c, aclexplode(c.relacl) x where c.oid = %s""", (oid,))
            acl = {(r[0].strip('"'), r[1], None) for r in cur.fetchall()}
            cur.execute("""select a.attname, coalesce(nullif(x.grantee, 0)::regrole::text, 'public'), x.privilege_type
                           from pg_attribute a, aclexplode(a.attacl) x
                           where a.attrelid = %s and a.attnum > 0 and not a.attisdropped""", (oid,))
            acl |= {(r[1].strip('"'), r[2], r[0]) for r in cur.fetchall()}
            tb["acl"] = sorted(e for e in acl if e[0] != owner)
            out["tables"][t] = tb
        # functions in the schema (ours are named mls_*): body, language, security, owner, EXECUTE acl
        cur.execute("""select p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
                              p.proname, p.prosrc, l.lanname, p.prosecdef, pg_get_userbyid(p.proowner),
                              array(select coalesce(nullif(x.grantee, 0)::regrole::text, 'public')
                                    from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x where x.privilege_type = 'EXECUTE' order by 1)
                       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                       join pg_language l on l.oid = p.prolang
                       where n.nspname = %s order by 1""", (schema,))
        out["functions"] = {}
        for sig, name, src, lang, secdef, owner, execute in cur.fetchall():
            out["functions"][name] = {"signature": sig, "body": " ".join(src.split()), "language": lang,
                                      "security_definer": secdef, "owner": owner,
                                      "execute": sorted(g.strip('"') for g in execute if g.strip('"') != owner)}
        for r in roles:
            cur.execute("""select rolbypassrls, rolsuper, rolcanlogin,
                                  has_parameter_privilege(rolname, 'session_replication_role', 'SET'),
                                  array(select m.rolname from pg_auth_members am join pg_roles m on m.oid = am.member
                                        where am.roleid = pg_roles.oid order by 1),
                                  rolcreaterole,
                                  array(select x.rolname from pg_roles x
                                        where x.oid <> pg_roles.oid and (x.rolbypassrls or x.rolsuper)
                                          and """ + CAN_BECOME.format(a="pg_roles.oid", b="x.oid") + """ order by 1)
                           from pg_roles where rolname = %s""", (r,))
            row = cur.fetchone()
            if row is None:
                out["roles"][r] = None
                continue
            # D47 hardening: functions (any schema) whose body sets the app.* namespace and that
            # the role may execute, and ALTER ROLE ... SET defaults for app.*
            cur.execute("""select n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
                           from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                           where n.nspname not in ('pg_catalog', 'information_schema')
                             and (p.prosrc ~* $$set_config\\s*\\(\\s*'app\\.$$ or p.prosrc ~* $$\\mset\\s+(local\\s+|session\\s+)?app\\.$$)
                             and has_function_privilege(%s, p.oid, 'EXECUTE') order by 1""", (r,))
            setters = [x[0] for x in cur.fetchall()]
            cur.execute("""select array_agg(c order by c) from pg_db_role_setting s join pg_roles o on o.oid = s.setrole,
                           unnest(s.setconfig) c where o.rolname = %s and c like 'app.%%'""", (r,))
            defaults = cur.fetchone()[0] or []
            out["roles"][r] = {"bypassrls": row[0], "super": row[1], "login": row[2],
                               "can_set_replication_role": row[3], "members": list(row[4]),
                               "createrole": row[5], "escalates_to": list(row[6]),  # #68
                               "app_setters": setters, "app_defaults": list(defaults)}
    return out


# D54: the views and functions through which a role reaches a table without its policies
# #91: who may use a path is every role that is not trusted with the table anyway (a superuser, a
# BYPASSRLS role, a member of the table's owner, a predefined `pg_*` role, MLS's internal role), named
# in the spec or not; `{owner}` is the table owner's oid column in the query that splices it.
_UNTRUSTED = r"""not ro.rolsuper and not ro.rolbypassrls and ro.rolname !~ '^pg_' and ro.rolname <> 'mls_internal'
                 and not pg_has_role(ro.oid, {owner}, 'USAGE')"""

# the roles an object's ACL grants one of `privs` to directly ('public' for PUBLIC), untrusted ones only
_GRANTEES = r"""array(select g from (select distinct case when x.grantee = 0 then 'public' else ro.rolname end g
                      from ({acl}) x left join pg_roles ro on ro.oid = x.grantee
                      where x.privilege_type in ({privs}) and x.grantee <> {obj_owner}
                        and (x.grantee = 0 or ({untrusted}))) s
                order by s.g <> 'public', s.g)"""

_PUBLIC_USAGE = r"""exists (select from aclexplode(coalesce({nsp}.nspacl, acldefault('n', {nsp}.nspowner))) e
                           where e.grantee = 0 and e.privilege_type = 'USAGE')"""

_BYPASS_VIEWS = r"""
with recursive dep(view, tbl, towner, tforced) as (
  select distinct r.ev_class, t.relname, t.relowner, t.relforcerowsecurity
  from pg_class t join pg_namespace tn on tn.oid = t.relnamespace
  join pg_depend d on d.refclassid = 'pg_class'::regclass and d.refobjid = t.oid
  join pg_rewrite r on d.classid = 'pg_rewrite'::regclass and r.oid = d.objid
  where tn.nspname = %(schema)s and t.relname = any(%(tables)s) and r.ev_class <> t.oid
  union
  select r.ev_class, dep.tbl, dep.towner, dep.tforced
  from dep join pg_depend d on d.refclassid = 'pg_class'::regclass and d.refobjid = dep.view
  join pg_rewrite r on d.classid = 'pg_rewrite'::regclass and r.oid = d.objid
  where r.ev_class <> dep.view
)
select dep.tbl, vn.nspname, v.relname, v.relkind, o.rolname,
       o.rolsuper or o.rolbypassrls or (pg_has_role(o.oid, dep.towner, 'USAGE') and not dep.tforced),
       array(select ro.rolname from pg_roles ro
             where """ + _UNTRUSTED.format(owner="dep.towner") + r""" and ro.oid <> v.relowner
               and (has_table_privilege(ro.oid, v.oid, 'SELECT, INSERT, UPDATE, DELETE')
                    or has_any_column_privilege(ro.oid, v.oid, 'SELECT, INSERT, UPDATE'))
               and has_schema_privilege(ro.oid, v.relnamespace, 'USAGE') order by 1),
       """ + _GRANTEES.format(
    acl="select * from aclexplode(coalesce(v.relacl, acldefault('r', v.relowner))) union all "
        "select e.* from pg_attribute a, aclexplode(a.attacl) e where a.attrelid = v.oid and a.attacl is not null",
    privs="'SELECT', 'INSERT', 'UPDATE', 'DELETE'", obj_owner="v.relowner",
    untrusted=_UNTRUSTED.format(owner="dep.towner")) + r""",
       """ + _PUBLIC_USAGE.format(nsp="vn") + r"""
from dep join pg_class v on v.oid = dep.view join pg_namespace vn on vn.oid = v.relnamespace
join pg_roles o on o.oid = v.relowner
where v.relkind = 'm'
   or (v.relkind = 'v' and not coalesce((select o.option_value::boolean from pg_options_to_table(v.reloptions) o
                                         where o.option_name = 'security_invoker'), false))
order by 1, 2, 3"""

_BYPASS_FUNCTIONS = r"""
select t.relname, n.nspname, p.proname, oidvectortypes(p.proargtypes), pg_get_userbyid(p.proowner),
       array(select ro.rolname from pg_roles ro
             where """ + _UNTRUSTED.format(owner="t.relowner") + r"""
               and has_function_privilege(ro.oid, p.oid, 'EXECUTE')
               and (has_schema_privilege(ro.oid, n.oid, 'USAGE')
                    or exists (select from pg_proc w join pg_namespace wn on wn.oid = w.pronamespace
                               where w.prosecdef and w.oid <> p.oid
                                 and has_schema_privilege(ro.oid, wn.oid, 'USAGE')
                                 and has_function_privilege(ro.oid, w.oid, 'EXECUTE')
                                 and w.prosrc ~* ('\m' || p.proname || '\M')))
             order by 1),
       """ + _GRANTEES.format(acl="select * from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner)))",
                              privs="'EXECUTE'", obj_owner="p.proowner",
                              untrusted=_UNTRUSTED.format(owner="t.relowner")) + r""",
       """ + _PUBLIC_USAGE.format(nsp="n") + r"""
from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_roles o on o.oid = p.proowner,
     pg_class t join pg_namespace tn on tn.oid = t.relnamespace
where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema')
  and p.prorettype not in ('trigger'::regtype, 'event_trigger'::regtype)
  and tn.nspname = %(schema)s and t.relname = any(%(tables)s) and t.relkind in ('r', 'p')
  and (o.rolsuper or o.rolbypassrls or (pg_has_role(o.oid, t.relowner, 'USAGE') and not t.relforcerowsecurity))
  and p.prosrc ~* ('\m' || regexp_replace(t.relname, '([^a-zA-Z0-9_])', '\\\1', 'g') || '\M')
order by 1, 2, 3, 4"""


def bypass_paths(conn: psycopg.Connection, schema: str, tables: list[str], roles: list[str]) -> dict[str, list[dict]]:
    """Per table, the bypass paths (D54) a role may use: every view over the table (directly or
    through other views) that is not `security_invoker` and whose owner the table's policies do not
    bind, every materialized view, and every SECURITY DEFINER function whose owner bypasses the
    table's policies (a superuser, a BYPASSRLS role, or the table's owner while row level security
    is not forced) and whose body names the table (a conservative text match, as for D47's setters).
    A role reaches a view or function only with USAGE on its schema, except a function that the body
    of another SECURITY DEFINER function it reaches names (that call runs as the other's owner; one
    level, by text match); a trigger function is never one, since nobody calls it outside its
    trigger (#44).  #91: the roles asked about are every role not trusted with the table anyway,
    not only the spec's `roles`.  Each is `{"path": "view v" | "function f(types)", "kind", "roles"
    (the spec's roles that may use it), "outside" (the others), "grantees" (the untrusted roles, or
    'public', it is granted to directly: what a revoke names), "public" (granted to PUBLIC, in a
    schema PUBLIC may use), "owner"?}`; a name outside `schema` is qualified.  #92: a view whose
    owner is one of `roles` and is bound by the policies is no bypass path but kind "delegation":
    its users act as its owner on the table."""
    out: dict[str, list[dict]] = {t: [] for t in tables}
    args = {"schema": schema, "tables": list(tables)}

    def part(n: str) -> str:  # as SQL spells it, so the fix in the drift report runs as printed
        return n if re.fullmatch(r"[a-z_][a-z0-9_$]*", n) else '"' + n.replace('"', '""') + '"'

    def name(nsp: str, rel: str) -> str:
        return part(rel) if nsp == schema else f"{part(nsp)}.{part(rel)}"

    def who(users, grantees, public) -> dict:
        return {"roles": [r for r in users if r in roles], "outside": [r for r in users if r not in roles],
                "grantees": list(grantees), "public": bool(public and "public" in grantees)}

    with conn.cursor() as cur:
        cur.execute(_BYPASS_VIEWS, args)
        for tbl, nsp, rel, kind, owner, owner_bypasses, users, grantees, public in cur.fetchall():
            if not users:
                continue
            if kind == "v" and not owner_bypasses:
                if owner in roles:  # #92: the policies bind the owner, so its users act as it
                    out[tbl].append({"path": f"view {name(nsp, rel)}", "kind": "delegation", "owner": owner,
                                     **who(users, grantees, public)})
                continue
            out[tbl].append({"path": f"view {name(nsp, rel)}", **who(users, grantees, public),
                             "kind": "materialized view" if kind == "m" else "view"})
        # the argument types print as the search path has them: fix it to the deploy's (`<schema>, public`), so
        # that import and drift (inside its snapshot's path) spell one function alike, and restore the caller's
        prev = cur.execute("select current_setting('search_path')").fetchone()[0]
        cur.execute("select set_config('search_path', quote_ident(%s) || ', public, pg_catalog', true)", (schema,))
        cur.execute(_BYPASS_FUNCTIONS, args)
        rows = cur.fetchall()
        cur.execute("select set_config('search_path', %s, true)", (prev,))
        for tbl, nsp, fn, types, owner, users, grantees, public in rows:
            if users:
                out[tbl].append({"path": f"function {name(nsp, fn)}({types})", **who(users, grantees, public),
                                 "kind": "function", "owner": owner})
    return out


def delegation_text(f: dict) -> str:
    """#92: a delegation as its assumption spells it: `view v as owner to r1, r2` (`public` when
    every role may use the view)."""
    callers = "public" if f["public"] else ", ".join(f["roles"] + f["outside"])
    return f"{f['path']} as {f['owner']} to {callers}"


FOREIGN_KEYS = """
select c.conname, t.relname, a.attname, pn.nspname, p.relname, pa.attname
from pg_constraint c
join pg_class t on t.oid = c.conrelid join pg_namespace n on n.oid = t.relnamespace
join pg_class p on p.oid = c.confrelid join pg_namespace pn on pn.oid = p.relnamespace
join pg_attribute a on a.attrelid = c.conrelid and a.attnum = c.conkey[1]
join pg_attribute pa on pa.attrelid = c.confrelid and pa.attnum = c.confkey[1]
where c.contype = 'f' and n.nspname = %s and t.relname = any(%s) and cardinality(c.conkey) = 1
order by t.relname, c.conname
"""


ALL_FOREIGN_KEYS = """
select c.conname, t.relname, p.relname, c.condeferrable, c.confdeltype,
       array(select a.attname::text from unnest(c.conkey) k join pg_attribute a
             on a.attrelid = c.conrelid and a.attnum = k)
from pg_constraint c
join pg_class t on t.oid = c.conrelid join pg_namespace n on n.oid = t.relnamespace
join pg_class p on p.oid = c.confrelid join pg_namespace pn on pn.oid = p.relnamespace
where c.contype = 'f' and n.nspname = %s and pn.nspname = %s
order by t.relname, c.conname
"""


BEFORE_UPDATE_TRIGGERS = """
select c.relname, t.tgname
from pg_trigger t join pg_class c on c.oid = t.tgrelid join pg_namespace n on n.oid = c.relnamespace
where n.nspname = %s and not t.tgisinternal and t.tgtype & 1 = 1 and t.tgtype & 2 = 2 and t.tgtype & 16 = 16
order by 1, 2
"""


def before_update_triggers(conn: psycopg.Connection, schema: str) -> list[dict]:
    """Every BEFORE UPDATE row trigger on a table of `schema`: {table, name} (#58: one that fires
    before a column guard can rewrite a column the guard then sees changed)."""
    return [{"table": t, "name": n} for t, n in conn.execute(BEFORE_UPDATE_TRIGGERS, (schema,)).fetchall()]


def all_foreign_keys(conn: psycopg.Connection, schema: str) -> list[dict]:
    """Every foreign key between two tables of `schema`, of any width: {name, table, parent,
    deferrable, on_delete, columns} (#35: a cycle of immediate ones makes two-statement inserts
    fail; #60: one whose delete action differs from an inclusion's on the same rows).  A key that
    is deferrable but initially immediate counts as deferrable: the app can defer it.  `on_delete`
    is pg_constraint's confdeltype letter."""
    return [{"name": n, "table": t, "parent": p, "deferrable": d, "on_delete": a, "columns": list(cols)}
            for n, t, p, d, a, cols in conn.execute(ALL_FOREIGN_KEYS, (schema, schema)).fetchall()]


def foreign_keys(conn: psycopg.Connection, schema: str, tables: list[str], owned: set[str]) -> list[dict[str, str]]:
    """The single-column foreign keys on `tables` whose names are not in `owned` (the ones the
    spec declares): {name, table, column, parent, parent_column}, the parent schema-qualified
    when it is in another schema (`auth.users`).  The differential harness reads them so that its
    data satisfies the schema's own keys (D45: a foreign constraint is not modelled)."""
    out = []
    for name, table, col, pschema, parent, pcol in conn.execute(FOREIGN_KEYS, (schema, tables)).fetchall():
        if name in owned:
            continue
        out.append({"name": name, "table": table, "column": col,
                    "parent": parent if pschema == schema else f"{pschema}.{parent}", "parent_column": pcol})
    return out


def schema_mismatch(conn: psycopg.Connection, schema: str, tables: dict[str, str]) -> str | None:
    """#70: the spec's tables that must exist (adopted and observed; `tables` maps name -> mode)
    and none of them is in `schema`: the command would report every one missing.  Returns the
    message, naming the schema they are in, or None."""
    must = [t for t, mode in tables.items() if mode in ("adopted", "observed")]
    if not must:
        return None
    rows = conn.execute("""select n.nspname, count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
                           where c.relkind in ('r', 'p') and c.relname = any(%s)
                           group by 1 order by 2 desc, 1""", (must,)).fetchall()
    if any(nsp == schema for nsp, _ in rows):
        return None
    names = ", ".join(must[:3]) + (", ..." if len(must) > 3 else "")
    where = (f"they are in schema '{rows[0][0]}': pass --schema {rows[0][0]}" if rows
             else "they are in no schema of this database: check the connection string")
    return f"none of the spec's tables ({names}) is in schema '{schema}'; {where}"

