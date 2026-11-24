"""`mls import` (D45): read a live schema into a spec that is a starting point for a human or
the loop, and `mls check --dsn`: verify a spec's adopted tables against the catalog.

Every table becomes `adopted` when it has row level security enabled and `observed` otherwise
(a policy on a table without RLS means nothing, so nothing is assumed about it).  Columns,
primary key and unique constraints are read from the catalog (MLS types only; others are left
out and noted).  The identity adapter is guessed from the policy expressions and reported when
ambiguous.  Relations are proposed for every (key, value) pair an inclusion-shaped foreign key
targets, and for every two-column primary key a policy's SQL reads.  Every policy becomes a rule
whose predicate the lifter (D46, `pg/lift.py`) reads into the fragment where it can; what it
cannot read is an opaque block with the policy's catalog signature: the columns it depends on
(pg_depend) or names, the context values whose source it reads, the proposed relations whose
table it names.  A membership the lifter reads proposes its relation; the compiler's own
relation-visibility policies and relation grants are recognized and not imported as rules (the
compiler regenerates them from the lifted memberships).  A CHECK the lifter reads becomes a
check rule (a stored-row assumption); one it cannot read is listed.  Column privileges become
column rules; a foreign key of the inclusion shape becomes an inclusion rule; triggers, other
foreign keys and table-level grants with no policy are listed, not imported.

`--policies discard` (D52) writes a skeleton for a takeover instead: every table is `adopted`
(RLS enabled today or not: the deploy enables it; `observe` keeps tables out), no policy,
column grant or opaque block is imported (the notes list each discarded policy with its text),
and relations are proposed from the schema alone: a table whose two-column primary or unique
key has a foreign key on each column is a membership table, keyed by the column that refers to
the user table (`auth.users`, or the type of the identity's `uid`).  Without policy text the
identity is guessed from the schema: a foreign key to `auth.users` means Supabase.

Either way the trusted platform roles (D55: `service_role`) are not app roles, and the bypass
paths of the adopted tables (D54: views that are not `security_invoker`, SECURITY DEFINER
functions whose owner bypasses the policies) are listed with their fix; the import never
assumes one (drift reports them as `hardening` until they are fixed or assumed).
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg import sql as psql

from mls.compile.internal import INTERNAL_ROLE
from mls.errors import MlsError, SpecError
from mls.pg.catalog import _strip_schema, bypass_paths
from mls.pg.lift import (
    CAST_TO_MLS, Env, Unreadable, function_body, inline_functions, split_args, inline_lookups, restore_calls, lift, lookup_calls, nullable_columns, parse, strip_check, transition_expr, guard_parts, inclusion_parts,
    mls_type,
)
from mls.pg.lift import IsTrue as _IsTrue
from mls.spec.chain import levels
from mls.spec.model import Spec
from mls.spec.check import CATALOG_IDENT

CMD = {"*": "all", "r": "select", "a": "insert", "w": "update", "d": "delete"}
MARKERS = {"supabase": re.compile(r"\bauth\.(uid|jwt)\(\)"),
           "session_setting": re.compile(r"current_setting\('app\."),
           "pg_roles": re.compile(r"\bcurrent_user\b|\bsession_user\b")}
# the deparser writes the claim name as 'name'::text and the cast of the whole as ((...))::integer
JWT_CLAIM = re.compile(r"auth\.jwt\(\)\s*->>\s*'([A-Za-z_][A-Za-z0-9_]*)'(?:::text)?\s*\)*\s*(?:::([a-z ]+))?")
# bare `current_setting('app.x', true)::t` and the compiler's `(NULLIF(current_setting('app.x'::text, true), ''::text))::t`
APP_SETTING = re.compile(r"current_setting\('app\.([a-z_][a-z0-9_]*)'(?:::text)?[^)]*\)(?:,\s*''(?:::text)?\))?"
                         r"\s*\)*\s*(?:::([a-z ]+))?")


USER_TABLE = "auth.users"  # what a membership table's user column refers to on Supabase



def _hop_base(env, table: str, using: str) -> tuple | None:
    """The base relation (table, key, value, condition key) a hop visibility policy's chain starts
    from, read in a copy of the environment so that nothing is declared."""
    import copy

    from mls.pg.lift import lift

    seen: list[tuple] = []
    sandbox = copy.deepcopy(env)
    sandbox.invalidate()

    def make_relation(t: str, k: str, v: str, where: dict | None = None) -> str:
        seen.append((t, k, v, _cond_key(where)))
        return f"base_{len(seen)}"

    lift(using, table, sandbox, "policy", lambda *a: "_", make_relation)
    return seen[0] if seen else None


def _qualified_params(expr: str, fname: str, params: list[str]) -> str:
    """#64: a parameter written qualified by its function's name (`has_role_on_account.account_id`,
    how a body tells a parameter from a column of the same name) as the bare parameter, so that the
    call's argument takes its place."""
    for p in params:
        if p:
            expr = re.sub(rf'(?<![\w."])"?{re.escape(fname)}"?\."?{re.escape(p)}"?(?![\w"])', p, expr)
    return expr


def _cond_key(where: dict | None) -> str | None:
    """A relation condition (D61) as a key: two readings of one condition are one relation."""
    return None if where is None else json.dumps(where, sort_keys=True)

def _trusted_roles(adapter: str) -> tuple[str, ...]:
    from mls.identity.pg_roles import PgRolesAdapter
    from mls.identity.session_setting import SessionSettingAdapter
    from mls.identity.supabase import SupabaseAdapter
    from mls.identity.trusted_function import TrustedFunctionAdapter

    return {"supabase": SupabaseAdapter, "pg_roles": PgRolesAdapter, "session_setting": SessionSettingAdapter,
            "trusted_function": TrustedFunctionAdapter}[adapter].trusted_roles


@dataclass
class ImportResult:
    spec: dict
    notes: list[str] = field(default_factory=list)


def ident(name: str) -> str:
    """An MLS identifier for a catalog name (lower-case, underscores, at most 63 characters)."""
    s = re.sub(r"[^a-z0-9_]", "_", name.lower())
    if not s or not re.match(r"[a-z_]", s[0]):
        s = "_" + s
    return s[:63]


def suffixed(name: str, suffix: str) -> str:
    """`ident(name_suffix)` with the suffix kept whole: a long name is shortened before it, so two
    suffixes of one long name never truncate to the same identifier."""
    tail = "_" + ident(suffix).lstrip("_")
    return ident(name)[:63 - len(tail)] + tail


# ----------------------------------------------------------------------------- catalog reads
def _read(conn: psycopg.Connection, schema: str) -> dict[str, Any]:
    cat: dict[str, Any] = {"tables": {}, "superusers": set(), "roles": {}}
    with conn.cursor() as cur:
        cur.execute(psql.SQL("set local search_path to {}, pg_catalog").format(psql.Identifier(schema)))
        cur.execute("""select t.typname, array(select e.enumlabel from pg_enum e where e.enumtypid = t.oid
                                               order by e.enumsortorder)
                       from pg_type t join pg_namespace n on n.oid = t.typnamespace
                       where n.nspname = %s and t.typtype = 'e' order by 1""", (schema,))
        cat["enums"] = {r[0]: list(r[1]) for r in cur.fetchall()}  # D59: the schema's enum types
        cur.execute("""select p.proname, p.prosrc from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                       where n.nspname = %s and p.proname like 'mls\\_lookup\\_%%' and p.prosecdef
                         and pg_get_userbyid(p.proowner) = %s""", (schema, INTERNAL_ROLE))
        cat["lookups"] = dict(cur.fetchall())  # D67: the compiler's lookup helpers, read back inline
        # #52: the schema's one-statement SQL helpers that return a boolean, read back inline.  A
        # SECURITY DEFINER one counts only when its owner bypasses the policies of every table its
        # body names (then its body reads all rows, as a relation does); an invoker one reads as
        # the same subquery written in the policy would.  #64: a VOLATILE one too (the default for
        # a function that declares none), with its parameters' defaults for a shorter call
        cur.execute("""select p.proname, coalesce(p.proargnames, '{}'), p.pronargs, p.prosrc,
                              oidvectortypes(p.proargtypes), md5(p.prosrc), p.prosecdef,
                              p.provolatile = 'v', p.pronargdefaults, pg_get_expr(p.proargdefaults, 0), p.proretset
                       from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
                         join pg_roles o on o.oid = p.proowner
                       where n.nspname = %s and l.lanname = 'sql'
                         and (not p.proretset and p.prorettype = 'bool'::regtype
                              or p.proretset and p.prorettype in ('uuid'::regtype, 'integer'::regtype,
                                                                  'bigint'::regtype, 'text'::regtype))
                         and p.proname not like 'mls\\_%%'
                         and (not p.prosecdef or o.rolsuper or o.rolbypassrls or not exists (
                           select 1 from pg_class t join pg_namespace tn on tn.oid = t.relnamespace
                           where t.relkind in ('r', 'p') and tn.nspname not in ('pg_catalog', 'information_schema')
                             and p.prosrc ~* ('\\m' || t.relname || '\\M')
                             and (t.relforcerowsecurity or not pg_has_role(o.oid, t.relowner, 'USAGE'))))
                         and (select count(*) from pg_proc q where q.proname = p.proname and q.pronamespace = p.pronamespace) = 1""",
                    (schema,))
        cat["functions"] = {}
        for fname, argnames, nargs, src, types, digest, definer, volatile, ndefaults, defaults, retset in cur.fetchall():
            expr = function_body(_strip_schema(src, schema))  # #64: `basejump.account_user` is the table
            if expr is not None:
                expr = _qualified_params(expr, fname, (list(argnames) + [""] * nargs)[:nargs])
                given = split_args(_strip_schema(defaults, schema)) if defaults else []
                cat["functions"][fname] = {"params": (list(argnames) + [""] * nargs)[:nargs], "expr": expr,
                                           "assume": f"function {fname}({types}) md5 {digest}", "definer": definer,
                                           "volatile": volatile, "set": retset,
                                           "defaults": [None] * (nargs - ndefaults) + given if len(given) == ndefaults
                                           else [None] * nargs}
        cur.execute("select distinct proname from pg_proc where pronamespace = 'pg_catalog'::regnamespace")
        cat["builtins"] = frozenset(r[0] for r in cur.fetchall())
        # #72: zero-argument functions a policy may read the user from (graphile's current_user_id()),
        # with the table their result refers to when the body is `select <col> from <table> ...`
        cur.execute("""select n.nspname, p.proname, format_type(p.prorettype, null), md5(p.prosrc), p.prosrc
                       from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                       where p.pronargs = 0 and p.prokind = 'f' and not p.proretset and p.provolatile <> 'v'
                         and p.prorettype in ('uuid'::regtype, 'integer'::regtype, 'bigint'::regtype, 'text'::regtype)
                         and n.nspname not in ('pg_catalog', 'information_schema', 'auth')
                         and n.nspname not like 'pg\\_%%' and p.proname not like 'mls\\_%%'""")
        cat["identity_functions"] = {}
        for nsp, fname, rettype, digest, src in cur.fetchall():
            ty = CAST_TO_MLS.get(rettype)
            m = re.match(r"\s*select\s+([a-z_][a-z0-9_]*)\s+from\s+([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\b",
                         src, re.I)
            refers = None
            if m:
                cur.execute("""select c.confrelid::regclass::text from pg_constraint c
                               join pg_attribute a on a.attrelid = c.conrelid and a.attnum = c.conkey[1]
                               where c.contype = 'f' and c.conrelid = to_regclass(%s)
                                 and cardinality(c.conkey) = 1 and a.attname = %s""", (m.group(2), m.group(1)))
                row = cur.fetchone()
                refers = row[0] if row else None
            if ty is not None:
                cat["identity_functions"][(nsp, fname)] = {"type": ty, "md5": digest, "refers": refers}
        cur.execute("select rolname, rolsuper, rolcanlogin, rolbypassrls from pg_roles")
        for name, sup, login, bypass in cur.fetchall():
            cat["roles"][name] = {"super": sup, "login": login, "bypassrls": bypass}
            if sup:
                cat["superusers"].add(name)
        cur.execute("""select c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner)
                       from pg_class c join pg_namespace n on n.oid = c.relnamespace
                       where n.nspname = %s and c.relkind in ('r', 'p') order by c.relname""", (schema,))
        tables = cur.fetchall()
        for oid, name, rls, force, owner in tables:
            t: dict[str, Any] = {"oid": oid, "rls": rls, "force": force, "owner": owner}
            # the enum type of an enum column, or of an enum array's elements (D88)
            cur.execute("""select a.attnum, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
                                  case when et.typtype = 'e' and tn.nspname = %s then et.typname end
                           from pg_attribute a join pg_type ty on ty.oid = a.atttypid
                                join pg_type et on et.oid = case when ty.typelem <> 0 and ty.typlen = -1
                                                                 then ty.typelem else ty.oid end
                                join pg_namespace tn on tn.oid = et.typnamespace
                           where a.attrelid = %s and a.attnum > 0 and not a.attisdropped
                           order by a.attnum""", (schema, oid))
            t["columns"] = [{"num": r[0], "name": r[1], "type": r[2], "notnull": r[3], "enum": r[4]}
                            for r in cur.fetchall()]
            cur.execute("""select conname, contype, pg_get_constraintdef(oid), conkey, confrelid, confkey,
                                  confupdtype, confdeltype, confmatchtype, convalidated,
                                  case when confrelid <> 0 then confrelid::regclass::text end,
                                  condeferrable, condeferred, confdelsetcols
                           from pg_constraint where conrelid = %s order by conname""", (oid,))
            t["constraints"] = [{"name": r[0], "type": r[1], "def": _strip_schema(r[2], schema), "cols": list(r[3] or []),
                                 "ref": r[4], "refcols": list(r[5] or []), "upd": r[6], "del": r[7], "match": r[8],
                                 "validated": r[9], "refname": r[10], "deferrable": r[11], "deferred": r[12],
                                 "delsetcols": list(r[13]) if r[13] else None}
                                for r in cur.fetchall()]
            cur.execute("""select p.oid, p.polname, p.polcmd, p.polpermissive,
                                  array(select rolname from pg_roles where oid = any (p.polroles) order by 1),
                                  0 = any (p.polroles),
                                  pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid),
                                  array(select d.refobjsubid from pg_depend d
                                        where d.classid = 'pg_policy'::regclass and d.objid = p.oid
                                          and d.refobjid = p.polrelid and d.refobjsubid > 0)
                           from pg_policy p where p.polrelid = %s order by p.polname""", (oid,))
            t["policies"] = [{"name": r[1], "cmd": CMD[r[2]], "permissive": r[3], "roles": list(r[4]), "public": r[5],
                              "using": _strip_schema(r[6], schema), "check": _strip_schema(r[7], schema),
                              "depcols": list(r[8])} for r in cur.fetchall()]
            cur.execute("""select t.tgname, pg_get_triggerdef(t.oid), p.proname, p.prosrc
                           from pg_trigger t join pg_proc p on p.oid = t.tgfoid
                           where t.tgrelid = %s and not t.tgisinternal order by 1""", (oid,))
            t["triggers"] = [{"name": r[0], "def": _strip_schema(r[1], schema), "function": r[2], "body": r[3]}
                             for r in cur.fetchall()]
            cur.execute("""select coalesce(nullif(x.grantee, 0)::regrole::text, 'public'), x.privilege_type
                           from pg_class c, aclexplode(c.relacl) x where c.oid = %s""", (oid,))
            t["acl"] = [(r[0].strip('"'), r[1].lower(), None) for r in cur.fetchall()]
            cur.execute("""select a.attname, coalesce(nullif(x.grantee, 0)::regrole::text, 'public'), x.privilege_type
                           from pg_attribute a, aclexplode(a.attacl) x
                           where a.attrelid = %s and a.attnum > 0 and not a.attisdropped""", (oid,))
            t["acl"] += [(r[1].strip('"'), r[2].lower(), r[0]) for r in cur.fetchall()]
            cat["tables"][name] = t
    oids = {t["oid"]: name for name, t in cat["tables"].items()}
    for t in cat["tables"].values():
        t["colname"] = {c["num"]: c["name"] for c in t["columns"]}
    for t in cat["tables"].values():
        for con in t["constraints"]:
            con["colnames"] = [t["colname"][n] for n in con["cols"]]
            # #62: `ON DELETE SET NULL (c)` names the columns it nulls; none listed is every column
            con["delsetcols"] = ([t["colname"][n] for n in con["delsetcols"]] if con["delsetcols"]
                                 else list(con["colnames"]))
            ref = oids.get(con["ref"])
            con["reftable"] = ref
            con["refcolnames"] = [cat["tables"][ref]["colname"][n] for n in con["refcols"]] if ref else []
    return cat


# ----------------------------------------------------------------------------- the import
def import_schema(conn: psycopg.Connection, schema: str = "public", roles: list[str] | None = None,
                  policies: str = "keep", observe: list[str] | None = None) -> ImportResult:
    """`policies` is `keep` (lift them) or `discard` (a skeleton, D52); `observe` names tables a
    discard import leaves `observed`."""
    with conn.transaction():
        cat = _read(conn, schema)
    notes: list[str] = []
    tables = cat["tables"]
    if not tables:
        raise SpecError([MlsError("$.tables", f"schema '{schema}' has no tables", "pass --schema", "import")])
    discard = policies == "discard"
    observe = list(observe or [])
    for i, o in enumerate(observe):
        if o not in tables:
            raise SpecError([MlsError(f"--observe[{i}]", f"schema '{schema}' has no table '{o}'",
                                      f"one of: {', '.join(tables)}", "import")])
    if observe and not discard:
        raise SpecError([MlsError("--observe", "--observe applies to --policies discard (a keep import makes "
                                               "the tables without RLS observed)", "add --policies discard", "import")])

    # --- identity: guessed from the policy expressions
    texts = [e for t in tables.values() for p in t["policies"] for e in (p["using"], p["check"]) if e]
    texts += [f["expr"] for n, f in cat["functions"].items() if any(n + "(" in e for e in texts)]  # #52
    hits = {a: sum(1 for e in texts if m.search(e)) for a, m in MARKERS.items()}
    # #72: a policy calling a zero-argument function, qualified or with its schema on the search path
    called = {k: re.compile(rf"(?<![\w.]){re.escape(k[0])}\.{re.escape(k[1])}\(\)|(?<![\w.]){re.escape(k[1])}\(\)"
                            if k[0] == schema else rf"(?<![\w.]){re.escape(k[0])}\.{re.escape(k[1])}\(\)")
              for k in cat["identity_functions"]}
    called = {k: m for k, m in called.items() if any(m.search(e) for e in texts)}
    hits["trusted_function"] = sum(1 for e in texts if any(m.search(e) for m in called.values()))
    ranked = sorted((n, a) for a, n in hits.items() if n)
    user_fks = discard and any(con["type"] == "f" and con["refname"] == USER_TABLE
                               for t in tables.values() for con in t["constraints"])
    if not ranked and user_fks:
        adapter = "supabase"
        notes.append(f"identity: no policy text to read; foreign keys refer to {USER_TABLE}: the adapter is supabase")
    elif not ranked:
        adapter = "pg_roles"
        notes.append("identity: no policy reads auth.uid()/auth.jwt(), current_setting('app.*') or current_user; "
                     "the adapter defaults to pg_roles")
    else:
        adapter = ranked[-1][1]
        if len(ranked) > 1:
            notes.append(f"identity: ambiguous, policies read " + ", ".join(f"{a} ({n})" for n, a in ranked[::-1])
                         + f"; the adapter is {adapter} (the most read); the others' policies stay opaque")
    context: dict[str, dict] = {}
    user_table = USER_TABLE  # #72: or the table a trusted function's result refers to
    if adapter == "supabase":
        if any("auth.uid()" in e for e in texts) or user_fks:
            context["uid"] = {"source": "auth.uid", "type": "uuid"}
        for e in texts:
            for claim, cast in JWT_CLAIM.findall(e):
                name = ident(claim)
                ty = CAST_TO_MLS.get((cast or "").strip())
                if ty is None:
                    ty = "text"
                    if cast:
                        notes.append(f"identity: claim '{claim}' is cast to {cast.strip()}, not an MLS type; "
                                     f"declared as text")
                if name not in context:
                    context[name] = {"source": f"jwt.claims.{claim}", "type": ty}
    elif adapter == "trusted_function":
        for (nsp, fname), f in sorted((k, cat["identity_functions"][k]) for k in called):
            context[ident(fname)] = {"source": f"{nsp}.{fname}", "type": f["type"], "md5": f["md5"]}
            if f["refers"]:
                user_table = f["refers"]
            notes.append(f"identity: the policies call {nsp}.{fname}(), a function without arguments: the adapter is "
                         f"trusted_function, and every proof assumes it returns the current user's value; its "
                         f"body is pinned (md5 {f['md5']}), and drift reports a change"
                         + (f"; its result refers to {f['refers']}, the user table" if f["refers"] else ""))
    elif adapter == "session_setting":
        for e in texts:
            for name, cast in APP_SETTING.findall(e):
                ty = CAST_TO_MLS.get((cast or "").strip())
                if ty is None:
                    ty = "text"
                    if cast:
                        notes.append(f"identity: app.{name} is cast to {cast.strip()}, not an MLS type; declared as text")
                if name not in context:
                    context[name] = {"source": f"app.{name}", "type": ty}
    else:
        context["role"] = {"source": "current_user", "type": "text"}

    # --- roles: what the policies and grants name, minus owners, superusers and the internal role
    if roles is None:
        found: set[str] = set()
        for name, t in tables.items():
            for p in t["policies"]:
                found.update(p["roles"])
            found.update(g for g, _, _ in t["acl"])
        owners = {t["owner"] for t in tables.values()}
        trusted = set(_trusted_roles(adapter))  # D55, both modes
        skipped = sorted(r for r in found if r in owners or r in cat["superusers"] or r == INTERNAL_ROLE
                         or r.startswith("pg_") or r == "public" or r in trusted)
        roles = sorted(r for r in found if r not in skipped and r in cat["roles"])
        if skipped:
            notes.append(f"roles not taken as app roles: {', '.join(skipped)} (owners, superusers, public, "
                         f"MLS's internal role" + (", or the platform's trusted roles" if trusted else "") + ")")
    if not roles:
        raise SpecError([MlsError("$.roles", "no app role was found in the policies and grants of schema "
                                             f"'{schema}'", "pass --role NAME for each app role", "import")])

    # --- tables
    spec_tables: dict[str, dict] = {}
    modelled: dict[str, set[str]] = {}
    enums: dict[str, list[str]] = {}
    mls_keys: dict[str, list[list[str]]] = {}  # #59: per table, the keys MLS added (`mls_key_*`)
    for name, t in tables.items():
        cols: dict[str, dict] = {}
        for c in t["columns"]:
            if c["enum"] is not None and CATALOG_IDENT.match(c["enum"]):  # an enum type of the schema (D59)
                enums[c["enum"]] = cat["enums"][c["enum"]]
                cols[c["name"]] = {"type": "enum[]" if c["type"].endswith("[]") else "enum", "enum": c["enum"],
                                   "nullable": not c["notnull"]}
                continue
            ty = mls_type(c["type"])
            if ty is None:
                notes.append(f"column {name}.{c['name']} has type {c['type']}, not an MLS type: left out of the "
                             f"spec (drift lists it as foreign)")
                continue
            cols[c["name"]] = {"type": ty, "nullable": not c["notnull"]}
        modelled[name] = set(cols)
        adopt = (name not in observe) if discard else t["rls"]
        tb: dict[str, Any] = {"columns": cols, "mode": "adopted" if adopt else "observed"}
        if discard and name in observe:
            notes.append(f"table {name} is observed (--observe)")
        elif not adopt:
            notes.append(f"table {name} has row level security disabled: observed, not adopted (enable it and "
                         f"set mode to adopted to govern it)")
        else:
            if not t["rls"]:
                notes.append(f"table {name} has row level security disabled today: the deploy enables it, and "
                             f"until then every app role with a grant reads every row")  # the hardening state, recorded as assumptions (D45): what drift would otherwise report
            assume: list[dict] = []
            if t["owner"] in roles:
                assume.append({"owner": t["owner"]})
            if not t["force"]:
                assume.append({"rls": "not_forced"})
            assume += [{"bypassrls": r} for r in roles if cat["roles"][r]["bypassrls"]]
            if assume:
                tb["assume"] = assume
                notes.append(f"table {name}: assumed " + ", ".join(
                    f"owner {a['owner']} is trusted" if "owner" in a else
                    f"row level security is not forced" if "rls" in a else
                    f"{a['bypassrls']} has BYPASSRLS" for a in assume) + " (fix the hardening and remove the assumption)")
        for con in t["constraints"]:
            if con["type"] == "p":
                if set(con["colnames"]) <= set(cols):
                    tb["primary_key"] = con["colnames"]
                else:
                    notes.append(f"primary key of {name} uses a column that is not modelled; left out")
                if con["name"] != f"{name}_pkey":
                    notes.append(f"primary key of {name} is named {con['name']}, MLS expects {name}_pkey "
                                 f"(drift reports the name)")
            elif con["type"] == "u" and con["name"].startswith("mls_key_"):
                # #59: the key MLS adds for an inclusion; the compiler adds it again, and the
                # foreign key that references it still reads as an inclusion
                mls_keys.setdefault(name, []).append(con["colnames"])
            elif con["type"] == "u":
                if set(con["colnames"]) <= set(cols):
                    # #69: kept under its own name; drift matches an adopted key by its columns
                    tb.setdefault("unique", []).append(con["colnames"])
                else:
                    notes.append(f"unique constraint {con['name']} on {name} uses a column that is not modelled; left out")
        spec_tables[name] = tb
    governed = {n for n, tb in spec_tables.items() if tb["mode"] == "adopted"}

    def key_sets(table: str) -> list[list[str]]:
        tb = spec_tables[table]
        return ([tb["primary_key"]] if tb.get("primary_key") else []) + tb.get("unique", [])

    # --- the lifter's view of the spec so far
    env = Env(adapter=adapter, context={n: (cv["source"], cv["type"]) for n, cv in context.items()},
              tables={t: {c: (col["type"], col["nullable"]) for c, col in tb["columns"].items()}
                      for t, tb in spec_tables.items()},
              enums=enums, enum_cols={t: {c: col["enum"] for c, col in tb["columns"].items() if "enum" in col}
                                      for t, tb in spec_tables.items()},
              governed=set(governed), roles=list(roles), builtins=cat.get("builtins", frozenset()),
              keys={t: [frozenset(k) for k in key_sets(t)] for t in spec_tables})

    # --- relations: inclusion-shaped foreign keys, what the lifter reads as a membership, and (for
    # the opaque blocks) two-column keys their SQL reads.  The compiler's relation-visibility
    # policy `mls_rel_<relation>_<role>_<n>` (`key = <ctx>` on the relation's table, and the
    # relation's condition, D61) gives the relation its original name back.
    relations: dict[str, dict] = {}
    rel_by_pair: dict[tuple[str, str, str, str | None], str] = {}
    rel_names: dict[tuple[str, str, str | None], str] = {}  # (table, key, condition) -> the policy's name
    # D67: a lookup helper's name is its relation's, exactly; read first, so that a hop visibility
    # policy named after a longer chain (the shorter one reads through the helper) cannot claim it
    for name, t in tables.items():
        if name not in governed:
            continue
        for p in t["policies"]:
            for text in (p["using"], p["check"]):
                for rel, start, end, sub in lookup_calls(text or "", cat["lookups"]):
                    col = re.search(r'("[^"]+"|[a-z_][a-z0-9_]*) = ANY \($', text[:start])
                    if col is None:
                        continue
                    hops = sub.count("= any (array(")
                    last = re.match(r'ARRAY\(select "[^"]+" from "([^"]+)"', sub)
                    base = _hop_base(env, name, f"({col.group(1)} = ANY ({sub}))")
                    if hops == 0 and base is not None:
                        rel_names.setdefault((base[0], base[1], base[3]), rel)
                    elif last is not None:
                        env.composed_names.setdefault((last.group(1), hops), rel)
                        if base is not None:
                            env.composed_names.setdefault((last.group(1), hops, base), rel)
    for name, t in tables.items():
        if name not in governed:
            continue
        for p in t["policies"]:
            for role in roles:
                h = re.fullmatch(r"mls_rel_(.+)_h(\d+)_" + re.escape(role) + r"_\d+", p["name"])
                if h and p["cmd"] == "select":  # D56: a hop's visibility policy names its composed relation
                    env.composed_names.setdefault((name, int(h.group(2))), h.group(1))
                    base = _hop_base(env, name, p["using"]) if p["using"] else None
                    if base is not None:  # D61: and, with its base relation, tells two such chains apart
                        env.composed_names.setdefault((name, int(h.group(2)), base), h.group(1))
                    break
                m = re.fullmatch(r"mls_rel_(.+)_" + re.escape(role) + r"_\d+", p["name"])
                if m and p["using"] and p["cmd"] == "select":
                    r = lift(p["using"], name, env, "policy", lambda *a: "_", lambda *a: None)
                    pr, cond = r.pred, None
                    if r.kind == "lifted" and "and" in pr and len(pr["and"]) > 1 and "cmp" in pr["and"][0]:
                        rest = pr["and"][1:]  # D61: `key = <ctx> and <condition>`
                        pr, cond = pr["and"][0], rest[0] if len(rest) == 1 else {"and": rest}
                    if r.kind == "lifted" and "cmp" in pr and pr["cmp"][1] == "=" and "col" in pr["cmp"][0]:
                        rel_names.setdefault((name, pr["cmp"][0]["col"], _cond_key(cond)), m.group(1))
                    break

    def propose(table: str, key: str, value: str, why: str, where: dict | None = None) -> str | None:
        cols = value if key is None else f"{key}, {value}"  # #63: a set has no key
        if table not in governed:
            notes.append(f"relation on {table} ({cols}) not proposed: the table is observed ({why})")
            return None
        pair = (table, key, value, _cond_key(where))
        if pair in rel_by_pair:
            return rel_by_pair[pair]
        name = rel_names.get((table, key, _cond_key(where)))
        if name is None or name in relations:
            if where is None:
                name = ident(table) if ident(table) not in relations else ident(f"{table}_{key}_{value}")
            else:  # D61: named after the columns its condition reads
                cols = sorted(set(re.findall(r'"col": "([^"]+)"', json.dumps(where))))
                base_n = name = ident(f"{table}_by_{'_'.join(cols)}")
                i = 2
                while name in relations:
                    name, i = suffixed(base_n, str(i)), i + 1
        relations[name] = {"table": table, **({"key": key} if key is not None else {}), "value": value,
                           **({"where": where} if where else {})}
        rel_by_pair[pair] = name
        env.relations[name] = (table, key, value)
        if where is not None:
            env.conditions[name] = where
        env.invalidate()
        notes.append(f"relation {name} proposed: ({cols}) of {table}"
                     + (" where its condition holds" if where else "") + f" ({why})")
        return name

    inclusions: list[dict] = []
    for name, t in tables.items():
        if name not in governed:
            continue
        for con in t["constraints"]:
            if con["type"] != "f":
                continue
            actions = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}
            unmet = [why for bad, why in (
                (len(con["colnames"]) != 2, f"{len(con['colnames'])} column(s), not a pair"),
                (con["reftable"] not in spec_tables, f"it refers to {con['reftable'] or con['refname']}, outside the spec"),
                (con["reftable"] in spec_tables
                 and con["refcolnames"] not in key_sets(con["reftable"]) + mls_keys.get(con["reftable"], []),
                 "the referenced columns are not a key"),
                (con["match"] != "s", "not MATCH SIMPLE"),
                (con["upd"] != "r", f"ON UPDATE {actions.get(con['upd'], con['upd'])}"),
                (con["deferrable"] and not con["deferred"], "DEFERRABLE INITIALLY IMMEDIATE"),
                (con["del"] not in ("r", "c", "n"), f"ON DELETE {actions.get(con['del'], con['del'])}"),
                (con["del"] == "n" and con.get("delsetcols") != [con["colnames"][0]],
                 "ON DELETE SET NULL of other than its first column"),
                (con["del"] == "n" and any(c["name"] == con["colnames"][0] and c["notnull"] for c in t["columns"]),
                 "ON DELETE SET NULL of a NOT NULL column"),
                (not set(con["colnames"]) <= modelled[name], "a column of it is not modelled")) if bad]
            if unmet:
                notes.append(f"foreign key {con['name']} on {name} is not an inclusion ({', '.join(unmet)}; an "
                             f"inclusion is two columns onto a key pair, MATCH SIMPLE, ON UPDATE RESTRICT, ON DELETE "
                             f"RESTRICT, CASCADE or SET NULL of its first column): "
                             f"listed as foreign, not imported")
                continue
            rel = propose(con["reftable"], con["refcolnames"][0], con["refcolnames"][1], f"foreign key {con['name']}")
            if rel is None:
                continue
            inclusions.append({"kind": "inclusion", "name": ident(con["name"]), "table": name,
                               "columns": con["colnames"], "relation": rel,
                               "on_delete": {"c": "cascade", "n": "set_null"}.get(con["del"], "restrict"),
                               **({"deferred": True} if con["deferred"] else {})})

    # --- membership tables, from the schema alone (D52): a two-column key with a foreign key on
    # each column, keyed by the column that refers to the user table
    if discard:
        uid_type = (context["uid"]["type"] if "uid" in context
                    else next(iter(context.values()))["type"] if adapter == "trusted_function" and len(context) == 1
                    else None)
        # the user table, and the tables keyed by it (`profiles.id references auth.users`)
        user_tables = {user_table} | {
            n for n, t in tables.items()
            if any(con["type"] == "p" and len(con["colnames"]) == 1 for con in t["constraints"])
            and any(con["type"] == "f" and con["refname"] == user_table and con["colnames"]
                    == next(c["colnames"] for c in t["constraints"] if c["type"] == "p") for con in t["constraints"])}
        for name, t in tables.items():
            if name not in governed:
                continue
            single = {con["colnames"][0]: con for con in t["constraints"] if con["type"] == "f"
                      and len(con["colnames"]) == 1}
            for k in key_sets(name):
                if len(k) != 2 or not all(c in single for c in k):
                    continue
                users = [c for c in k if single[c]["refname"] in user_tables]
                by_type = not users and uid_type is not None
                if by_type:
                    users = [c for c in k if spec_tables[name]["columns"][c]["type"] == uid_type]
                if len(users) != 1:
                    refs = ", ".join(f"{c} to {single[c]['refname']}" for c in k)
                    if not by_type:  # #45: say which test failed, and what the columns refer to
                        why = (f"both refer to the user table ({user_table})" if users else
                               f"neither refers to the user table ({user_table})")
                    elif users:
                        why = (f"neither refers to the user table ({user_table}) and both have the user id's "
                               f"type ({uid_type}), so either could be the user")
                    else:
                        why = (f"neither refers to the user table ({user_table}) nor has the user id's type "
                               f"({uid_type})")
                    notes.append(f"table {name}: the key ({', '.join(k)}) has a foreign key on each column ({refs}), "
                                 f"but {why}: no relation proposed")
                    continue
                key = users[0]
                value = next(c for c in k if c != key)
                propose(name, key, value, f"membership table: ({key}, {value}) is a key, {key} refers to "
                                          f"{single[key]['refname']}, {value} to {single[value]['refname']}")
                break

    # --- policies through the lifter (D46); what it cannot read is an opaque block
    opaques: dict[str, dict] = {}
    inlined_by: dict[str, set[str]] = {}  # #52: per table, the helpers its policies were read through
    volatile_by: dict[str, set[str]] = {}  # #64: those among them that are VOLATILE
    lifted_exprs: list[dict] = []  # #41: every policy expression lifted, with the memberships read as the caller
    depcols_of: dict[str, dict[str, list[str]]] = {}
    # #35: a cycle of inclusions checked after each statement cannot be stated (the checker refuses
    # it, and calling it deferred would change it); one inclusion per cycle stays foreign
    from mls.spec.fkcycle import Fk, cycles

    while True:
        found = cycles([Fk(r["name"], r["table"], relations[r["relation"]]["table"], bool(r.get("deferred")), r["name"])
                        for r in inclusions])
        if not found:
            break
        inc, path = found[0]
        inclusions = [r for r in inclusions if r["name"] != inc.name]
        notes.append(f"foreign key {inc.name} on {inc.table} closes a cycle of foreign keys checked after each "
                     f"statement ({' -> '.join([inc.table, inc.parent] + [f.parent for f in path])}): listed as "
                     f"foreign, not imported (make it DEFERRABLE INITIALLY DEFERRED, and the import reads it as a "
                     f"deferred inclusion)")
    rules: list[dict] = list(inclusions)
    lifted_n = opaque_n = 0

    def lift_expr(table: str, text: str, base: str, scope: str, depcols: list[str], top_is_true: bool = False):
        parts = 0
        calls: list[tuple[str, str]] = []  # #52: the inlined helpers, put back in an opaque block

        class Retry(Exception):
            pass

        def make_opaque(sql: str, cols: list[str], ctx: list[str], rels: list[str]) -> str:
            nonlocal parts
            if calls:
                restored = restore_calls(sql, calls)
                if restored is None:
                    raise Retry
                sql = restored
            parts += 1
            whole = sql.strip() == text.strip()
            oname = ident(base) if whole else suffixed(base, str(parts))
            if oname in opaques and opaques[oname]["table"] != table:  # #71: policy names repeat across tables
                oname = suffixed(f"{table}_{base}", "" if whole else str(parts)).rstrip("_")
            if whole:
                cols = sorted(set(cols) | {c for c in depcols if c in modelled[table]})
            opaques[oname] = {"table": table, "columns": cols, "context": ctx, "relations": rels, "sql": sql}
            env.opaques[oname] = dict(opaques[oname])
            env.invalidate()
            return oname

        def make_relation(rtable: str, key: str, value: str, where: dict | None = None) -> str | None:
            return propose(rtable, key, value, f"{scope} expression on {table} reads it as a membership", where)

        inlined = inline_functions(text, table, set(modelled[table]), cat["functions"], calls)
        if calls:
            try:
                r = lift(inline_lookups(inlined, cat["lookups"]), table, env, scope, make_opaque, make_relation,
                         top_is_true=top_is_true)
                used = {re.search(r"(\w+)\s*\(", call).group(1) for _, call in calls}  # #74: `select f() as x`
                inlined_by.setdefault(table, set()).update(cat["functions"][n]["assume"] for n in used)
                volatile_by.setdefault(table, set()).update(n for n in used if cat["functions"][n]["volatile"])
                return r
            except Retry:  # an opaque part inside a helper's body: read the text with the calls as written
                calls.clear()
        return lift(inline_lookups(text, cat["lookups"]), table, env, scope, make_opaque, make_relation,
                    top_is_true=top_is_true)

    for name, t in tables.items():
        if name not in governed:
            if t["policies"]:
                notes.append(f"table {name} is observed: its {len(t['policies'])} policies are not imported")
            continue
        depcols = {}
        for p in t["policies"]:
            depcols[p["name"]] = [t["colname"][n] for n in p["depcols"] if n in t["colname"]]
        depcols_of[name] = depcols
        for p in t["policies"]:
            if discard:
                text = f"for {p['cmd']} to {', '.join(p['roles']) or 'public'}" + (
                    f" using ({p['using']})" if p["using"] else "") + (
                    f" with check ({p['check']})" if p["check"] else "")
                notes.append(f"policy {p['name']} on {name} discarded (--policies discard; the deploy drops it): "
                             f"{'permissive' if p['permissive'] else 'restrictive'} {text}")
                continue
            pol_roles = list(p["roles"])
            if p["public"]:
                pol_roles = list(roles)
                notes.append(f"policy {p['name']} on {name} applies to public: imported once per app role")
            pol_roles = [r for r in pol_roles if r in roles]
            if not pol_roles:
                notes.append(f"policy {p['name']} on {name} applies to no app role ({', '.join(p['roles'])}): not imported")
                continue
            if len(pol_roles) > 1:
                notes.append(f"policy {p['name']} on {name} applies to {', '.join(pol_roles)}: imported as one rule per "
                             f"role (MLS policies have one role; after a deploy the catalog holds one policy per rule)")
            preds: dict[str, dict] = {}
            for which, text in (("using", p["using"]), ("check", p["check"])):
                if text is None:
                    continue
                if which == "check" and p["cmd"] in ("update", "all") and text == p["using"]:
                    continue  # equal to USING: one predicate, as the compiler writes it
                env.caller_reads = []
                r = lift_expr(name, text, f"{p['name']}_{which}", "policy", depcols[p["name"]])
                preds[which] = r.pred
                lifted_exprs.append({"table": name, "policy": p, "which": which, "text": text, "result": r,
                                     "caller": set(env.caller_reads), "rules": [
                                         (ident(p["name"]) if i == 0 else suffixed(p["name"], role), role)
                                         for i, role in enumerate(pol_roles)]})
                what = f"policy {p['name']} on {name}, {'with check' if which == 'check' else 'using'}"
                if r.kind == "lifted":
                    lifted_n += 1
                else:
                    opaque_n += len(r.opaques)
                    notes.append(f"{what}: " + ("an opaque block" if r.kind == "opaque" else "partly opaque")
                                 + " (" + "; ".join(r.reasons) + ")")
                for h in r.hints:
                    notes.append(f"lint: {what}: {h}")
            if p["cmd"] != "insert" and "using" not in preds:
                preds["using"] = {"lit": True}
            if p["cmd"] == "insert" and "check" not in preds:
                preds["check"] = {"lit": True}
            if ident(p["name"]) != p["name"]:
                notes.append(f"policy \"{p['name']}\" on {name} is imported as rule {ident(p['name'])} (MLS names are "
                             f"identifiers); until a deploy renames it, drift shows the old name as unexpected")
            for i, role in enumerate(pol_roles):
                rname = ident(p["name"]) if i == 0 else suffixed(p["name"], role)
                rule = {"kind": "policy", "name": rname, "table": name, "role": role, "command": p["cmd"],
                        "mode": "permissive" if p["permissive"] else "restrictive", **preds}
                rules.append(rule)
        permissive = {(r["role"], c) for r in rules if r["kind"] == "policy" and r["table"] == name
                      and r["mode"] == "permissive"
                      for c in (("select", "insert", "update", "delete") if r["command"] == "all" else (r["command"],))}
        grants: dict[tuple[str, str], set[str] | None] = {}
        if discard and any(g in roles for g, _, _ in t["acl"]):
            notes.append(f"the grants on {name} are not imported (--policies discard): the deploy grants what the "
                         f"rules need")
        for grantee, priv, col in ([] if discard else t["acl"]):
            if grantee not in roles or priv not in ("select", "insert", "update", "delete"):
                continue
            cur = grants.get((grantee, priv), set())
            grants[(grantee, priv)] = None if col is None or cur is None else cur | {col}
        for (role, priv), cols in sorted(grants.items(), key=lambda kv: kv[0]):
            if (role, priv) not in permissive:
                notes.append(f"{role} has {priv} on {name} but no permissive {priv} policy: not imported (revoke it, "
                             f"or add the policy)")
                continue
            if cols is None:
                continue
            if cols - modelled[name]:  # #71: a column the import left out (its type) has no rule
                left = ", ".join(sorted(cols - modelled[name]))
                cols = cols & modelled[name]
                if not cols:
                    # no modelled column: without a column rule the spec would grant every column, so the
                    # role's policies for the command go instead (stricter, never weaker)
                    gone = [r for r in rules if r["kind"] == "policy" and r["table"] == name and r["role"] == role
                            and r["mode"] == "permissive" and r["command"] in (priv, "all")]
                    for r in gone:
                        rules.remove(r)
                    names = {r["name"] for r in gone}
                    for x in lifted_exprs:
                        if x["table"] == name:
                            x["rules"] = [(n, ro) for n, ro in x["rules"] if n not in names]
                    notes.append(f"{role}'s {priv} grant on {name} names only {left}, not modelled: the spec cannot "
                                 f"limit {priv} to it, so {', '.join(sorted(names))} "
                                 f"{'is' if len(names) == 1 else 'are'} not imported and the spec denies the {priv}")
                    continue
                notes.append(f"{role}'s {priv} grant on {name} names {left}, not modelled: the column rule leaves "
                             f"it out, so a deploy revokes it (drift reports it as unexpected until then)")
            access = "read" if priv == "select" else "write"
            existing = next((r for r in rules if r["kind"] == "column_rule" and r["table"] == name
                             and r["role"] == role and r["access"] == access), None)
            if existing is not None:
                if set(existing["columns"]) != cols:
                    notes.append(f"{role}'s insert and update column grants on {name} differ; the write column rule "
                                 f"takes their union")
                    existing["columns"] = sorted(set(existing["columns"]) | cols)
                continue
            if priv == "delete":
                continue
            rules.append({"kind": "column_rule", "name": suffixed(name, f"{role}_{access}"), "table": name,
                          "role": role, "columns": sorted(cols), "access": access})
        # CHECKs: a stored-row assumption when the lifter reads one (ROADMAP M5), else listed
        for con in t["constraints"]:
            if con["type"] != "c":
                continue
            what = f"CHECK {con['name']} on {name}"
            if not con["validated"]:
                notes.append(f"{what} is NOT VALID (rows may violate it): listed, not imported: {con['def']}")
                continue
            try:
                expr = strip_check(con["def"])
                tree = parse(expr)
            except Unreadable as e:
                notes.append(f"{what} is listed, not imported ({e}): {con['def']}")
                continue
            is_true = isinstance(tree, _IsTrue) and tree.value and not tree.negated
            if not is_true:
                nullable = nullable_columns(expr, env.tables[name]) or set()
                if nullable:
                    notes.append(f"{what} is listed, not imported: it passes when {', '.join(sorted(nullable))} is "
                                 f"NULL, where an MLS check rule (`(p) is true`) rejects the row: {con['def']}")
                    continue
            r = lift_expr(name, expr, con["name"], "check", [], top_is_true=is_true)
            if r.kind == "opaque" or (r.kind == "partial" and not is_true):
                for o in r.opaques:
                    opaques.pop(o, None)
                    env.opaques.pop(o, None)
                env.invalidate()
                notes.append(f"{what} is listed, not imported ({'; '.join(r.reasons)}): {con['def']}")
                continue
            try:
                env.validate(r.pred, name, "check", False)
            except Unreadable as e:
                for o in r.opaques:
                    opaques.pop(o, None)
                    env.opaques.pop(o, None)
                env.invalidate()
                notes.append(f"{what} is listed, not imported ({e}): {con['def']}")
                continue
            rules.append({"kind": "check", "name": ident(con["name"]), "table": name, "predicate": r.pred})
            if r.kind == "partial":
                opaque_n += len(r.opaques)
                notes.append(f"{what} is imported as a check rule, partly opaque (" + "; ".join(r.reasons) + ")")
            else:
                lifted_n += 1
            if not is_true:
                notes.append(f"{what} is imported as check rule {ident(con['name'])}: its columns are NOT NULL, so "
                             f"it means what MLS's `(p) is true` form means; a deploy rewrites it to that form, "
                             f"and drift reports the definition as differs until then")
            if ident(con["name"]) != con["name"]:
                notes.append(f"{what} is imported as rule {ident(con['name'])} (MLS names are identifiers)")
        # triggers: the compiler's own transition and column guard templates are read back; any
        # other trigger is listed
        for tg in t["triggers"]:
            what = f"trigger {tg['name']} on {name}"
            inc = inclusion_parts(tg["def"], tg["function"], tg["body"])
            if inc == "target":  # #54: read with the trigger on the inclusion's table
                continue
            if inc is not None:
                unknown = [f"{tb}.{c}" for tb, cs in ((name, inc.columns), (inc.target, (inc.key, inc.value)))
                           for c in cs if tb not in modelled or c not in modelled[tb]]
                if unknown or inc.target not in governed:
                    notes.append(f"{what} is listed, not imported (" + (f"columns {', '.join(unknown)} are not "
                                 f"modelled" if unknown else f"table {inc.target} is observed") + ")")
                    continue
                r = lift_expr(inc.target, inc.condition, tg["name"], "relation", [])
                if r.kind != "lifted":
                    for o in r.opaques:
                        opaques.pop(o, None)
                        env.opaques.pop(o, None)
                    env.invalidate()
                    notes.append(f"{what} is listed, not imported ({'; '.join(r.reasons)})")
                    continue
                rel_names.setdefault((inc.target, inc.key, _cond_key(r.pred)), inc.relation)  # its message names it
                rname = propose(inc.target, inc.key, inc.value, f"inclusion trigger {tg['name']} on {name} reads it",
                                r.pred)
                if rname is None:
                    continue
                rules.append({"kind": "inclusion", "name": ident(inc.name), "table": name, "columns": list(inc.columns),
                              "relation": rname, "on_delete": "restrict", "deferred": True})
                lifted_n += 1
                continue
            g = guard_parts(tg["def"], tg["function"], tg["body"])
            if g is not None:  # #57
                depth = {h["depth"] for h in env.hierarchies.values() if h.get("table") == name}
                cols = [c for c in g.kept if c not in depth]
                unknown = [c for c in cols if c not in modelled[name]]
                if unknown or g.role not in roles:
                    notes.append(f"{what} is listed, not imported (its "
                                 + (f"columns {', '.join(unknown)} are not modelled" if unknown
                                    else f"role {g.role} is not an app role") + ")")
                    continue
                r = lift_expr(name, g.condition, tg["name"], "guard", [])
                if r.kind != "lifted":
                    for o in r.opaques:
                        opaques.pop(o, None)
                        env.opaques.pop(o, None)
                    env.invalidate()
                    notes.append(f"{what} is listed, not imported ({'; '.join(r.reasons)})")
                    continue
                rules.append({"kind": "column_rule", "name": ident(g.name), "table": name, "role": g.role,
                              "columns": cols, "access": "write", "when": r.pred})
                lifted_n += 1
                continue
            expr = transition_expr(tg["def"], tg["function"], tg["body"])
            if expr is None:
                notes.append(f"{what} is listed, not imported (only the transition template MLS emits is read back; "
                             f"a hand-written trigger is never inlined)")
                continue
            r = lift_expr(name, expr, tg["name"], "transition", [])
            if r.kind != "lifted":
                for o in r.opaques:
                    opaques.pop(o, None)
                    env.opaques.pop(o, None)
                env.invalidate()
                notes.append(f"{what} is listed, not imported ({'; '.join(r.reasons)})")
                continue
            try:
                env.validate(r.pred, name, "transition", False)
            except Unreadable as e:
                notes.append(f"{what} is listed, not imported ({e})")
                continue
            rules.append({"kind": "transition", "name": ident(tg["name"]), "table": name, "predicate": r.pred})
            lifted_n += 1

    # --- an opaque block's signature names every relation on the tables its SQL reads; a table it
    # reads that has a two-column key and no relation yet gets one (the block depends on that state)
    for oname, o in opaques.items():
        for other in tables:
            if other == o["table"] or not re.search(r'(?<![\w."])"?' + re.escape(other) + r'"?(?![\w"])', o["sql"]):
                continue
            if other in governed and not any(r["table"] == other for r in relations.values()):
                for k in key_sets(other):
                    if len(k) == 2:
                        propose(other, k[0], k[1], f"opaque block {oname} reads it")
                        break
            o["relations"] = sorted(set(o["relations"]) | {rn for rn, r in relations.items() if r["table"] == other})

    # --- what the compiler regenerates from the lifted memberships is not a rule of the spec
    def finish(rules: list[dict]) -> Spec:
        for i, r in enumerate(rules, 1):
            r.pop("id", None)
            rules[i - 1] = {"id": f"R{i}", **r}
        spec = {"mls_version": "0.1", "identity": {"adapter": adapter, "context": context},
                "roles": roles, "enums": enums, "tables": spec_tables, "relations": relations, "opaques": opaques, "rules": rules,
                "properties": []}
        from mls.spec.check import check_spec

        try:
            return check_spec(Spec.model_validate(spec))
        except SpecError as e:
            raise SpecError([MlsError(x.path, f"the imported spec does not check (an import bug): {x.message}",
                                      x.fix, "import") for x in e.errors]) from None

    from mls.compile.column import relations_in
    from mls.props.effective import implicit_policies

    for cname, (of, hops) in env.composed.items():  # D56: the chains the lifter read
        relations[cname] = {"of": of, "through": [{"table": t, "key": k, "value": v} for t, k, v in hops]}
        notes.append(f"relation {cname} proposed: {of} . " + " . ".join(f"{t}({k}, {v})" for t, k, v in hops)
                     + " (a nested membership subquery reads it)")
    # #60: a cascade deletes rows nothing else may read (the checker refuses one on a table that
    # backs a relation); such a key stays foreign
    backing = {r["table"] for r in relations.values() if "table" in r}
    for r in [r for r in rules if r.get("on_delete") in ("cascade", "set_null") and r["table"] in backing]:
        rules.remove(r)
        notes.append(f"foreign key {r['name']} on {r['table']} is ON DELETE {r['on_delete'].upper().replace('_', ' ')}, "
                     f"and a relation reads "
                     f"{r['table']}, so the proofs could not follow the rows it deletes: listed as foreign, "
                     f"not imported")
    checked = finish(rules)
    hidden = _hidden_memberships(checked, lifted_exprs)
    for x in lifted_exprs:  # #41: read again, the hidden memberships left to opaque blocks
        refuse = {rel for rname, role in x["rules"] for rel in hidden.get((x["table"], rname), ())}
        if not refuse:
            continue
        for o in x["result"].opaques:
            opaques.pop(o, None)
            env.opaques.pop(o, None)
        env.hidden, env.caller_reads = refuse, []
        env.invalidate()
        p, which = x["policy"], x["which"]
        r = lift_expr(x["table"], x["text"], f"{p['name']}_{which}_rls", "policy", depcols_of[x["table"]][p["name"]])
        env.hidden = set()
        for rname, _ in x["rules"]:
            rule = next(rr for rr in rules if rr.get("kind") == "policy" and rr["table"] == x["table"]
                        and rr["name"] == rname)
            rule[which] = r.pred
        for rel in sorted(refuse):
            notes.append(f"policy {p['name']} on {x['table']}, {'with check' if which == 'check' else 'using'}: its "
                         f"subquery over {rel} runs as the caller, and the policies on that table hide some of the "
                         f"rows it reads (the relation would claim them): read as an opaque block")
    if hidden:
        checked = finish(rules)
        # a chain read only by a subquery read again as opaque is no longer used: not proposed
        used = {rn for p in checked.policies() for rn in relations_in(p.using, relations_in(p.check, set()))}
        used |= {r for o in checked.opaques.values() for r in o.relations}
        unused = [c for c in env.composed if c not in used]
        for c in unused:
            relations.pop(c)
            notes[:] = [n for n in notes if not n.startswith(f"relation {c} proposed: ")]
        if unused:
            checked = finish(rules)
    from mls.compile.sql import SqlCompiler
    from mls.identity import get_adapter

    from mls.spec.expand import expand_spec

    expanded = expand_spec(checked)  # the SQL renderer never sees an `in` (a relation's condition may hold one)
    sqlc = SqlCompiler(expanded, get_adapter(expanded))
    # compared as the SQL they compile to: a hop's policy names a prefix of its chain (D56), which
    # the lifter reads back as the composed relation with the same levels
    # and by name as the import spells rule names: `ident` lower-cases a mixed-case role in it
    implicit = {(ident(p.name), p.table, p.role, p.command, p.mode): sqlc.pred(p.using, p.table)
                for p in implicit_policies(expanded)}
    drop: set[str] = set()
    for p in expanded.policies():
        key = (p.name, p.table, p.role, p.command, p.mode)
        if key in implicit and p.check is None and sqlc.pred(p.using, p.table) == implicit[key]:
            drop.add(p.id)
            notes.append(f"policy {p.name} on {p.table} is the compiler's relation-visibility policy: not imported "
                         f"as a rule (the compiler regenerates it from the lifted membership)")
    rel_reads: dict[tuple[str, str], set[str]] = {}  # (role, table) -> columns the relation grants read
    for p in checked.policies():
        if p.id in drop:
            continue
        for rn in relations_in(p.using, relations_in(p.check, set())):
            for rel in levels(checked, rn):
                rel_reads.setdefault((p.role, rel.table), set()).update(c for c in (rel.key, rel.value) if c is not None)
    for r in checked.column_rules():
        if r.access == "read" and rel_reads.get((r.role, r.table)) == set(r.columns) and not any(
                p.role == r.role and p.table == r.table and p.mode == "permissive" and p.command in ("select", "all")
                for p in checked.policies() if p.id not in drop):
            drop.add(r.id)
            notes.append(f"column grant select ({', '.join(r.columns)}) on {r.table} to {r.role} is the compiler's "
                         f"relation grant: not imported as a column rule (regenerated from the lifted membership)")
    if drop:
        rules = [r for r in rules if r["id"] not in drop]
        checked = finish(rules)
    for t, fns in sorted(inlined_by.items()):  # #52: drift checks that each helper keeps its body
        spec_tables[t].setdefault("assume", []).extend({"inlined": f} for f in sorted(fns))
        notes.append(f"table {t}: its policies call {', '.join(f.split(' md5 ')[0] for f in sorted(fns))}, read "
                     f"inline as the body each has now (assumed; drift reports a changed body)")
        for f in sorted(volatile_by.get(t, ())):
            notes.append(f"table {t}: function {f}() is VOLATILE (it declares no volatility) and is read as its "
                         f"body, which sees the statement's snapshot: a statement that changes the tables it reads "
                         f"and is checked by a policy that calls it may see fewer of its own changes once the "
                         f"policies are compiled (declare it stable to say it reads one snapshot)")
    spec = {"mls_version": "0.1", "identity": {"adapter": adapter, "context": context}, "roles": roles,
            "enums": enums, "tables": spec_tables, "relations": relations, "opaques": opaques, "rules": rules, "properties": []}

    # --- bypass paths (D54): listed with their fix, never assumed by the import
    from mls.pg.drift import bypass_report

    with conn.transaction():
        paths = bypass_paths(conn, schema, sorted(governed), list(roles))
    notes += [f"bypass path: {i.object}" for i in bypass_report(checked, paths)[0]]

    n_adopted = len(governed)
    comment = (f"imported by mls import{' --policies discard' if discard else ''} from schema '{schema}' on "
               f"{dt.date.today().isoformat()}: "
               f"{len(spec_tables)} tables ({n_adopted} adopted, {len(spec_tables) - n_adopted} observed), "
               f"{lifted_n} policy and CHECK expressions lifted into the fragment, {opaque_n} opaque blocks; "
               f"see the import notes for what was left out")
    spec = {"$comment": comment, **spec}
    return ImportResult(spec, notes)


# ----------------------------------------------------------------------------- check --dsn
def database_checks(conn: psycopg.Connection, schema: str = "public"):
    """The checks of a spec's rules against the database's own objects, read once: its foreign keys
    (a cycle an inclusion closes, #35; a delete action that clashes, #60) and its BEFORE UPDATE
    triggers (a column guard that would fire after one, #58).  Returns spec -> errors; `mls
    generate --dsn` gives it to the loop, so that the rules pass repairs what they find."""
    from mls.pg.catalog import all_foreign_keys, before_update_triggers
    from mls.spec.check import fk_action_errors, fk_cycle_errors, guard_order_errors
    from mls.spec.fkcycle import database_fks

    with conn.transaction():
        fks = all_foreign_keys(conn, schema)
        triggers = before_update_triggers(conn, schema)

    def errors(spec: Spec) -> list[MlsError]:
        return (guard_order_errors(spec, triggers) + fk_cycle_errors(spec, database_fks(fks, spec))
                + fk_action_errors(spec, fks))
    return errors


def verify_adopted(conn: psycopg.Connection, spec: Spec, schema: str = "public") -> list[MlsError]:
    """`mls check --dsn`: every adopted table exists with the columns and types the spec declares,
    every observed table exists, no owned table is owned by an app role (D45), and no app role can
    become a role that bypasses the policies (#68)."""
    errors: list[MlsError] = database_checks(conn, schema)(spec)
    with conn.transaction():
        cat = _read(conn, schema)
    for name, labels in spec.enums.items():
        live_labels = cat["enums"].get(name)
        if live_labels is None:
            errors.append(MlsError(f"$.enums.{name}", f"enum type '{name}' does not exist in schema '{schema}'",
                                   "remove it and its columns from the spec, or create the type outside MLS", "check"))
        elif live_labels != labels:
            errors.append(MlsError(f"$.enums.{name}", f"enum type '{name}' has the labels "
                                                      f"{', '.join(map(repr, live_labels))} in the catalog, declared "
                                                      f"{', '.join(map(repr, labels))}",
                                   "declare the catalog's labels, in its order", "check"))
    for name, t in spec.tables.items():
        path = f"$.tables.{name}"
        live = cat["tables"].get(name)
        if t.mode == "owned":
            if live is not None and live["owner"] in spec.roles:
                errors.append(MlsError(f"{path}.mode", f"owned table '{name}' is owned by app role '{live['owner']}' "
                                                       f"in schema '{schema}'; an app-role owner can alter the "
                                                       f"policies, which the compiler refuses to rely on",
                                       f"change the owner outside MLS, or set mode to \"adopted\" and add "
                                       f"{{\"owner\": \"{live['owner']}\"}} to assume", "check"))
            continue
        if live is None:
            errors.append(MlsError(path, f"{t.mode} table '{name}' does not exist in schema '{schema}'",
                                   "create it outside MLS, set mode to \"owned\" so that MLS creates it, or remove it",
                                   "check"))
            continue
        if t.mode == "observed":
            continue
        live_cols = {c["name"]: c for c in live["columns"]}
        for c, col in t.columns.items():
            lc = live_cols.get(c)
            if lc is None:
                errors.append(MlsError(f"{path}.columns.{c}", f"adopted table '{name}' has no column '{c}'",
                                       f"remove it from the spec, or add it outside MLS; the table has: "
                                       f"{', '.join(live_cols)}", "check"))
            elif col.type in ("enum", "enum[]") or lc["enum"] is not None:
                live_type = "enum[]" if lc["type"].endswith("[]") else "enum"
                if lc["enum"] != col.enum or (lc["enum"] is not None and live_type != col.type):
                    errors.append(MlsError(f"{path}.columns.{c}", f"column '{name}.{c}' is {lc['type']} in the "
                                                                  f"catalog, declared {col.type} {col.enum or ''}".rstrip(),
                                           f"declare it as {live_type} {lc['enum']}" if lc["enum"] is not None
                                           else f"declare it as {mls_type(lc['type']) or 'a type MLS does not model'}",
                                           "check"))
            elif mls_type(lc["type"]) != col.type:
                errors.append(MlsError(f"{path}.columns.{c}.type", f"column '{name}.{c}' is {lc['type']} in the "
                                                                   f"catalog, declared {col.type}",
                                       f"declare it as {mls_type(lc['type']) or 'a type MLS does not model'}",
                                       "check"))
    return errors + role_escalation_errors(conn, spec)


def role_escalation_errors(conn: psycopg.Connection, spec: Spec) -> list[MlsError]:
    """#68, for `check --dsn`: an app role (not a platform service role) that can become a role
    bypassing the policies; no upper bound about it would hold, and the deploy refuses it.
    (CREATEROLE the deploy removes, and drift reports it after.)"""
    from mls.compile.hardening import CAN_BECOME
    from mls.identity.base import bounded_roles

    bounded = bounded_roles(spec)
    with conn.cursor() as cur:
        cur.execute("""select a.rolname, b.rolname from pg_roles a join pg_roles b
                         on b.oid <> a.oid and (b.rolbypassrls or b.rolsuper)
                        and """ + CAN_BECOME.format(a="a.oid", b="b.oid") + """
                       where a.rolname = any(%s) order by 1, 2""", (bounded,))
        found = cur.fetchall()
    return [MlsError(f"$.roles[{spec.roles.index(r)}]",
                     f"app role '{r}' can become '{x}', which bypasses the policies, so no property can "
                     f"bound what '{r}' reaches",
                     f"revoke '{x}' from '{r}' (and through every role between), or take '{r}' out of the "
                     f"roles if it is meant to be trusted", "check")
            for r, x in found]


def _hidden_memberships(spec: Spec, lifted: list[dict]) -> dict[tuple[str, str], set[str]]:
    """#41: per (table, rule name), the memberships the policy reads from a subquery that runs as the
    caller whose rows the relation table's own policies can hide: the relation-visibility
    obligation against the spec's policies alone (a hand-written database has no visibility
    policies of the compiler's; a deployed spec's own are imported as rules, so it holds there).
    A membership read through a SECURITY DEFINER helper reads every row and is not checked."""
    from mls.props.obligations import relation_visibility_obligations
    from mls.props.runner import run_obligation

    ids = {(r.table, r.name): r.id for r in spec.policies()}
    only = {(ids[(x["table"], rname)], rel) for x in lifted for rname, _ in x["rules"]
            if (x["table"], rname) in ids for rel in x["caller"]}
    if not only:
        return {}
    by_id = {r.id: r for r in spec.policies()}
    out: dict[tuple[str, str], set[str]] = {}
    for ob in relation_visibility_obligations(spec, only):
        if run_obligation(spec, ob).verdict == "PROVED":
            continue
        rel = re.match(r"relation (\S+) visible to (\S+)", ob.name)
        role = rel.group(2)
        for rid, rn in only:  # the obligation stands for every rule of that role reading the relation
            r = by_id[rid]
            if rn == rel.group(1) and r.role == role:
                out.setdefault((r.table, r.name), set()).add(rn)
    return out
