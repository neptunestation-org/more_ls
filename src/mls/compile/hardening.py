"""Bypass-path hardening (D13): app roles are not owners and have no BYPASSRLS; RLS is enabled and
FORCED on every table; TRUNCATE is never granted; app roles cannot SET session_replication_role.

On an `adopted` table (D45) the compiler enables row level security and sets the privileges the
rules need, but does not FORCE it and does not touch the owner: that hardening is verified by
drift or stated in the table's `assume`, never silently emitted."""
from __future__ import annotations

from mls.compile.mutations import Mutation
from mls.compile.sql import q
from mls.spec.model import Spec


def preamble_ddl(spec: Spec) -> list[str]:
    roles = ", ".join(f"'{r}'" for r in [*spec.roles, "mls_internal"])
    return [
        f"do $mls$ begin\n"
        f"  if current_user = any (array[{roles}]) then\n"
        f"    raise exception 'MLS DDL must run as the owner role, not an app role';\n"
        f"  end if;\n"
        f"end $mls$",
    ]


# pg_roles column -> the clause that clears it
APP_ROLE_ATTRIBUTES = {"rolsuper": "nosuperuser", "rolbypassrls": "nobypassrls", "rolcreatedb": "nocreatedb",
                       "rolcreaterole": "nocreaterole"}


def role_attributes_ddl(role: str, attributes: dict[str, str]) -> str:
    """Clear each attribute the role has, one ALTER ROLE per attribute, and none when it has none.
    The end state is the unconditional `alter role r nobypassrls nosuperuser ...`; the difference
    is on a platform whose deployer is not a superuser (Supabase, D55): there `nosuperuser` needs
    a superuser even when it changes nothing, and the API roles are reserved (any ALTER ROLE on
    them is refused).  A role that really has the attribute still fails the deploy (invariant 4)."""
    body = "".join(f"  if r.{col} then alter role {q(role)} {clause}; end if;\n" for col, clause in attributes.items())
    return (f"do $mls$ declare r pg_roles; begin\n"
            f"  select * into r from pg_roles where rolname = '{role}';\n"
            f"{body}"
            f"end $mls$")


# #68: whether role {a} can SET ROLE to {b} (through other roles too).  Attributes such as
# BYPASSRLS are never inherited, so SET is what escalates; PG 15 has no SET option on a grant.
CAN_BECOME = ("(case when current_setting('server_version_num')::int >= 160000 "
              "then pg_has_role({a}, {b}, 'SET') else pg_has_role({a}, {b}, 'MEMBER') end)")


def escalation_check_ddl(role: str) -> str:
    """#68: refuse an app role that can become (directly or through other roles) a role that
    bypasses the policies: every upper bound about it would be false.  The deploy cannot fix
    it: the membership may be the platform's own."""
    return (f"do $mls$ declare x text; begin\n"
            f"  select string_agg(b.rolname, ', ' order by b.rolname) into x from pg_roles a, pg_roles b\n"
            f"   where a.rolname = '{role}' and b.oid <> a.oid and (b.rolbypassrls or b.rolsuper)\n"
            f"     and {CAN_BECOME.format(a='a.oid', b='b.oid')};\n"
            f"  if x is not null then\n"
            f"    raise exception 'MLS: app role {role} can become %, which bypasses the policies', x\n"
            f"      using hint = 'revoke that membership from {role} (and through every role between), "
            f"or take {role} out of the spec''s roles if it is meant to be trusted';\n"
            f"  end if;\n"
            f"end $mls$")


def app_role_ddl(spec: Spec, role: str, mutations: frozenset[Mutation] | set[Mutation] = frozenset()) -> list[str]:
    """Create an app role if missing and harden it.  A platform service role (#68: on Supabase,
    authenticator and supabase_auth_admin) is the platform's: reserved, never altered."""
    from mls.identity import get_adapter

    out = [f"do $mls$ begin\n"
           f"  if not exists (select 1 from pg_roles where rolname = '{role}') then\n"
           f"    create role {q(role)} nologin;\n"
           f"  end if;\n"
           f"end $mls$"]
    if role in get_adapter(spec).service_roles:
        return out
    out.append(role_attributes_ddl(role, APP_ROLE_ATTRIBUTES))
    if Mutation.ROLE_ESCALATION_UNCHECKED not in mutations:
        out.append(escalation_check_ddl(role))
    out.append(f"revoke set on parameter session_replication_role from {q(role)}")
    return out


def role_ddl(spec: Spec, mutations: frozenset[Mutation] | set[Mutation] = frozenset()) -> list[str]:
    return [s for r in spec.roles for s in app_role_ddl(spec, r, mutations)]


def platform_revokes(spec: Spec) -> list[str]:
    """The platform's untrusted roles (D55: on Supabase, anon and authenticated), which its default
    privileges grant every new table and function directly: MLS functions revoke them unless the
    function grants them EXECUTE."""
    from mls.identity import get_adapter

    adapter = get_adapter(spec)
    return [r for r in adapter.platform_roles if r not in adapter.trusted_roles]


def platform_table_revokes(spec: Spec) -> list[str]:
    """The platform's untrusted roles the spec does not use (D55: on Supabase, `anon` when no rule
    names it): the deploy takes back the default privileges they hold on governed tables."""
    return [r for r in platform_revokes(spec) if r not in spec.roles]


def revoke_platform_ddl(obj: str, roles: list[str]) -> str | None:
    """`revoke all on <obj>` from each platform role that exists: a platform role is not created
    by the script, and the same spec deploys on plain Postgres, where it may not exist."""
    if not roles:
        return None
    body = "".join(f"  if exists (select 1 from pg_roles where rolname = '{r}') then revoke all on {obj} from {q(r)}; end if;\n"
                   for r in roles)
    return f"do $mls$ begin\n{body}end $mls$"


def table_hardening_ddl(spec: Spec, mutations: frozenset[Mutation] = frozenset()) -> list[str]:
    out = []
    for t, tb in spec.governed().items():
        out.append(f"revoke all on {q(t)} from public")
        for r in spec.roles:
            out.append(f"revoke all on {q(t)} from {q(r)}")
        platform = revoke_platform_ddl(q(t), platform_table_revokes(spec))
        if platform:
            out.append(platform)
        out.append(f"alter table {q(t)} enable row level security")
        if tb.mode == "owned" and Mutation.HARDENING_NO_FORCE not in mutations:
            out.append(f"alter table {q(t)} force row level security")
    return out
