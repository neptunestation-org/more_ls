"""Identity adapters (D1, SEMANTICS §6): map context names to SQL expressions and state the
trust assumption that every proof report repeats."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mls.spec.model import CONTEXT_NOW, Spec

SQL_TYPE = {"int": "integer", "bigint": "bigint", "text": "text", "bool": "boolean", "timestamp": "timestamptz",
            "uuid": "uuid", "citext": "citext"}


def ctx_type_sql(cv) -> str:
    """A context value's SQL type: an enum value's is its Postgres type, quoted (#89)."""
    from mls.sqltext import q

    return q(cv.enum) if cv.type == "enum" else SQL_TYPE[cv.type]


class Adapter(ABC):
    name: str
    assumption: str
    # Roles the platform creates and grants by default privileges (D55).  The deploy revokes every
    # privilege on governed tables and MLS functions from those the spec does not use, except the
    # trusted ones: roles the platform gives BYPASSRLS on purpose, which every proof report names
    # and whose privileges drift does not compare (they bypass the policies whatever they hold).
    platform_roles: tuple[str, ...] = ()
    trusted_roles: tuple[str, ...] = ()
    trusted_note: str = ""
    # #68: the platform's own service roles.  They log in and reach rows through their own rules,
    # which a spec states and the compiler keeps, but they can act as a trusted role (become one,
    # or create roles), so no upper bound holds for them and the deploy never alters them.
    service_roles: tuple[str, ...] = ()
    service_note: str = ""
    # #83: roles whose callers carry no identity (Supabase's anon key has no claims): every context
    # value is NULL for them
    anonymous_roles: tuple[str, ...] = ()
    anonymous_note: str = ""

    def __init__(self, spec: Spec):
        self.spec = spec

    def ctx_sql(self, name: str) -> str:
        """SQL expression for a context value, wrapped as an InitPlan (constant per statement)."""
        if name == CONTEXT_NOW:
            return "(select now())"
        cv = self.spec.identity.context[name]
        return self._ctx_sql(name, cv.source, ctx_type_sql(cv))

    @abstractmethod
    def _ctx_sql(self, name: str, source: str, sql_type: str) -> str: ...

    # --- differential-test harness hooks (plain Postgres stands in for the real environment)
    @abstractmethod
    def harness_setup_sql(self, spec: Spec) -> list[str]:
        """Statements (run once as superuser) that make the adapter's SQL work on plain Postgres."""

    @abstractmethod
    def harness_context_sql(self, role: str, ctx: dict[str, Any]) -> list[str]:
        """Statements to run inside a transaction so the session carries `ctx` for `role`."""

    @abstractmethod
    def harness_user_values(self, n: int) -> list[Any]:
        """n distinct identity values for the user context (uuid strings or role names)."""

    @abstractmethod
    def user_context_name(self) -> str | None:
        """The context name that identifies the user (auth.uid / current_user), if declared."""


def bounded_roles(spec: Spec) -> list[str]:
    """The roles an upper bound speaks for (#68): the spec's roles but the platform's service roles."""
    service = get_adapter(spec).service_roles
    return [r for r in spec.roles if r not in service]


def anonymous_roles(spec: Spec) -> frozenset[str]:
    """#83: the spec's roles whose callers have no context values (every one is NULL for them)."""
    return frozenset(r for r in get_adapter(spec).anonymous_roles if r in spec.roles)


def adapter_anonymous_roles(adapter: str, roles) -> frozenset[str]:
    """#85: `anonymous_roles` from an adapter's name and a list of roles (the import's view)."""
    return frozenset(r for r in adapter_class(adapter).anonymous_roles if r in roles)


def adapter_class(name: str) -> type[Adapter]:
    from mls.identity.pg_roles import PgRolesAdapter
    from mls.identity.session_setting import SessionSettingAdapter
    from mls.identity.supabase import SupabaseAdapter
    from mls.identity.trusted_function import TrustedFunctionAdapter

    return {"supabase": SupabaseAdapter, "pg_roles": PgRolesAdapter, "session_setting": SessionSettingAdapter,
            "trusted_function": TrustedFunctionAdapter}[name]


def get_adapter(spec: Spec) -> Adapter:
    return adapter_class(spec.identity.adapter)(spec)
