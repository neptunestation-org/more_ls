"""Identity adapters (D1, SEMANTICS §6): map context names to SQL expressions and state the
trust assumption that every proof report repeats."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mls.spec.model import CONTEXT_NOW, ColType, Spec

SQL_TYPE = {"int": "integer", "bigint": "bigint", "text": "text", "bool": "boolean", "timestamp": "timestamptz",
            "uuid": "uuid"}


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

    def __init__(self, spec: Spec):
        self.spec = spec

    def ctx_sql(self, name: str) -> str:
        """SQL expression for a context value, wrapped as an InitPlan (constant per statement)."""
        if name == CONTEXT_NOW:
            return "(select now())"
        cv = self.spec.identity.context[name]
        return self._ctx_sql(name, cv.source, cv.type)

    @abstractmethod
    def _ctx_sql(self, name: str, source: str, type_: ColType) -> str: ...

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


def get_adapter(spec: Spec) -> Adapter:
    from mls.identity.pg_roles import PgRolesAdapter
    from mls.identity.session_setting import SessionSettingAdapter
    from mls.identity.supabase import SupabaseAdapter

    return {"supabase": SupabaseAdapter, "pg_roles": PgRolesAdapter,
            "session_setting": SessionSettingAdapter}[spec.identity.adapter](spec)
