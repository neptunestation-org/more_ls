"""trusted_function adapter (#72): each context value is the result of a zero-argument function,
`(select <schema>.<function>())`, read once per statement as an InitPlan.  graphile/starter's
`app_public.current_user_id()` looks the user up from a session id a trusted path sets.

The proofs treat the result as any context value; the trust is in the function, so the spec pins
its body (`md5`) and drift reports a changed body, a changed signature or volatility, and an app
role as its owner (pg/drift.py)."""
from __future__ import annotations

from typing import Any

from mls.identity.base import SQL_TYPE
from mls.identity.session_setting import SessionSettingAdapter
from mls.sqltext import q
from mls.spec.model import ColType

HARNESS_NAMESPACE = "mls_harness"


def call_sql(source: str) -> str:
    schema, fn = source.split(".", 1)
    return f"{q(schema)}.{q(fn)}()"


def stand_in_body(name: str, type_: ColType) -> str:
    """The body of the harness's stand-in for the function behind context value `name`."""
    return f" select nullif(current_setting('{HARNESS_NAMESPACE}.{name}', true), '')::{SQL_TYPE[type_]} "


class TrustedFunctionAdapter(SessionSettingAdapter):
    name = "trusted_function"

    @property
    def assumption(self) -> str:  # type: ignore[override]
        fns = ", ".join(f"{cv.source}()" for cv in self.spec.identity.context.values())
        return (f"{fns} return{'s' if len(self.spec.identity.context) == 1 else ''} the current user's values, "
                f"established by a trusted path that no untrusted client can change; the spec pins each "
                f"function's body, and drift reports a change to it.")

    def user_context_name(self) -> str | None:
        """The policies' membership key, as on session_setting; else the only context value."""
        name = super().user_context_name()
        if name is None and len(self.spec.identity.context) == 1:
            return next(iter(self.spec.identity.context))
        return name

    def _ctx_sql(self, name: str, source: str, type_: ColType) -> str:
        return f"(select {call_sql(source)})"

    # --- harness: a stand-in function of the same name reads a setting the harness sets
    def harness_setup_sql(self, spec) -> list[str]:
        out = []
        for n, cv in spec.identity.context.items():
            schema = cv.source.split(".", 1)[0]
            out += [f"create schema if not exists {q(schema)}",
                    f"create or replace function {call_sql(cv.source)} returns {SQL_TYPE[cv.type]} "
                    f"language sql stable as $${stand_in_body(n, cv.type)}$$",
                    *[f"grant usage on schema {q(schema)} to {q(r)}; "
                      f"grant execute on function {call_sql(cv.source)} to {q(r)}" for r in spec.roles]]
        return out

    def harness_context_sql(self, role: str, ctx: dict[str, Any]) -> list[str]:
        out = []
        for n, cv in self.spec.identity.context.items():
            if ctx.get(n) is None:
                continue
            v = ("true" if ctx[n] else "false") if cv.type == "bool" else str(ctx[n]).replace("'", "''")
            out.append(f"select set_config('{HARNESS_NAMESPACE}.{n}', '{v}', true)")
        out.append(f"set local role {q(role)}")
        return out
