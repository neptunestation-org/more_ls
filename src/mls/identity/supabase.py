"""Supabase adapter: identity from auth.uid() and auth.jwt() claims, always as InitPlans."""
from __future__ import annotations

import json
import uuid
from typing import Any

from mls.identity.base import Adapter
from mls.sqltext import q
from mls.spec.model import Spec


# the claims of Supabase's anon key (its own JWT, signed by the project)
ANON_KEY_CLAIMS = frozenset({"iss", "ref", "role", "iat", "exp"})


class SupabaseAdapter(Adapter):
    name = "supabase"
    platform_roles = ("anon", "authenticated", "service_role")
    trusted_roles = ("service_role",)
    trusted_note = ("service_role has BYPASSRLS (Supabase's backend key) and is trusted: it reads and "
                    "writes every row whatever the policies say")
    service_roles = ("authenticator", "supabase_auth_admin")
    service_note = ("authenticator (the API's login, which can become service_role) and "
                    "supabase_auth_admin (the auth service, which can create roles) are the platform's "
                    "service roles and are trusted: their own rules are deployed and what they must be "
                    "able to do is proved, but no property bounds what they can reach, and the deploy "
                    "never alters them")
    assumption = ("Clients reach the database only through Supabase's API layer, which verifies "
                  "the JWT before setting request.jwt.claims; direct database connections by "
                  "untrusted clients are out of scope.")

    @classmethod
    def unstated_availability(cls, roles, cv) -> list[tuple[str, str]]:
        """#98: Supabase's API serves a request without a user's token as `anon` (PostgREST's anonymous
        role, as Supabase configures it), whose key carries only its own claims: no `sub`, so
        auth.uid() is NULL, and no claim the auth service adds."""
        if "anon" not in roles or cv.optional or "anon" in cv.unset_for or "anon" in cv.optional_for:
            return []
        if cv.source == "auth.uid":
            return [("anon", "Supabase starts anon's sessions with its anon key, which has no user, so "
                             "auth.uid() is NULL there")]
        claim = cv.source[len("jwt.claims."):]
        if cv.source.startswith("jwt.claims.") and claim not in ANON_KEY_CLAIMS:
            return [("anon", f"Supabase starts anon's sessions with its anon key, which carries no "
                             f"'{claim}' claim")]
        return []

    def _ctx_sql(self, name: str, source: str, sql_type: str) -> str:
        if source == "auth.uid":
            return "(select auth.uid())"
        claim = source[len("jwt.claims."):]
        return f"(select (auth.jwt() ->> '{claim}')::{sql_type})"

    def user_context_name(self) -> str | None:
        for n, cv in self.spec.identity.context.items():
            if cv.source == "auth.uid":
                return n
        return None

    # Supabase's own definitions (supabase/postgres, migrations 20210809183423 / 20211124212715)
    def harness_setup_sql(self, spec: Spec) -> list[str]:
        return [
            "create schema if not exists auth",
            """create or replace function auth.jwt() returns jsonb language sql stable as $$
                 select coalesce(
                   nullif(current_setting('request.jwt.claim', true), ''),
                   nullif(current_setting('request.jwt.claims', true), '')
                 )::jsonb $$""",
            """create or replace function auth.uid() returns uuid language sql stable as $$
                 select coalesce(
                   nullif(current_setting('request.jwt.claim.sub', true), ''),
                   (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
                 )::uuid $$""",
            *[f"grant usage on schema auth to {q(r)}; grant execute on function auth.jwt(), auth.uid() to {q(r)}"
              for r in spec.roles],
        ]

    def harness_context_sql(self, role: str, ctx: dict[str, Any]) -> list[str]:
        claims: dict[str, Any] = {}
        for n, cv in self.spec.identity.context.items():
            if ctx.get(n) is None:  # #75: an optional value the caller lacks: no claim
                continue
            if cv.source == "auth.uid":
                claims["sub"] = str(ctx[n])
            else:
                claims[cv.source[len("jwt.claims."):]] = ctx[n]
        j = json.dumps(claims).replace("'", "''")
        return [f"select set_config('request.jwt.claims', '{j}', true)", f"set local role {q(role)}"]

    def harness_user_values(self, n: int) -> list[Any]:
        return [str(uuid.UUID(int=i + 1)) for i in range(n)]
