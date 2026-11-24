"""The trusted_function adapter (#72) without Postgres: SQL shape, source grammar and the md5 pin,
both syntaxes, the trust assumption, the harness hooks."""
from __future__ import annotations

import json

from mls import english
from mls.compile import compile_spec
from mls.identity import get_adapter
from mls.props.report import assumptions
from mls.spec import check_spec
from mls.spec.check import Checker
from mls.spec.model import Spec
from mls.spec.syntax import parse
from mls.terse import render
from tests.templates import specs


def test_context_sql_calls_the_function_once_per_statement():
    spec = specs.function_spec()
    a = get_adapter(spec)
    assert a.name == "trusted_function"
    assert a.ctx_sql("uid") == '(select "mls_ident"."current_uid"())'
    assert a.ctx_sql("now") == "(select now())"
    assert '(select "mls_ident"."current_uid"())' in compile_spec(spec).sql()


def test_source_grammar_and_the_md5_pin():
    d = json.loads(json.dumps(specs.function_spec().model_dump(mode="json", by_alias=True, exclude_none=True)))

    def errors(**cv):
        x = json.loads(json.dumps(d))
        x["identity"]["context"]["uid"].update(cv)
        x["identity"]["context"]["uid"] = {k: v for k, v in x["identity"]["context"]["uid"].items() if v is not None}
        return {e.path: e for e in Checker(Spec.model_validate(x)).run()}

    assert errors() == {}
    e = errors(source="current_uid")["$.identity.context.uid.source"]
    assert "schema-qualified" in e.message and "<schema>.<function>" in e.fix
    e = errors(md5=None)["$.identity.context.uid.md5"]
    assert "md5" in e.message and "mls import" in e.fix
    assert "$.identity.context.uid.md5" in errors(md5="xyz")
    # the other adapters take no md5
    s = json.loads(specs.SESSION.read_text())
    s["identity"]["context"]["uid"]["md5"] = "0" * 32
    assert any(e.path == "$.identity.context.uid.md5" for e in Checker(Spec.model_validate(s)).run())


def test_terse_round_trip():
    spec = specs.function_spec()
    text = render(spec)
    assert "uid: mls_ident.current_uid uuid md5 '" in text, text
    assert check_spec(parse(text)) == spec


def test_assumption_names_the_functions():
    spec = specs.function_spec()
    a = get_adapter(spec)
    assert "mls_ident.current_uid()" in a.assumption and "trusted path" in a.assumption
    assert f"identity adapter 'trusted_function': {a.assumption}" in assumptions(spec, [])
    assert "no context set: denied" in english.spec_summary(spec)


def test_harness_hooks():
    spec = specs.function_spec()
    a = get_adapter(spec)
    assert a.user_context_name() == "uid"
    setup = " ".join(a.harness_setup_sql(spec))
    assert 'create schema if not exists "mls_ident"' in setup
    assert "create or replace function \"mls_ident\".\"current_uid\"() returns uuid" in setup
    stmts = a.harness_context_sql("authenticated", {"uid": "00000000-0000-0000-0000-000000000001"})
    assert stmts == ["select set_config('mls_harness.uid', '00000000-0000-0000-0000-000000000001', true)",
                     "set local role \"authenticated\""]
