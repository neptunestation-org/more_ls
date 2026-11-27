# MLS — "More LS": RLS more-or-less

MLS is a specification language and compiler for PostgreSQL access-control and data-integrity rules.
A spec (JSON) states who may see and change which rows and which invariants the data must satisfy.
The toolchain **proves properties** about the spec with an SMT solver, then **compiles** it to
Postgres primitives: RLS policies, CHECK constraints, foreign keys, triggers from fixed templates,
column privileges, indexes and grants. RLS is one compilation target, not the foundation.

Specs are written by LLMs from human business requirements. Humans approve **properties and
scenarios** (plain English, concrete examples), never MLS or DDL.

Read before writing code, in this order:
1. `docs/design/DECISIONS.md` — settled decisions. Do not reopen them; flag conflicts instead.
2. `docs/SEMANTICS.md` — the meaning of every construct. This is the source of truth.
3. `docs/design/FINDINGS.md` — what experiments on real Postgres already established.
4. `docs/design/BACKGROUND.md` — what `pg_more_ls` established before this project: the undecidability
   theorem and the survey of authorization languages, cited, not restated.
5. `prototype/` — a working throwaway prototype (Python + Z3). Reuse ideas, not code structure.
6. `examples/` — the example specs, each as `.mls` and `.mls.json`.

The milestones that built all of this are in `docs/design/archive/ROADMAP.md` (archived; every one is implemented).

`docs/` is for users: `docs/GUIDE.md` (user guide; §3 is the takeover, step by step),
`docs/REFERENCE.md` (language and CLI reference) and `docs/SEMANTICS.md`.
`docs/design/` is for contributors: DECISIONS, FINDINGS, LLM (the LLM loop's internals,
corpus and measured runs), TAKEOVERS (the program of open-source takeovers: protocol, log, coverage;
a takeover follows it and adds its row), BACKGROUND and `archive/`. The user docs state the current behaviour without its
history (invariant 8); the reasoning goes in DECISIONS. When you add or change a construct, a property template, a CLI flag, an exit
code or a generated object name, update them in the same change. A construct lives in both
syntaxes (D50): give it its terse form in `terse.py` and its parse in `spec/syntax.py`
in the same change; `tests/test_terse.py` fails the fast suite when the model has a field or a
union member the renderer does not cover.

## Non-negotiable invariants

1. **Three-valued logic everywhere.** Every predicate has SQL semantics (TRUE / FALSE / UNKNOWN).
   The SMT encoding uses (is-true, is-false) pairs. A two-valued shortcut is a bug.
2. **One meaning per predicate across targets.** RLS denies on UNKNOWN; CHECK passes on UNKNOWN.
   The compiler normalizes (`CHECK ((p) IS TRUE)`, trigger `IF NOT ((p) IS TRUE)`).
3. **The compiler emits only fixed templates.** Every template has a differential test against real
   Postgres (15, 16, 17, 18) and at least one mutation test proving the differential test can fail.
4. **Never silently weaken enforcement.** If a target cannot enforce a construct soundly, the
   compiler refuses with an actionable error. Out-of-fragment logic is only allowed as an explicit
   `opaque` block, and every proof report lists the opaque blocks it depends on.
5. **Proofs are about the model; tests tie the model to Postgres.** Every proof report states its
   assumptions (identity adapter, trusted roles, isolation level, opaque blocks).
6. **Decidability is a property of the spec language.** Do not add a construct whose proof
   obligations leave quantifier-free / EPR + linear integer arithmetic + uninterpreted functions
   without a declared bound (e.g. hierarchy depth).
7. **Error messages are written for an LLM to act on**: what is wrong, where (JSON path), and the
   allowed alternative.
8. **Development artefacts never reach users.**  Decision numbers (D45), issue numbers (#27),
   milestones and amendments are for contributors: they may appear in comments, docstrings, commit
   messages and `docs/design/`, never in anything the tool prints (output, errors, CLI help,
   generated SQL, the LLM's prompts) or in the user docs.  Say what the decision means instead.
   `tests/test_no_dev_artefacts.py` enforces it in the fast suite.

## Stack and conventions

- `z3-solver` primary; solver access goes through our own small term layer that can also print
  SMT-LIB2 so `cvc5` cross-checks results in CI.
- Parse `EXPLAIN (FORMAT JSON)`, never text plans (InitPlan display differs across versions).

## Running things

- `uv sync --all-extras`; `uv run mls <check|prove|compile|test|lint|fmt|schema|eval> ...` (a spec
  is `.mls` terse or JSON, by extension).
- `uv run pytest -m "not pg"` is fast and needs no Docker. `uv run pytest -m pg` starts
  `postgres:15..18` containers (set `MLS_PG_VERSIONS=16` for one, `MLS_PG_DSN=...` for an existing
  server). `-m slow` runs the EXPLAIN checks at 1M rows.
- D55: `-m supabase` (also selected by `-m pg`) runs `tests/platform` on the `supabase/postgres`
  image as its non-superuser `postgres` role (`pg/server.py:supabase_container`; each test database
  gets the image's auth schema, default privileges and GoTrue's auth functions via `prepare`).
  A template that works as a superuser can still fail there: FINDINGS "Supabase as a platform".
- D53: `int` and `bigint` are one SMT sort and compare with each other (`model.comparable`);
  only constants are bounded (`model.INT_RANGE`). The `bigint` fixture (`specs.bigint_spec`)
  draws values beyond 2³¹, so an `integer` left anywhere in a template fails its load. An
  adopted `varchar(n)` column is `text` (`lift.mls_type`); drift's stand-in takes the live type.
- D52: `mls import --policies discard` writes the takeover skeleton (`pg/adopt.py`; membership
  tables from FK-backed two-column keys). On an adopted table a check or inclusion rule compiles
  to `compile/adopted.py`'s compare-or-replace block (mutation `ADOPTED_KEEPS_CONSTRAINT`).
  `tests/brownfield/starter_schema.sql` is the Supabase starter; `tests/platform/test_takeover.py`.
- D54: bypass paths (`pg/catalog.py:bypass_paths`: non-invoker views, transitively, materialized
  views, SECURITY DEFINER functions whose owner bypasses the policies and whose body names the
  table) are drift `hardening` (`pg/drift.py:bypass_report`, also read by `mls status --dsn` and
  import's notes) unless the table assumes `{"bypass": "view v"}`; `tests/templates/test_bypass.py`
  has the positive and negative fixtures, the takeover test fixes the starter's two.
- #24: GUIDE §3 is the takeover, step by step, replayed by `tests/platform/test_guide_takeover.py`
  on the starter plus `tests/brownfield/starter_data.sql` (same block/command conventions as
  `test_guide.py`; `psql` and `pg_dump` lines are emulated); its spec is
  `examples/starter_takeover.mls`.  A change to import, diff, drift, status or deploy notices
  updates GUIDE §3 in the same change.  `Harness(foreign=catalog.foreign_keys(..))`
  runs the differential on a deployed brownfield database.  #26: `mls generate --skeleton` keeps
  the skeleton's own rules as fixed rules (`Loop(fixed_rules=...)`), shown to both passes and
  appended after the model's; a clash of id or name is an error at the answer's path.
- #28: `mls generate` runs a relations pass first (`Loop._relations`, `ROLE_RELATIONS`; answer
  `relations { relation ... }` via `syntax.parse_section(.., "relations")`, or JSON
  `{"relations": {}}`); its relations join the skeleton both other passes see and are printed for
  approval (`english.relation_line`).  Every scripted test answers it first (`{"relations": {}}` /
  `relations { }`), except runs that start from given rules or properties, which skip it.  Eval
  cases may carry `withheld_relations`; the grader aligns relations by definition
  (`grade.align_relations`).  The prompt's relation example uses tables the corpus must not
  (`buildings`, `floors`, `rooms`; checked in `test_loop.py`).
- #27: "conditional on an opaque block" means the proof needs it: `props/runner.py:needed_opaques`
  re-solves a PROVED obligation with the block freed (`logic/tvl.py:free_opaques`, each occurrence
  an independent (T, F) pair); the lint uses the same re-check, the diff only the occurrence filter.
- D56: a composed relation (`ComposedRelation`, `of` + `through` hops, `spec/chain.py:levels`;
  a prefix is named `R/i` internally) is a policy atom, refused in invariants, inclusions,
  hierarchies, opaque blocks and `monotone_in`.  Encoded with `hop.T.v` / `hop.T.v.k` functions
  plus `obligations.hop_row_axioms`; compiled to nested `= any(array(...))`, a hop visibility
  policy `mls_rel_<R>_h<i>_*` per hop (mutation `HOP_VISIBILITY_DROPPED`); fixture
  `specs.composed_spec` on `examples/team_tasks.mls`; Lean `Pred.memberVia`.
- Every compiler template has a `Mutation` (compile/mutations.py); `tests/templates` proves each
  mutation is caught by the differential test. Add a mutation when you add a template. The
  fixtures (`tests/templates/specs.py`) derive from the example specs; `test_specs.py` builds and
  checks every one without Docker, so an example edit that breaks a fixture fails in the fast
  suite, not only in the Postgres jobs.
- The guide's tour (GUIDE §4) is replayed by `tests/test_guide.py` on `examples/team_notes.mls`
  (adapter `session_setting`: the README and the explainer quote it and name no identity provider):
  every command it shows runs in its own process (in-process runs get other counterexamples)
  and must print the lines the guide shows. A change to report, lint, explain or compile output
  updates the tour in the same change.
- D58: table, column and role names are case-sensitive (`spec/check.py:CATALOG_IDENT`, no `$`:
  it could close `$mls$`); every name MLS emits goes through `sqltext.q` (the identity adapters'
  `set local role` too), never spliced bare.  MLS's own names stay lower-case.  Fixture
  `specs.mixed_case_spec` (with lower-case twins of its mixed-case columns), mutation `IDENT_UNQUOTED`.
- D59: enum columns (`Spec.enums`, `Column.enum`; adopted tables only) compare with their labels
  by `=`/`<>`/`in`; the proofs add `obligations.enum_row_axioms` (Lean: known gap); the harness and
  drift's shadow create the types (`compile/sql.py:enum_ddl`), `sql_type(col)` is a column's SQL
  type; fixture `specs.enum_spec`, mutation `IN_DROP_LAST`, lift shapes in `tests/pg/test_lift.py`.  #39: two references of one enum type compare by `=`/`<>`
  (`check._cmp`; `comparable` still refuses enums), fixture T1, case `enum_transition`.
- D60: a base relation's pair need only be unique (`model.pair_unique`: some key lies within it),
  so the owner of a parent row is `projects(owner_id, id)`; an enum key column is read with a label
  key.  D82 (#59): an inclusion into one gets the key on exactly the pair from the compiler,
  `mls_key_<table>_<key>_<value>` (`compile/table.py:implied_keys`, a `TableObj.uniques` entry;
  import skips it), mutation `PAIR_KEY_DROPPED` in `tests/templates/test_pair_key.py`; the relations
  pass is told to write inclusion targets (eval case `sc_good`).  The lifter reads an
  `exists` over inner joins as a composed relation (`Lifter.exists_join`); fixture
  `specs.owner_spec`.
- D61: a base relation may carry `where` (its own table's columns and constants,
  `check.relation_scope`); facts are the rows where it is TRUE (`relation_row_axioms` is an
  iff), the subquery conjoins it (`chain.condition`, mutation `RELATION_CONDITION_DROPPED`),
  its visibility policy is its own (`key = k and cond`) and the grant adds its columns
  (`chain.read_columns`); refused as hierarchy members and in invariants (an inclusion target since D86).
  The lifter reads the extra WHERE conditions (`Lifter.condition`); fixture `specs.condition_spec`.
- D62: a filtered relation implies its unfiltered twin on the same table, key and value
  (`obligations.subset_axioms`, inside `relation_axioms`); test `SUBSET` in `tests/props/test_properties.py`.
- D63: at most one `least_privilege` property (`spec/check.py`; the loop repairs it in the properties pass).
- D64: update obligations assume the column privileges (`update_assumptions` conjoins `unwritable_unchanged`, as `net_terms` does).
- D65: the diff ties base relations of the two versions by definition (`diff.both_axioms`), not by name.
- D66/D67: a lookup Postgres would refuse as infinite recursion (a policy on the relation's own
  table, or one closing a cycle of policies through several tables, per role) compiles to a call of
  `mls_lookup_<R>(key)` (`compile/lookup.py`, SECURITY DEFINER, owned by `mls_internal`); which
  lookups is `spec/recursion.py:routed`, read by the renderer, the implicit policies, the grants and
  the visibility obligation (none for a routed lookup).  Import inlines the helpers' bodies
  (`lift.inline_lookups`) and takes the relation's name from the helper's.  Fixture
  `specs.lookup_spec`, mutation `LOOKUP_KEY_DROPPED`; `tests/templates/test_recursion.py` ties the
  routing to PG 15–18.
- D68: a `member`/`in_group` value column may be nullable in a policy (NULL is UNKNOWN, the row is
  hidden); fixture `specs.nullable_member_spec`, mutation `MEMBER_NULL_PASSES`.
- D69: a composed hop may go up a foreign key (key unique, value not: `chain.is_up`); the chain up to
  it is its own symbol `up.<chain>` with one-way row axioms (`obligations.up_row_axioms`; never in
  `hops_used`); fixture `specs.up_spec`.  Routing (D67) is by (table, relation, role), not rule order.
- D70: a lookup keyed by a constant is routed too (`recursion.Use.const_key`): its visibility policy
  would grant every row with that key; fixture `specs.storefront_spec`.
- D71: a relation's key and value may be nullable (a NULL row is no pair: `relation_row_axioms`, the
  visibility obligation, `Dataset.database`); fixture `specs.nullable_relation_spec`, mutation
  `RELATION_NULL_KEY_MATCHES`.
- D72: `subset_axioms` also relates nested filters (`_implies_on_rows`, a cached solver call), and a
  relation's unique value names one row (`relation_row_axioms`); tests in `tests/props/test_properties.py`.
- D73/D85 (#64): import inlines a one-statement boolean SQL helper (D94, #74: or a `setof` scalar one
  where a policy selects from it, `select f() as x` replaced by its select; volatile too, with a note; a short
  call takes the defaults; `lift.fold` folds `const is null` and constant `and`/`or` parts; `p = true` is p) (`lift.inline_functions`; a definer one only
  when its owner bypasses the tables' policies); an opaque part keeps the call (`restore_calls`); the table
  assumes `{"inlined": "function f(t) md5 h"}` and drift reports a changed body.
- D74: import keeps a membership read as the caller (`Env.caller_reads`; definer bodies are aliased
  `mls_definer`) only if the visibility obligation holds against the imported policies alone
  (`relation_visibility_obligations(spec, only=..)`); else that subquery is re-read as opaque (`Env.hidden`).
- D75: `InclusionRule.deferred` compiles `deferrable initially deferred`; proofs leave it out
  (`row_constraints(.., at_commit=)`, `relation_axioms`); the harness checks it per statement with
  `set constraints all immediate`.  `spec/fkcycle.py` refuses an immediate inclusion closing a cycle of
  immediate keys (`check_spec`; with the catalog's keys `check --dsn`/`preflight`); mutation
  `INCLUSION_NOT_DEFERRED`, `tests/templates/test_fkcycle.py`.
- D76: a hop needs only its pair unique (`model.pair_unique`): a membership-table hop (co-members,
  `member_of . team_members(team_id, user_id)`) is encoded as an up-hop (`chain.is_lookup`; `is_up`
  stays the harness's); a chain whose hop visibility closes a cycle (a table twice) is routed
  (`recursion.routed`, after the policy-table check); `exists_join` reads self-joins; fixture
  `specs.comember_spec`.
- D77: `always_on_update <table>: p` (`AlwaysOnUpdate`, `obligations.always_on_update`) is a
  property for every writer, trusted roles included: constraints on both images and the transitions
  imply `p`, no policies or column privileges assumed; test in `tests/props/test_properties.py`.
- D78: a write `column_rule` with `when p` is a per-row column guard (`compile/guard.py`, trigger
  `WHEN (current_user = role)`; `obligations.guard_terms` `T(p(old)) → unchanged`; `Oracle.guards_ok`);
  its memberships read as the caller through `Spec.caller_reads` (routing, visibility, grants);
  fixture `specs.guard_spec`, mutation `GUARD_ANY_ROW`.  #58: the trigger is `0_mls_cg_<name>` so it
  fires before the table's own (`check.guard_order_errors` refuses one that sorts first);
  `tests/templates/test_guard.py`, mutation `GUARD_SORTS_LAST`.
- D79: an inclusion's `on_delete` may be `cascade` (ON UPDATE stays RESTRICT); refused on a table a
  relation, hierarchy or cardinality rule reads; `obligations.cascade_obligations` (in
  `soundness_errors`) proves a cascade deletes only rows the deleter could delete; `check --dsn` and
  `preflight` refuse a clashing delete action on the table's own key (`check.fk_action_errors`);
  import reads cascade keys; fixture `specs.cascade_spec`, mutation `CASCADE_AS_RESTRICT`.
- D81: `on_delete set_null` nulls the (nullable) first column (`SET NULL (c1)`); the induction step's
  third case covers the nulled rows, `_set_null_obligations` prove the checks/transitions allow it
  and the deleter could make that update; fixture `specs.set_null_spec`, mutation `SET_NULL_BOTH`.
- D80: property `changes_only <table> <role>: cols when p` (`obligations.changes_only`) is the upper
  bound of a column guard: the role's update assumptions and `T(p(old))` imply the other columns
  unchanged; test in `tests/props/test_properties.py`.
- D42: row-dependent column visibility is normalization
  (the column is its own table with its own policies); there is no masking construct.
- M4 (the LLM loop and evals): `src/mls/llm/CLAUDE.md`. Tests never call the API (`MLS_LLM_SCRIPT=<json>`
  or `ScriptedClient` replays answers); terse is the default, so tests that script JSON answers pass
  `syntax="json"` / `--syntax json`.
- D84 (#63): a relation may have no key, a set (`Relation.key`/`MemberBody.key` None, `chain.is_set`;
  value a single-column key), encoded with one key `tvl.SET_KEY`; always routed to a no-argument
  `mls_lookup_<R>()`; import reads keyless subqueries over a parent key as sets (`SET_ALIAS` marks the
  helper's base); refused as an inclusion target, hierarchy members, in tenant_isolation and
  invariants; fixture `specs.set_spec`, mutation `SET_HELPER_INVOKER`.
- D93 (#72): adapter `trusted_function` (`identity/trusted_function.py`): context value = a
  zero-argument function `<schema>.<function>` with `md5` (of `prosrc`), compiled `(select s.f())`;
  drift's hardening on it (`drift.identity_functions`, a gone function is a `DriftError`); import
  reads such calls (`cat["identity_functions"]`, the user table from the body's FK); fixture
  `specs.function_spec` (the harness's stand-in, `mls_harness.<name>`), `tests/templates/test_trusted_function.py`.
- D95 (#73): `citext` columns (adopted only) compare with ASCII string constants by `=`/`<>`/`in`;
  the encoder interns those constants lower-cased (`tvl._fold_citext`), the oracle holds values as
  `model.CIText`, the harness draws the constants in three cases (`harness.string_constants`) and
  creates the extension; fixture `specs.citext_spec`, mutation `CITEXT_AS_TEXT`.
- D96 (#76): `Column.default` (adopted only: const, ctx, `fresh`); `obligations.insert_written` (the
  left-out columns' defaults; one with none is unconstrained, and FALSE only in a lower bound) in
  access_terms, net_terms, insert_assumptions and the must_allow antecedent; import `lift.read_default`, drift `drift.live_defaults`, harness
  `default_sql`/`default_value`; fixture `specs.defaults_spec`, `tests/templates/test_defaults.py`.
- D97 (#75): `ContextVar.optional` (a caller may lack it: NULL); `Encoder.ctx_null` (free flag
  `ctx.<n>.null`), `is_null` of a ctx only when optional, `pg_roles` refuses it; import marks
  `trusted_function` values optional and keeps their `IS NULL` (`Env.optional`); diff compares a
  one-sided optional value for callers who have it (`diff.one_sided_optional`); harness draws it unset;
  fixture `specs.optional_spec`, mutation `CTX_IS_NULL_FOLDED`; Lean `Env.ctxUnset`.
- D98 (#83), amended by D106 (#98): per-role obligations and the diff pass the role (`Encoder(role=..)`);
  whether a session has a context value is the spec's `ContextVar.unset_for` / `optional_for`
  (`availability(role)`; `ctx_null` TRUE / free / FALSE, role-less free when any role may lack it, #85),
  never a role's name; the diff pins a one-sided optional flag (`diff.common_ctx_nulls`); Supabase's
  `unstated_availability` makes the checker refuse an undeclared `anon` and import declare `unset for anon`
  (note); harness and scenarios read it; import keeps `IS NULL` of such a value.
- D100 (#89): `ContextVar.enum` (a claim of an enum type); `check.enum_name` answers for it,
  `enum_row_axioms` bounds it to its labels, `identity.base.ctx_type_sql` casts it; import reads
  the cast (optional); fixture `specs.role_claim_spec`, mutation `IN_DROP_LAST`; Lean known gap.
- D101 (#90): a membership's value may be a constant when its key is no column (`check`'s
  `const_value`; `role_grants(@user_role, 'channels.delete')`); import reads Supabase's plpgsql
  `authorize()` (`lift.count_body`, uncorrelated EXISTS in `Lifter._member`); fixture
  `specs.grants_spec`, mutation `MEMBER_CONST_ANY_VALUE`.
- D102 (#91, #92): `catalog.bypass_paths` asks every untrusted role (`_UNTRUSTED`), not only the spec's
  (`roles`/`outside`/`grantees`/`public` per path; `drift._who`); a non-invoker view whose owner is a bound
  app role is kind `delegation`, assumed by import as `{"delegate": "view v as o to r1, r2"}`
  (`DelegateAssumed`, `catalog.delegation_text`), stated in the proof report, a drift note when it differs;
  tests in `tests/templates/test_bypass.py`.
- D103 (#94): a field of an adopted composite column is the column `c.f` with `Column.composite` (its type);
  rendered `sqltext.col` / `sqltext.target`, types from `sql.composite_ddl` (harness, drift's shadow), refused in primary
  keys, inclusions, hierarchies, cardinality groups and column rules (`check.check_field_uses`); import reads
  `(c).f` (`Parser.postfix`); fixture `specs.composite_spec`, mutation `FIELD_OTHER` (a sibling of the same type).
- D107 (#97): a relation may read fields (`recursion.field_relations`), always routed (helper body via
  `SqlCompiler.column`; `plan.soundness_errors` skips routed uses); a `unique` key on fields is a unique expression
  index (`table.field_key_ddl`), read by import (`adopt.index_column`, `unique_indexes`), matched by definition in
  drift (`_own_key_names`); fixture `specs.field_relation_spec` (neutree's shape).
- D104 (#95): import inlines plpgsql helpers of guards and one `return` (`lift.plpgsql_body`); the lifter reads
  `(c) is [not] true` only over a test never UNKNOWN (IS NULL, IS TRUE, or a folded constant); a call whose inlined
  body holds an unreadable part quotes it in its note (`Env.unread_bodies`).
- D99 (#86): on Supabase, import lifts a policy that reads `auth.role()` once per role (`Env.role`;
  `lift.fold`'s `_role_test` makes `auth.role() = 'x'` a constant); test in `tests/templates/test_adopt.py`.
- D86 (#54): an inclusion into a relation with a condition (`restrict deferred` required) compiles to two
  deferred constraint triggers (`compile/fk.py`: `<name>` reads the target row `FOR SHARE`, `<name>_target`
  refuses a demotion), owned by `mls_internal`; never assumed by the proofs; preflight counts existing
  violators; import reads it back (`lift.inclusion_parts`); fixture `specs.filtered_inclusion_spec`,
  mutations `INCLUSION_CONDITION_DROPPED`, `INCLUSION_TARGET_UNCHECKED`, `INCLUSION_NO_LOCK`
  (`tests/templates/test_filtered_inclusion.py`).  The diff's integrity part compares committed data
  (`row_constraints(.., at_commit=True)`), so a deferred inclusion shows.  `mls generate --dsn` runs
  `adopt.database_checks` (the database's own keys and triggers) on every spec the loop builds.
- D88 (#65): array columns `text[]` / `enum[] T` (adopted tables) and the atom `{"has": [col, label]}`,
  terse `'x' = any(col)`; exact encoding (`tvl.ARRAY_HAS`, `ARRAY_HAS_NULL` over the column's integer
  value), scenarios list the tested labels (`Encoder.array_labels`); the harness writes lists cast to
  the column type and reads enum arrays as `text[]`; import reads `= any` / `<> all`, refuses `@>`,
  `<@`, `&&`; fixture `specs.array_spec`, mutation `HAS_NULL_ELEMENT_FALSE`; Lean `Pred.has`.
- D90 (#68): an adapter's `service_roles` (Supabase: `authenticator`, `supabase_auth_admin`) are named
  in specs and keep their rules, but are trusted: `identity.base.bounded_roles` drops them from the
  all-roles upper bounds and least_privilege, the checker refuses upper bounds naming one, the deploy
  never alters them.  Any other app role that can become a BYPASSRLS/superuser role is refused
  (`hardening.escalation_check_ddl`, mutation `ROLE_ESCALATION_UNCHECKED`, `adopt.role_escalation_errors`,
  drift `hardening`); `tests/platform/test_supabase.py` deploys both roles as `postgres`.
- D83 (#61): a cardinality rule has `max` and/or `min` and an optional `where`; `min` is a deferred
  constraint trigger `<name>_min` (at commit, parent row locked; a parent deleted in the transaction
  is exempt), no invariant (refused in `invariant_preserved`), unused by the proofs; fixture
  `specs.min_count_spec`, mutations `CARDINALITY_MIN_OFF_BY_ONE`, `CARDINALITY_WHERE_DROPPED`; the
  harness resets its data in one transaction.
- M3: hierarchies and cardinality limits compile to SECURITY DEFINER helpers owned by `mls_internal`
  (compile/internal.py, hierarchy.py, cardinality.py). The parent-row lock is only testable with
  parallel writers (`tests/templates/test_cardinality.py`); `-m cvc5` cross-checks the org_tree
  example too (integer-quantified obligations need cvc5 without finite-model-find).
- `uv run mls explain|diff|migrate|preflight|drift ...` (M2). `mls explain --terse`, the diff's
  `before`/`after` lines and the transcripts' `spec_terse` use `mls/terse.py` (D44, D50):
  `terse.render` is the whole spec in the terse syntax (sections `mls`, `comment`, `identity`,
  `roles`, `table` blocks, `relation`, `hierarchy`, `opaque` with `$$` SQL, `rules {}`,
  `properties {}`; the grammar is the module docstring and REFERENCE §13). `spec/syntax.py` is
  the parser (`parse`, `parse_data` with a span per JSON path); `load_spec` dispatches on the
  extension (`.mls` terse, else JSON), `mls fmt` converts, every example has a committed `.mls`
  twin that `tests/test_terse.py` checks is the renderer's output, and the round trip
  `parse(render(spec)) == spec` over every example and eval case (plus hypothesis specs in
  `tests/spec/test_syntax.py`) is the evidence; the JSON stays canonical (D15) and the English
  (`english.py`, D33) stays the approval artifact. A one-element `and`/`or` is the one shape
  the round trip cannot keep; a nested same-connective group keeps its parentheses. Errors on
  terse input carry a span (`MlsError.span`, `syntax.Source.locate`; the JSON path stays the
  key): the CLI loads through `spec.load_checked`, later errors go through `spec.locate(path,
  errors)`, and `tests/spec/test_check.py` runs every error fixture through both syntaxes. Migrations are phased; every statement
  kind has a lock mode in `compile/migrate.py:LOCKS` that `tests/templates/test_locks.py` observes
  on every PG version — add the kind and its mode when you add a migration statement.
- `tests/templates/test_migrate.py` is the migration acceptance test: deploy v1 + data, migrate,
  `drift` against v2 must be clean, then the v2 differential test on the migrated database.
- M5 (brownfield): `in` with a constant list is sugar. `check_spec` validates it natively (error
  paths point into the `in`) and returns the spec with it expanded to an `or` of `=`
  (`spec/expand.py`); every consumer must use the returned spec, and nothing downstream of the
  checker ever sees an `In` node. `compile/sql.py` renders that `or` shape as one IN list
  (mutation `IN_DROP_LAST`, fixture `in_spec`), and `pg/explain.py` requires it as an index condition.
  The `session_setting` adapter (D47) reads `current_setting('app.<name>', true)` through
  `nullif(.., '')`; its hardening is drift-only (`pg/catalog.py` collects per role the functions
  that set `app.*` and the `ALTER ROLE .. SET app.*` defaults; `pg/drift.py` reports them for this
  adapter). The harness user context is the membership key (`user_context_name`), not a source.
  Table modes (D45): `Table.mode` is `owned` | `adopted` | `observed`; `Spec.governed()` is what the
  compiler, harness, objects and drift iterate (observed tables are only checked to exist). The
  compiler never creates or forces an adopted table (`compile/hardening.py`) but replaces its whole policy set (D51, `compile/policy.py:replace_policies_ddl`; the harness seeds every adopted table with foreign policies, mutation `REPLACE_KEEPS_FOREIGN`); `drift` shadow-creates
  it from the spec, reports undeclared constraints/triggers/indexes/columns on it as `foreign`
  (non-failing) and the `assume` entries as `assumed` (non-failing; a stale one is a note). The
  assumptions are rendered once (`english.assumption_lines`) for the proof report, explain, diff
  and the script header. `pg/adopt.py` is `mls import` (policies through the lifter; what it
  cannot read an opaque block with its catalog signature; inclusion-shaped FKs as inclusion
  rules; column grants as column rules; readable CHECKs as check rules; the compiler's own
  transition triggers as transition rules, its guard triggers as guards (#57, `lift.guard_parts`);
  hardening state as `assume`; the compiler's
  `mls_rel_*` policies and relation grants recognized, not imported) and `verify_adopted`
  (`check --dsn`). `pg/lift.py` is the lifter (D46): a tokenizer and recursive-descent parser for
  the deparsed text, an `Env` (the spec so far) and a `Lifter` that reads the compiler's shapes
  and the hand-written idioms at the boolean connectives, validating every atom with
  `spec/check.py` before keeping it; `tests/pg/test_lift.py` pins every shape (fast, no Docker),
  `tests/templates/test_lift.py` is the per-template round trip (deploy, import, drift clean,
  `behaviour_diff` empty) on PG 15–18. The harness creates adopted tables itself before the
  script (`Harness.pre_existing_sql`). `tests/brownfield/supabase_schema.sql` is the hand-written
  acceptance fixture. Selectors (D48): `Rule.applies_to` in place of `table`; `check_spec` runs
  `spec/selectors.py:expand_selectors` first (one rule per governed table, id `<id>.<table>`,
  `from`, the selector kept on the expansion for `english.selector_line`), then the checker
  with the original rule paths; nothing downstream sees a selector. `in_schema` is not
  implemented (tables carry no schema). `mls status` (`status.py`) is the per-table overlay:
  `ungoverned` / `refuted` / `opaque` / `unproved` / `proved` from the proof results (global
  properties attributed per obligation through `Obligation.rows`) plus, with `--dsn`, the live
  RLS state and the tables outside the spec; `tests/props/test_status.py` pins the output.
  Lint pack (D49, `props/lint.py`): coverage, contradiction, subsumption, redundancy as
  `mls lint` findings (never verdicts, exit 0), solver questions on the (T, F) encoding
  (`tests/logic/test_tvl.py` keeps the case the two-valued check gets wrong), a positive and
  a negative fixture per lint in `tests/props/test_lint.py`; the LLM loop quotes them as hints
  in proof-driven repair prompts. `role_separation` is a property template (one obligation,
  both roles under the same context values).
- Lean track (D11, D41): `lean/` formalizes the core semantics; details in `lean/CLAUDE.md`. When you
  change `logic/tvl.py`, `props/effective.py`, `pg/model.py`, `props/obligations.py` or the CHECK, FK,
  transition, hierarchy or cardinality templates, change the `lean/MLS/*.lean` transcription and re-prove
  (or record the gap under "Known gaps" in `lean/CLAUDE.md`), and regenerate `lean/MLS/Vectors.lean` (`uv run python -m tests.lean.vectors`).
