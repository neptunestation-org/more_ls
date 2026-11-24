# MLS semantics (v1)

This document defines what every construct means. The SMT encoding, the concrete evaluator used in
differential tests, and every compiler template must agree with it; `docs/REFERENCE.md` describes
how to write them, and `docs/design/DECISIONS.md` why each choice was made.

## 1. Values and logic

- Column values are integers (`int` or `bigint`: one sort, the type only bounds constants),
  text (compared for equality only in v1), enum labels (text from a fixed list, compared for
  equality only), booleans, timestamps (modeled as integers), arrays of text or enum labels
  (tested only for a constant label, §2), or NULL if the column is nullable.
  Context values are never NULL.
- Predicates evaluate to TRUE, FALSE or UNKNOWN with SQL semantics:
  - comparison with a NULL operand → UNKNOWN; `IS NULL` is two-valued;
  - AND: FALSE dominates, then UNKNOWN; OR: TRUE dominates, then UNKNOWN; NOT swaps TRUE/FALSE.
- SMT encoding: each predicate becomes a pair (T, F) of booleans; UNKNOWN is ¬T ∧ ¬F.
- **Admission rule:** every target admits a row iff the predicate is TRUE (normalized; see §4).

## 2. Atoms (the verified fragment)

| Atom | Meaning | Index-driven when |
|---|---|---|
| `cmp(col, op, ctx|const)` | ordinary comparison | `col` indexed |
| `in(term, [c1, …, cn])` | sugar for `cmp(term, =, c1) ∨ … ∨ cmp(term, =, cn)`, expanded by the checker before encoding; compiled as `term in (c1, …, cn)` | `col` indexed (one `= any` condition) |
| `member(rel, key=ctx, val=col)` | `(ctx, col) ∈ rel` | compiles to `col = any(array(select ...))` |
| `member(R, key=ctx, val=col)`, `R` composed (§3.4) | `∃ t₁…tₙ: (ctx, t₁) ∈ base ∧ T₁(k₁ = t₁, v₁ = t₂) ∧ … ∧ Tₙ(kₙ = tₙ, vₙ = col)` | one nested `= any(array(select ...))` per level, each hop key indexed |
| `member(S, val=col)`, `S` a relation without a key (`T(v) where p`) | `col ∈ S`: some stored `T` row has `v = col` and `T(p(row))` | `col = any((select mls_lookup_S())::t[])`, a definer helper without an argument |
| `now_between(from_col, until_col)` | `from <= now < until`, NULL bound = open | indexed bounds or small row set |
| `in_group(hierarchy, key=ctx, value=col)` | `∃ g: (ctx, g) ∈ members ∧ g = col ∨ g = parent(col) ∨ … ∨ g = parentᵈ(col)` (the row's group is one of the user's groups or lies below one, within depth d) | array InitPlan from a recursive CTE descending from the user's groups |
| `is_null(col)` | two-valued | — |
| `has(col, 'label')`, `col` an array | SQL `'label' = any(col)`: TRUE when an element is the label; UNKNOWN when `col` is NULL, or has a NULL element and none is the label; FALSE otherwise. Encoded exactly: the array's value `v` is an integer read through uninterpreted `arr.has(v, label)` and `arr.has_null(v)`, T = ¬null ∧ has, F = ¬null ∧ ¬has ∧ ¬has_null, so equal arrays agree on every label and every model is an array that exists | — (a GIN index serves `@>`, not `= any`) |
| `opaque(name)` | uninterpreted predicate over declared inputs | never (excluded from perf guarantees) |

A relation is the `(key, value)` projection of one table whose pair is unique there: the pair, or
one of its columns, is a primary key or unique constraint of the table (the owner of a parent row,
`projects(owner_id, id)`, is the second case).  Its facts are the pairs of the stored rows; a
relation with a condition (`where p`, over the table's own columns and constants) has the pairs
of the stored rows for which `p` is TRUE, so they are among the facts of a relation without a
condition over the same table, key and value, and the proofs assume so.

Restrictions checked by the fragment checker: right-hand sides of comparisons are context or
constants; membership keys are context or constants, not columns (no per-row correlated
subqueries in policies), and a key read through an enum column is one of its labels;
negated membership is rejected in policies (anti-join) unless inside an `opaque` block.  A
membership value column may be nullable: a NULL value makes the atom UNKNOWN, so the policy hides
the row.  `in_group` follows the membership rules (key is context, value is a
column of the hierarchy's id type, no negation in policies) and is not allowed in checks and
transitions (it reads other tables).  NULL key or value makes it UNKNOWN; the walk-up stops at a
missing parent row (the FK makes that impossible for stored data) or at a root.

`now()` is the transaction start time and is modeled as a context value `ctx.now`.
Compiled as `(select now())`.

## 3. Rule constructs and compilation targets

| Construct | Logic | Target |
|---|---|---|
| `policy` (role, command, permissive/restrictive, using, check) | QF + UF | `CREATE POLICY` |
| `check` (table, predicate) | QF | `CHECK ((p) IS TRUE)` |
| `inclusion` (table, cols → rel, on_delete) | EPR | composite FK, MATCH SIMPLE, `ON UPDATE RESTRICT`, `ON DELETE RESTRICT`, `CASCADE` or `SET NULL (c1)` |
| `transition` (table, predicate over old/new) | QF over two rows | one `BEFORE UPDATE` row trigger template |
| `column_rule` (role, table, columns, read/write) | propositional | column privileges (`GRANT SELECT (cols)`; no table-level grant to that role) |
| `column_rule` with `when` (write) | old image + context + memberships | BEFORE UPDATE trigger, for the role only: `T(when(old)) → other columns unchanged` |
| `cardinality` (table, group col, parent, max N, min M, where p) | LIA + UF | trigger template: lock parent row `FOR UPDATE`, count, raise; `min` at commit |
| `hierarchy` (group table, parent col, max depth d) | unrolled to depth d | depth column + `CHECK (depth <= d)`, immutable parent (transition), recursive-CTE InitPlan in policies |
| `opaque` (name, inputs, sql) | uninterpreted predicate | raw SQL, wrapped and named |

Column rules are per Postgres role, not per row.  Row-dependent column visibility (a user sees
their own salary, only the titles of others) is modelled by normalization: the column is its
own table, one row per parent row, with its own row policies.  MLS has no masking construct.

### 3.1 Hierarchies

A hierarchy names a table, its single-column primary key `id`, a nullable `parent` column of the
same type, an int NOT NULL `depth` column, a bound `max_depth` (1–16) and a `members` relation
whose value has the id's type.  Meaning of the stored data: `parent` is NULL for roots and a stored
id otherwise (FK); `depth` is 0 for roots and the parent's depth + 1 otherwise (a BEFORE INSERT OR
UPDATE trigger sets it; the app never writes it); `0 ≤ depth ≤ max_depth` (CHECK); `parent` never
changes (implicit transition rule `mls_h_<name>_parent_immutable`, NULL-aware: a NULL parent stays
NULL).  Because the parent is immutable and every stored row's parent existed before it, the
stored rows form a forest of depth ≤ max_depth and a chain of parents from any row reaches a root in
≤ max_depth steps.  The members relation value column gets an FK to the id.  The proof side
unrolls `parent` exactly max_depth times (the `has_parent`/`parent` functions are uninterpreted;
the depth bound is what makes the unrolling exact).

### 3.2 Cardinality limits

`cardinality(table, group, parent, max)` means: for every stored value `g` of `group`, at most
`max` rows of `table` have `group = g`.  Rows with `group` NULL are not counted.  `group` gets an
FK to the parent table's single-column primary key.  Enforcement is a BEFORE INSERT OR UPDATE OF
`group` row trigger: a NULL new group returns; an UPDATE that keeps the group returns (no change
of the count); otherwise it locks the parent row `FOR UPDATE`, counts the rows of the new group
and raises `check_violation` if `count + 1 > max`.  Correct under READ COMMITTED (the count after
the lock sees committed rows of the writers that held the lock before); not under REPEATABLE READ,
where the count uses the transaction's snapshot (stated as an assumption in every report).  The
proof side uses integer functions `cnt@before`, `cnt@after` (SEMANTICS §7).

With `where p`, a row counts when its group is set and `p` is TRUE of it (`p` reads the row's
own columns and constants); the `max` trigger then fires on every update, and an update that keeps
a counted row counted in its group returns.  `min M`: a constraint trigger AFTER DELETE OR UPDATE,
deferred to commit, for a row that counted and no longer counts in its group: if the parent row
still exists, it is locked `FOR UPDATE` and the counted rows of the group must number at least `M`.
A parent row inserted, or never lowered, may have fewer.  So `min` is a transition property of the
transactions that lower a count, not an invariant of the stored rows; the proofs do not use it.

### 3.3 The internal role

Both templates need to read tables as a role the app policies do not filter: the reachability
function must see every group (a user's policy on `groups` would hide the ancestors they are not a
member of), the depth trigger must read the parent row, the counting trigger must see every row of
the group.  The compiler creates one NOLOGIN, NOBYPASSRLS, NOINHERIT role `mls_internal` that owns
the generated helpers (`SECURITY DEFINER`, `SET search_path FROM CURRENT`); for every table a helper
reads it gets a permissive `SELECT ... USING (true)` policy `mls_internal_<table>` (and `FOR ALL`
on cardinality parents, which it locks), plus the matching grants.  Nobody can log in as it, no app
role is a member of it (drift reports both), and the helpers are the only code it runs.  It also
owns the lookup helpers of §3.5.

### 3.4 Composed relations

A composed relation is a base relation followed through up to three hops:
`relation in_task = member_of . projects(team_id, id) . tasks(project_id, id)` (JSON `{"of":
"member_of", "through": [{"table": "projects", "key": "team_id", "value": "id"}, ...]}`).  `(k,
v) ∈ in_task` iff some `t` has `(k, t) ∈ member_of`, a stored `projects` row has `team_id = t`
and `id = p`, and a stored `tasks` row has `project_id = p` and `id = v`.  Requirements, checked
with the JSON path of the offending hop: the base is a declared base relation (not composed);
each hop's `value`, `key` or pair is its table's primary key or unique, its `key` and
`value` NOT NULL, and its `key`'s type that of the previous level's value; at most three hops.
When a hop's value is a key (down to the rows a value names), the hop is a function from value to
key and the ∃ disappears: the
encoding is `hop.T.v(x)` (a row with `v = x` exists) and `hop.T.v.k(x)` (its key), so
`(k, v) ∈ base . T(key, value)` is `hop.T.value(v) ∧ base(k, hop.T.value.key(v))`, unrolled
per hop, quantifier-free with uninterpreted functions (invariant 6).  An obligation that also
reads a stored row of a hop table (any image but `new`) adds `hop.T.v(row.v) ∧ hop.T.v.k(row.v)
= row.k`.  NULL behaves as for any membership: a NULL key or value is UNKNOWN; the hop columns
are NOT NULL.

A hop whose value is not a key goes up a foreign key (its key is one: a project's organization) or
through a membership table (only the pair is a key: the users who share a team,
`member_of . team_members(team_id, user_id)`): a value may come from many rows, so there is no
function back and the ∃ would stay.  The chain
up to the last such hop is instead its own uninterpreted relation `up.<chain>` (named after its
definition, so identical chains share it), and every stored row `x` of that hop's table read by an
obligation (any image but `new`) adds `∀k: prefix(k, x.key) → up(k, x.value)`, where `prefix` is
the chain before the hop.  That is one direction of the definition: the encoding allows a pair in
the chain that no row produces, so it over-approximates the relation.  Proofs stay sound (they hold
for every relation the axioms allow, the real one among them) and in EPR (`k` is only ever an
argument of a relation); a property that reaches the same access by another path than the rules
may be refuted with such a pair in its scenario.  Where an obligation compares two copies of the
base relation (`monotone_in`: fewer facts, more facts, the hop tables the same), the chain is a
symbol per copy, ordered as the copies are: `∀k,v: up_small(k, v) → up_big(k, v)`.

A composed relation is a policy atom (and may appear in goals, `must_allow` and `tenant_isolation`).
It is refused, with the alternative, in an invariant (a write to a hop table changes it, which the
induction step does not model), as the relation of an inclusion rule (an FK names one table), as a
hierarchy's members relation, in an opaque block's relations and in `monotone_in` (each is about one
table's facts). Compilation nests one subquery per level: `task_id = any(array(select id from tasks
where project_id = any(array(select id from projects where team_id = any(array(select team_id from
team_members where user_id = (select auth.uid())))))))`. Every hop table is read as the app role, so
each hop gets the implicit relation policy: a permissive SELECT policy `mls_rel_<R>_h<i>_<role>_<n>`
whose `using` is the hop key's membership in the previous level (`<R>` the shortest composed
relation through that hop, so two relations sharing a prefix share the policy), a column grant on
`(key, value)`, and the relation-visibility obligation per level (a restrictive policy on a hop
table that could hide a reached row fails it). The hop key is indexed on an owned table and required
as an index condition by the EXPLAIN check.

### 3.5 Lookups through a helper

A membership's subquery runs as the app role, under the SELECT policies of the relation's tables
(the implicit relation policies among them).  When those policies' lookups lead back to the table
the membership's policy is on, for the same role, Postgres expands that table's policies inside
themselves and refuses every statement that reads it ("infinite recursion detected in policy";
the rule is measured, FINDINGS).  The compiler compiles exactly those lookups to a call of
`mls_lookup_<R>(key)`, a stable `SECURITY DEFINER` function owned by `mls_internal` whose body is
the subquery the policy would have had (the base relation's rows for the key where its condition is
TRUE, then one level per hop), read through `mls_internal_<table>`:
`v = any((select mls_lookup_R(<k>))::<type>[])`, an uncorrelated InitPlan.  Which lookups: those
keyed by a constant (their visibility policy, `key = <constant>`, would grant every row with that
key to whoever asks: a shopper checking that a product is active could list the active products
of every shop); those whose relation reads the policy's own table; then, in order of policy table and relation name, each
lookup that still closes a cycle once the earlier ones go through a helper, until none does (a lookup through a helper is no
step of the expansion).  A helper means the same for every role, so the choice is per policy table
and relation, not per role.

The meaning is unchanged: the atom is `(k, v) ∈ R` over the stored rows, as the encoding already
reads it (§7).  A plain subquery equals that only when the role sees every row it reads, which
the relation-visibility obligation proves; a helper reads every row, so its lookup has no such
obligation, no implicit relation policy and no column grant.

## 4. NULL normalization (verified on PG 16)

- RLS: UNKNOWN denies. CHECK: UNKNOWN passes. Therefore every CHECK is emitted as
  `CHECK ((p) IS TRUE)` and every trigger test as `IF NOT ((p) IS TRUE)`.
- FK uses MATCH SIMPLE (any NULL in the referencing columns passes). The inclusion predicate is
  `is_null(c1) ∨ ... ∨ member(rel, c1, c2)` over the nullable columns.
- A deferred inclusion's FK is `DEFERRABLE INITIALLY DEFERRED`: its predicate holds on every
  committed state, not while a statement inside the transaction runs, so no obligation assumes
  it (the stored-row constraints and the relation axioms leave it out).  Its `RESTRICT` side is
  immediate, as for any inclusion.  An inclusion that closes a cycle of FKs checked after each
  statement is refused (two inserts would fail in either order).
- An inclusion into a relation with a condition is no FK but two deferred constraint triggers
  (`restrict` and `deferred` only): at commit, a row with both columns set has a row of the
  relation's table holding the pair with `T(p)`, read `FOR SHARE`; and a row of that table that
  held a referenced pair with `T(p)` and no longer does (deleted, pair changed, `p` FALSE or
  UNKNOWN) is refused.  Its predicate is the same `is_null(c1) ∨ ... ∨ member(rel, c1, c2)`, with
  the relation's facts the rows where `p` is TRUE; it holds on committed states, so, like any
  deferred inclusion, no obligation assumes it, and no invariant may name it.
- An `on_delete cascade` inclusion's FK deletes the referring rows in the statement that deletes
  the referenced row, as the table owner, past their policies.  For an invariant the rows left
  are the ones that did not refer to it, the same guard as `RESTRICT` gives.  Nothing else may read
  the rows it deletes (no relation, hierarchy or cardinality rule on that table), and the
  compiler proves, per role that can delete the referenced row, that its delete policies on the
  referring table pass every referring row: a cascade deletes nothing a direct delete could not.
  Updating a referenced pair stays `RESTRICT`.
- An `on_delete set_null` inclusion's FK (`SET NULL (c1)`) updates each referring row to
  `c1 = NULL`, everything else unchanged, as the table owner: no policy or column guard, but the
  CHECKs and transition triggers run.  The induction step adds the nulled rows as a third case
  (`I(row) ∧ refers(row, deleted) ∧ row' = row[c1 := NULL] → I(row')`), the compiler proves the
  checks and transitions allow `row'` (else the delete fails), and, per role that can delete the
  referenced row, that the role's own update of `row` to `row'` would be admitted.
- Other targets differ (e.g. Snowflake defaults FKs to MATCH FULL); out of scope for v1.

## 5. Policy combination (Postgres semantics)

For a table, role and command:
`effective = (OR of permissive) AND (AND of restrictive)`; no permissive policy → deny.
`WITH CHECK` defaults to `USING` for `ALL` and `UPDATE` policies.

**UPDATE** (verified by differential test on PG 16, 1,280 statements):
- a row is targeted iff UPDATE-USING(old) and, when the statement reads columns (any WHERE or
  RETURNING), SELECT-USING(old). Untargeted rows are silently skipped (0 rows, no error);
- the statement errors unless UPDATE-CHECK(new) and, when it reads columns, SELECT-USING(new),
  and all CHECKs, FKs and transitions hold. So an update that would hide the row from its
  author (e.g. raising `level` above clearance) is an error.
- The differential tests check this on every supported Postgres version.

**INSERT**: errors unless INSERT-CHECK(new) and constraints hold.
**DELETE**: rows targeted by DELETE-USING (and SELECT-USING when reading columns).

## 6. Identity adapters

An adapter maps context names to SQL expressions and declares its trust assumption.
- `supabase`: `uid → (select auth.uid())`, claims → `(select auth.jwt() ->> 'claim')`.
  Assumption: claims are set only by the API layer after JWT verification.
- `pg_roles`: `current_user → (select current_user::text)`; memberships are ordinary relations
  keyed by the role name. No external assumption: Postgres authenticated the session.
- `session_setting`: `name → (select nullif(current_setting('app.name', true), '')::type)`.
  A missing or empty setting is NULL, so every comparison with it is UNKNOWN and the row is
  denied. Assumption: clients cannot execute `SET` on `app.*`; a trusted path (pooler,
  `SET LOCAL` in a `SECURITY DEFINER` entry point, the application's connection layer) sets it.
- `trusted_function`: `name → (select schema.function())`, a function without arguments.  A NULL
  result denies as a missing setting does.  Assumption: the function returns the current user's
  value, established by a trusted path no untrusted client can change; the spec pins its body
  (md5), and drift checks it.

## 7. Proof obligations

All are "assumptions ∧ ¬goal is UNSAT"; SAT yields a counterexample rendered as a scenario.

- **Template properties**, e.g. isolation: `effective_select(r) → member(memberships, uid, r.tenant)`.
  An update's assumptions include the column privileges: every column the role may not write
  keeps its value (Postgres refuses the statement otherwise), as in `must_allow` below.  They
  include the role's column guards too: `T(when(old)) → ∧ (new.c = old.c, NULL-safe)` over the
  columns outside the guard's list.  The antecedent is the condition's truth, not the
  predicate itself: an UNKNOWN condition limits nothing, as the trigger's `(when) is true`.  The
  guard reads memberships as the caller, so the relation-visibility obligation covers it as it
  does a policy.  Trusted roles are not guarded, so `always_on_update` does not assume it.
- **must_allow (the lower bound):** `constraints(every image) ∧ when → admitted`, where
  `admitted` is the command's access layers — the effective policies and, for an update, the
  transition rules and the column privileges.  For an insert, a role whose insert privilege does
  not cover every column admits nothing: an unlisted column takes its default, which the model
  does not know, so not every row meeting `when` can be written.  The written image is assumed *valid* (it satisfies
  the table's CHECKs and FKs), so `when` states what the role can do, not the integrity rules; the
  net effect the behaviour diff compares includes the constraints, the lower bound does not.  For
  update `when` ranges over `old`/`new`.  A second, *witness* obligation asks that
  `constraints ∧ when` be satisfiable; its model is reported as an example, and a condition no
  valid row meets refutes the property (it would require nothing) — an over-restrictive CHECK is
  caught here, not by the main obligation.
- **Invariant preservation (induction):** for every compiled transition τ (INSERT/UPDATE/DELETE on
  every table the invariant mentions, including referenced tables):
  `I(state) ∧ guards(τ) → I(τ(state))`. Referenced-table deletes are modeled with two copies of
  the relation (`small(x,y) ⇔ big(x,y) ∧ ¬(x=u ∧ y=t)`) plus the FK RESTRICT guard (for a
  cascade inclusion the same guard: the rows that referred to the pair are gone).
- **Every writer's update (`always_on_update`):** `constraints(old) ∧ constraints(new) ∧
  transitions(old, new) → p(old, new)`, one step, with no policy and no column privilege among
  the assumptions: the trusted roles bypass both, and the CHECKs, foreign keys and transition
  triggers bind them too.  It holds for every writer as long as the triggers fire, which the
  hardening keeps (no app role may set `session_replication_role`).
- **One role's edits change only some columns (`changes_only`):** `update_assumptions(role) ∧
  T(p(old)) → unchanged_except(columns)(old, new)`, one step; the update assumptions hold the
  policies, the constraints on both rows, the transitions, the column privileges and the column
  guards (`T(g(old)) → unchanged_except(g.columns)`), so a guard with the same condition and
  columns proves it.  NULL-safe equality per column; a hierarchy's depth counts as listed.
- **Access diff (v1 → v2):** for each table × command × role, check SAT of `v2 ∧ ¬v1` (new grants)
  and `v1 ∧ ¬v2` (new denials) over shared relation symbols; each model is a scenario.  Two base
  relations of the two versions over the same table, key and value are the same pairs when their
  conditions are equal, whatever their names, and one with a condition lies within one without.
- **Cardinality:** counts are integer functions `cnt(g)`; insert into g: `cnt'(g) = cnt(g)+1`, guarded
  by `cnt(g)+1 <= N`; prove `cnt(g) <= N` is preserved.
- **Hierarchy:** `in_group(h, k, v)` is encoded as `∨_{i=0..d} chain_i(v) ∧ member(members, k, parentⁱ(v))`
  with `chain_i(v)` = the first i ancestors exist (`has_parent`), over uninterpreted `parent` /
  `has_parent` functions; the depth bound d is the declared `max_depth`.  Two versions of a spec
  share these functions when the tree (table, columns, members relation) is the same, so a
  changed `max_depth` diffs exactly; a changed tree is a different function (tagged `@new`).
- **Composed relations:** the hop functions `hop.T.v`, `hop.T.v.k` are named by the hop, so
  two versions of a spec (and two relations sharing a hop) share them; the stored-row axioms of
  §3.4 tie them to every stored row an obligation reads.
- **Relation row axioms:** a stored row of a base relation's table is in the relation.  For
  every row an obligation reads of the table of a relation it uses (any image but `new`, which is
  not stored yet when the policies read the table), the encoding asserts `rel(row.key,
  row.value)`; for a relation with a condition `p`, `rel(row.key, row.value) ⇔ T(p(row))`, exact
  because the table holds each pair at most once.  When the key or the value column is nullable
  the fact also needs both to be set: `rel(row.key, row.value) ⇔ ¬null(key) ∧ ¬null(value) [∧
  T(p(row))]` (a row with NULL in either is no pair; the subquery `key = k` never reads one, and a
  NULL value matches nothing), and the relation-visibility obligation reads only the rows whose
  key is set.  When the value (or the key) is a single-column key of the table, the row is the
  only one with it, so every pair with that value is this row's: `∀k: rel(k, row.value) → k =
  row.key ∧ <the fact's conditions>` (a courier row whose `user_id` is NULL is nobody's).
  Without these a property over the relation table itself (`team_id in team_members(@uid)` on
  `team_members`) is refuted by a row the relation does not contain, a state no database can be
  in.  A relation without a key (a set, `T(v) where p`, `v` a single-column key of `T`) is encoded
  as a relation whose every fact has one fixed key `κ`: `col ∈ S` is `S(κ, col)`, the row axiom
  `S(κ, row.v) ⇔ ¬null(v) ∧ T(p(row))`, and a relation composed from it follows its hops from
  `κ` as from any key.  A set is never read as the caller: its lookup always goes through a
  helper (a visibility policy would grant every row the condition keeps), so it has no
  visibility obligation in a compiled spec; an import reading one from a hand-written subquery
  checks that the caller sees every row the condition keeps, as for any relation.
- **Subset axioms:** two base relations over the same table, key and value, where every row
  that meets A's condition meets B's (B has none, or the solver proves `T(a(row)) → T(b(row))`
  under the table's row constraints): `∀x,y: A(x,y) → B(x,y)`.  The owners among a shop's admins,
  `role = 'owner'` within `role = 'owner' or role = 'admin'`.
- **citext constants:** a string constant compared with a `citext` column is encoded as its
  lower-case value (the checker admits only ASCII constants, whose case Postgres and the encoder
  fold alike), so two constants equal up to case are one value there.
- **Enum domain axioms:** an enum column holds one of its type's labels (or NULL when it is
  nullable): Postgres refuses any other value.  For every row an obligation reads, every enum
  column of its table is asserted equal to one of the labels, interned as distinct constants like
  any text constant.  When two versions of a spec are compared, the domain is the union of their
  labels, and a column that one version does not declare enum is not constrained.
- **role_separation:** `constraints ∧ effective_a ∧ effective_b` is UNSAT over the command's
  images (for update: `using` on `old`, `check` on `new`, plus the transition constraints), with one
  set of context values for both roles; a model is a row both roles may touch.
- **Opaque blocks:** uninterpreted predicates (a block is a function of its declared inputs). A
  PROVED obligation is conditional on a block when its proof needs that: re-encoded with every
  occurrence of the block an independent, unconstrained (T, F) pair, it is no longer UNSAT.
  Freeing over-approximates whatever the block's SQL does, so a proof that survives holds for
  every block and is not conditional on it; only the blocks occurring in the obligation's own
  terms are tried (the block's `¬(T ∧ F)` axiom is not a use). A property that holds only by
  constraining an opaque block is REFUTED.

Policy-set hygiene asks the solver the same kind of question but is never a verdict: a
contradiction is `constraints ∧ T(p)` UNSAT, a subsumption `constraints ∧ T(p2) → T(p1)` valid,
a redundancy `constraints → (T(eff) ↔ T(eff without p))` valid, all on the (T, F) encoding; the
two-valued `p2 ∧ ¬p1` UNSAT is wrong where `p1` is UNKNOWN on a row `p2` admits.

## 8. Explicit assumptions in every proof report

Identity adapter assumption; trusted roles (owner, superuser, the internal role `mls_internal`
that owns the SECURITY DEFINER helpers, and the platform's service roles, which can act as a
trusted role: their rules are deployed and their lower bounds proved, but no upper bound speaks
for them) after hardening; the `assume` entries of adopted tables
(an app-role owner, unforced row-level security, an app role with BYPASSRLS, each trusted),
and the lists of adopted and observed tables; isolation level for non-engine-enforced
constructs (cardinality relies on the parent-row lock under READ COMMITTED); opaque blocks used,
each with its declared signature and SQL, and the number of proofs conditional on them; Postgres
version range validated by the differential tests.
