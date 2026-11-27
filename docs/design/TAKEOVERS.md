# Takeovers of open-source projects

A program of takeovers (GUIDE §3) on open-source Postgres applications, run to find what MLS gets
wrong or cannot do on schemas it was not written for.  Each takeover follows the protocol below and
adds one row to the log; the next project is chosen from the coverage table, not by availability.

## Contents

- [The question](#the-question)
- [Classes of fix](#classes-of-fix)
- [Protocol](#protocol)
- [What a row records](#what-a-row-records)
- [Log](#log)
- [Coverage](#coverage)
- [Choosing the next project](#choosing-the-next-project)
- [Candidates](#candidates)

## The question

Two questions, the first the more important:

1. **Can MLS express the project's policies?**  Written by hand if need be, with the schema as it
   is or after a change a careful designer would accept (a join table for an array of keys, a
   parent column for a path).  A no names the construct the language lacks.
2. **Does the tooling get there by itself?**  Import reads today's policies, the loop writes and
   proves the spec.  A gap here is tooling work, not a limit of the language.

A takeover that stalls on the second still answers the first (protocol step 5).

The second question has a convergence test of its own.  Is MLS converging: does a takeover of an unfamiliar project still turn up cases where the tool says
something false?  A falling count of fixes alone does not answer it.  Projects differ in size,
and every new project brings idioms import has not seen, which produce fixes however sound the core
is.  So fixes are counted by class, projects by size, and the claim we test is about class A only.

**Converged, provisionally,** means: three consecutive takeovers, each in a coverage cell no earlier
takeover filled, with no class A fix.  Any class A fix resets the count.

## Classes of fix

Every issue a takeover files, and every fix made without one, gets exactly one class, recorded in
the issue body (`Class: A`) and in the log.

- **A, wrong answer.** The tool said something false about the database or the spec: a proof that
  does not hold on Postgres, an import that misreads today's policies (so `before.mls` and the diff
  are wrong), enforcement weaker than the spec, a scenario that is not a real state.
- **B, missing.** The tool could not express or read something, and said so: an opaque block, a
  construct the language lacks, an import shape not yet read, a check that refuses.  A B issue says
  which: **B (language)** when MLS cannot state it even by hand (question 1), **B (import)** when
  only the tooling cannot read or write it (question 2).  An issue with parts of both says so per part.
- **C, friction.** Crashes, error messages, wording, CLI ergonomics, drift noise.

When an issue is both, it takes the higher class (A over B over C).

## Protocol

1. **Choose** the project from [Coverage](#coverage) and record in its row which cell it fills and why.
2. **Load** it into a throwaway database (the scratchpad loaders; `supabase/postgres` for Supabase
   projects, plain `postgres` otherwise) with its own migrations, unchanged except where the row says.
3. **Measure before fixing.**  Run both imports and record tables, policies, opaque blocks and
   import notes *before any fix*.  These are the row's baseline; later fixes never change them.
4. **File** every gap as an issue with its class, then fix in the usual way (decision, tests,
   docs).  Re-import after the fixes and record the opaque blocks left.
5. **Express what import could not.**  For every policy still opaque, write it by hand in MLS
   against the imported skeleton (a measurement, not the spec that is deployed), check it, and
   compare it with the original on the loaded data.  Record each as expressible, expressible after
   a schema change (which), or not expressible (the construct missing, filed as B (language)).
6. **Takeover**: requirements, `mls generate` (record attempts and repair rounds), approval, prove,
   diff, check, preflight, compile, deploy, drift, status.  Record the outcome.
7. **Close the row** with the numbers below and one sentence on what the project taught.
8. **Stop the database.**

## What a row records

| Column | Meaning |
|---|---|
| Project | repository, and the date the takeover ended |
| Cell | platform / identity, size, the patterns it exercises (see [Coverage](#coverage)) |
| Tables, policies | governed tables and today's policies, at load |
| Opaque, first / final | opaque blocks on the first import (before any fix) / after the fixes |
| Expressible | question 1: yes; yes after a schema change; partly (what is not); — not established |
| A, B, C | fixes by class, with their issues |
| Generate | attempts and repair rounds of the run that was approved |
| Properties | properties proved in the approved spec |
| Outcome | deployed, drift, status |

## Log

Rows before slack-clone were backfilled on 2026-11-25 from commits, issues and session notes; their
baselines were not recorded before the fixes, so "—" marks what is not known, and their classes
were assigned after the fact.  Their "yes" in Expressible means an approved spec stated the
project's rules; it was not established policy by policy, as step 5 now does.

| Project | Cell | Tables, policies | Opaque first / final | Expressible | A | B | C | Generate | Props | Outcome |
|---|---|---|---|---|---|---|---|---|---|---|
| scarpar (11-23) | Supabase JWT, M, ownership through parents | — | — / — | yes | 1 (#58) | 6 (#56 #57 #59 #60 #61 #62) | 1 (#55) | run 21 | — | approved |
| aural-oss (11-23) | Supabase JWT, M, filtered owner rule | — | — / — | yes | 0 | 1 (#54) | 0 | run 22 | — | approved |
| chatbot-ui (11-23) | Supabase JWT, L, parent-flag sharing | —, 79 | 8 / 0 | yes | 0 | 1 (#63) | 3 (c0469e2) | not run | — | import only |
| basejump (11-23) | Supabase JWT, M, accounts with roles, own schema | —, 14 | 10 / 4 | — | 0 | 1 (#64) | 0 | not run | — | import only |
| supabase-tenant-rbac (11-24) | Supabase JWT, S, RBAC in text[] claims, own schema | 7, 14 | 14 / — | yes | 1 (#67) | 3 (#65 #66 #68) | 2 (#69 #70) | run 6 | — | deployed, drift none, 7 proved |
| graphile/starter (11-25) | plain PG, function identity, M, own schemas, citext | —, — | — / — | yes | 0 | 5 (#72 #73 #74 #75 #76) | 3 (#71 #77 #78) | run 2, first try | — | deployed, drift none, 6 proved |
| midday (11-25) | Supabase JWT, L, teams, helpers in another schema | 49, 110 | — / 0 | yes | 3 (#81 #83 #84) | 2 (#80 #82) | 1 (#79) | run 1, first try | 221 | deployed, drift none, 49 proved |
| nextbase (11-25) | Supabase JWT, S, `to public` policies, `auth.role()` | 3, 12 | — / — | yes | 1 (#85) | 1 (#86) | 2 (#87 #88) | first try | 43 | deployed, drift none, 3 proved |
| slack-clone (11-25) | Supabase JWT, S, RBAC through a role claim and `authorize()` | 5, 13 | — / 0 | yes | 0 | 2 (#89 #90) | 1 (b3e95f4) | 1 repair round | 34 | deployed, drift none, 5 proved |
| postgrest-starter-kit (11-25) | session settings (PostgREST claims, read through helper functions), S, views as the API | 2, 1 | 0 / 0 | yes | 1 (#91) | 1 (#92) | 1 (#93) | first try | 12 | deployed, drift none, 2 proved |
| neutree (11-26) | plain PG with GoTrue's `auth.uid()` (read as the Supabase identity), L, Kubernetes-style composite columns, RBAC through plpgsql definer helpers | 31, 93 | 119 / 147 | partly (direct grants after two schema changes; teams, org units, service accounts not) | 0 | 3 (#94 #95 #97; #100 #101 open) | 1 (#96) | not run | — | import only |

postgrest-starter-kit, the first row chosen by the program (empty identity cell, unexercised
pattern), loaded unchanged as the superuser its Docker setup uses.  Its claims come through helper
functions, so the existing trusted-function identity read them with no new construct.  The wrong
answer was in the bypass paths: the callers are roles the spec never names, because the policies
bind only the view owner.  Today's policy let a signed-in user delete or take over another user's
public todo; the deployed rules refuse both through the real API (checked as `webuser` on
`api.todos`).

neutree was chosen for session settings at size L and turned out not to fill that cell: its
policies read the user through GoTrue's `auth.uid()`, which import takes as the Supabase identity,
and read `request.jwt.claims` directly only inside triggers.  It was loaded unchanged (GoTrue's
own migrations run by its image, then 141 migrations and the seed, as superuser).  The first import
failed at every composite field (`(metadata).workspace`); after #94 it reads them, and after #95 it
reads plpgsql helpers of guards and one return, but every permission check ends in
`user_role_assignments()`, a set-returning UNION over groups, teams, org units and service
accounts, so the policies stay opaque, now in finer parts (147 blocks for 119).  Rewriting the RBAC
in MLS needed relations over composite fields (#97).  A second import after #97 reads the
composite-field keys but still leaves 147 blocks: 145 reach `user_role_assignments()`, whose
`UNION ALL` of four subject paths import does not split, one arm reading org-unit ancestors from a
materialized path and one synthesizing rows from unnested role arrays (#100, open).  The row stays
import-only and does not count toward convergence.

Step 5 on neutree, by hand against the skeleton (`mls check` only: the seed holds one role
assignment and no teams, org units or service accounts, too little to compare on), for
`has_permission`, which 106 of the blocks call.  It reads only global assignments, through four arms:

- **Direct assignments**: expressible after two schema changes.  No hop may read a field (hop columns
  must be NOT NULL and a field never is), so the RBAC tables lose their composites; and the role's
  permissions, an `enum[]`, become a join table `role_permissions(role, permission)`.  Then
  `global_perm = role_assignments(user_id, name) where global and deletion_timestamp is null .
  role_assignments(name, role) . role_permissions(role, permission)`, read as
  `global_perm(@uid, 'endpoint:read')`, checks (keyed by the assignment's name, since a user may hold a
  role twice and a relation's pair must be unique).
- **Teams**: not expressible.  Four hops (team, assignment by subject, role, permission; at most
  three), conditions on intermediate tables (team active, subject kind `Team`, global, not deleted;
  only a base relation has `where`), and "the caller is not a service account", a negated membership.
- **Org units**: the hierarchy is expressible after adding a parent id and a depth column, but roles
  flow down from an ancestor's assignments, so the check is "the assignment's unit is above the
  user's", and `in_group` reaches only downward from the caller's groups, to a column of the row;
  it cannot continue into assignments and permissions.
- **Service accounts**: not expressible.  Rows from an array's elements, a default when the team has
  no row, and a filter that is a negated array test.

The language gaps, in order of reach: a hop over a field; a condition on a hop; a membership that
ends in a set or a hierarchy (continuing a chain); more than three hops; upward hierarchy reach.  An open question for a later takeover on plain PostgREST: the
anonymous role there is `anonymous`, which the Supabase identity does not know is signed out
(it knows `anon`), so the proofs would let it carry a user id.

What the backfill shows: class B and C fixes fall over the last four rows (8, 6, 4, 3), but those
projects also got smaller.  Class A did not fall steadily: midday had three.  Five of the six class
A fixes concern callers without a full identity (signed-out visitors, `to public` policies, the
anonymous role), which is where the next takeovers should press.  The provisional count stands at
0: postgrest-starter-kit (class A, #91) reset it after slack-clone.  Its class A fix is of a new
kind: roles outside the spec.

## Coverage

The axes a project is placed on.  A cell is a combination that matters; the next project should
fill one no row has filled.

- **Platform and identity**: Supabase JWT (`auth.uid()`, claims); plain Postgres with a trusted
  function; session settings (`current_setting(..)`, as PostgREST's `request.jwt.claims`);
  database roles per user (`current_user`).
- **Size**: S (under 10 tables), M (10–30), L (over 30).
- **Patterns**: ownership through parents; tenants and teams; RBAC (tables, arrays, claims);
  sharing by flag or by grant; hierarchies (folders, org trees); signed-out reads; schemas other
  than `public`; enums, arrays, citext; views and SECURITY DEFINER functions as the API.

| Identity | S | M | L |
|---|---|---|---|
| Supabase JWT | rbac, nextbase, slack-clone | scarpar, aural-oss, basejump | chatbot-ui, midday, neutree (plain PG, import only) |
| Trusted function | | graphile/starter | |
| Session settings | postgrest-starter-kit | | |
| Database roles | | | |

Patterns not yet exercised by any row: hierarchies, signed-out reads of public content at scale,
the database-role identity, session settings read directly in policies (not through helpers).
Exercised at import only: composite columns, plpgsql permission helpers (neutree).

## Choosing the next project

1. Prefer an empty identity cell; then an empty size within a filled identity; then patterns no row
   has exercised.
2. Within that, prefer the project that exercises the most unexercised patterns, and one whose
   policies are its own (not generated by a framework MLS already reads).
3. Every third takeover goes back to the most-covered cell (Supabase JWT) with a large project, as a
   regression check: it should need no class A or B fix.
4. Record the choice and the reason in the row before loading.

## Candidates

To vet before choosing: each must have RLS policies in its migrations and load on a stock image.

- **A project whose policies read `current_setting(..)` directly** (newer PostgREST apps read
  `current_setting('request.jwt.claims', true)::json ->> 'sub'`): session settings, M or L; not the
  `app.*` shape the session-setting identity reads, so expect a class B finding.  Vet the policies
  themselves, not the docs: neutree's guide shows this shape, but its policies call `auth.uid()`.
- **An application with per-user database roles**: fills database roles.
- **A Supabase project with folders or nested organizations**: exercises hierarchies.
- **A large Supabase project as the regression check** (rule 3).
