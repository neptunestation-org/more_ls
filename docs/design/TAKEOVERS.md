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

Is MLS converging: does a takeover of an unfamiliar project still turn up cases where the tool says
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
  construct the language lacks, an import shape not yet read, a check that refuses.
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
5. **Takeover**: requirements, `mls generate` (record attempts and repair rounds), approval, prove,
   diff, check, preflight, compile, deploy, drift, status.  Record the outcome.
6. **Close the row** with the numbers below and one sentence on what the project taught.
7. **Stop the database.**

## What a row records

| Column | Meaning |
|---|---|
| Project | repository, and the date the takeover ended |
| Cell | platform / identity, size, the patterns it exercises (see [Coverage](#coverage)) |
| Tables, policies | governed tables and today's policies, at load |
| Opaque, first / final | opaque blocks on the first import (before any fix) / after the fixes |
| A, B, C | fixes by class, with their issues |
| Generate | attempts and repair rounds of the run that was approved |
| Properties | properties proved in the approved spec |
| Outcome | deployed, drift, status |

## Log

Rows before slack-clone were backfilled on 2026-11-25 from commits, issues and session notes; their
baselines were not recorded before the fixes, so "—" marks what is not known, and their classes
were assigned after the fact.

| Project | Cell | Tables, policies | Opaque first / final | A | B | C | Generate | Props | Outcome |
|---|---|---|---|---|---|---|---|---|---|
| scarpar (11-23) | Supabase JWT, M, ownership through parents | — | — / — | 1 (#58) | 6 (#56 #57 #59 #60 #61 #62) | 1 (#55) | run 21 | — | approved |
| aural-oss (11-23) | Supabase JWT, M, filtered owner rule | — | — / — | 0 | 1 (#54) | 0 | run 22 | — | approved |
| chatbot-ui (11-23) | Supabase JWT, L, parent-flag sharing | —, 79 | 8 / 0 | 0 | 1 (#63) | 3 (c0469e2) | not run | — | import only |
| basejump (11-23) | Supabase JWT, M, accounts with roles, own schema | —, 14 | 10 / 4 | 0 | 1 (#64) | 0 | not run | — | import only |
| supabase-tenant-rbac (11-24) | Supabase JWT, S, RBAC in text[] claims, own schema | 7, 14 | 14 / — | 1 (#67) | 3 (#65 #66 #68) | 2 (#69 #70) | run 6 | — | deployed, drift none, 7 proved |
| graphile/starter (11-25) | plain PG, function identity, M, own schemas, citext | —, — | — / — | 0 | 5 (#72 #73 #74 #75 #76) | 3 (#71 #77 #78) | run 2, first try | — | deployed, drift none, 6 proved |
| midday (11-25) | Supabase JWT, L, teams, helpers in another schema | 49, 110 | — / 0 | 3 (#81 #83 #84) | 2 (#80 #82) | 1 (#79) | run 1, first try | 221 | deployed, drift none, 49 proved |
| nextbase (11-25) | Supabase JWT, S, `to public` policies, `auth.role()` | 3, 12 | — / — | 1 (#85) | 1 (#86) | 2 (#87 #88) | first try | 43 | deployed, drift none, 3 proved |
| slack-clone (11-25) | Supabase JWT, S, RBAC through a role claim and `authorize()` | 5, 13 | — / 0 | 0 | 2 (#89 #90) | 1 (b3e95f4) | 1 repair round | 34 | deployed, drift none, 5 proved |

What the backfill shows: class B and C fixes fall over the last four rows (8, 6, 4, 3), but those
projects also got smaller.  Class A did not fall steadily: midday had three.  Five of the six class
A fixes concern callers without a full identity (signed-out visitors, `to public` policies, the
anonymous role), which is where the next takeovers should press.  The provisional count stands at
1 (slack-clone).

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
| Supabase JWT | rbac, nextbase, slack-clone | scarpar, aural-oss, basejump | chatbot-ui, midday |
| Trusted function | | graphile/starter | |
| Session settings | | | |
| Database roles | | | |

Patterns not yet exercised by any row: hierarchies, signed-out reads of public content at scale,
views as the API, the session-settings and database-role identities.

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

- **PostgREST with JWT claims in session settings** (a PostgREST starter kit, e.g.
  subzero-cloud/postgrest-starter-kit): fills session settings; `request.jwt.claims` is not
  the `app.*` shape the session-setting identity reads today, so expect a class B finding.
- **An application with per-user database roles**: fills database roles.
- **A Supabase project with folders or nested organizations**: exercises hierarchies.
- **A large Supabase project as the regression check** (rule 3).
