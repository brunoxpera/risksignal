# ADR-009 — Data access via sqlc and pgx/v5

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 7, 17.3; closes TD-02 (part 2) |

## Context

Chapter 3.1 requires "access via pgx and generated, typed SQL queries", and chapter
17.3 lists an "SQL query drift check" as a CI stage. That names the pattern but no
tool.

## Decision

Queries live as SQL files under `/db/queries` and are compiled into typed Go code by
**sqlc**. The driver is **pgx/v5** directly, without `database/sql`.

Generated code is committed. CI regenerates and fails on any diff against the commit.

## Rationale

SQL stays visible and reviewable — important for the queries in chapter 7.1, which
depend on indexes, partial uniqueness and `SKIP LOCKED`. An ORM would obscure
exactly those places.

Typing catches schema divergence at compile time rather than at runtime. Together
with the drift gate this produces the same mechanic as ADR-011: a divergence becomes
a build failure, not a test finding.

pgx/v5 without the `database/sql` layer gives access to `COPY` (ADR-013), batching
and the native PostgreSQL types needed for `JSONB` raw data and `timestamptz`.

## Consequences

- `sqlc.yaml` and the generation step are part of the build and of CI.
- Migrations (ADR-010) are authoritative for the schema; sqlc reads them to derive
  types. Build order: write the migration, then generate.
- The dynamic filters in chapter 10.4 (signal filter with many optional fields)
  cannot be fully generated. For those queries a clearly bounded, parameterised
  builder is permitted — never string concatenation with user input.

## Alternatives rejected

- **GORM / ent** — obscure the persistence details that chapter 7 depends on.
- **sqlx** — does not provide the typing, so drift protection would stay manual.
