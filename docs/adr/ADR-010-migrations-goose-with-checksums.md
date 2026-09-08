# ADR-010 — Migrations with goose and an own checksum log

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 4.4, 7.4; TR-014, TAT-10; closes TD-02 (part 3) |

## Context

Chapter 7.4 requires numbered, immutable, forward-only SQL migrations. Chapter 4.4
additionally requires that migrations run once under an exclusive lock, before
application start, and are "recorded with a checksum".

## Decision

1. **goose** as the migration tool, embedded as a library in the binaries.
2. Migrations are plain SQL under `/db/migrations`, embedded via `embed.FS`.
3. Execution only through `risksignal maintenance migrate`, with a mandatory dry run
   as required by chapter 11.3.
4. **An own checksum log** in a table `schema_migration_log`: per applied migration
   the version, a hash of the file content, timestamp and duration. Before every
   run, the hashes of already-applied migrations are verified against the files
   embedded in the binary; any divergence aborts.

## Rationale

goose matches the required model: numbered SQL files, forward-only, PostgreSQL
advisory lock, embeddable as a library. The migration therefore ships inside the
same immutable artefact as the application (TR-002) and no second tool enters the
deployment.

Point 4 is our own code because no widely used Go migration tool provides this in
the form chapter 4.4 intends. The effort is small and the benefit concrete: a
retroactively altered, already-applied migration is detected instead of silently
diverging. That is the technical counterpart of "immutable" in chapter 7.4.

## Consequences

- A dedicated I1a work package for the checksum log, including a negative test
  (an altered migration must prevent startup).
- `schema_migration_log` is itself part of the schema and is created by the first
  migration.
- Expand-migrate-contract (chapter 7.4) remains manual across several numbered
  steps — deliberately, so destructive steps are approved individually.

## Alternatives rejected

- **golang-migrate** — functionally close, but library embedding and error semantics
  are less straightforward.
- **Atlas** — powerful, but its declarative model (target schema, generated
  transition) conflicts with "numbered, immutable migration" and with a manually
  driven expand-migrate-contract.
