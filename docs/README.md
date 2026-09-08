# RiskSignal — project documentation

The authoritative documents are the **functional concept v0.2** and the
**implementation concept v0.2**. Where they conflict, the functional concept prevails
until a documented change has been agreed.

The implementation concept (v0.2) and the functional concept v0.2
(`fachkonzept-v0.2.md`) both live in `docs/concept/`.

## Language

**English is the official project language.** All documentation, code, comments,
commit messages, issues and prompts are written in English. The single exception is
the concept document itself, which is maintained in German.

## Structure

| Path | Contents |
|---|---|
| `docs/concept/` | The implementation concept v0.2 and the functional concept v0.2 (Markdown, German); v0.1 is archive, the change log is history |
| `docs/adr/` | Architecture decision records from ADR-008 onwards (ADR-001 to 007 live in implementation concept ch. 1.2) |
| `docs/plan/` | Iteration plan and work packages |
| `docs/prompts/` | Prompts handed to the implementation orchestrator |

## Status

The implementation concept is consolidated as v0.2 (8 September 2026): the seven
review findings are folded in, and ADR-008 through ADR-015 are carried in full as
Anhang A. v0.1 is the archive; the change log is history rather than a to-do.

## Decisions

| ADR | Title |
|---|---|
| [ADR-008](adr/ADR-008-http-routing-and-go-version.md) | HTTP routing on net/http, Go 1.27 |
| [ADR-009](adr/ADR-009-data-access-sqlc-pgx.md) | Data access via sqlc and pgx/v5 |
| [ADR-010](adr/ADR-010-migrations-goose-with-checksums.md) | Migrations with goose and an own checksum log |
| [ADR-011](adr/ADR-011-openapi-codegen-mandatory.md) | Generated server interfaces from OpenAPI (mandatory) |
| [ADR-012](adr/ADR-012-bulk-matching-inventory-driven.md) | Bulk matching is inventory-driven |
| [ADR-013](adr/ADR-013-bulk-sources-raw-records-and-loading.md) | Bulk file sources: one raw record per file |
| [ADR-014](adr/ADR-014-audit-identity.md) | Audit identity: deactivate, never delete |
| [ADR-015](adr/ADR-015-matching-method-led.md) | Matching is method-led, score derived |

## Plan

- [Iteration plan](plan/iterations.md) — I1a/I1b, I2 (time window), I3 (full import), I4, I5a/I5b, I6
- ~~WP-0.01 — consolidate the concept into v0.2~~ → **done** (`docs/concept/umsetzungskonzept-v0.2.md`)
- [I1a work packages](plan/i1a-work-packages.md) — 13 packages, skeleton and gates
- [Orchestrator kickoff prompt](prompts/orchestrator-kickoff.md) — initialises implementation; treats the I1a packages as customer-side work packages

## Open decisions

| ID | Decision needed | Due |
|---|---|---|
| TD-01 | OIDC provider and claims/role mapping | before I5a |
| TD-03 | Progressive web library and CSS toolchain | I1b/I5b |
| TD-04 | Delivery channel for the private demo | before I4 |
| TD-05 | BACS/NCSC source path and interval | after MVP |
| TD-06 | Ticketing target, mapping, automatic P1/P2 creation | after MVP |
| TD-07 | RPO/RTO for the private demo | before I6 |
| TD-08 | Legal basis and period for personal data in audit records | before I6 |

TD-02 is closed by ADR-008 through ADR-011.
