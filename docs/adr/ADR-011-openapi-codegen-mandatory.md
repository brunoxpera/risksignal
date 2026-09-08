# ADR-011 — Generated server interfaces from OpenAPI (mandatory)

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 10, 17.3; TR-003, TAT-03; extends TD-02 |

## Context

Chapter 3.1 listed generated clients and server types as **optional**. TR-003, by
contrast, requires that the OpenAPI contract does not drift from the implementation.
With hand-written handler types the contract test is the only safety net — and it
only checks what it checks. Untested fields drift silently.

## Decision

Code generation becomes **mandatory**. Tool: **oapi-codegen v2**, target `net/http`
(matching ADR-008).

Generated:

- request and response types, parameter structs
- the `ServerInterface` that handlers implement
- route registration
- request validation against the schema
- optionally the Go client, used for E2E tests and the CLI adapter

Not generated: the mapping between generated type and domain object. Generated types
are adapter types and must not appear in `internal/domain`.

## Rationale

A generated server interface turns contract drift into a **compile error** rather
than a test finding. A newly declared endpoint that nobody implements stops the
project from building.

oapi-codegen supports OpenAPI 3.1 including the 3.1 idioms (`type: [T, "null"]`,
enums via `oneOf` + `const`), and its `net/http` target requires Go 1.24 or newer —
satisfied by ADR-008 (Go 1.27).

## Consequences

Three CI gates instead of one:

1. validate the OpenAPI document against the 3.1 specification
2. re-run code generation, diff the result against the commit, fail on divergence
3. contract test against the running server (status codes, problem details, auth,
   pagination)

Gate 2 is the actual gain over v0.1.

Two things move out of prose and into the schema:

- RFC 9457 problem details as a reusable response component (chapter 10.1)
- `Idempotency-Key` and `If-Match` as declared header parameters

The architecture check in TR-001 must add the generated package path to the list of
imports forbidden in `internal/domain`.

## Alternatives rejected

- **Hand-written handler types with contract tests** — the v0.1 status quo; satisfies
  TR-003 only as far as the tests reach.
- **Code-first with a generated OpenAPI document** — contradicts "schema-first" in
  chapter 3.1 and makes the contract a by-product of the implementation.
