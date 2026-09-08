# ADR-008 — HTTP routing on net/http, Go 1.27

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 10.2; closes TD-02 (part 1) |

## Context

Chapter 3.1 requires "Go net/http with a lightweight router" but names no concrete
tool. TD-02 carried that decision with a due date of I1 — which was circular,
because I1 cannot start without it.

The concept likewise fixed no Go version, saying only "a supported stable Go
version".

## Decision

1. Routing on the standard library `net/http` using `http.ServeMux`. No router
   framework.
2. Middleware chaining as a small in-repository building block.
3. The toolchain is pinned to **Go 1.27** (`go.mod`, container image, CI).

## Rationale

Since Go 1.22, `ServeMux` supports method- and pattern-based routing of the form
`GET /api/v1/signals/{id}`. That covers the complete endpoint list in chapter 10.2.
An additional dependency at the centre of every HTTP request would add no
functional value and would conflict with chapter 3's instruction to keep
dependencies deliberately narrow.

Middleware chaining is a few dozen lines and therefore stays entirely under our own
control — which matters for the security requirements in chapter 12.3 (CSRF, CORS,
security headers, correlation ID).

On the Go version: currently supported are 1.27 (released 2026-08-19) and 1.26
(released 2026-02-10); 1.25 went out of support in August 2026. Go 1.26 loses
support when 1.28 ships (expected February 2027), which falls in the middle of
implementation. 1.27 is also a prerequisite for ADR-011 — oapi-codegen requires at
least Go 1.24 for the `net/http` target.

## Consequences

- A middleware building block must be written and tested in I1a.
- No sub-router convenience; endpoint groups are formed by path prefix and explicit
  registration. Uncritical at the size given in chapter 10.2.
- The Go version is part of build reproducibility (TR-002) and is kept identical
  across `go.mod`, containerfile and CI.

## Alternatives rejected

- **chi** — clean and slim, but the gain is limited to sub-routers and prebuilt
  middleware. Not enough to justify a central dependency.
- **gin / echo** — bring their own context and binding models, which compete with
  the generated types from ADR-011 and the port structure in chapter 2.3.
