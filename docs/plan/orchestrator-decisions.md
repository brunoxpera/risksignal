# Orchestrator decision protocol

> English is the project language; this file is part of the project documentation.
> Maintained by the orchestrator. Every tooling/technical choice made outside the
> binding ADRs is recorded here with its rationale and status. Bruno (author) may veto
> any line; a veto becomes the new decision and is recorded here.

**Created:** 2026-09-08 · **Maintained:** by the orchestrator, session `agent:main:risksignal`

---

## 1. Purpose

The kickoff prompt delegates the "open choices" (module path, CI platform, local test
providers, quality toolchain) to the orchestrator as defaults, on the condition that
they are **researched and recorded** rather than picked silently. This file is that
record. Binding decisions (ADR-001..ADR-015) are *not* restated here; they live in
`docs/adr/` and in the concept.

## 2. Toolchain — installed on this machine

| Tool | Version | Install method | Location |
|---|---|---|---|
| Go | 1.27.1 (darwin/amd64) | official tarball, SHA-256 verified | `~/sdk/go1.27` |
| sqlc | 1.31.1 | `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest` | `/usr/local/bin/sqlc` |
| goose | 3.28.0 | `go install github.com/pressly/goose/v3/cmd/goose@latest` | `/usr/local/bin/goose` |
| oapi-codegen | 2.8.0 | `go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest` | `/usr/local/bin/oapi-codegen` |
| go-arch-lint | 1.19.0 | `go install github.com/fe3dback/go-arch-lint@latest` (2026-09-08; resolved to v1.19.0) | `~/go/bin/go-arch-lint` (GOPATH/bin; not on PATH — the Makefile resolves it) |
| golangci-lint | 2.13.2 | `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest` (2026-09-09, DEV-013; resolved to v2.13.2; module path carries `/v2` since v2) | `~/go/bin/golangci-lint` (GOPATH/bin; not on PATH — the Makefile resolves it) |
| gitleaks | 8.30.1 | pre-existing Homebrew install (verified 2026-09-09, DEV-013; CI installs `go install github.com/gitleaks/gitleaks/v8@v8.30.1`) | `/usr/local/bin/gitleaks` |
| go-licenses | 1.6.0 | `go install github.com/google/go-licenses@latest` (2026-09-09, DEV-013; resolved to v1.6.0; no `version` subcommand — pinned via `go install`) | `~/go/bin/go-licenses` (GOPATH/bin; not on PATH — the Makefile resolves it) |
| Docker | 29.6.2 | pre-existing | — |
| Docker Compose | 5.3.1 | pre-existing | — |
| make | 3.81 | pre-existing | — |

**Go toolchain notes**

- The machine had Go 1.15.4 at `/usr/local/go` (system location). It is **left
  untouched**. Go 1.27.1 is installed to `~/sdk/go1.27` and exposed via symlinks
  `/usr/local/bin/go`, `/usr/local/bin/gofmt`, `/usr/local/bin/go1.27`. `go` now
  resolves to 1.27.1 because `/usr/local/bin` precedes `/usr/local/go/bin` on PATH.
- ADR-008 pins the toolchain to **Go 1.27**; the current patch (1.27.1) is used.
  `go.mod`, the containerfile and CI will all carry `1.27` (patch is a build-time
  detail). To remove the override later, delete the three symlinks — the system Go
  1.15.4 is fully recoverable.

## 3. Decisions (defaults accepted by Bruno, researched)

### D-001 — Go module path

- **Choice:** `github.com/xpera/risksignal`
- **Status:** default, pending Bruno confirmation (hard-ish to change after first
  published import, trivial before).
- **Rationale:** matches the company name (lowercase `xpera`), is a conventional
  VCS-style path, and does not depend on the (not yet chosen) CI/hosting provider.

### D-002 — CI platform

- **Choice:** GitHub Actions
- **Status:** default, pending Bruno confirmation. Repo has no remote yet; no lock-in
  is created before the first push.
- **Rationale:** de facto standard, first-class service containers (a short-lived
  PostgreSQL for WP-1a.12), free for private repos at this scale. Alternatives
  (GitLab CI) kept in mind; nothing in the code depends on the choice.

### D-003 — local OIDC test provider (TD-01 default, needed in I1a)

- **Choice:** `github.com/oauth2-proxy/mockoidc` (Go, MIT) for unit/integration tests,
  plus a minimal mock-OIDC sidecar for the Compose environment.
- **Status:** default. Provider-neutral per TD-01; the real provider (I5a) swaps in
  behind the OIDC port without touching the rest.
- **Rationale:** in-process, deterministic, supports discovery/JWKS/authorize/token/
  userinfo and error injection — exactly what the negative OIDC tests (TAT-06) need.
  Keycloak/dex are overkill for a "make the test provider available" gate and add an
  operational dependency not listed in kickoff §5.

### D-004 — mail test server (TD-04 default, needed in I1a)

- **Choice:** Mailpit (`axllent/mailpit`)
- **Status:** default.
- **Rationale:** MailHog is unmaintained; Mailpit is its actively maintained
  successor — single static binary, Docker image, SMTP + REST API + web UI, "accept
  any" auth mode. Fits the "SMTP test server behind a port" default from TD-04.

### D-005 — quality/security toolchain (for WP-1a.12 / WP-1a.13)

All tools below are installed and pinned (exceptions noted); the CI stages
and `make ci-lint` resolve these exact versions, so the pipeline has a
single source of truth for the toolchain. `.golangci.yml`, `.gitleaks.toml`
and `.go-arch-lint.yml` carry the per-tool configuration.

| Concern | Tool | Pinned version |
|---|---|---|
| Lint + static analysis | `golangci-lint` | **v2.13.2** (2026-09-09, DEV-013; v2 standard set + gosec, see `.golangci.yml`) |
| SAST (security) | `gosec` | runs inside golangci-lint v2.13.2 |
| Vulnerability scan (Go) | `govulncheck` | not installed — WP-1a.13 |
| Secret scan | `gitleaks` | **8.30.1** (pre-existing Homebrew, verified 2026-09-09, DEV-013; allowlist in `.gitleaks.toml`) |
| Licence check | `go-licenses` (google) | **v1.6.0** (2026-09-09, DEV-013) |
| SBOM (module) | `cyclonedx-gomod` | not installed — WP-1a.13 |
| SBOM + image scan | `syft` + `grype` | not installed — WP-1a.13 |
| Architecture check | `go-arch-lint` (fe3dback) | **v1.19.0** (2026-09-08, DEV-002); declarative YAML dependency rules in `.go-arch-lint.yml`; the WP-1a.11 / TR-001 gate |

**WP-1a.12 wiring (DEV-013):** the lint stage runs gofmt → `go vet` →
`golangci-lint run` (gosec) → `go-arch-lint check` (WP-1a.11 gate) →
`go-licenses check` → `gitleaks detect`; the test stage runs `go test -race`
against a `postgres:16` service container; the build stage runs `make build`.
GitHub Actions runs the stages as three parallel jobs
(`.github/workflows/ci.yml`, D-002); `make ci-lint` / `make ci-test` /
`make ci-build` reproduce each stage locally.

**Rationale:** standard-of-care, all free/open-source, all deterministic (no paid
service). `gosec`/`govulncheck`/`gitleaks` cover the security rows of TR-013/17.3;
`cyclonedx-gomod` + `syft` cover the SBOM requirement (TR-002/TAT-01). No runtime
dependency is added — these are build/CI-only.

### D-006 — configuration model (WP-1a.02)

- **Choice:** environment variables (prefix `RISKSIGNAL_`) with an optional JSON config file (`encoding/json`, stdlib — no new dependency) and versioned defaults; modes `local`/`demo`/`production`; local auth bypass via `RISKSIGNAL_AUTH_BYPASS_ENABLED` (only valid in `local` mode).
- **Status:** default, pending Bruno confirmation.
- **Rationale:** concept §3.3 fixes the *mechanism* (defaults → file → env) but not the file format or naming. JSON keeps the dependency set narrow (concept §3.1); env vars are the primary override in containerised deployment. Recorded so a later switch to YAML/TOML is an explicit change, not drift.

## 4. Reliance on TD defaults (isolated behind config/ports)

- **TD-01** (OIDC provider) relied on in I1a for the local test provider (D-003).
- **TD-04** (delivery channel) relied on in I1a for the mail test server (D-004).
- Both are isolated: OIDC behind the OIDC port, mail behind the notify port. A later
  real decision does not force a migration.

## 5. Known documentation gap

The **functional concept v0.2** (Fachkonzept) is still absent from the repository.
Traceability to FR-/NFR-IDs is therefore not verifiable from the repo alone; claims
are treated as best-available evidence (kickoff §2a).

## 6. Change log

| Date | Decision | Status |
|---|---|---|
| 2026-09-08 | Installed Go 1.27.1 + sqlc 1.31.1 + goose 3.28.0 + oapi-codegen 2.8.0; recorded D-001..D-005 | Accepted (defaults) |
| 2026-09-09 | DEV-013/WP-1a.12: installed golangci-lint v2.13.2 + go-licenses v1.6.0; gitleaks 8.30.1 (pre-existing Homebrew) verified; `.golangci.yml`, `.gitleaks.toml`, `ci-lint`/`ci-test`/`ci-build` targets and `.github/workflows/ci.yml` landed; D-005 rows pinned | Accepted (defaults) |
| 2026-09-08 | DEV-002/WP-1a.11: installed go-arch-lint v1.19.0; `.go-arch-lint.yml` gate + `lint-arch`/`test-arch` targets landed; D-005 row pinned | Accepted (defaults) |
