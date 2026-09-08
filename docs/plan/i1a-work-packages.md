# I1a — work packages: skeleton & gates

**Goal:** every quality and security gate is in place before the first domain logic
exists. I1a deliberately delivers **no** domain functionality.

**Overall exit criterion:** `docker compose up` brings the environment up,
`/health/ready` is green, CI aborts on a forbidden import, an empty reference database
migrates cleanly, and a retroactively altered migration prevents startup.

Estimates are deliberately left out — they belong in effort planning, not in the
package definition.

---

## WP-1a.01 — Repository skeleton and Go module

**Scope:** create the directory structure per ch. 3.2. `go.mod` on Go 1.27. Three
`main` packages under `/cmd` (`risksignal-server`, `risksignal-worker`, `risksignal`)
that start and shut down cleanly. `Makefile` or `Taskfile` with targets `build`,
`test`, `lint`, `generate`, `migrate`, `up`, `down`. Licence file, `.gitignore`,
`README` with a getting-started section.

**Depends on:** nothing.

**Exit:** `make build` produces three artefacts; all three start and exit with code 0.

**Relates to:** ch. 3.2, 4.1; TR-002, TAT-01.

---

## WP-1a.02 — Configuration and startup validation

**Scope:** versioned defaults, override by environment variable, optional mounted
configuration file. Validation at startup: mandatory values, URLs, durations, mutually
exclusive modes. Secrets injected at runtime only, never in diagnostic output. The
startup log reports security-relevant values with provenance but without content.
**Negative startup test:** production or online-demo mode refuses to start when the
local authentication bypass is enabled.

**Depends on:** WP-1a.01.

**Exit:** missing mandatory values prevent startup with a clear message; the bypass
lock is demonstrably effective.

**Relates to:** ch. 3.3, 12.1; TR-010.

---

## WP-1a.03 — Compose environment

**Scope:** PostgreSQL, local OIDC test provider, mail test server. Only loopback ports
published. Persistent volumes optionally retained or explicitly recreated. Server and
worker as separate services, startable together.

**Depends on:** WP-1a.01.

**Exit:** `make up` brings the environment up; the database is reachable from server
and worker; no ports exposed beyond loopback.

**Relates to:** ch. 4.2.

---

## WP-1a.04 — Migration runner with checksum log

**Scope:** goose embedded as a library, migrations via `embed.FS`. Execution through
`risksignal maintenance migrate` with a dry run. Advisory lock so only one instance
migrates. Table `schema_migration_log` with version, file hash, timestamp and duration.
**Before every run**, the hashes of already-applied migrations are verified against the
embedded files; divergence aborts.

**Depends on:** WP-1a.01, WP-1a.02, WP-1a.03.

**Exit:** an empty database migrates cleanly; a second run is a no-op; concurrent runs
block each other correctly; **an altered applied migration prevents startup** (negative
test).

**Relates to:** ch. 4.4, 7.4; ADR-010; TR-014, TR-018, TAT-10, TAT-14.

---

## WP-1a.05 — Data access: pgx pool and sqlc scaffolding

**Scope:** pgx/v5 pool with timeouts, connection limits and clean shutdown.
`sqlc.yaml` and one generated trivial query to anchor the toolchain. A transaction
helper that enforces the principle from ch. 5.1: one domain command, one transaction.

**Depends on:** WP-1a.04.

**Exit:** `make generate` produces code; an integration test against a short-lived real
PostgreSQL instance passes.

**Relates to:** ch. 3.1, 5.1, 7.3; ADR-009.

---

## WP-1a.06 — HTTP scaffolding and middleware chain

**Scope:** `http.ServeMux` with an own middleware chain. Includes: correlation ID
(generate or adopt), structured access log, panic handling with a neutral external
message, security headers, restrictive content security policy, clickjacking
protection, CORS disabled by default, input limits on body size. Clean shutdown with a
grace period.

**Depends on:** WP-1a.01, WP-1a.02.

**Exit:** header test passes; an unexpected error returns a neutral message with a
correlation ID, technical detail only in the log.

**Relates to:** ch. 5.2, 12.3, 16.1; TR-013.

---

## WP-1a.07 — Health, readiness and version

**Scope:** `GET /health/live` checks only that the process responds.
`GET /health/ready` checks the database, completed migrations and mandatory
configuration. `GET /version` reports commit and version metadata. External sources are
explicitly **not** a liveness criterion.

**Depends on:** WP-1a.05, WP-1a.06.

**Exit:** with the database stopped, readiness is red and liveness green; `/version`
shows the build values.

**Relates to:** ch. 10.2, 16.3; TR-002.

---

## WP-1a.08 — Structured logging

**Scope:** JSON in online environments, human-readable locally. Uniform fields
`timestamp`, `level`, `service`, `version`, `environment`, `correlation_id`. A
redaction component for tokens, secrets and free text. Security events as their own
category. Automated redaction test.

**Depends on:** WP-1a.06.

**Exit:** redaction test passes; no token and no complete payload appears in the log.

**Relates to:** ch. 16.1; TR-013.

---

## WP-1a.09 — CLI scaffolding

**Scope:** consistent subcommand structure per ch. 11.3, initially populated with
`maintenance migrate` and `diagnose config|connectivity|health`. `--output json`
produces stable machine-readable structures. Defined exit codes for success,
validation, authentication, authorisation, conflict and infrastructure failure.
Non-interactive commands require `--yes` or complete parameters and read no hidden
defaults from a terminal dialogue.

**Depends on:** WP-1a.02, WP-1a.04.

**Exit:** exit codes demonstrated per failure class; `--output json` is schema-stable.

**Relates to:** ch. 11.3.

---

## WP-1a.10 — Worker scaffolding

**Scope:** scheduler loop without job types, heartbeat, clean shutdown with a grace
period, worker health reporting heartbeat and last successful run. The clock port from
ch. 7.2 is introduced here so that later SLA and retention tests need no real waiting.

**Depends on:** WP-1a.05, WP-1a.07.

**Exit:** the worker starts, reports a heartbeat and shuts down cleanly; the clock port
is injectable in tests.

**Relates to:** ch. 4.1, 7.2, 16.3; TR-009.

---

## WP-1a.11 — Architecture check as a CI gate

**Scope:** automated verification of the dependency rules: `internal/domain` must not
import HTTP, database, OIDC or UI adapters; domain modules import no adapters; the path
of the generated API code is likewise on the forbidden list. The rule lives as
configuration in the repository, not as a comment.

**Depends on:** WP-1a.01.

**Exit:** a deliberately introduced forbidden import makes CI abort.

**Relates to:** ch. 2.3, 3.2; TR-001, TAT-02.

---

## WP-1a.12 — CI pipeline stages 1–2

**Scope:** formatting, `go vet`, static analysis, licence check, secret scan, unit
tests, race detection, build. A short-lived real PostgreSQL instance for integration
tests. Deterministic and parallel.

**Depends on:** WP-1a.05, WP-1a.11.

**Exit:** the pipeline is green on the main branch and blocks on a violation at every
stage.

**Relates to:** ch. 17.1, 17.3.

---

## WP-1a.13 — Reproducible build, containers and SBOM

**Scope:** containerfiles for server and worker, a platform-appropriate CLI binary.
Build carries commit and version metadata. SBOM generation, dependency and container
vulnerability scanning. Signing or provenance groundwork for release artefacts.

**Depends on:** WP-1a.12.

**Exit:** a clean build environment produces all artefacts with version and SBOM
(TAT-01); scans run and report.

**Relates to:** ch. 4.4, 17.3, 18.2; TR-002, TAT-01.

---

## Explicitly not in I1a

- any domain logic: sources, matching, prioritisation, signals, SLA
- the OpenAPI document and code generation (those are work packages of I1b)
- OIDC integration beyond the mere availability of the test provider
- the web interface

## Suggested order

WP-1a.01 → 02 → 03 → 04 → 05, then 06 / 09 / 11 in parallel, then 07 → 08 → 10,
finally 12 → 13.

WP-1a.11 (architecture check) should land as early as possible — it is the gate that
disciplines the rest of the implementation.
