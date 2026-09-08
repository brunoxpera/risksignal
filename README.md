# RiskSignal

RiskSignal turns public vulnerability data (NVD, KEV, EPSS) into prioritised,
auditable risk signals for an owned inventory: sources, inventory, matching,
prioritisation, signal workflow, SLA and notifications — one repository, one Go
module.

The authoritative technical design is the implementation concept
(`docs/concept/umsetzungskonzept-v0.2.md`, German); binding technical decisions
are recorded in `docs/adr/` (ADR-001..ADR-015). Work is planned in iterations
and work packages under `docs/plan/`.

## Repository layout

The layout follows implementation concept ch. 3.2:

- `cmd/risksignal-server` — REST API and web (process role: ch. 4.1)
- `cmd/risksignal-worker` — jobs, scheduler, outbox (process role: ch. 4.1)
- `cmd/risksignal` — administrative CLI (process role: ch. 4.1)
- `internal/` — domain, application, adapters and platform packages
- `api/openapi/` — OpenAPI contract
- `db/` — migrations and sqlc queries
- `web/` — templates and assets
- `deploy/` — container and deployment assets

## Getting started

### Prerequisites

- Go 1.27 (pinned by ADR-008 and declared in `go.mod`)
- make

### Build

    make build

Produces `bin/risksignal-server`, `bin/risksignal-worker` and `bin/risksignal`.
Each binary loads and validates its configuration at startup (WP-1a.02):
built-in defaults, an optional JSON config file (`RISKSIGNAL_CONFIG_FILE`)
and `RISKSIGNAL_*` environment variables, with environment variables taking
precedence. `database.url` and `oidc.issuer` are mandatory; the local
authentication bypass (`RISKSIGNAL_AUTH_BYPASS_ENABLED`) is accepted in
`local` mode only (TR-010). On invalid configuration the binary prints the
problem and exits 1; on success it prints a provenance summary (sources, no
secret values) and exits 0. Example:

    RISKSIGNAL_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/risksignal \
    RISKSIGNAL_OIDC_ISSUER=https://auth.local.example/ \
    bin/risksignal-server

### Test

    make test

Runs the architecture-gate negative test (`make test-arch`), then
`go test ./...`. The negative test proves the arch gate rejects a forbidden
import; see `testdata/arch-gate/verify-arch-gate.sh`. To run only that
negative test:

    make test-arch

### Local environment

    make up
    make down

Stubs in WP-1a.01 — they print "not yet implemented — WP-1a.04" and exit 0.
The compose-based local environment lands in WP-1a.03, the migration runner
in WP-1a.04.

### Lint and generate

    make lint      # architecture gate (go-arch-lint check) plus gofmt check plus go vet
    make generate  # run code generators

To run only the architecture gate:

    make lint-arch
