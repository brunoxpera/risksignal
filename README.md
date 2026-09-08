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
problem and exits 1 (the CLI classifies it as validation and exits 2, see
"CLI commands and exit codes"); on success it prints a provenance summary
(sources, no secret values) and exits 0. `risksignal-server` then keeps
running and serves HTTP on `http.addr` through the WP-1a.06 middleware
chain (ADR-008), shutting down cleanly on SIGINT/SIGTERM. Example:

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

Brings up the Compose environment — PostgreSQL, a mock OIDC test provider and
Mailpit — with loopback-only port bindings. `make down` tears it down, and
`make verify-connectivity` proves the database is reachable from the service
network (WP-1a.03).

With the environment up, `make migrate` applies pending schema migrations
against the compose database through the checksum-guarded migration runner
(`risksignal maintenance migrate`, WP-1a.04, ADR-010). A dry run only
verifies the checksums of the applied migrations and reports what would
change, without touching the database:

    RISKSIGNAL_DATABASE_URL='postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable' \
    RISKSIGNAL_OIDC_ISSUER='http://127.0.0.1:9000/oidc' \
    bin/risksignal maintenance migrate --dry-run

### Lint and generate

    make lint      # architecture gate (go-arch-lint check) plus gofmt check plus go vet
    make generate  # run code generators

To run only the architecture gate:

    make lint-arch

## CLI commands and exit codes

`bin/risksignal` is the administrative CLI (command model per concept
ch. 11.3, WP-1a.09): `risksignal <command> <subcommand>`.

- `maintenance migrate [--dry-run]` — apply pending schema migrations
  through the checksum-guarded runner (WP-1a.04, ADR-010); `--dry-run`
  verifies checksums and reports what would change without touching the
  database.
- `maintenance retention`, `maintenance recompute` — recognised but not yet
  implemented; they print "not yet implemented" and exit 1.
- `diagnose config` — the WP-1a.02 provenance report: source of every
  configuration leaf, never the content of a secret-capable value.
- `diagnose connectivity` — TCP-dial the database host:port from
  `database.url`. Proves reachability only, never credentials or schema
  state.
- `diagnose health` — process and configuration state plus the database
  connectivity probe.
- `help` — usage text.

Exit codes are part of the automation contract — branch on them, never on
parsed output:

| Code | Class | Meaning |
|---|---|---|
| 0 | success | command completed |
| 1 | generic/unknown | runtime failure without a more specific class; not-yet-implemented commands |
| 2 | validation | unknown command/subcommand, invalid or missing arguments, invalid configuration |
| 3 | authentication | reserved — OIDC authentication lands in a later iteration and is not exercised yet |
| 4 | authorisation | reserved — permission checks land later |
| 5 | conflict | state conflict, e.g. an applied migration was modified (ADR-010) |
| 6 | infrastructure | database host unreachable, connection failures |

With `--output json` every command prints exactly one machine-readable
envelope on stdout and nothing else (success and failure alike):

    {
      "schema_version": 1,
      "command": "diagnose config",
      "exit_code": 0,
      "status": "ok",
      "result": { ... },
      "error": null
    }

The envelope keys are fixed and schema-stable: `schema_version`, `command`,
`exit_code`, `status` (`ok` or `error`), `result` (command payload, `null`
on error) and `error` (`null` on success, otherwise `{"class": ...,
"message": ...}` using the class vocabulary above). Human-readable text
remains the default output; help output is always human-oriented. Examples:

    RISKSIGNAL_DATABASE_URL=... RISKSIGNAL_OIDC_ISSUER=... \
      bin/risksignal diagnose config --output json
    bin/risksignal badcmd; echo $?        # 2 (validation)
    RISKSIGNAL_DATABASE_URL=postgres://u:p@127.0.0.1:1/rs \
      bin/risksignal diagnose connectivity; echo $?   # 6 (infrastructure)

The CLI is strictly non-interactive: it never prompts and never reads
hidden defaults from a terminal. Destructive maintenance commands require
complete parameters (an explicit `--yes` once implemented), never a
terminal dialogue.
