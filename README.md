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
The build injects build metadata (version, git commit, build time) into every
binary via `-ldflags -X` (WP-1a.07); `make VERSION=1.2.3 build` overrides the
version, which otherwise defaults to `dev`.
Each binary loads and validates its configuration at startup (WP-1a.02):
built-in defaults, an optional JSON config file (`RISKSIGNAL_CONFIG_FILE`)
and `RISKSIGNAL_*` environment variables, with environment variables taking
precedence. `database.url` and `oidc.issuer` are mandatory; the local
authentication bypass (`RISKSIGNAL_AUTH_BYPASS_ENABLED`) is accepted in
`local` mode only (TR-010). On invalid configuration the binary prints the
problem and exits 1 (the CLI classifies it as validation and exits 2, see
"CLI commands and exit codes"); on success it prints a provenance summary
(sources, no secret values) and starts its process role.
`risksignal-server` keeps running and serves HTTP on `http.addr` through the
WP-1a.06 middleware chain (ADR-008), shutting down cleanly on
SIGINT/SIGTERM. `risksignal-worker` keeps running and drives its scheduler
loop (WP-1a.10, WP-1b.06): a heartbeat plus one outbox-relay drain per
`worker.interval` (default 30s, overridable via
`RISKSIGNAL_WORKER_INTERVAL`), recording worker health (heartbeat and last
successful run, ch. 16.3) and shutting down cleanly on SIGINT/SIGTERM
within a grace period. The drain is the transactional-outbox relay of
ARCH-001 §2: it claims the bounded batch of due rows (lease-based
`FOR UPDATE SKIP LOCKED`, so several workers can drain concurrently),
dispatches each row to the handler registered for its `outbox.type`, acks
delivered rows (`claimed → done`, guarded so a redelivery cannot double-ack)
and dead-letters a permanently failed row or one past the attempt cap with
`last_error` recorded — a temporary failure stays `claimed` and the expired
lease redelivers it (at-least-once delivery, idempotent on the immutable
event id). The I1b registry carries one handler, the `signal.created` sink
(sink.go): a no-op standing in for the I4 notification adapter, so the
observable effect of a delivery is the terminal `claimed → done` transition
— the relay mechanics are what the walking skeleton proves. Examples:

    RISKSIGNAL_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/risksignal \
    RISKSIGNAL_OIDC_ISSUER=https://auth.local.example/ \
    bin/risksignal-server

    RISKSIGNAL_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/risksignal \
    RISKSIGNAL_OIDC_ISSUER=https://auth.local.example/ \
    RISKSIGNAL_WORKER_INTERVAL=5s \
    bin/risksignal-worker

### System endpoints

`bin/risksignal-server` answers the System endpoints of concept ch. 10.2 and
16.3 (WP-1a.07) on the paths below, outside the future `/api/v1` contract
and through the same middleware chain as everything else:

- `GET /health/live` — liveness: answers 200 whenever the process responds;
  external sources and the database are deliberately not criteria.
- `GET /health/ready` — readiness: checks the database (pgx pool ping), the
  completed schema migrations (checksum-verified, ADR-010) and the
  mandatory configuration; answers 200 with `{"status":"ready"}` when all
  pass and 503 with a distinct reason per failing check otherwise. A
  database that is down at startup does not stop the server — readiness
  reports red until the database is back.
- `GET /version` — the build metadata injected at link time
  (`make build`), e.g. `{"version":"dev","commit":"9418a984",
  "build_time":"2026-09-08T22:57:42Z"}`; binaries built without the
  Makefile report `dev`/`unknown`/`unknown`.

Probe them while the server runs:

    curl -i http://127.0.0.1:8080/health/live
    curl -i http://127.0.0.1:8080/health/ready
    curl -i http://127.0.0.1:8080/version

### Test

    make test

Runs the architecture-gate negative test (`make test-arch`), then
`go test ./...`. The negative test proves the arch gate rejects a forbidden
import; see `testdata/arch-gate/verify-arch-gate.sh`. To run only that
negative test:

    make test-arch

### End-to-end demo (WP-1b.11)

The iteration I1b exit criterion — a synthetic record imported and readable
as a risk signal over the API — is one command:

    make demo

`make demo` builds the binaries, starts the compose database (`make up-db`)
and applies the schema migrations, then runs `scripts/demo.sh`: it resets
the I1b demo tables (`demo reset --yes`) so every run starts from the same
deterministic state, seeds the synthetic source (`demo seed`, WP-1b.05),
starts `bin/risksignal-server` on the loopback demo address
(`127.0.0.1:18080`; override `RISKSIGNAL_HTTP_ADDR`) and asserts that
`GET /api/v1/signals` serves the four reference signals with the expected
P1/P2/P2/P3 priorities — the exit-criterion read, via the list and the
detail endpoint — then stops the demo server. The demo uses synthetic seed
data and loopback bindings only; the compose db stays up afterwards
(`make down` stops it). Running `make demo` again always demonstrates the
same outcome.

The manual equivalent, with the compose defaults exported:

    export RISKSIGNAL_DATABASE_URL='postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable'
    export RISKSIGNAL_OIDC_ISSUER='http://127.0.0.1:9000/oidc'

    make up-db && make migrate    # db up and healthy, schema applied
    bin/risksignal demo seed      # deterministic synthetic run (C1-C4 -> 4 signals)
    bin/risksignal-server &       # serves /api/v1/signals on 127.0.0.1:8080
    curl -s 'http://127.0.0.1:8080/api/v1/signals?limit=100'

The reference cases C1–C4 (ARCH-001 §3) are deterministic: the list comes
back priority-ascending with CVE-2024-0001 first at `"priority":"P1"`
(then P2/P2/P3), every signal carrying `"status":"new"` and the readable
join (asset, product, summary, confidence, method). `demo run` re-runs the
source idempotently; `demo reset --yes` clears the demo tables. The demo
CLI commands are documented under "CLI commands and exit codes".

### CI pipeline stages 1–2 (WP-1a.12)

The CI pipeline (`.github/workflows/ci.yml`, GitHub Actions) runs three
parallel jobs — lint, test, build — and every stage is reproducible locally
without GitHub:

    make ci-lint    # gofmt check, go vet, golangci-lint (incl. gosec), go-arch-lint,
                    # go-licenses check, gitleaks detect, then the ADR-011 OpenAPI
                    # gates (WP-1b.11): validate + generate diff
    make ci-test    # go test -race ./... against the compose PostgreSQL (starts it)
    make test-contract  # the ADR-011 gate-3 contract suite only: OpenAPI document
                    # validation + generated client against the demo-seeded server
    make ci-build   # make build

Since WP-1b.11 the lint job also enforces the two ADR-011 contract-machinery
gates: gate 1 validates `api/openapi/openapi.yaml` against the 3.1
specification through the kin-openapi validation of the contract suite
(`make lint-openapi-validate`) — the no-Node CI equivalent of the redocly
`make validate-openapi` gate, which needs Node via npx and stays the local
developer validator — and gate 2 regenerates the sqlc/oapi-codegen output
(`make generate`) and fails on any diff of the committed generated trees
(`make lint-openapi-diff`).

The tools are pinned to the versions recorded in
`docs/plan/orchestrator-decisions.md` (D-005): golangci-lint v2.13.2,
gitleaks 8.30.1, go-licenses v1.6.0, go-arch-lint v1.19.0. Their
configuration lives in `.golangci.yml`, `.gitleaks.toml` and
`.go-arch-lint.yml` in the repository root. `make ci-test` starts the
compose `db` service (with `postgres:16`) first so the integration tests
run against a real database instead of skipping.

### Images, SBOM and scans (WP-1a.13)

The production container images build multi-stage from `deploy/server/` and
`deploy/worker/` Containerfiles: Go 1.27 build stage (ADR-008) onto a
non-root `distroless/static-debian12` runtime pinned by digest, with the
same build metadata as the binaries (WP-1a.07) injected via build args.
`make VERSION=1.2.3 image` tags them `risksignal/server:1.2.3` and
`risksignal/worker:1.2.3`; a future registry (ghcr.io/xpera/...) would
carry those names.

    make image   # build both production images
    make sbom    # CycloneDX SBOMs: module (cyclonedx-gomod) + both images (syft) -> dist/sbom/
    make scan    # govulncheck on the module, grype --fail-on high on both images -> dist/scan/
    make sign    # cosign keyless signing skeleton — verifies the tool, signs nothing

Tooling is pinned in `docs/plan/orchestrator-decisions.md` (D-005):
cyclonedx-gomod v1.12.0, govulncheck v1.8.0, syft v1.51.1, grype v0.118.0,
cosign v2.6.5. The CI image job (stages 4–6) mirrors these targets and
uploads the SBOMs and scan reports as workflow artifacts. There is no
GitHub remote and no registry yet, so that job runs only after the first
push, and real (keyless) signing happens at release time — the intended
flow is documented in `docs/plan/release-signing.md`.

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
    make ci-lint   # complete WP-1a.12 lint stage (see above)
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
- `demo seed` — register the synthetic source
  (`type=synthetic`, `name=synthetic-source`), seed the demo inventory
  (acme/portal 2.4.4 on a critical/internet asset, acme/api 1.0 on a
  normal/internal asset) and run the deterministic reference source once
  (WP-1b.05, ARCH-001 §3). Seeding twice yields no duplicates. The
  malformed reference case E1 (missing `cve_id`) is counted as a run error
  without aborting the run: the reported run `status` is `failed` — that is
  the expected reference behaviour — while the command itself exits 0 and
  the counted error plus the run counters are part of the result.
- `demo run` — re-run the synthetic source against the seeded inventory:
  an idempotent no-op that creates no duplicate rows and no new signals.
- `demo reset --yes` — truncate the I1b demo tables (sources, source runs,
  raw records, vulnerabilities, evidences, matches, risk signals, assets,
  components, audit events, outbox). Dev-only: requires the explicit
  `--yes` and never prompts; the next `demo seed` rebuilds the demo state.
- `source run <type|id> [--request-id <id>]` — the manual trigger of the
  source.run loop (WP-2.08, ARCH-002 §5): enqueue one `source.fetch` job
  for the named source (resolved by id, or by type when exactly one source
  of that type is registered). The job bypasses the schedule and the
  background worker delivers it on its next drain — nothing runs a fetch
  in the CLI process. Without `--request-id` every invocation enqueues a
  new job (fresh request id); a fixed `--request-id` makes the trigger
  idempotent (dedupe key `source_id + request_id`).
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
    RISKSIGNAL_DATABASE_URL=... RISKSIGNAL_OIDC_ISSUER=... \
      bin/risksignal demo seed
    bin/risksignal demo seed --output json   # run id, status, counters, errors
    bin/risksignal demo run                  # idempotent re-run, no new signals
    bin/risksignal demo reset --yes          # dev-only, truncates the demo tables

    RISKSIGNAL_DATABASE_URL=postgres://u:p@127.0.0.1:1/rs \
      bin/risksignal diagnose connectivity; echo $?   # 6 (infrastructure)

The CLI is strictly non-interactive: it never prompts and never reads
hidden defaults from a terminal. Destructive commands require complete
parameters — the dev-only `demo reset` takes an explicit `--yes` — never a
terminal dialogue.
