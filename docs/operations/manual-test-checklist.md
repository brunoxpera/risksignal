# Manual test checklist

Hands-on pass over the delivered RiskSignal surface (I1a–I6) before the
production-readiness work. This is a *manual* companion to the automated gates
(`make ci-test`, `make test-i6-exit-criteria`, `make demo-smoke`): it walks a
human through the same flows to catch anything the suites can't (UX, runbook
friction, surprising output, channel parity).

Procedure-focused runbooks for the operations features live alongside this file:
[`retention.md`](retention.md), [`export.md`](export.md),
[`backup-restore.md`](backup-restore.md), [`security-hardening.md`](security-hardening.md).
Use those for the exact step-by-step commands; this checklist is the pass/fail
inventory of *what to try* and *what to expect*.

## Prerequisites

- Go 1.27, `make`, Docker (compose v2), `curl`, `jq`
- A reachable PostgreSQL (the compose `db` service)

## Environment bring-up

Two ways to run it by hand. Use **A** for the bulk of the pass (fastest,
loopback, no login friction); use **B** for the production-like topology.

### A. Loopback dev stack (recommended for this checklist)

```sh
make up-db          # postgres only, waits until healthy
make build          # bin/risksignal, bin/risksignal-server, bin/risksignal-worker
bin/risksignal maintenance migrate
```

Start the server and worker in two terminals (loopback + local auth bypass —
accepted only because `env=local` and the bind is loopback):

```sh
export RISKSIGNAL_DATABASE_URL='postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable'
export RISKSIGNAL_OIDC_ISSUER='http://127.0.0.1:9000/oidc'
export RISKSIGNAL_ENV=local
export RISKSIGNAL_AUTH_BYPASS_ENABLED=true
export RISKSIGNAL_HTTP_ADDR=127.0.0.1:8080

bin/risksignal-server        # terminal 1
bin/risksignal-worker        # terminal 2 (drives scheduler + outbox relay)
```

Web UI: `http://127.0.0.1:8080/`.

### B. Full compose stack / demo overlay

```sh
make up                        # db + mail (mailpit) + oidc (mock) + server + worker, loopback
# or the hardened single-host demo (TLS via Caddy, env=demo, no bypass):
cp deploy/demo/.env.example deploy/demo/.env   # edit placeholders
docker compose -f deploy/demo/compose.yaml up -d --build
```

`make down` stops the compose stack.

---

## 0. System endpoints & startup

- [ ] `GET /health/live` → `200` (process responds; DB/sources deliberately not criteria).
- [ ] `GET /health/ready` → `200 {"status":"ready"}`; with DB stopped → `503` + a distinct reason.
- [ ] `GET /version` → JSON build metadata (`version`/`commit`/`build_time`).
- [ ] `GET /metrics` → Prometheus exposition; confirm the §16.2 families render (gauges + counters + summaries).
- [ ] Server startup with invalid config (e.g. missing `oidc.issuer`) → prints problem, exits non-zero (CLI exit code 2 = validation).
- [ ] `env=demo` + `auth.bypass_enabled=true` (or `sources.allow_private=true`) → **refuses to start** before binding (non-zero, no listener). *(§8 lockdown)*
- [ ] `bin/risksignal diagnose config` → provenance summary (sources, no secret values).
- [ ] `bin/risksignal diagnose connectivity` → probes DB host reachability.
- [ ] `bin/risksignal diagnose health` → process + DB connectivity.

## 1. Sources & evidence

- [ ] `bin/risksignal source list` → monitor projection of every registered source (latest run, data age, degraded flag, quarantine open count).
- [ ] `bin/risksignal source status` (no args) → detailed monitor view for all sources with current metric values.
- [ ] `bin/risksignal source run synthetic` → enqueues a manual `source.fetch` job; the worker runs it (dedupe by `source_id`+`request_id`).
- [ ] `bin/risksignal quarantine list` → the isolated-records working list (position, reason, payload hash, status).
- [ ] `bin/risksignal quarantine ack <id>` → `new → acknowledged`, audited.
- [ ] `bin/risksignal quarantine reprocess <id>` → re-runs the normaliser; resolves on success, stays retryable on failure.
- [ ] Confirm a deliberate failure case (e.g. the seeded malformed E1 record) is isolated and reprocessable.

## 2. Inventory & matching

- [ ] `bin/risksignal inventory validate <file>` → parses one inventory CSV, reports every positioned failure (read-only).
- [ ] `bin/risksignal inventory preview <file>` → diff vs current inventory (created/updated/unchanged, read-only).
- [ ] `bin/risksignal inventory import <file>` → dry-run by default (nothing written).
- [ ] `bin/risksignal inventory import <file> --commit` → one transaction: additive upserts + `inventory.import` audit + `matching.rebuild` job. Re-commit of identical content is a no-op.
- [ ] `GET /api/v1/assets` and `GET /api/v1/assets/{id}/components` → filterable asset list + component detail.

## 3. Signals & triage

- [ ] `bin/risksignal signal list` → cursor-paged working list; filters apply in the URL.
- [ ] `bin/risksignal signal show --signal <id>` → signal detail.
- [ ] `bin/risksignal signal acknowledge --signal <id> --version <n>` → `new → in_review` (gated by `signals.triage`).
- [ ] `bin/risksignal signal assign --signal <id> --owner <u>` (and `--clear`) → owner assignment.
- [ ] `bin/risksignal signal transition --signal <id> --to <state>` → state-machine transition.
- [ ] `bin/risksignal signal comment --signal <id> --comment <t>` → comment recorded.
- [ ] `bin/risksignal signal override --signal <id> --priority <P1..P4> --reason <t> --version <n>` → priority override (gated `signals.override`, Analyst only), reason + actor stamped.
- [ ] `bin/risksignal signal revert --signal <id> ...` → revert the override.
- [ ] `bin/risksignal signal pause|resume --signal <id> --target <clock> --reason <t>` → SLA clock pause/resume.
- [ ] `POST /api/v1/signals/{id}/commands` → same command vocabulary over HTTP (channel parity with the CLI).

## 4. Priority & SLA

- [ ] `bin/risksignal demo seed` → deterministic P1–P4 fixture (statuses + SLA clocks + audits).
- [ ] `bin/risksignal demo run` → accelerated UC-08 SLA lifecycle: create → deliver → ack → `action_planned` → resolve, plus a P3→P1 upgrade and a P1 escalation.
- [ ] `bin/risksignal demo reset --yes` → truncates demo tables (dev-only).
- [ ] Confirm SLA clocks: deadline derives from the injected profile; a P1 breach escalates (see the `signals_sla_escalations_total` metric, renamed in DEV-144).

## 5. Identity & authorisation

- [ ] `bin/risksignal auth login --issuer <url> --flow device` (and `--flow loopback`) → OIDC login; tokens stored in the OS credential store, never logged.
- [ ] `bin/risksignal auth status` → reads the stored login (non-secret identity only).
- [ ] `bin/risksignal auth logout` → removes the stored credential.
- [ ] Verify the credential store file/dir are owner-only: file `0600`, dir `0700` (DEV-145 fix).
- [ ] `bin/risksignal user list` → users.
- [ ] `bin/risksignal user grant --user <id> --role <role>` / `revoke` / `deactivate --yes` → role administration, deny-by-default.
- [ ] `bin/risksignal maintenance identity-lookup --event <id> --reason <t>` → governed `audit.reveal_identity` (mandatory reason, self-audited, permission-gated).
- [ ] Confirm a permission-gated command without the role → authorisation failure (CLI exit code 4).
- [ ] Confirm an unauthenticated API call → `401` (except `/health/*`, `/version`, auth endpoints).

## 6. Web UI

- [ ] Dashboard (`/`) renders.
- [ ] Triage list (`/signals`) — filter bar, signal rows, SLA badges.
- [ ] Signal detail (`/signals/{id}`) — status, owner, comments, priority, clocks.
- [ ] Inventory (`/inventory`) and Inventory import (`/inventory/imports`).
- [ ] Source monitor page (`/sources`) — degraded flags, data age, quarantine counts (gated by `sources.manage`).
- [ ] Administration: roles (`/admin/roles`) and users (`/admin/users`).
- [ ] Login flow (`/auth/login` → mock OIDC → callback) when bypass is off.
- [ ] Confirm the UI and the CLI show the same data/state (NFR-013 channel parity).

## 7. Operations

Follow the runbooks; record pass/fail per stage:

**Export** ([`export.md`](export.md)):
- [ ] `export create --format csv` (and `--format json`) schedules an async export.
- [ ] Worker materialises the artifact into the export spool.
- [ ] `export download --export <id> --out <file>` streams it back; content-type matches the format (CSV `text/csv`, JSON `application/json`).
- [ ] An expired export fails to download.

**Retention & legal hold** ([`retention.md`](retention.md)):
- [ ] `maintenance retention --dry-run` → counts-only report (`candidates / held / to_pseudonymise / to_delete`), reads only.
- [ ] `maintenance retention --list` → stored report.
- [ ] `maintenance retention --approve <id> --reason <t> --yes` → four-eyes approval enqueues `retention.execute`.
- [ ] `legal-hold create --aggregate <id> --reason <t>` → blocks deletion/pseudonymisation.
- [ ] `legal-hold list` / `legal-hold release --hold <id> --reason <t> --yes`.
- [ ] `maintenance identity-pseudonymize --user <id> --dry-run` → redaction counts, nothing written; `--commit` performs the audited redaction.

**Backup / restore** ([`backup-restore.md`](backup-restore.md)):
- [ ] `diagnose backup` → encrypted (age) off-host `pg_dump -Fc` once.
- [ ] `diagnose restore-test` → decrypts newest backup into a throwaway DB, runs checksum-guarded migrations, asserts schema/counts/hashes/open-signals/audit-chain, records `backup.restored`.

## 8. Observability

- [ ] Structured logs from server + worker (JSON, no secrets in any log line).
- [ ] `/metrics` exposes the full §16.2 contract (all declared families have writers — DEV-138/142).
- [ ] Worker heartbeat + last-successful-run recorded (ch. 16.3).
- [ ] Traces exported (OpenTelemetry-compatible) if a collector is configured.

## 9. Security hardening (spot-check)

- [ ] `make lint-secrets` clean.
- [ ] `make scan` (govulncheck + grype) — optional, needs images + pinned tools.
- [ ] Dedicated retention DB role used for retention/pseudonymisation commits (see `security-hardening.md`).
- [ ] Loopback lock: bypass refused on a non-loopback `http.addr`.

## 10. Performance (optional, slow)

- [ ] `make perf PERF_SCALE=smoke` → quick subset, writes `dist/perf/<version>-smoke.md` with pass/fail.
- [ ] Full `make perf` → reference volume (250k CVEs + 10k assets), list-query p95 ≤ 2s, incremental run ≤ 15min, job count far below CVE count.

## 11. End-to-end scripts (automated, run to confirm the "happy path" still holds)

- [ ] `make demo` → walking-skeleton E2E: reset → seed → server up → deterministic reference signals → teardown.
- [ ] `make demo-smoke` → §8 negative-startup proof + §4.4 step-5 flow (mock OIDC login → signals → source monitor → signal read).

---

## Findings log

| # | Area | Observation | Severity | Follow-up |
|---|---|---|---|---|
| 1 |  |  |  |  |

*Fill rows as you go; anything not matching "expected" becomes a tracked task before the I7 production-readiness work begins.*
