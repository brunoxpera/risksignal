# Export and CSV neutralisation runbook (WP-6.03/6.04/6.06/6.07 / DEV-114, DEV-115, DEV-118, DEV-119)

The asynchronous export surface of ARCH-007 §1.1–§1.3 and §10.4: the frozen
filter context, the create → poll → download lifecycle, the server-local
artifact spool with its `export.ttl` self-expiry, the `export.max_rows` strict
input bound and the spreadsheet-formula neutralisation the CSV writer applies
to every cell.

Exports are **user-triggered and asynchronous**: the create command is one
guarded transaction that schedules the work, the worker materialises the
artifact out of band, and the download streams a time-limited, audited file.
The application layer is the single gate of record, so the CLI and the HTTP API
drive the same use cases with the same permission and the same audit (NFR-013
channel parity).

| Step | Actor gate | CLI | HTTP API (parity) |
|---|---|---|---|
| 1. Create | `exports.create` (deny-by-default) | `export create --format csv\|json [filter flags]` | `POST /api/v1/exports` |
| 2. Poll | `exports.create` (object-scoped to the creator) | read the status through the API | `GET /api/v1/exports/{id}` |
| 3. Download | `exports.create` (object-scoped to the creator) | `export download --export <id> --out <file>` | `GET /api/v1/exports/{id}/download` |

`exports.create` is the single permission across the three steps (ARCH-007
§12.2): an all-scope role creates, polls and downloads any export; an
`assigned`/`own` grant freezes the filter to the principal's own signals and
the download is object-scoped to the export's creator. There is no separate
read gate.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `export.dir` (`RISKSIGNAL_EXPORT_DIR`) | `var/exports` | The server-local spool root the `export.generate` job writes artifacts into and the download/sweep read them from. A volume shared by the server and the worker in the demo deployment; never a database `bytea`. |
| `export.ttl` (`RISKSIGNAL_EXPORT_TTL`) | `7d` (`168h`) | The artifact lifetime. An export expires at `created_at + TTL`; the daily sweep then deletes the file and marks the row `expired`. |
| `export.max_rows` (`RISKSIGNAL_EXPORT_MAX_ROWS`) | `100000` | The strict input bound of a single export (§12.3): a filter matching more rows is a **validation error**, never a silent truncation. |
| `worker.export_sweep_interval` (`RISKSIGNAL_WORKER_EXPORT_SWEEP_INTERVAL`) | `24h` | The cadence of the worker's expiry sweep (evaluated on the injected clock, NFR-015). |

All four are validated at startup: a blank `export.dir` or a non-positive
`export.ttl`/`export.max_rows` prevents boot.

## 1. Create

```
risksignal export create --format csv|json [--priority --status --asset-id --asset-type
    --product --cve --owner-id --source-id --created-from --created-to --sla-state
    --free-text] [--as <subject>]
```

`--format` is mandatory (`csv` or `json`); the filter flags freeze the §10.4
signal filter context at the creation instant and an out-of-vocabulary enum
value is a validation error. The command authorises `exports.create`
(deny-by-default, before any transaction), then, in one transaction, inserts a
`pending` export row and enqueues exactly one `export.generate` outbox job keyed
on the export id — the row and the job commit or roll back together, so no
export can exist without its job (ARCH-001 §5). A failing job append rolls the
row back with it. The printed export id is the argument to every later read and
download.

An `assigned`/`own` grant additionally injects `owner_id = principal.id` into
the frozen filter, so the artifact can never range beyond the creator's
assignment, whatever the request asked for.

## 2. Poll

```
GET /api/v1/exports/{id}
```

The create is asynchronous: it returns immediately with `status = pending`. The
worker's `export.generate` job loads the row, streams the frozen filter through
the §10.4 standard sort (bounded by `export.max_rows`), materialises the
artifact into the spool (atomic write + SHA-256) and stamps the row `completed`
with the row count, size, checksum, `schema_version`, `rule_version`
(`MAX(priority_rules.version)`) and `expires_at`. The lifecycle is one-way:

```
pending ──▶ completed ──▶ expired
   └──────▶ failed
```

- `pending` — created, no artifact yet.
- `completed` — the artifact is downloadable; carries the generation stamps.
- `failed` — generation failed; `last_error` is recorded and visible like any
  dead-letter/source-runs error. A redelivered attempt regenerates.
- `expired` — the TTL elapsed and the sweep deleted the artifact (terminal).

The read is idempotent and object-scoped to the creator. The CLI has no
separate poll verb — `export create` and `export download` are the whole 1:1
command vocabulary; the status is read through the API `GET`, which is the same
`GetExport` use case.

## 3. Download

```
risksignal export download --export <id> --out <file> [--as <subject>]
```

`--export` and `--out` are both mandatory. The command authorises
`exports.create` (object-scoped to the creator), then requires the export to be
`completed` and unexpired **before any artifact is opened** — a `pending`/
`failed` export is a conflict, and an expired one is a conflict too (the API
answers the declared `410 Gone` for the expiry, a `409 Conflict` for the
not-yet-completed export). A successful stream appends one `export.downloaded`
audit event in a transaction (carrying the minimised counts-and-hashes
snapshot, never the frozen filter's free text); a denied, not-ready or expired
download writes no audit row. The spool reader is closed on every path, so a
write failure is an infrastructure failure, never a silent partial file.

The response is the file `export-<id>.<format>` with the stored format's
content type — `text/csv; charset=utf-8` for a CSV export and
`application/json; charset=utf-8` for a JSON export (never negotiated, never
the generic `application/octet-stream`).

## 4. Artifact lifetime and sweep

The artifact is a **file in a server-local spool**, never a database `bytea`, so
it self-expires and stays out of the audit and backup retention path. The
worker's daily sweep (`worker.export_sweep_interval`, default `24h`) lists the
completed exports whose `expires_at <= now` (injected clock, NFR-015), deletes
their artifacts best-effort and marks the rows `expired`. It is idempotent (an
already-swept row is no longer `completed`) and tolerant of an already-deleted
file (the row is still marked expired), so a crash between the deletion and the
mark cannot strand a row. The retention and audit rows are never touched: an
export is a time-limited business-content copy, not an audit record.

## 5. CSV formula-injection neutralisation

CSV is a spreadsheet vector: a cell beginning with `=`, `+`, `-`, `@`, TAB or
CR can be evaluated as a formula when the file is opened. The CSV writer
therefore passes **every** cell — the header row and each data row, never only
"suspected" fields — through `domain.NeutralizeCSVField` (ARCH-007 §1.3, OWASP
"CSV Injection"): a dangerous first rune is prefixed with a single ASCII
apostrophe, so a consumer spreadsheet reads the cell as text instead of
evaluating it.

| Input | Output |
|---|---|
| `=cmd\|'/C calc'!A0` | `'=cmd\|'/C calc'!A0` |
| `+1` | `'+1` |
| `-2` | `'-2` |
| `@SUM(A1)` | `'@SUM(A1)` |
| `␉TSV` (leading TAB) | `'␉TSV` |
| `a=b` (separator not first) | `a=b` (unchanged) |
| `P1` | `P1` (unchanged) |

Only the first rune is inspected, the transform is idempotent (the prepended
apostrophe is itself a safe first rune), and it is applied uniformly, so a
user-controlled product/CVE/owner/free-text value can never survive as a
formula. The JSON writer does **not** neutralise: JSON is not a spreadsheet
vector, so its `encoding/json` escaping is the only transformation. Both
formats stamp `schema_version` and `rule_version` (plus the frozen `created_at`
and the row count) so a downloaded artifact is self-describing.

## 6. The `export.max_rows` bound

`export.max_rows` is the strict input limit of §12.3: the materialisation scans
the frozen filter, and when it matches more rows than the bound it rejects the
export with `export matches N rows, exceeding export.max_rows M`. The rejection
is a **validation error** and the row is stamped `failed` with that
`last_error` — the export is never silently truncated. Raise the bound only with
the spool capacity and the consumer in mind; the default is `100000`.

## Exit-code contract

The export commands follow the project-wide CLI contract: a validation mistake
(missing `--format`, an unknown format, an out-of-vocabulary filter value,
missing `--export`/`--out`) exits **2**; a denied `exports.create` exits **4**
(authorisation); a download of a not-completed or expired export exits **5**
(conflict); infrastructure trouble (the spool unreadable or unwritable, the
database unreachable) exits **6**.

## See also

- [`security-hardening.md`](security-hardening.md) — the append-only roles and
  the runtime role grants for the `exports` table, plus the TLS/secure-headers
  edge the download rides.
- [`retention.md`](retention.md) — the governed retention procedure; the export
  spool is deliberately outside its deletion scope.
- [`backup-restore.md`](backup-restore.md) — the encrypted off-host backup; the
  self-expiring spool is deliberately outside it too.
- `deploy/demo/README.md` — the private demo runbook; the export spool is a
  volume shared by the server and the worker.
