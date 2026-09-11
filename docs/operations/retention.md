# Retention and pseudonymisation runbook (WP-6.05/6.07 / DEV-116, DEV-119)

The governed, four-eyes retention procedure of ARCH-007 §2 and §3 (concept
ch. 11.3): the scheduled dry-run proposal, the Product-Owner approval, the
bounded execution in the §2.3 referentially-safe order, the retention report,
the legal holds that block both stages and the identity pseudonymisation. The
dedicated retention database role and the `database.retention_url` DSN that the
commits authenticate on are documented in
[`security-hardening.md`](security-hardening.md) ("Dedicated retention role");
this document is the operator-facing procedure.

Retention is **governed and non-interactive**: every step is a complete command
line, the CLI never prompts, a dry-run is mandatory before any deletion, and
only the Product Owner may approve. The application layer is the single gate of
record, so the CLI and the HTTP API drive the same use cases with the same
permissions and the same audit (NFR-013 channel parity).

| Step | Actor gate | CLI | HTTP API (parity) |
|---|---|---|---|
| 1. Dry-run (propose) | `retention.manage` (Administrator) | `maintenance retention --dry-run` | `POST /api/v1/retention/runs` |
| 2. Approve (four-eyes) | `settings.approve` (Product Owner) | `maintenance retention --approve <id> --reason <t> --yes` | `POST /api/v1/retention/runs/{id}/approve` |
| 3. Execute | `retention.manage` (enqueued by the approval) | `retention.execute` worker job | （same job) |
| 4. Report | `retention.manage` | `maintenance retention --list` | `GET /api/v1/retention/runs[/{id}]` |

The two gates are deliberately distinct: `retention.manage` drives the dry-run,
the execution, the holds and the pseudonymisation; `settings.approve` authorises
the deletion. No deletion runs without an approved dry-run.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `retention.closed_signal_years` (`RISKSIGNAL_RETENTION_CLOSED_SIGNAL_YEARS`) | `5` | A signal is due for retention when `closed_at <= now − this many years` (cutoff derived from the injected clock, NFR-015). |
| `retention.pseudonymise_years` (`RISKSIGNAL_RETENTION_PSEUDONYMISE_YEARS`) | `0` | The pseudonymisation cutoff. `0` means "same period as `closed_signal_years`" (the MVP default — pseudonymisation and deletion run in the same pass; configurable shorter per TD-08). |
| `retention.batch_size` (`RISKSIGNAL_RETENTION_BATCH_SIZE`) | `500` | The bounded execution batch size (§14.1 recompute guideline): one transaction per batch. |
| `retention.schedule` (`RISKSIGNAL_RETENTION_SCHEDULE`) | `720h` (30 days) | The cadence of the worker's monthly dry-run proposal. It proposes, it never deletes. |
| `retention.hash_chain_enabled` (`RISKSIGNAL_RETENTION_HASH_CHAIN_ENABLED`) | `false` | The optional audit hash chain (§7 control 3b); see `security-hardening.md`. |
| `database.retention_url` (`RISKSIGNAL_DATABASE_RETENTION_URL`) | *unset* | The separate DSN the retention and pseudonymisation **commits** authenticate as the dedicated retention login on. |

## 1. Dry-run (propose)

```
risksignal maintenance retention --dry-run [--stage pseudonymise|delete] [--as <subject>]
```

Scans the closed signals whose retention deadline has elapsed, splits them into
the actionable candidates and the ones protected by an active legal hold, counts
them (`candidates / held / to_pseudonymise / to_delete`) and stores a
**counts-only** `retention_runs` row (`status='dry_run'`, `stage`). It reads
only — no domain state changes and no audit row; the report row is the only
write and it is the operational record the approval and execution act on. The
run id printed by the command is the argument to the approval.

Two stages (ARCH-007 §2.1):

- `--stage pseudonymise` — redact in place only (see §5).
- `--stage delete` — pseudonymise first, then delete in the §2.3
  referentially-safe order. **This is the default.**

The monthly worker scheduler proposes one dry-run per `retention.schedule` on
the injected clock; it never deletes anything (only an approved run executes).

## 2. Approve (four-eyes)

```
risksignal maintenance retention --approve <run-id> --reason "<ticket>" --yes [--as <subject>]
```

The Product Owner reviews the counts-only report and approves with a **mandatory
non-blank reason**. `--reason` and `--yes` are both required (the approval is
destructive; the CLI never prompts). A rejection reuses the same gate:

```
risksignal maintenance retention --approve <run-id> --reject --reason "<ticket>" --yes
```

Only a `dry_run` run can be decided (else conflict). In one transaction the run
is flipped (`dry_run → approved`/`rejected`, recording `approved_by /
approved_at / approval_reason`) and the `retention.approved`/`retention.rejected`
audit event is appended — atomically. The approval enqueues exactly one
`retention.execute` job (dedupe key `policy_id + cutoff + partition_key`); a
retried approval of the same plan is a no-op at the schema level.

## 3. Execute

The `retention.execute` worker job claims the approved run (`approved →
executing`), re-scans the candidates at the frozen cutoff, re-checks each
candidate's legal hold (a hold set between the dry-run and the execution is
honoured: a held signal is skipped, preserving the record as-is) and processes
the non-held candidates in bounded batches of `retention.batch_size` — one
transaction per batch. Per candidate it pseudonymises first, then (in the
`delete` stage) deletes the non-shared dependents in the ARCH-007 §2.3
referentially-safe order (§2.3), and appends **one `retention.executed` audit
event per batch** carrying counts and the processed `closed_at` time range — no
business content. The run is closed with the final counts.

- **Resumable.** A re-run re-scans the candidates and naturally skips the
  already-deleted rows.
- **Per-batch isolation.** A failing batch stops only that batch
  (`failed_count++`, `last_error` recorded); the remaining batches still run.
  The run is then closed `failed` with the counters and the last error, if any.
- An infrastructure failure of the run is temporary (the lease redelivers it);
  an unknown run or missing approval is permanent and dead-letters the job.

**The commit runs on the dedicated retention connection**, authenticated as
`risksignal_retention_login` (never the application runtime role, never
`SET ROLE`; see `security-hardening.md`).

## 4. Report

```
risksignal maintenance retention --list
```

Prints every stored run, newest cutoff first: the counts-only dry-run report,
the approval stamps and the final counts (`deleted / pseudonymised / failed`,
`last_error`). The same rows are the `GET /api/v1/retention/runs` and
`GET /api/v1/retention/runs/{id}` reads. `retention_runs` **survives the
deletion it reports on** (§13.4 step 5) — it is the audit-adjacent operational
record of what was removed.

Audit events produced across the procedure: `retention.approved` /
`retention.rejected` (four-eyes decision), `retention.executed` (per batch) and
`retention.pseudonymised` (standalone pseudonymisation, §5). List them with the
usual audit reads.

## 5. Pseudonymisation stage

Pseudonymisation reduces the **personal reference** of an identity or a due
signal in place; it is reversible-by-resolution (through the governed
`audit.reveal_identity` act) and explicitly **not anonymisation** (ADR-014). It
keeps `actor_id` and the `users` row.

Inside a retention run, the `pseudonymise` stage (and the first half of the
`delete` stage) redacts the due signals' identity references. It runs on the
same dedicated retention connection and is blocked by an active legal hold.

The standalone, operator-driven form is the governed in-place pseudonymisation
of **one identity** (concept ch. 11.3):

```
# mandatory dry-run first: report the per-target redaction counts, nothing written
risksignal maintenance identity-pseudonymize --user <id> [--as <subject>]

# the real, audited redaction; --reason is then mandatory
risksignal maintenance identity-pseudonymize --user <id> --reason "<ticket>" --commit [--as <subject>]
```

`--commit` (alias `--yes`) is the real run and requires a documented `--reason`
(an unlogged pseudonymisation would be worse than none, ADR-014 point 4). It
clears the identity's actor **display names** on its audit rows and redacts the
free text the identity authored or triggered:

| Target | Effect |
|---|---|
| display names | cleared on the identity's audit rows |
| `comments.body` | replaced with the fixed marker `[redacted]` |
| priority override reasons | redacted |
| before/after snapshot "reason" free text | redacted |

The report is the per-target redaction counts (`display_names_cleared`,
`comment_bodies_redacted`, `override_reasons_redacted`,
`snapshot_reasons_redacted`). Pseudonymisation is audited as
`retention.pseudonymised` in the same transaction as the redaction.

**Fail-closed.** A `--commit` run requires `database.retention_url`. When it is
unset the command refuses to start (validation error, exit 2) **rather than fall
back to the application role**; the dry-run preview stays on the app-role
connection and needs no retention DSN. The `retention.execute` worker job fails
closed the same way (the job dead-letters). Set the DSN and provision the login
first — see `security-hardening.md` ("Provisioning the retention login") and the
demo runbook in `deploy/demo/README.md` (local: `make provision-retention-login`).

## 6. Legal holds

A legal hold preserves an aggregate against **both** the deletion and the
pseudonymisation stage; it is set and released on the same `retention.manage`
gate (CLI and API parity):

```
strictly non-interactive:
  risksignal legal-hold create  --aggregate <id> [--aggregate-type <t>] --reason <text> [--as <subject>]
  risksignal legal-hold release --hold <id> --reason <text> --yes [--as <subject>]   # destructive: --yes mandatory
  risksignal legal-hold list    [--aggregate <id>] [--aggregate-type <t>] [--active] [--as <subject>]

API parity:
  POST /api/v1/legal-holds
  GET  /api/v1/legal-holds
  POST /api/v1/legal-holds/{id}/release
```

`--aggregate-type` defaults to `risk_signal`. `create` needs a mandatory
non-blank `--reason`; `release` weakens the protection (the aggregate becomes
deletable/pseudonymisable again) so it is destructive and requires `--reason`
**and** `--yes`. The dry-run reports held candidates with their hold reason, and
the executor re-checks the hold per candidate, so a hold set after the dry-run
still blocks the record.

## Exit-code contract

The retention commands follow the project-wide CLI contract: a validation
mistake (missing/blank flag, unset `database.retention_url` on a commit, bad
stage) exits **2**; a denied permission exits **4** (authorisation); a conflict
(approving a non-`dry_run` run, an illegal lifecycle edge) exits **5**;
infrastructure trouble exits **6**.

## See also

- [`security-hardening.md`](security-hardening.md) — the `risksignal_retention`
  role, its grant matrix, the `risksignal_retention_login`, the
  `database.retention_url` fail-closed behaviour and the optional audit hash
  chain.
- [`backup-restore.md`](backup-restore.md) — the encrypted off-host backup that
  preserves the post-deletion evidence (and, with the hash chain, the audit
  trail's external anchor).
- `deploy/demo/README.md` — the private demo runbook, including the retention
  login provisioning.
