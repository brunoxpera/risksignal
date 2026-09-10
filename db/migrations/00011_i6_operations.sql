-- 00011_i6_operations.sql — I6 operations schema (ARCH-007 §1.2/§2.1/§2.3/§11,
-- WP-6.02 / DEV-112).
--
-- Iteration I6 layers operations on top of the landed I1b–I5b domain: the
-- asynchronous CSV/JSON export surface (FR-022, AT-014), the governed
-- five-year retention run with its mandatory dry-run/approval and
-- referentially-safe, audited deletion (FR-033, AT-021, §13.3/§13.4) and the
-- legal-hold override that blocks both deletion and pseudonymisation of an
-- aggregate (§13.4 step 2). This migration carries exactly the three tables
-- those operations persist (ARCH-007 §1.2/§2.1) — it adds no business logic
-- and touches no existing table, so it is purely additive and every existing
-- row stays valid (ADR-010).
--
--   * legal_holds    — a documented hold (§13.4 step 2) that blocks deletion
--                      and pseudonymisation of the held aggregate; the hold
--                      reason is the audit record, released_at marks the
--                      release (set-once).
--   * retention_runs — the retention report (§2.2): one row per run/partition
--                      carrying the dry-run counts, the four-eyes approval and
--                      the final counts only — never business content. It is
--                      what survives the deletion (the operational evidence).
--   * exports        — one export job (§1.2): the frozen filter + format and
--                      the generation stamps (counts, size, checksum, schema/
--                      rule version, expiry). The artifact itself lives in the
--                      server-local export spool, not in the database.
--
-- Identifier rules (implementation concept ch. 7.2, ARCH-001 §1): uuid primary
-- keys via gen_random_uuid() (core PostgreSQL since 13; the environment runs
-- postgres:16), every timestamp timestamptz, every instant from the injected
-- clock. No table carries a foreign key: legal_holds.aggregate_id is
-- polymorphic (like audit_events.aggregate_id) and exports/retention_runs
-- reference nothing but their own immutable id — retention must survive the
-- deletion of the rows it reports on.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- legal_holds (ARCH-007 §2.1, §13.4 step 2): one documented legal hold on one
-- aggregate. A hold preserves the original record as-is — it blocks both the
-- deletion *and* the pseudonymisation of the held aggregate (ARCH-007 §2.1).
-- aggregate_type defaults to 'risk_signal' (the MVP retention subject) and is
-- kept explicit so the same table can carry a hold on another aggregate type
-- later; the (aggregate_type, aggregate_id) index serves the retention
-- candidate anti-join ("no active legal_hold") and the per-aggregate hold
-- read. reason is the documented justification (mandatory — a hold without a
-- reason is not a hold); actor_id is the principal that set it (audited);
-- created_at is the hold instant from the injected clock; released_at NULL =
-- active, non-NULL = released (a release is set-once, §2.3 ReleaseLegalHold).
CREATE TABLE legal_holds (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type text        NOT NULL DEFAULT 'risk_signal',
    aggregate_id   uuid        NOT NULL,
    reason         text        NOT NULL,
    actor_id       text        NOT NULL,
    created_at     timestamptz NOT NULL,
    released_at    timestamptz NULL
);

-- IX (aggregate_type, aggregate_id) serves the retention candidate anti-join
-- (a held signal is excluded) and the per-aggregate active-hold read
-- (HasActiveLegalHold). It is the only secondary read; ListLegalHolds walks it
-- too (ordered by created_at).
CREATE INDEX legal_holds_aggregate_type_aggregate_id_idx ON legal_holds (aggregate_type, aggregate_id);

COMMENT ON TABLE legal_holds IS
    'Documented legal holds (ARCH-007 §2.1, §13.4 step 2): one row per held aggregate; an active hold (released_at IS NULL) blocks both deletion and pseudonymisation of the aggregate and preserves the original record as-is';
COMMENT ON COLUMN legal_holds.id IS
    'Hold id; the release acts by id (set-once)';
COMMENT ON COLUMN legal_holds.aggregate_type IS
    'Type of the held aggregate (default risk_signal — the MVP retention subject); polymorphic like audit_events.aggregate_type';
COMMENT ON COLUMN legal_holds.aggregate_id IS
    'UUID of the held aggregate (polymorphic — no FK, the aggregate type disambiguates)';
COMMENT ON COLUMN legal_holds.reason IS
    'Documented justification of the hold (mandatory, ch. 13.4)';
COMMENT ON COLUMN legal_holds.actor_id IS
    'Principal that set the hold (audited, ARCH-007 §2.1)';
COMMENT ON COLUMN legal_holds.created_at IS
    'Hold instant from the injected clock';
COMMENT ON COLUMN legal_holds.released_at IS
    'Release instant from the injected clock; NULL = active hold, non-NULL = released (a release is set-once)';

-- retention_runs (ARCH-007 §2.1/§2.2): the retention report — one row per
-- run/partition. It carries the dry-run counts (dry_run jsonb: candidates /
-- held / to_pseudonymise / to_delete, counts only, no business content), the
-- four-eyes approval (approved_by/approved_at/approval_reason — the Product
-- Owner's settings.approve authorises the deletion) and the final counts. The
-- stage column is the two-value vocabulary (§13.4: pseudonymise runs before
-- delete); status is the fixed lifecycle vocabulary enforced as a DB CHECK
-- (dry_run → approved → executing → completed, plus failed/rejected — the
-- same controlled-vocabulary style as user_roles.role and
-- inventory_imports.status). The row survives the deletion of the signals it
-- reports on (no FK); it is the operational record that remains (§13.4
-- step 5).
CREATE TABLE retention_runs (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id            text        NOT NULL,
    stage                text        NOT NULL,
    cutoff               timestamptz NOT NULL,
    partition_key        text        NOT NULL,
    status               text        NOT NULL,
    dry_run              jsonb       NULL,
    approved_by          text        NULL,
    approved_at          timestamptz NULL,
    approval_reason      text        NULL,
    started_at           timestamptz NULL,
    finished_at          timestamptz NULL,
    pseudonymised_count  int         NOT NULL DEFAULT 0,
    deleted_count        int         NOT NULL DEFAULT 0,
    failed_count         int         NOT NULL DEFAULT 0,
    last_error           text        NULL,
    CONSTRAINT retention_runs_stage_check CHECK (stage IN ('pseudonymise', 'delete')),
    CONSTRAINT retention_runs_status_check CHECK (status IN ('dry_run', 'approved', 'executing', 'completed', 'failed', 'rejected'))
);

COMMENT ON TABLE retention_runs IS
    'Retention reports (ARCH-007 §2.1/§2.2): one row per run/partition carrying the dry-run counts, the four-eyes approval and the final counts only (no business content); the row survives the deletion it reports on';
COMMENT ON COLUMN retention_runs.id IS
    'Run id; the lifecycle transitions (approve/execute/complete/fail) act by id';
COMMENT ON COLUMN retention_runs.policy_id IS
    'Retention policy the run applies, e.g. closed-signals-5y (the job idempotency key is policy_id + cutoff + batch)';
COMMENT ON COLUMN retention_runs.stage IS
    'Retention stage: pseudonymise | delete (retention_runs_stage_check) — pseudonymise runs before delete (§13.4)';
COMMENT ON COLUMN retention_runs.cutoff IS
    'Retention cutoff from the injected clock (closed_at <= cutoff are candidates); part of the job idempotency key';
COMMENT ON COLUMN retention_runs.partition_key IS
    'Stable partition of the run (month bucket / id-hash range); one partition per row, part of the job idempotency key';
COMMENT ON COLUMN retention_runs.status IS
    'Lifecycle: dry_run | approved | executing | completed | failed | rejected (retention_runs_status_check) — only an approved run may be executed';
COMMENT ON COLUMN retention_runs.dry_run IS
    'Dry-run counts only (candidates / held / to_pseudonymise / to_delete) — no business content (ARCH-007 §2.1)';
COMMENT ON COLUMN retention_runs.approved_by IS
    'Approving principal (four-eyes: the Product Owner holding settings.approve); NULL until approved';
COMMENT ON COLUMN retention_runs.approved_at IS
    'Approval instant from the injected clock; NULL until approved';
COMMENT ON COLUMN retention_runs.approval_reason IS
    'Mandatory approval reason (ch. 13.4 four-eyes); NULL until approved';
COMMENT ON COLUMN retention_runs.started_at IS
    'Execution start instant from the injected clock; NULL until executing';
COMMENT ON COLUMN retention_runs.finished_at IS
    'Run end instant from the injected clock; NULL until completed or failed';
COMMENT ON COLUMN retention_runs.pseudonymised_count IS
    'Rows pseudonymised by the run (final counter, default 0)';
COMMENT ON COLUMN retention_runs.deleted_count IS
    'Rows deleted by the run (final counter, default 0)';
COMMENT ON COLUMN retention_runs.failed_count IS
    'Batches that failed within the run (final counter, default 0); a failing batch never fails the run silently';
COMMENT ON COLUMN retention_runs.last_error IS
    'Error text of the last failed batch/run; NULL when none failed';
COMMENT ON CONSTRAINT retention_runs_stage_check ON retention_runs IS
    'The two-value retention stage vocabulary (ARCH-007 §2.1): pseudonymise | delete';
COMMENT ON CONSTRAINT retention_runs_status_check ON retention_runs IS
    'The fixed retention-run lifecycle vocabulary (ARCH-007 §2.2): dry_run | approved | executing | completed | failed | rejected';

-- exports (ARCH-007 §1.2): one export job. The frozen filter context and
-- created_at are fixed at creation; the generation stamps (storage_path,
-- row_count, size_bytes, checksum, schema_version, rule_version, expires_at)
-- are filled when the export.generate worker job completes and stay NULL while
-- the row is pending (or failed/expired). The artifact itself is a file in the
-- server-local export spool — exports are large, time-limited business-content
-- copies that self-expire and must not enter the audit/backup retention path,
-- so only the reference (storage_path/size_bytes/checksum) is stored here.
-- status is the fixed lifecycle vocabulary (pending | completed | failed |
-- expired) enforced as a DB CHECK; format is csv | json. The (status,
-- created_at) index serves the expiry sweep (ListExpiredExports) and the
-- operator list ordered by creation instant.
CREATE TABLE exports (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    status         text        NOT NULL,
    filter         jsonb       NOT NULL,
    format         text        NOT NULL,
    storage_path   text        NULL,
    row_count      int         NULL,
    size_bytes     bigint      NULL,
    checksum       text        NULL,
    schema_version text        NULL,
    rule_version   text        NULL,
    created_by     text        NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NULL,
    last_error     text        NULL,
    CONSTRAINT exports_status_check CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
    CONSTRAINT exports_format_check CHECK (format IN ('csv', 'json'))
);

-- IX (status, created_at) serves the expiry sweep (status = completed AND
-- expires_at <= now, ordered by creation instant) and the operator list. The
-- by-id Get/Download resolves through the primary key.
CREATE INDEX exports_status_created_at_idx ON exports (status, created_at);

COMMENT ON TABLE exports IS
    'Asynchronous export jobs (ARCH-007 §1.2, FR-022/AT-014): the frozen filter context + format and the generation stamps; the artifact lives in the server-local spool, only its reference is stored here';
COMMENT ON COLUMN exports.id IS
    'Export id returned by POST /exports (gen_random_uuid()) and resolved by the status/download endpoints';
COMMENT ON COLUMN exports.status IS
    'Lifecycle: pending | completed | failed | expired (exports_status_check) — pending at creation, stamped by the export.generate job and the expiry sweep';
COMMENT ON COLUMN exports.filter IS
    'Frozen signal filter context (ch. 10.4 vocabulary) + creation time; never changes after creation (ARCH-007 §1.2)';
COMMENT ON COLUMN exports.format IS
    'Serialisation format: csv | json (exports_format_check)';
COMMENT ON COLUMN exports.storage_path IS
    'Server-local spool path of the materialised artifact; NULL until completed (never a bytea — the artifact stays out of the audit/backup path)';
COMMENT ON COLUMN exports.row_count IS
    'Materialised row count; NULL until completed';
COMMENT ON COLUMN exports.size_bytes IS
    'Artifact size in bytes; NULL until completed';
COMMENT ON COLUMN exports.checksum IS
    'SHA-256 of the artifact; NULL until completed';
COMMENT ON COLUMN exports.schema_version IS
    'Export schema version stamped at generation; NULL until completed';
COMMENT ON COLUMN exports.rule_version IS
    'Priority-rule version at generation time; NULL until completed';
COMMENT ON COLUMN exports.created_by IS
    'Principal that created the export (audited); the object-scope creator for an assigned grant';
COMMENT ON COLUMN exports.created_at IS
    'Creation instant from the injected clock (frozen at creation)';
COMMENT ON COLUMN exports.expires_at IS
    'Artifact expiry (created_at + export.ttl); NULL until completed; the download checks it against the injected clock';
COMMENT ON COLUMN exports.last_error IS
    'Error text of the failed generation; NULL while pending/completed';
COMMENT ON CONSTRAINT exports_status_check ON exports IS
    'The fixed export lifecycle vocabulary (ARCH-007 §1.2): pending | completed | failed | expired';
COMMENT ON CONSTRAINT exports_format_check ON exports IS
    'The export format vocabulary (ARCH-007 §1.2): csv | json';
