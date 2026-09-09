-- 00004_i2_sources_evidence.sql — I2 sources & evidence schema (ARCH-002 §3,
-- WP-2.02).
--
-- Adds the I2 minimal data model to the I1b schema (migrations 00002/00003):
--   * quarantine — the ch. 8.6 isolation state machine;
--   * epss_current — the current EPSS daily set (ADR-013: TRUNCATE + COPY
--     loaded, no foreign keys onto it);
--   * raw_records.payload jsonb -> bytea + content_encoding (ADR-013: a raw
--     record is the unchanged source document/file bytes — the compressed
--     EPSS file, the KEV catalog, the NVD page — not JSON; the sqlc layer
--     already maps the column to []byte, so no Go signatures change);
--   * source_runs.cursor_before/cursor_after (ch. 7.1 cursor bookkeeping);
--   * vulnerabilities.description/cvss/references/cpe_config (the full NVD
--     fields, all nullable so I1b rows stay valid).
--
-- Every change is an extension or a byte-compatible column change; nothing
-- is renamed. I3/I4 tables and columns (epss_history, the candidate
-- pre-filter/index, components cpe/purl/image/digest, alias/decision rules,
-- priority state) are deliberately NOT added (ARCH-002 §7).
--
-- Identifier rules (implementation concept ch. 7.2, ARCH-001 §1): uuid
-- primary keys via gen_random_uuid(), every timestamp timestamptz. The
-- quarantine acknowledged_*/resolved_* timestamps and created_at/updated_at
-- come from the injected clock like the I1b state-machine rows
-- (matches/risk_signals), not from the DB wall clock.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- quarantine — the ch. 8.6 isolation state machine (ARCH-002 §3/§4). One row
-- per record slice that failed to parse or normalise, written in the same
-- transaction as the run counters: the failure is positioned (position),
-- attributed (source_id, source_run_id, raw_record_id) and re-addressable on
-- reprocess (payload_hash — SHA-256 of the offending record/slice). The run
-- itself continues and succeeds: an isolated error is counted, not fatal
-- (ch. 8.1 step 5). status holds the state machine new -> acknowledged ->
-- ready_for_retry -> resolved (reprocess failures stay retryable with
-- attempts + 1); the acknowledged_*/resolved_* columns are written by the
-- operator/reprocess paths only. IX (status) serves the monitor/open-count
-- read; IX (source_id) and IX (source_run_id) the per-source/per-run reads.
CREATE TABLE quarantine (
    id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id                 uuid        NOT NULL REFERENCES sources (id),
    source_run_id             uuid        NULL REFERENCES source_runs (id),
    raw_record_id             uuid        NULL REFERENCES raw_records (id),
    position                  text        NOT NULL,
    reason                    text        NOT NULL,
    payload_hash              text        NOT NULL,
    status                    text        NOT NULL,
    attempts                  integer     NOT NULL DEFAULT 0,
    acknowledged_at           timestamptz NULL,
    acknowledged_by           text        NULL,
    acknowledged_note         text        NULL,
    resolved_at               timestamptz NULL,
    resolved_vulnerability_id uuid        NULL REFERENCES vulnerabilities (id),
    resolved_evidence_id      uuid        NULL REFERENCES evidences (id),
    resolved_note             text        NULL,
    created_at                timestamptz NOT NULL,
    updated_at                timestamptz NOT NULL,
    CONSTRAINT quarantine_status_check CHECK (status IN ('new', 'acknowledged', 'ready_for_retry', 'resolved'))
);

CREATE INDEX quarantine_status_idx ON quarantine (status);
CREATE INDEX quarantine_source_id_idx ON quarantine (source_id);
CREATE INDEX quarantine_source_run_id_idx ON quarantine (source_run_id);

COMMENT ON TABLE quarantine IS
    'Isolated parse/normalise failures (ch. 8.6 state machine, ARCH-002 §3): one row per offending record slice, positioned, attributed and re-addressable via payload_hash';
COMMENT ON COLUMN quarantine.position IS
    'Position of the offending slice within the raw payload: byte offset, line number or JSON pointer';
COMMENT ON COLUMN quarantine.reason IS
    'Stable error_code plus human message (ch. 5.2), e.g. parse.invalid_cve_id: CVE id is empty';
COMMENT ON COLUMN quarantine.payload_hash IS
    'SHA-256 of the offending record/slice — re-addresses the record on reprocess';
COMMENT ON COLUMN quarantine.status IS
    'new | acknowledged | ready_for_retry | resolved (ch. 8.6 state machine); reprocess failures increment attempts and stay retryable';
COMMENT ON COLUMN quarantine.attempts IS
    'Reprocess attempts; incremented on every failed reprocess';
COMMENT ON COLUMN quarantine.acknowledged_at IS
    'When the operator acknowledged the row; NULL until then';
COMMENT ON COLUMN quarantine.acknowledged_by IS
    'Operator principal that acknowledged the row (system in I2, ch. 13.2)';
COMMENT ON COLUMN quarantine.acknowledged_note IS
    'Operator note written with the acknowledgement';
COMMENT ON COLUMN quarantine.resolved_at IS
    'When reprocess succeeded and the row left the quarantine';
COMMENT ON COLUMN quarantine.resolved_vulnerability_id IS
    'Vulnerability created by the successful reprocess, when the record normalised to one';
COMMENT ON COLUMN quarantine.resolved_evidence_id IS
    'Evidence created by the successful reprocess, when the record normalised to one';
COMMENT ON COLUMN quarantine.resolved_note IS
    'Outcome note of the successful reprocess';
COMMENT ON COLUMN quarantine.created_at IS
    'Isolation time from the injected clock (never the DB wall clock)';
COMMENT ON COLUMN quarantine.updated_at IS
    'Last state change from the injected clock (never the DB wall clock)';

-- epss_current — the current EPSS daily set (ADR-013, ch. 8.4; ARCH-002 §3).
-- One row per scored CVE of the loaded day. The set is replaced whole by a
-- TRUNCATE + COPY inside one transaction at load time, so the table carries
-- no surrogate id and no per-row bookkeeping: cve_id is the natural primary
-- key (a malformed duplicate-cve CSV fails the COPY loudly) and no foreign
-- key points onto this table (prioritisation reads by cve_id lookup, and
-- TRUNCATE stays unfettered). score and percentile hold the raw EPSS
-- probability values in [0,1]; model_version tags the scoring model/date;
-- loaded_at is the run fetch time from the clock port. epss_history is I3
-- and is deliberately NOT created here (ADR-012/013, ARCH-002 §7).
CREATE TABLE epss_current (
    cve_id        text        PRIMARY KEY,
    score         numeric     NOT NULL,
    percentile    numeric     NOT NULL,
    model_version text        NOT NULL,
    loaded_at     timestamptz NOT NULL
);

COMMENT ON TABLE epss_current IS
    'Current EPSS daily set (ADR-013, ARCH-002 §3): one row per scored CVE, replaced atomically by TRUNCATE + COPY; read by cve_id lookup';
COMMENT ON COLUMN epss_current.cve_id IS
    'CVE id, the natural key of the set (no surrogate id — TRUNCATE + COPY friendly)';
COMMENT ON COLUMN epss_current.score IS
    'EPSS score, the probability in [0,1] the CVE is exploited';
COMMENT ON COLUMN epss_current.percentile IS
    'EPSS percentile in [0,1] of the score within the set';
COMMENT ON COLUMN epss_current.model_version IS
    'EPSS scoring model/date of the loaded set, e.g. 2026-09-09';
COMMENT ON COLUMN epss_current.loaded_at IS
    'Fetch time of the loaded set from the clock port (never the DB wall clock)';

-- raw_records.payload jsonb -> bytea (ADR-013, ARCH-002 §3): a raw record is
-- the unchanged source document/file bytes — the compressed EPSS file, the
-- KEV catalog, the NVD page — not JSON. The pre-existing (I1b) rows are
-- synthetic JSON documents stored as jsonb; they are backfilled with their
-- UTF-8 JSON text bytes via convert_to(payload::text, 'UTF8'), so every
-- stored payload is exactly what the source adapter wrote. The sqlc layer
-- already maps the column to []byte (gen/raw_records.sql.go), so no Go
-- signature changes here.
ALTER TABLE raw_records
    ALTER COLUMN payload TYPE bytea
    USING convert_to(payload::text, 'UTF8');

-- content_encoding makes a stored payload self-describing for reprocess
-- (ARCH-002 §3): 'identity' | 'gzip' | 'json', written by the adapter that
-- fetched the document. The rows converted above are UTF-8 JSON by
-- construction (they were jsonb), so they are stamped 'json' here.
ALTER TABLE raw_records
    ADD COLUMN content_encoding text NULL;

UPDATE raw_records
   SET content_encoding = 'json'
 WHERE content_encoding IS NULL;

COMMENT ON COLUMN raw_records.payload IS
    'Unchanged source document bytes (ch. 8.1 step 4, ADR-013): jsonb in I1b, bytea from 00004 on — the raw record is the file/document, not the row';
COMMENT ON COLUMN raw_records.content_encoding IS
    'Encoding of the stored payload bytes: identity | gzip | json — set by the fetching adapter, self-describing for reprocess';

-- source_runs gains cursor bookkeeping (ch. 7.1, ARCH-002 §1/§3):
-- cursor_before is the cursor value when the run opened, cursor_after the
-- cursor committed with a successful run. cursor_after stays NULL on failure
-- — the cursor advances only after the commit of a successful run (ch. 6.1)
-- — and full-set sources (KEV, EPSS) leave both NULL.
ALTER TABLE source_runs
    ADD COLUMN cursor_before jsonb NULL,
    ADD COLUMN cursor_after  jsonb NULL;

COMMENT ON COLUMN source_runs.cursor_before IS
    'Cursor value when the run opened (e.g. NVD last_modified window start); NULL for full-set sources';
COMMENT ON COLUMN source_runs.cursor_after IS
    'Cursor committed with a successful run (ch. 6.1); NULL on failure — the cursor advances only after commit';

-- vulnerabilities gains the full NVD fields (ARCH-002 §2.1/§3): the English
-- description, the cvss metrics block {version, base_score, base_severity,
-- vector}, the references array and the raw NVD configurations block
-- (cpe_config — normalised into the product index in I3). All columns are
-- nullable so the I1b skeleton rows stay valid; summary/published_at/
-- modified_at keep their semantics (published_at stays the original on
-- refresh, ch. 8.2).
--
-- references is a reserved keyword in PostgreSQL and is therefore always
-- quoted as "references" (also in the sqlc queries, WP-2.03).
ALTER TABLE vulnerabilities
    ADD COLUMN description text   NULL,
    ADD COLUMN cvss        jsonb  NULL,
    ADD COLUMN "references" jsonb NULL,
    ADD COLUMN cpe_config  jsonb  NULL;

COMMENT ON COLUMN vulnerabilities.description IS
    'Full English description of the vulnerability (I2+, NVD); NULL on I1b/KEV skeleton rows';
COMMENT ON COLUMN vulnerabilities.cvss IS
    'CVSS metrics block {version, base_score, base_severity, vector} (ARCH-002 §2.1); the prioritisation cvss evidence shape';
COMMENT ON COLUMN vulnerabilities."references" IS
    'References array of the NVD record (I2+)';
COMMENT ON COLUMN vulnerabilities.cpe_config IS
    'Raw NVD configurations block (I2+); normalised into the product index in I3';
