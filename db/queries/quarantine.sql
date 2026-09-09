-- quarantine: the ch. 8.6 isolation state machine statements (ARCH-002 §3/§4,
-- WP-2.03a). One row per record slice that failed to parse or normalise,
-- written in the same transaction as the run counters. status holds the state
-- machine new -> acknowledged -> ready_for_retry -> resolved; every state
-- change below is guarded on the source status of the transition table
-- (ARCH-002 §4) so a transition that does not apply matches zero rows and the
-- command layer sees pgx.ErrNoRows — it must not write the audit event of a
-- transition that did not happen (ch. 13.2: one command, one transaction).
-- created_at/updated_at and the acknowledged_*/resolved_* timestamps come
-- from the injected clock (ch. 7.2), never from the database wall clock.

-- InsertQuarantine isolates one failed record slice: the run continues and
-- succeeds (an isolated error is counted, not fatal — ch. 8.1 step 5), the
-- row is created in status 'new' with attempts at the column default 0. The
-- row is positioned (position), attributed (source_id, source_run_id,
-- raw_record_id — both run and raw record may be NULL when the failure
-- happened outside a run/raw record) and re-addressable on reprocess
-- (payload_hash). created_at and updated_at are the same clock instant of the
-- isolation; the caller supplies both.
-- name: InsertQuarantine :one
INSERT INTO quarantine (
    source_id,
    source_run_id,
    raw_record_id,
    position,
    reason,
    payload_hash,
    status,
    created_at,
    updated_at
)
VALUES (
    @source_id,
    @source_run_id,
    @raw_record_id,
    @position,
    @reason,
    @payload_hash,
    'new',
    @created_at,
    @updated_at
)
RETURNING *;

-- GetQuarantineByID loads one quarantined row by id — the read the reprocess
-- command (quarantine reprocess <id>) and the monitor open-count path start
-- from.
-- name: GetQuarantineByID :one
SELECT *
FROM quarantine
WHERE id = @id;

-- ListQuarantine is the working-list read of the quarantine (ARCH-002 §4,
-- ch. 11.3 quarantine list): oldest isolation first with id as the stable
-- tiebreak. status and source_id filter optionally — pass NULL to keep a
-- filter open (the open-count monitor read filters status = 'new' +
-- 'acknowledged' + 'ready_for_retry' per source).
-- name: ListQuarantine :many
SELECT *
FROM quarantine
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('source_id')::uuid IS NULL OR source_id = sqlc.narg('source_id'))
ORDER BY created_at, id
LIMIT @max_rows;

-- AcknowledgeQuarantine is the operator review transition new ->
-- acknowledged (ARCH-002 §4): records who acknowledged, when and the note.
-- Guarded on status = 'new' — an already acknowledged/resolved row is not
-- re-acknowledged, so a double ack matches zero rows and writes no audit
-- event.
-- name: AcknowledgeQuarantine :one
UPDATE quarantine
SET status            = 'acknowledged',
    acknowledged_at   = @acknowledged_at,
    acknowledged_by   = @acknowledged_by,
    acknowledged_note = @acknowledged_note,
    updated_at        = @updated_at
WHERE id = @id AND status = 'new'
RETURNING *;

-- MarkQuarantineReadyForRetry moves a reviewed row to the retryable state
-- (new / acknowledged -> ready_for_retry, ARCH-002 §4): the adapter, rule or
-- data has been fixed (e.g. normalizer_version bumped) and a reprocess may
-- pick the row up. Guarded on status IN ('new', 'acknowledged').
-- name: MarkQuarantineReadyForRetry :one
UPDATE quarantine
SET status     = 'ready_for_retry',
    updated_at = @updated_at
WHERE id = @id AND status IN ('new', 'acknowledged')
RETURNING *;

-- MarkQuarantineResolved is the terminal transition of a successful
-- reprocess (ready_for_retry or new -> resolved, ARCH-002 §4): resolved_at
-- plus the link to the domain object the reprocess materialised —
-- resolved_vulnerability_id and/or resolved_evidence_id (both NULL when the
-- record normalised to neither, e.g. a full-set outcome) — and a resolved_note
-- for other outcomes. Guarded on status IN ('ready_for_retry', 'new'); a
-- resolved row is terminal and never leaves that state.
-- name: MarkQuarantineResolved :one
UPDATE quarantine
SET status                    = 'resolved',
    resolved_at               = @resolved_at,
    resolved_vulnerability_id = @resolved_vulnerability_id,
    resolved_evidence_id      = @resolved_evidence_id,
    resolved_note             = @resolved_note,
    updated_at                = @updated_at
WHERE id = @id AND status IN ('ready_for_retry', 'new')
RETURNING *;

-- IncrementQuarantineAttempts records a failed reprocess (ARCH-002 §4:
-- reprocess failed -> attempts + 1, the row stays retryable): attempts is
-- bumped and the row keeps its retryable status — it can be reprocessed again
-- or moved back through the machine. Guarded on status IN ('new',
-- 'ready_for_retry'), the states a reprocess can launch from; the increment
-- never applies to a terminal row.
-- name: IncrementQuarantineAttempts :one
UPDATE quarantine
SET attempts   = attempts + 1,
    updated_at = @updated_at
WHERE id = @id AND status IN ('new', 'ready_for_retry')
RETURNING *;
