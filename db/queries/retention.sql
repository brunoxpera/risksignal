-- retention: the governed retention-run statements (ARCH-007 §2.1/§2.2/§2.3,
-- WP-6.02 / DEV-112).
--
-- Retention is a governed, partitionable, monthly maintenance run over the
-- existing signal set — never an automatic per-row trigger (ARCH-007 §2).
-- The candidate scan drives the dry-run; the legal-hold statements are the
-- §13.4 step 2 override that blocks both deletion and pseudonymisation; the
-- retention_runs statements are the run lifecycle (dry_run → approved →
-- executing → completed, plus failed/rejected) whose row is the retention
-- report that survives the deletion. The referentially-safe deletion order
-- itself (§2.3) is a transactional batch in the retention.execute use case —
-- it is not re-expressed here, and no statement here changes the append path.

-- ListRetentionCandidates returns the closed signals due for retention: a
-- closed status (resolved | accepted | not_affected — domain.SignalStatus
-- .IsClosed), a non-NULL closed_at <= @cutoff (cutoff = clock.Now() −
-- retention.closed_signal_years), and no *active* legal hold (§13.4 step 2).
-- A reopened signal has its closed_at cleared, so it is excluded by the
-- closed_at IS NOT NULL guard — no separate "reopened" flag is needed. The
-- active-hold anti-join walks IX (aggregate_type, aggregate_id); the result is
-- ordered by closed_at then id (the stable, partition-friendly order). No due
-- signal yields no rows, never an error.
-- name: ListRetentionCandidates :many
SELECT rs.*
FROM risk_signals rs
WHERE rs.status IN ('resolved', 'accepted', 'not_affected')
  AND rs.closed_at IS NOT NULL
  AND rs.closed_at <= @cutoff
  AND NOT EXISTS (
      SELECT 1
      FROM legal_holds h
      WHERE h.aggregate_type = 'risk_signal'
        AND h.aggregate_id = rs.id
        AND h.released_at IS NULL
  )
ORDER BY rs.closed_at, rs.id;

-- CreateLegalHold records one documented hold on one aggregate (§13.4 step 2):
-- the mandatory reason, the setting principal and the hold instant from the
-- injected clock; released_at stays NULL (active). aggregate_type is passed
-- explicitly (the column default is 'risk_signal'); the use case sets
-- 'risk_signal' for the MVP. Returns the stored row.
-- name: CreateLegalHold :one
INSERT INTO legal_holds (
    aggregate_type, aggregate_id, reason, actor_id, created_at
)
VALUES (
    @aggregate_type, @aggregate_id, @reason, @actor_id, @created_at
)
RETURNING *;

-- ReleaseLegalHold releases one hold by id (set-once): the `released_at IS
-- NULL` guard makes the release idempotent at the statement level — a second
-- release of the same hold matches zero rows (pgx.ErrNoRows), so the stored
-- release instant is never overwritten. released_at comes from the injected
-- clock. Returns the released row.
-- name: ReleaseLegalHold :one
UPDATE legal_holds
SET released_at = @released_at
WHERE id = @id
  AND released_at IS NULL
RETURNING *;

-- ListLegalHolds returns the holds for the operator view, ordered by hold
-- instant then id. aggregate_type, aggregate_id and active (true = active,
-- false = released) filter optionally — pass NULL to keep a filter open (the
-- same sqlc.narg style as ListSignals). No hold yields no rows, never an
-- error.
-- name: ListLegalHolds :many
SELECT *
FROM legal_holds
WHERE (sqlc.narg('aggregate_type')::text IS NULL OR aggregate_type = sqlc.narg('aggregate_type'))
  AND (sqlc.narg('aggregate_id')::uuid IS NULL OR aggregate_id = sqlc.narg('aggregate_id'))
  AND (sqlc.narg('active')::boolean IS NULL OR (released_at IS NULL) = sqlc.narg('active'))
ORDER BY created_at, id;

-- HasActiveLegalHold reports whether one aggregate currently has an active
-- hold (released_at IS NULL) — the per-aggregate check the pseudonymise/delete
-- paths and the legal-hold use cases take before touching an aggregate. It is
-- a single-row EXISTS over IX (aggregate_type, aggregate_id) and never errors
-- on a missing aggregate (false).
-- name: HasActiveLegalHold :one
SELECT EXISTS (
    SELECT 1
    FROM legal_holds
    WHERE aggregate_type = @aggregate_type
      AND aggregate_id = @aggregate_id
      AND released_at IS NULL
) AS active;

-- InsertRetentionRun records a new run/partition (ARCH-007 §2.2 step 1): the
-- dry-run inserts status 'dry_run' with the counts-only dry_run report; the
-- caller may pass status explicitly so the same statement records an
-- already-approved run in a future back-fill. dry_run is NULL for a run with
-- no report yet. The final counters keep their column default (0). Returns
-- the stored row.
-- name: InsertRetentionRun :one
INSERT INTO retention_runs (
    policy_id, stage, cutoff, partition_key, status, dry_run
)
VALUES (
    @policy_id, @stage, @cutoff, @partition_key, @status, @dry_run
)
RETURNING *;

-- GetRetentionRun reads one run by its id — the load step of the approve/
-- execute/complete use cases. A missing id is pgx.ErrNoRows, mapped to a
-- not-found error.
-- name: GetRetentionRun :one
SELECT *
FROM retention_runs
WHERE id = @id;

-- MarkRetentionRunApproved records the four-eyes approval (§2.2 step 2): the
-- approving principal (the Product Owner holding settings.approve), the
-- approval instant and the mandatory reason, flipping dry_run → approved. The
-- `status = 'dry_run'` guard makes the approval set-once (a second approval
-- matches zero rows) and — critically — means only a dry_run run can be
-- approved, so no deletion runs without an approved run. Returns the approved
-- row.
-- name: MarkRetentionRunApproved :one
UPDATE retention_runs
SET status          = 'approved',
    approved_by     = @approved_by,
    approved_at     = @approved_at,
    approval_reason = @approval_reason
WHERE id = @id
  AND status = 'dry_run'
RETURNING *;

-- MarkRetentionRunExecuting flips an approved run to 'executing' and stamps
-- started_at (§2.2 step 3). The `status = 'approved'` guard is the lifecycle
-- gate: the retention.execute job only claims approved runs, so an
-- un-approved run can never enter execution. Returns the executing row.
-- name: MarkRetentionRunExecuting :one
UPDATE retention_runs
SET status     = 'executing',
    started_at = @started_at
WHERE id = @id
  AND status = 'approved'
RETURNING *;

-- MarkRetentionRunCompleted closes an executing run with the final counts and
-- the end instant (§2.2 step 4): the counters (pseudonymised/deleted/failed)
-- and finished_at. The `status = 'executing'` guard makes completion follow
-- execution exactly. Returns the completed row — the retention report.
-- name: MarkRetentionRunCompleted :one
UPDATE retention_runs
SET status              = 'completed',
    finished_at         = @finished_at,
    pseudonymised_count = @pseudonymised_count,
    deleted_count       = @deleted_count,
    failed_count        = @failed_count
WHERE id = @id
  AND status = 'executing'
RETURNING *;

-- MarkRetentionRunFailed marks a run 'failed' with the end instant, the failed
-- batch count and the last error (§2.2 step 3: a failing batch stops only that
-- batch, but a run that cannot proceed is failed and visible). The guard
-- allows the failure from 'approved' (failure before/at start) or 'executing'
-- (failure during execution); a completed/rejected run is never failed
-- retroactively. Returns the failed row.
-- name: MarkRetentionRunFailed :one
UPDATE retention_runs
SET status       = 'failed',
    finished_at  = @finished_at,
    failed_count = @failed_count,
    last_error   = @last_error
WHERE id = @id
  AND status IN ('approved', 'executing')
RETURNING *;
