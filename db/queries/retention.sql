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
-- retention.closed_signal_years). A reopened signal has its closed_at
-- cleared, so it is excluded by the closed_at IS NOT NULL guard — no separate
-- "reopened" flag is needed.
--
-- Held candidates are SURFACED with their reason, not excluded (ARCH-007
-- §2.2 step 1, DEV-117 corrective): the `NOT EXISTS` anti-join of DEV-112
-- silently dropped a held signal, so the dry-run could never report the true
-- `held` count nor show the operator why a signal was blocked. The
-- LEFT JOIN LATERAL below brings each signal's *active* hold (released_at IS
-- NULL) and its documented reason; `held` is true exactly when such a hold
-- exists. The lateral is deterministic (earliest active hold by created_at,
-- id) so a signal with more than one active hold row still yields exactly one
-- candidate row — an ordinary LEFT JOIN could multiply the signal and
-- double-count it. The active-hold probe walks IX (aggregate_type,
-- aggregate_id); the result is ordered by closed_at then id (the stable,
-- partition-friendly order). No due signal yields no rows, never an error.
-- name: ListRetentionCandidates :many
SELECT
    rs.id                  AS signal_id,
    rs.closed_at           AS closed_at,
    (h.reason IS NOT NULL)::boolean AS held,
    COALESCE(h.reason, '') AS hold_reason
FROM risk_signals rs
LEFT JOIN LATERAL (
    SELECT lh.reason
    FROM legal_holds lh
    WHERE lh.aggregate_type = 'risk_signal'
      AND lh.aggregate_id = rs.id
      AND lh.released_at IS NULL
    ORDER BY lh.created_at, lh.id
    LIMIT 1
) h ON true
WHERE rs.status IN ('resolved', 'accepted', 'not_affected')
  AND rs.closed_at IS NOT NULL
  AND rs.closed_at <= @cutoff
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

-- ListRetentionRuns returns every stored run — the operator report read
-- behind GET /retention/runs (ARCH-007 §2.2 step 4). The rows survive the
-- deletion they report on; they are the operational record (§13.4 step 5)
-- and carry counts only. Ordered newest-cutoff first (cutoff DESC, then id)
-- so an operator sees the most recent proposal first; no run yields no rows,
-- never an error.
-- name: ListRetentionRuns :many
SELECT *
FROM retention_runs
ORDER BY cutoff DESC, id;

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

-- MarkRetentionRunRejected records a refused approval (dry_run → rejected,
-- ARCH-007 §2.2 step 2, DEV-117): the mandatory justification is stored and
-- the decision instant stamped, so the operator view shows why the run was
-- not authorised. Like the approval it is set-once — only a dry_run run can
-- be rejected (a second rejection matches zero rows), so a run that already
-- moved on is never retroactively refused. There is no dedicated rejected_at
-- column (retention_runs carries approved_at/approval_reason for the
-- decision), so the decision instant lands in approved_at. Returns the
-- rejected row.
-- name: MarkRetentionRunRejected :one
UPDATE retention_runs
SET status          = 'rejected',
    approved_at     = @rejected_at,
    approval_reason = @approval_reason
WHERE id = @id
  AND status = 'dry_run'
RETURNING *;

-- ClearSignalAuditActorDisplayNames clears the display name of every audit
-- row of one signal (ARCH-007 §3 redaction target set, DEV-117): the free
-- text of the actor identity is removed in place while actor_id (the
-- resolution key) is retained, so the identity stays reversible via the
-- governed audit.reveal_identity. Only rows that still carry a display name
-- are touched; the update reports the number of cleared rows.
-- name: ClearSignalAuditActorDisplayNames :execrows
UPDATE audit_events
SET actor_display_name = NULL
WHERE aggregate_type = 'risk_signal'
  AND aggregate_id = @signal_id
  AND actor_display_name IS NOT NULL;

-- RedactSignalCommentBodies replaces every non-empty comment body of one
-- signal with the fixed redaction marker (§3): the free text is
-- non-recoverable (ADR-014 — only the identity is reversible). The marker is
-- the application-layer RetentionRedactionMarker; an empty or already-marked
-- body is left untouched so the count is exactly the rows redacted.
-- name: RedactSignalCommentBodies :execrows
UPDATE comments
SET body = @marker
WHERE signal_id = @signal_id
  AND body <> ''
  AND body <> @marker;

-- RedactSignalOverrideReason replaces one signal's override free text with
-- the redaction marker (§3). It is redacted *in place* rather than cleared:
-- the risk_signals_override_check invariant requires the override quartet
-- (auto_priority/override_reason/override_actor_id/override_at) all-set or
-- all-NULL, so NULLing override_reason alone would violate the schema. The
-- structured override (computed value, actor, instant) is retained; only the
-- free text is removed.
-- name: RedactSignalOverrideReason :execrows
UPDATE risk_signals
SET override_reason = @marker
WHERE id = @signal_id
  AND override_reason IS NOT NULL
  AND override_reason <> ''
  AND override_reason <> @marker;

-- RedactSignalAuditBeforeReason replaces the free-text "reason" key inside
-- the `before` snapshot of one signal's audit rows with the redaction marker
-- (§3, DEV-117): the JSON is edited in place, every other (structured) key
-- is retained. Only rows whose before snapshot carries a reason other than
-- the marker are touched, so a second pseudonymisation is a no-op
-- (idempotent); the update reports their number. jsonb_exists is the function
-- form of the `?` key-existence operator (avoids placeholder ambiguity).
-- Snapshot reasons are non-empty when present (the snapshots serialise with
-- omitempty), so no emptiness guard is needed and a non-string reason is
-- simply skipped by the `->>` comparison.
-- name: RedactSignalAuditBeforeReason :execrows
UPDATE audit_events
SET before = jsonb_set(before, '{reason}', to_jsonb(@marker::text))
WHERE aggregate_type = 'risk_signal'
  AND aggregate_id = @signal_id
  AND jsonb_exists(before, 'reason')
  AND before->>'reason' <> @marker;

-- RedactSignalAuditAfterReason is the `after`-snapshot counterpart of
-- RedactSignalAuditBeforeReason (§3): one signal's audit rows whose after
-- snapshot carries a free-text reason, the reason replaced by the marker with
-- the structured keys retained.
-- name: RedactSignalAuditAfterReason :execrows
UPDATE audit_events
SET after = jsonb_set(after, '{reason}', to_jsonb(@marker::text))
WHERE aggregate_type = 'risk_signal'
  AND aggregate_id = @signal_id
  AND jsonb_exists(after, 'reason')
  AND after->>'reason' <> @marker;

-- ClearIdentityAuditActorDisplayNames clears the display name of every audit
-- row the identity acted on (ARCH-007 §3, ADR-014 point 5, DEV-117): the
-- standalone pseudonymisation's identity-scoped counterpart of
-- ClearSignalAuditActorDisplayNames. actor_id is retained (reversible).
-- name: ClearIdentityAuditActorDisplayNames :execrows
UPDATE audit_events
SET actor_display_name = NULL
WHERE actor_id = @user_id
  AND actor_display_name IS NOT NULL;

-- RedactIdentityCommentBodies replaces every non-empty comment body the
-- identity authored with the redaction marker (§3): the free text the identity
-- wrote is removed; the comment row and its actor_id are retained.
-- name: RedactIdentityCommentBodies :execrows
UPDATE comments
SET body = @marker
WHERE actor_id = @user_id
  AND body <> ''
  AND body <> @marker;

-- RedactIdentityOverrideReasons replaces the override reason of every signal
-- the identity overrode with the redaction marker (§3): redacted in place to
-- keep the risk_signals_override_check quartet intact (see
-- RedactSignalOverrideReason). override_actor_id is the resolution key and is
-- retained.
-- name: RedactIdentityOverrideReasons :execrows
UPDATE risk_signals
SET override_reason = @marker
WHERE override_actor_id = @user_id
  AND override_reason IS NOT NULL
  AND override_reason <> ''
  AND override_reason <> @marker;

-- RedactIdentityAuditBeforeReason replaces the free-text "reason" key inside
-- the `before` snapshot of the identity's audit rows with the redaction marker
-- (§3, ADR-014 point 5): the identity's snapshot free text is reduced, the
-- structured keys and actor_id retained. A reason already holding the marker
-- is skipped (idempotent).
-- name: RedactIdentityAuditBeforeReason :execrows
UPDATE audit_events
SET before = jsonb_set(before, '{reason}', to_jsonb(@marker::text))
WHERE actor_id = @user_id
  AND jsonb_exists(before, 'reason')
  AND before->>'reason' <> @marker;

-- RedactIdentityAuditAfterReason is the `after`-snapshot counterpart of
-- RedactIdentityAuditBeforeReason (§3).
-- name: RedactIdentityAuditAfterReason :execrows
UPDATE audit_events
SET after = jsonb_set(after, '{reason}', to_jsonb(@marker::text))
WHERE actor_id = @user_id
  AND jsonb_exists(after, 'reason')
  AND after->>'reason' <> @marker;

-- CountIdentityPseudonymisationTargets reports the rows a
-- PseudonymiseIdentity act would change, without changing anything — the
-- standalone command's mandatory dry-run (§3, ch. 11.3). Every predicate
-- matches the corresponding redaction statement above exactly (including the
-- marker-exclusion, so the preview is idempotent), so the preview equals the
-- real run's per-target counts. Snapshot reasons are counted per snapshot
-- (before + after), matching RetentionRedaction.SnapshotReasonsRedacted.
-- name: CountIdentityPseudonymisationTargets :one
SELECT
    (SELECT count(*) FROM audit_events ae WHERE ae.actor_id = @user_id AND ae.actor_display_name IS NOT NULL)::int AS display_names,
    (SELECT count(*) FROM comments cm WHERE cm.actor_id = @user_id AND cm.body <> '' AND cm.body <> @marker)::int AS comment_bodies,
    (SELECT count(*) FROM risk_signals rs WHERE rs.override_actor_id = @user_id AND rs.override_reason IS NOT NULL AND rs.override_reason <> '' AND rs.override_reason <> @marker)::int AS override_reasons,
    (SELECT count(*) FROM audit_events ae WHERE ae.actor_id = @user_id AND jsonb_exists(ae.before, 'reason') AND ae.before->>'reason' <> @marker)::int AS before_reasons,
    (SELECT count(*) FROM audit_events ae WHERE ae.actor_id = @user_id AND jsonb_exists(ae.after, 'reason') AND ae.after->>'reason' <> @marker)::int AS after_reasons;

-- DeleteRetentionSlaClocks deletes the signal's SLA clocks — the first step
-- of the referentially-safe §2.3 order (ARCH-007 §2.3, DEV-117). It is
-- per-table and scoped to one signal_id; the order itself is orchestrated by
-- the ExecuteRetention use case, not here. Returns the deleted row count.
-- name: DeleteRetentionSlaClocks :execrows
DELETE FROM sla_clocks
WHERE signal_id = @signal_id;

-- DeleteRetentionComments deletes the signal's comments (step 2 of §2.3).
-- name: DeleteRetentionComments :execrows
DELETE FROM comments
WHERE signal_id = @signal_id;

-- DeleteRetentionMatches deletes the match the signal references (step 3 of
-- §2.3). FK-safety note (DEV-117): risk_signals.match_id references matches
-- (id), so the match is the signal's *parent* — it cannot be removed while a
-- risk_signals row still references it. The `NOT EXISTS` guard therefore makes
-- this statement a no-op while the signal exists and is the FK-safe form of
-- the step; the match is actually removed together with the signal in
-- DeleteRetentionSignal once the reference is gone. Returns the deleted row
-- count (0 while the referencing signal still exists).
-- name: DeleteRetentionMatches :execrows
DELETE FROM matches
WHERE id = (SELECT rs.match_id FROM risk_signals rs WHERE rs.id = @signal_id)
  AND NOT EXISTS (
      SELECT 1 FROM risk_signals other WHERE other.match_id = matches.id
  );

-- DeleteRetentionNotifications deletes the signal's notifications (step 4 of
-- §2.3).
-- name: DeleteRetentionNotifications :execrows
DELETE FROM notifications
WHERE signal_id = @signal_id;

-- DeleteRetentionAuditEvents deletes the signal's audit trail (step 6 of
-- §2.3): the rows of aggregate_type 'risk_signal' for this signal only — after
-- the pseudonymisation, never before. The run's own retention.* audit rows
-- carry aggregate_type 'retention' and are untouched, so the retention report
-- survives (ARCH-007 §2.2 step 4).
-- name: DeleteRetentionAuditEvents :execrows
DELETE FROM audit_events
WHERE aggregate_type = 'risk_signal'
  AND aggregate_id = @signal_id;

-- GetSignalMatchID reads the match id a signal references — the helper the
-- adapter uses to remove the signal's match together with the signal
-- (DEV-117). A missing signal is pgx.ErrNoRows, which the adapter treats as
-- "already deleted" (the retention run is resumable).
-- name: GetSignalMatchID :one
SELECT match_id
FROM risk_signals
WHERE id = @signal_id;

-- DeleteRetentionSignal deletes the signal row itself — the last step of the
-- referentially-safe §2.3 order (ARCH-007 §2.3). FK-safety note (DEV-117):
-- risk_signals.match_id references matches (id), so the signal is the *child*
-- of its match; the signal must be removed before the match can be (the
-- DeleteRetentionMatches step is FK-guarded and a no-op while the signal
-- exists — see its comment). The adapter therefore deletes the signal here
-- and then its now-orphaned match (DeleteRetentionMatch), in the same
-- transaction. Returns the deleted signal row count.
-- name: DeleteRetentionSignal :execrows
DELETE FROM risk_signals
WHERE id = @signal_id;

-- DeleteRetentionMatch deletes one match by its id — the parent row that
-- DeleteRetentionSignal orphans. It is called (by the adapter) only after the
-- referencing signal is gone, so it never violates
-- risk_signals_match_id_fkey. Returns the deleted row count.
-- name: DeleteRetentionMatch :execrows
DELETE FROM matches
WHERE id = @match_id;
