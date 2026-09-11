package application

// This file owns the I6 retention and pseudonymisation surface of the
// application layer (ARCH-007 §2/§3, WP-6.05 / DEV-116): the vocabulary
// (policy, stage, run lifecycle), the run/legal-hold/redaction models and the
// single port the retention use cases (and the retention.execute worker job of
// WP-6.06) program against — the retention repository. The concrete postgres
// adapter is wired at the composition root; the application layer never
// imports the generated package (.go-arch-lint.yml).
//
// Retention is a governed, partitionable maintenance run, never an automatic
// per-row trigger (ARCH-007 §2). The run lifecycle is dry_run → approved →
// executing → completed (plus failed/rejected); only a dry-run run may be
// approved (four-eyes, settings.approve), and only an approved run may be
// executed. The run row is the retention report that survives the deletion it
// reports on (§13.4 step 5). A legal hold blocks both deletion and
// pseudonymisation of its aggregate. The referentially-safe deletion order
// itself (§2.3) is orchestrated by the ExecuteRetention use case against the
// per-table operations below — the port re-expresses no order, it only
// persists.

import (
	"context"
	"time"
)

// Retention policy vocabulary (ARCH-007 §2.1/§2.2).
const (
	// RetentionPolicyClosedSignals is the MVP retention policy id
	// (ARCH-007 §2.1): five years from closed_at (retention.closed_signal_years).
	RetentionPolicyClosedSignals = "closed-signals-5y"
	// AuditAggregateRetention is the aggregate type of the run-lifecycle audit
	// rows (retention.approved/rejected/executed): the run row is the
	// aggregate they describe.
	AuditAggregateRetention = "retention"
)

// Retention configuration defaults (ARCH-007 §2.4; injected via
// ServiceDeps).
const (
	// DefaultRetentionClosedSignalYears is the default retention period
	// (retention.closed_signal_years): the cutoff is closed_at <= now − this.
	DefaultRetentionClosedSignalYears = 5
	// DefaultRetentionBatchSize is the default bounded batch size
	// (retention.batch_size, the §14.1 recompute Richtwert).
	DefaultRetentionBatchSize = 500
)

// RetentionStage is the two-value retention stage vocabulary (ARCH-007 §2.1,
// retention_runs_stage_check): 'pseudonymise' runs before 'delete' (§13.4).
type RetentionStage string

// Allowed RetentionStage values (ARCH-007 §2.1).
const (
	// RetentionStagePseudonymise is the pseudonymisation stage: the run
	// redacts the due signals' identity/free text, it deletes nothing.
	RetentionStagePseudonymise RetentionStage = "pseudonymise"
	// RetentionStageDelete is the deletion stage: the run pseudonymises first
	// and then deletes the due signals in the §2.3 referentially-safe order.
	RetentionStageDelete RetentionStage = "delete"
)

// Valid reports whether s is an allowed RetentionStage value.
func (s RetentionStage) Valid() bool {
	switch s {
	case RetentionStagePseudonymise, RetentionStageDelete:
		return true
	}
	return false
}

// RetentionRunStatus is the retention-run lifecycle vocabulary (ARCH-007
// §2.1/§2.2, retention_runs_status_check). Only a dry_run run approves into
// 'approved'; only an approved run executes into 'executing'; the terminal
// states are completed, failed and rejected.
type RetentionRunStatus string

// Allowed RetentionRunStatus values (ARCH-007 §2.1/§2.2).
const (
	// RetentionStatusDryRun is the state a dry-run row is stored in; the
	// report (DryRun counts) is set, nothing was changed.
	RetentionStatusDryRun RetentionRunStatus = "dry_run"
	// RetentionStatusApproved records the four-eyes approval; only an approved
	// run may be executed.
	RetentionStatusApproved RetentionRunStatus = "approved"
	// RetentionStatusExecuting is the in-progress state of a claimed run.
	RetentionStatusExecuting RetentionRunStatus = "executing"
	// RetentionStatusCompleted is the terminal success state carrying the
	// final counts.
	RetentionStatusCompleted RetentionRunStatus = "completed"
	// RetentionStatusFailed is the terminal failure state; the run is
	// resumable (a re-scan skips already-deleted rows).
	RetentionStatusFailed RetentionRunStatus = "failed"
	// RetentionStatusRejected records a refused approval; the run is never
	// executed.
	RetentionStatusRejected RetentionRunStatus = "rejected"
)

// Valid reports whether s is an allowed RetentionRunStatus value.
func (s RetentionRunStatus) Valid() bool {
	switch s {
	case RetentionStatusDryRun, RetentionStatusApproved, RetentionStatusExecuting,
		RetentionStatusCompleted, RetentionStatusFailed, RetentionStatusRejected:
		return true
	}
	return false
}

// RetentionCounts is the counts-only dry-run report of one run/partition
// (ARCH-007 §2.1, retention_runs.dry_run): candidates / held / to_pseudonymise
// / to_delete. It is stored as jsonb and carries no business content — never a
// signal id, a title or a free-text value.
type RetentionCounts struct {
	// Candidates is the number of closed signals due at the cutoff without an
	// active legal hold (the actionable set).
	Candidates int `json:"candidates"`
	// Held is the number of due signals blocked by an active legal hold.
	Held int `json:"held"`
	// ToPseudonymise is the number of candidates the run's stage will
	// pseudonymise (the candidates of a pseudonymise-stage run, 0 otherwise).
	ToPseudonymise int `json:"to_pseudonymise"`
	// ToDelete is the number of candidates the run's stage will delete (the
	// candidates of a delete-stage run, 0 otherwise).
	ToDelete int `json:"to_delete"`
}

// RetentionRedaction counts the rows one pseudonymisation act changed (the
// §3 redaction target set). It is the minimised report of a redaction — counts
// only, never a value.
type RetentionRedaction struct {
	// DisplayNamesCleared is the number of audit rows whose actor display name
	// was cleared (actor_id and the users row are retained — reversible).
	DisplayNamesCleared int `json:"display_names_cleared"`
	// CommentBodiesRedacted is the number of comment bodies replaced by the
	// redaction marker.
	CommentBodiesRedacted int `json:"comment_bodies_redacted"`
	// OverrideReasonsRedacted is the number of signal override reasons cleared.
	OverrideReasonsRedacted int `json:"override_reasons_redacted"`
	// SnapshotReasonsRedacted is the number of audit before/after snapshots
	// whose free-text "reason" key was redacted.
	SnapshotReasonsRedacted int `json:"snapshot_reasons_redacted"`
}

// Total is the number of rows the redaction act changed.
func (r RetentionRedaction) Total() int {
	return r.DisplayNamesCleared + r.CommentBodiesRedacted + r.OverrideReasonsRedacted + r.SnapshotReasonsRedacted
}

// RetentionCandidate is one closed signal due at the cutoff (ARCH-007 §2.2
// step 1). Held marks a candidate blocked by an active legal hold (it is
// reported, never processed); HoldReason carries the documented hold reason
// for the operator view. It carries no business content beyond the hold reason.
type RetentionCandidate struct {
	SignalID   string
	ClosedAt   time.Time
	Held       bool
	HoldReason string
}

// RetentionRun is the stored run/report row (ARCH-007 §2.1, retention_runs):
// the operational record that survives the deletion it reports on (§13.4
// step 5). The zero time marks a NULL instant (not yet approved/started/
// finished); DryRun is nil until the dry-run report is stored.
type RetentionRun struct {
	ID           string
	PolicyID     string
	Stage        RetentionStage
	Cutoff       time.Time
	PartitionKey string
	Status       RetentionRunStatus
	DryRun       *RetentionCounts
	ApprovedBy   string
	ApprovedAt   time.Time
	// ApprovalReason is the mandatory four-eyes justification (empty until
	// approved).
	ApprovalReason string
	StartedAt      time.Time
	FinishedAt     time.Time
	Pseudonymised  int
	Deleted        int
	Failed         int
	LastError      string
}

// RetentionRunRecord is the insert payload of one dry-run row (ARCH-007 §2.2
// step 1): the policy, stage, cutoff, partition and the counts-only report.
// The id, the 'dry_run' status and the approval/execution columns' NULLs are
// assigned by the database.
type RetentionRunRecord struct {
	PolicyID     string
	Stage        RetentionStage
	Cutoff       time.Time
	PartitionKey string
	Counts       RetentionCounts
}

// RetentionRunCounts are the final counters a run is closed with (ARCH-007
// §2.2 step 4): the pseudonymised/deleted/failed counts; LastError is the
// text of the last failed batch ("" when none failed).
type RetentionRunCounts struct {
	Pseudonymised int
	Deleted       int
	Failed        int
	LastError     string
}

// LegalHold is one stored legal hold (ARCH-007 §2.1, legal_holds): a
// documented hold on one aggregate. ReleasedAt is the zero time while the hold
// is active — an active hold blocks both deletion and pseudonymisation of the
// aggregate (a hold preserves the original record as-is, §13.4 step 2).
type LegalHold struct {
	ID            string
	AggregateType string
	AggregateID   string
	Reason        string
	ActorID       string
	CreatedAt     time.Time
	ReleasedAt    time.Time // zero = active
}

// Active reports whether the hold is active (not yet released).
func (h LegalHold) Active() bool { return h.ReleasedAt.IsZero() }

// HoldRecord is the insert payload of one legal hold (ARCH-007 §2.1):
// aggregateType defaults to 'risk_signal' at the use case; the reason is the
// documented justification and actorID the setting principal; CreatedAt comes
// from the injected clock.
type HoldRecord struct {
	AggregateType string
	AggregateID   string
	Reason        string
	ActorID       string
	CreatedAt     time.Time
}

// HoldFilter narrows the legal-hold list read. Empty strings and a nil Active
// keep the filter open (the same shape as ListSignals/sqlc.narg).
type HoldFilter struct {
	AggregateType string
	AggregateID   string
	Active        *bool
}

// RetentionRepo persists and reads the retention state (ARCH-007 §2/§3,
// WP-6.02 / DEV-112): the candidate scan, the run-lifecycle CRUD, the
// legal-hold CRUD, the in-place pseudonymisation and the per-table deletion
// primitives of the referentially-safe order (§2.3). Every mutating method
// runs on the caller's transaction so a state change and its audit event
// commit or roll back together (one command, one transaction, ch. 5.1); the
// reads (candidate scan, GetRun, ListHolds, the redaction preview) are
// pool-scoped. The concrete DEV-112 postgres adapter maps the stored rows onto
// the models above, so the application layer never imports the generated
// package.
//
// The Delete* methods are deliberately per-table and unordered: the §2.3
// deletion order is the ExecuteRetention use case's responsibility, and the
// port carries no shared-table operation — evidences, vulnerabilities and
// raw_records are never deleted by signal retention (their own TTLs govern
// them, §2.3).
type RetentionRepo interface {
	// ScanRetentionCandidates returns every closed signal whose closed_at is
	// at or before cutoff (the retention countdown has expired), together with
	// whether an active legal hold blocks it. Held candidates are included
	// (Held=true, with the documented reason) so the dry-run can report them;
	// the execute path skips them. Ordered by closed_at then id. No due signal
	// yields an empty slice, never an error.
	ScanRetentionCandidates(ctx context.Context, cutoff time.Time) ([]RetentionCandidate, error)

	// InsertRun stores one dry-run row (status 'dry_run') with the counts-only
	// report on the caller's transaction and returns the stored row.
	InsertRun(ctx context.Context, tx Tx, rec RetentionRunRecord) (RetentionRun, error)

	// GetRun reads one run by its id — the load step of the approve/execute
	// use cases. A missing id is a not-found Error.
	GetRun(ctx context.Context, id string) (RetentionRun, error)

	// ListRuns returns every stored retention run — the operator report read
	// behind GET /retention/runs (ARCH-007 §2.2 step 4). Ordered newest-cutoff
	// first (cutoff DESC, then id) so an operator sees the most recent
	// proposal first; no run yields an empty slice, never an error.
	ListRuns(ctx context.Context) ([]RetentionRun, error)

	// ApproveRun records the four-eyes approval (dry_run → approved) with the
	// approving principal, the approval instant and the mandatory reason. The
	// dry_run guard makes the approval set-once; a run not in dry_run is a
	// conflict Error. Returns the approved row.
	ApproveRun(ctx context.Context, tx Tx, id, approvedBy, reason string, at time.Time) (RetentionRun, error)

	// RejectRun records a refused approval (dry_run → rejected) with the
	// mandatory reason. A run not in dry_run is a conflict Error. Returns the
	// rejected row.
	RejectRun(ctx context.Context, tx Tx, id, reason string, at time.Time) (RetentionRun, error)

	// StartRun claims an approved run (approved → executing) and stamps
	// started_at. The approved guard is the lifecycle gate: an un-approved run
	// is a conflict Error and can never enter execution. Returns the executing
	// row.
	StartRun(ctx context.Context, tx Tx, id string, at time.Time) (RetentionRun, error)

	// CompleteRun closes an executing run with the final counts and the end
	// instant. A run not in executing is a conflict Error. Returns the
	// completed row — the retention report.
	CompleteRun(ctx context.Context, tx Tx, id string, counts RetentionRunCounts, at time.Time) (RetentionRun, error)

	// FailRun marks an approved/executing run failed with the end instant, the
	// failed-batch count and the last error. A completed/rejected run is a
	// conflict Error. Returns the failed row.
	FailRun(ctx context.Context, tx Tx, id string, counts RetentionRunCounts, at time.Time) (RetentionRun, error)

	// HasActiveHold reports whether one aggregate currently has an active hold
	// (released_at IS NULL) — the per-aggregate check the execute path takes
	// before touching an aggregate. A missing aggregate is false, never an
	// error.
	HasActiveHold(ctx context.Context, aggregateType, aggregateID string) (bool, error)

	// CreateHold stores one documented hold on the caller's transaction and
	// returns the stored row (active).
	CreateHold(ctx context.Context, tx Tx, rec HoldRecord) (LegalHold, error)

	// ReleaseHold releases one hold by id (set-once) at the injected instant
	// and returns the released row. An already-released (or unknown) hold is a
	// conflict/not-found Error.
	ReleaseHold(ctx context.Context, tx Tx, id string, at time.Time) (LegalHold, error)

	// ListHolds returns the holds matching filter, ordered by created_at then
	// id. No hold yields an empty slice, never an error.
	ListHolds(ctx context.Context, filter HoldFilter) ([]LegalHold, error)

	// PseudonymiseSignal redacts one signal's free text in place and clears
	// the actor display names of its audit rows on the caller's transaction
	// (§3): comments.body of the signal, risk_signals.override_reason, the
	// free-text "reason" key inside the signal's before/after audit snapshots
	// and audit_events.actor_display_name. actor_id and the users row are
	// retained (reversible via audit.reveal_identity). It reports the per-target
	// counts.
	PseudonymiseSignal(ctx context.Context, tx Tx, signalID string) (RetentionRedaction, error)

	// PseudonymiseIdentity redacts one user's identity in place (§3, ADR-014
	// point 5): clears audit_events.actor_display_name of the user's audit rows
	// and redacts the free text the user authored or triggered — comments.body
	// (actor_id), risk_signals.override_reason (override_actor_id) and the
	// "reason" key inside their before/after snapshots. actor_id and the users
	// row are retained. It reports the per-target counts.
	PseudonymiseIdentity(ctx context.Context, tx Tx, userID string) (RetentionRedaction, error)

	// PreviewPseudonymiseIdentity reports the rows a PseudonymiseIdentity call
	// would change, without changing anything — the standalone command's
	// mandatory dry-run.
	PreviewPseudonymiseIdentity(ctx context.Context, userID string) (RetentionRedaction, error)

	// DeleteSlaClocks deletes the signal's SLA clocks and returns the deleted
	// row count. It is the first step of the §2.3 referentially-safe order.
	DeleteSlaClocks(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeleteComments deletes the signal's comments (step 2).
	DeleteComments(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeleteMatches deletes the match the signal references (step 3).
	DeleteMatches(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeleteNotifications deletes the signal's notifications (step 4).
	DeleteNotifications(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeletePriorityFactors deletes the signal-scoped priority factors (step 5).
	DeletePriorityFactors(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeleteAuditEvents deletes the signal's audit rows (aggregate_type
	// 'risk_signal', step 6) — after the pseudonymisation, never before.
	DeleteAuditEvents(ctx context.Context, tx Tx, signalID string) (int, error)

	// DeleteSignal deletes the signal row itself (step 7, the last one).
	DeleteSignal(ctx context.Context, tx Tx, signalID string) (int, error)
}
