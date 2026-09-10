package repo

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// RetentionRepo is the postgres implementation of application.RetentionRepo
// (retention.sql, ARCH-007 §2/§3, WP-6.02 / DEV-112, adapter DEV-117): the
// candidate scan, the retention-run lifecycle, the legal-hold CRUD, the
// in-place pseudonymisation redactions and the per-table deletion primitives
// of the referentially-safe §2.3 order. Reads run on the pool-scoped query
// set; every mutating method rebinds through WithTx so the state change and
// its audit event commit or roll back together (one command, one transaction,
// ch. 5.1). Driver errors are translated to the typed application errors of
// ch. 5.2 (dbmap.go); a run/hold whose guarded transition matches no row is a
// conflict (the lifecycle gate), not a not-found.
type RetentionRepo struct {
	q *gen.Queries
}

// NewRetentionRepo binds the repository to one query set (pool-scoped for the
// reads; write methods rebind per transaction).
func NewRetentionRepo(q *gen.Queries) *RetentionRepo { return &RetentionRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.RetentionRepo = (*RetentionRepo)(nil)

// ScanRetentionCandidates implements application.RetentionRepo: every closed
// signal due at the cutoff, with the active-hold flag and reason surfaced
// (DEV-117). Ordered by closed_at then id (the stable, partition-friendly
// order); no due signal yields an empty slice, never an error.
func (r *RetentionRepo) ScanRetentionCandidates(ctx context.Context, cutoff time.Time) ([]application.RetentionCandidate, error) {
	const op = "retention.scan_candidates"

	rows, err := r.q.ListRetentionCandidates(ctx, toTS(cutoff))
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.RetentionCandidate, 0, len(rows))
	for _, row := range rows {
		out = append(out, application.RetentionCandidate{
			SignalID:   uuidString(row.SignalID),
			ClosedAt:   row.ClosedAt.Time,
			Held:       row.Held,
			HoldReason: row.HoldReason,
		})
	}
	return out, nil
}

// InsertRun implements application.RetentionRepo: store one dry_run row with
// the counts-only report on the caller's transaction. The id and the
// 'dry_run' status are database-assigned.
func (r *RetentionRepo) InsertRun(ctx context.Context, tx application.Tx, rec application.RetentionRunRecord) (application.RetentionRun, error) {
	const op = "retention.insert_run"

	counts, err := json.Marshal(rec.Counts)
	if err != nil {
		return application.RetentionRun{}, application.InfraError(op, err)
	}
	row, err := r.q.WithTx(tx).InsertRetentionRun(ctx, gen.InsertRetentionRunParams{
		PolicyID:     rec.PolicyID,
		Stage:        string(rec.Stage),
		Cutoff:       toTS(rec.Cutoff),
		PartitionKey: rec.PartitionKey,
		Status:       string(application.RetentionStatusDryRun),
		DryRun:       counts,
	})
	if err != nil {
		return application.RetentionRun{}, mapDBError(op, err)
	}
	return retentionRunFromRow(op, row)
}

// GetRun implements application.RetentionRepo: read one run by its id — the
// load step of the approve/execute/complete use cases. A missing id is a
// not-found Error.
func (r *RetentionRepo) GetRun(ctx context.Context, id string) (application.RetentionRun, error) {
	const op = "retention.get_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetRetentionRun(ctx, uid)
	if err != nil {
		return application.RetentionRun{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return retentionRunFromRow(op, row)
}

// ApproveRun implements application.RetentionRepo: the dry_run → approved
// four-eyes approval. The `status = 'dry_run'` guard makes it set-once; a run
// not in dry_run is a conflict Error, never a partial write.
func (r *RetentionRepo) ApproveRun(ctx context.Context, tx application.Tx, id, approvedBy, reason string, at time.Time) (application.RetentionRun, error) {
	const op = "retention.approve_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkRetentionRunApproved(ctx, gen.MarkRetentionRunApprovedParams{
		ApprovedBy:     toTextOpt(approvedBy),
		ApprovedAt:     toTS(at),
		ApprovalReason: toTextOpt(reason),
		ID:             uid,
	})
	if err != nil {
		return application.RetentionRun{}, retentionGuardMiss(op, err)
	}
	return retentionRunFromRow(op, row)
}

// RejectRun implements application.RetentionRepo: the dry_run → rejected
// refusal. The `status = 'dry_run'` guard makes it set-once; a run not in
// dry_run is a conflict Error.
func (r *RetentionRepo) RejectRun(ctx context.Context, tx application.Tx, id, reason string, at time.Time) (application.RetentionRun, error) {
	const op = "retention.reject_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkRetentionRunRejected(ctx, gen.MarkRetentionRunRejectedParams{
		RejectedAt:     toTS(at),
		ApprovalReason: toTextOpt(reason),
		ID:             uid,
	})
	if err != nil {
		return application.RetentionRun{}, retentionGuardMiss(op, err)
	}
	return retentionRunFromRow(op, row)
}

// StartRun implements application.RetentionRepo: claim an approved run
// (approved → executing). The `status = 'approved'` guard is the lifecycle
// gate; an un-approved run is a conflict Error and can never enter execution.
func (r *RetentionRepo) StartRun(ctx context.Context, tx application.Tx, id string, at time.Time) (application.RetentionRun, error) {
	const op = "retention.start_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkRetentionRunExecuting(ctx, gen.MarkRetentionRunExecutingParams{
		StartedAt: toTS(at),
		ID:        uid,
	})
	if err != nil {
		return application.RetentionRun{}, retentionGuardMiss(op, err)
	}
	return retentionRunFromRow(op, row)
}

// CompleteRun implements application.RetentionRepo: close an executing run
// with the final counts. The `status = 'executing'` guard makes completion
// follow execution exactly; otherwise a conflict Error.
func (r *RetentionRepo) CompleteRun(ctx context.Context, tx application.Tx, id string, counts application.RetentionRunCounts, at time.Time) (application.RetentionRun, error) {
	const op = "retention.complete_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	pseudo, err := retentionCountInt32(op, "pseudonymised", counts.Pseudonymised)
	if err != nil {
		return application.RetentionRun{}, err
	}
	deleted, err := retentionCountInt32(op, "deleted", counts.Deleted)
	if err != nil {
		return application.RetentionRun{}, err
	}
	failed, err := retentionCountInt32(op, "failed", counts.Failed)
	if err != nil {
		return application.RetentionRun{}, err
	}
	row, err := r.q.WithTx(tx).MarkRetentionRunCompleted(ctx, gen.MarkRetentionRunCompletedParams{
		FinishedAt:         toTS(at),
		PseudonymisedCount: pseudo,
		DeletedCount:       deleted,
		FailedCount:        failed,
		ID:                 uid,
	})
	if err != nil {
		return application.RetentionRun{}, retentionGuardMiss(op, err)
	}
	return retentionRunFromRow(op, row)
}

// FailRun implements application.RetentionRepo: mark an approved/executing run
// failed with the end instant, the failed-batch count and the last error. A
// completed/rejected run is a conflict Error.
func (r *RetentionRepo) FailRun(ctx context.Context, tx application.Tx, id string, counts application.RetentionRunCounts, at time.Time) (application.RetentionRun, error) {
	const op = "retention.fail_run"

	uid, err := toUUID(id)
	if err != nil {
		return application.RetentionRun{}, application.ValidationError(op, err)
	}
	failed, err := retentionCountInt32(op, "failed", counts.Failed)
	if err != nil {
		return application.RetentionRun{}, err
	}
	row, err := r.q.WithTx(tx).MarkRetentionRunFailed(ctx, gen.MarkRetentionRunFailedParams{
		FinishedAt:  toTS(at),
		FailedCount: failed,
		LastError:   toTextOpt(counts.LastError),
		ID:          uid,
	})
	if err != nil {
		return application.RetentionRun{}, retentionGuardMiss(op, err)
	}
	return retentionRunFromRow(op, row)
}

// HasActiveHold implements application.RetentionRepo: the per-aggregate active
// hold probe (released_at IS NULL); a missing aggregate is false, never an
// error.
func (r *RetentionRepo) HasActiveHold(ctx context.Context, aggregateType, aggregateID string) (bool, error) {
	const op = "retention.has_active_hold"

	aid, err := toUUID(aggregateID)
	if err != nil {
		return false, application.ValidationError(op, err)
	}
	active, err := r.q.HasActiveLegalHold(ctx, gen.HasActiveLegalHoldParams{
		AggregateType: aggregateType,
		AggregateID:   aid,
	})
	if err != nil {
		return false, mapDBError(op, err)
	}
	return active, nil
}

// CreateHold implements application.RetentionRepo: store one documented hold
// on the caller's transaction and return the stored row (active).
func (r *RetentionRepo) CreateHold(ctx context.Context, tx application.Tx, rec application.HoldRecord) (application.LegalHold, error) {
	const op = "retention.create_hold"

	aid, err := toUUID(rec.AggregateID)
	if err != nil {
		return application.LegalHold{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).CreateLegalHold(ctx, gen.CreateLegalHoldParams{
		AggregateType: rec.AggregateType,
		AggregateID:   aid,
		Reason:        rec.Reason,
		ActorID:       rec.ActorID,
		CreatedAt:     toTS(rec.CreatedAt),
	})
	if err != nil {
		return application.LegalHold{}, mapDBError(op, err)
	}
	return legalHoldFromRow(row), nil
}

// ReleaseHold implements application.RetentionRepo: release one hold by id
// (set-once). The `released_at IS NULL` guard makes a second release match no
// row, so an unknown or already-released hold is a not-found Error.
func (r *RetentionRepo) ReleaseHold(ctx context.Context, tx application.Tx, id string, at time.Time) (application.LegalHold, error) {
	const op = "retention.release_hold"

	uid, err := toUUID(id)
	if err != nil {
		return application.LegalHold{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).ReleaseLegalHold(ctx, gen.ReleaseLegalHoldParams{
		ReleasedAt: toTS(at),
		ID:         uid,
	})
	if err != nil {
		return application.LegalHold{}, mapDBError(op, err) // pgx.ErrNoRows → not-found (set-once)
	}
	return legalHoldFromRow(row), nil
}

// ListHolds implements application.RetentionRepo: the filtered hold read
// (empty fields keep a filter open). No hold yields an empty slice, never an
// error.
func (r *RetentionRepo) ListHolds(ctx context.Context, filter application.HoldFilter) ([]application.LegalHold, error) {
	const op = "retention.list_holds"

	var aggregateID pgtype.UUID
	if filter.AggregateID != "" {
		var err error
		aggregateID, err = toUUID(filter.AggregateID)
		if err != nil {
			return nil, application.ValidationError(op, err)
		}
	}
	var active pgtype.Bool
	if filter.Active != nil {
		active = pgtype.Bool{Bool: *filter.Active, Valid: true}
	}
	rows, err := r.q.ListLegalHolds(ctx, gen.ListLegalHoldsParams{
		AggregateType: toTextOpt(filter.AggregateType),
		AggregateID:   aggregateID,
		Active:        active,
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.LegalHold, 0, len(rows))
	for _, row := range rows {
		out = append(out, legalHoldFromRow(row))
	}
	return out, nil
}

// PseudonymiseSignal implements application.RetentionRepo: redact one signal's
// free text in place and clear the actor display names of its audit rows
// (§3). actor_id and the users row are retained (reversible). It reports the
// per-target counts. Runs entirely on the caller's transaction.
func (r *RetentionRepo) PseudonymiseSignal(ctx context.Context, tx application.Tx, signalID string) (application.RetentionRedaction, error) {
	const op = "retention.pseudonymise_signal"

	uid, err := toUUID(signalID)
	if err != nil {
		return application.RetentionRedaction{}, application.ValidationError(op, err)
	}
	q := r.q.WithTx(tx)

	names, err := q.ClearSignalAuditActorDisplayNames(ctx, uid)
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	bodies, err := q.RedactSignalCommentBodies(ctx, gen.RedactSignalCommentBodiesParams{SignalID: uid, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	reasons, err := q.RedactSignalOverrideReason(ctx, gen.RedactSignalOverrideReasonParams{SignalID: uid, Marker: pgtype.Text{String: application.RetentionRedactionMarker, Valid: true}})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	before, err := q.RedactSignalAuditBeforeReason(ctx, gen.RedactSignalAuditBeforeReasonParams{SignalID: uid, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	after, err := q.RedactSignalAuditAfterReason(ctx, gen.RedactSignalAuditAfterReasonParams{SignalID: uid, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	return application.RetentionRedaction{
		DisplayNamesCleared:     int(names),
		CommentBodiesRedacted:   int(bodies),
		OverrideReasonsRedacted: int(reasons),
		SnapshotReasonsRedacted: int(before + after),
	}, nil
}

// PseudonymiseIdentity implements application.RetentionRepo: redact one
// identity in place (§3, ADR-014 point 5) — clear the display names of the
// identity's audit rows and redact the free text the identity authored or
// triggered. actor_id and the users row are retained. Reports per-target
// counts. Runs on the caller's transaction.
func (r *RetentionRepo) PseudonymiseIdentity(ctx context.Context, tx application.Tx, userID string) (application.RetentionRedaction, error) {
	const op = "retention.pseudonymise_identity"

	q := r.q.WithTx(tx)
	names, err := q.ClearIdentityAuditActorDisplayNames(ctx, userID)
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	bodies, err := q.RedactIdentityCommentBodies(ctx, gen.RedactIdentityCommentBodiesParams{UserID: userID, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	reasons, err := q.RedactIdentityOverrideReasons(ctx, gen.RedactIdentityOverrideReasonsParams{UserID: pgtype.Text{String: userID, Valid: true}, Marker: pgtype.Text{String: application.RetentionRedactionMarker, Valid: true}})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	before, err := q.RedactIdentityAuditBeforeReason(ctx, gen.RedactIdentityAuditBeforeReasonParams{UserID: userID, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	after, err := q.RedactIdentityAuditAfterReason(ctx, gen.RedactIdentityAuditAfterReasonParams{UserID: userID, Marker: application.RetentionRedactionMarker})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	return application.RetentionRedaction{
		DisplayNamesCleared:     int(names),
		CommentBodiesRedacted:   int(bodies),
		OverrideReasonsRedacted: int(reasons),
		SnapshotReasonsRedacted: int(before + after),
	}, nil
}

// PreviewPseudonymiseIdentity implements application.RetentionRepo: the counts
// a PseudonymiseIdentity call would change, without changing anything (the
// standalone command's mandatory dry-run). It is a pool-scoped read.
func (r *RetentionRepo) PreviewPseudonymiseIdentity(ctx context.Context, userID string) (application.RetentionRedaction, error) {
	const op = "retention.preview_pseudonymise_identity"

	row, err := r.q.CountIdentityPseudonymisationTargets(ctx, gen.CountIdentityPseudonymisationTargetsParams{
		UserID: userID,
		Marker: application.RetentionRedactionMarker,
	})
	if err != nil {
		return application.RetentionRedaction{}, mapDBError(op, err)
	}
	return application.RetentionRedaction{
		DisplayNamesCleared:     int(row.DisplayNames),
		CommentBodiesRedacted:   int(row.CommentBodies),
		OverrideReasonsRedacted: int(row.OverrideReasons),
		SnapshotReasonsRedacted: int(row.BeforeReasons + row.AfterReasons),
	}, nil
}

// DeleteSlaClocks implements application.RetentionRepo (step 1 of §2.3).
func (r *RetentionRepo) DeleteSlaClocks(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return r.deleteBySignal(ctx, "retention.delete_sla_clocks", signalID,
		func(uid pgtype.UUID) (int64, error) { return r.q.WithTx(tx).DeleteRetentionSlaClocks(ctx, uid) })
}

// DeleteComments implements application.RetentionRepo (step 2 of §2.3).
func (r *RetentionRepo) DeleteComments(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return r.deleteBySignal(ctx, "retention.delete_comments", signalID,
		func(uid pgtype.UUID) (int64, error) { return r.q.WithTx(tx).DeleteRetentionComments(ctx, uid) })
}

// DeleteMatches implements application.RetentionRepo (step 3 of §2.3). The
// statement is FK-guarded: risk_signals.match_id references matches (id), so
// the match is the signal's parent and cannot be removed while the signal row
// still references it — the delete is a no-op until the signal is gone. The
// match is actually removed by DeleteSignal together with the signal (see
// retention.sql). Returns the rows removed (0 while the signal exists).
func (r *RetentionRepo) DeleteMatches(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return r.deleteBySignal(ctx, "retention.delete_matches", signalID,
		func(uid pgtype.UUID) (int64, error) { return r.q.WithTx(tx).DeleteRetentionMatches(ctx, uid) })
}

// DeleteNotifications implements application.RetentionRepo (step 4 of §2.3).
func (r *RetentionRepo) DeleteNotifications(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return r.deleteBySignal(ctx, "retention.delete_notifications", signalID,
		func(uid pgtype.UUID) (int64, error) { return r.q.WithTx(tx).DeleteRetentionNotifications(ctx, uid) })
}

// DeletePriorityFactors implements application.RetentionRepo (step 5 of
// §2.3). It is deliberately a no-op: this schema stores a signal's
// contributing factors as the risk_signals.factors jsonb column (§2.3
// "signal-scoped priority_factors" presupposes a separate table, which the
// I1b–I4 schema does not have). The factors are removed with the signal row
// itself at DeleteSignal, so there is no separate row to delete. Returns 0.
func (r *RetentionRepo) DeletePriorityFactors(_ context.Context, _ application.Tx, _ string) (int, error) {
	return 0, nil
}

// DeleteAuditEvents implements application.RetentionRepo (step 6 of §2.3):
// the signal's audit trail (aggregate_type 'risk_signal'); the run's own
// retention.* audit rows carry aggregate_type 'retention' and survive.
func (r *RetentionRepo) DeleteAuditEvents(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return r.deleteBySignal(ctx, "retention.delete_audit_events", signalID,
		func(uid pgtype.UUID) (int64, error) { return r.q.WithTx(tx).DeleteRetentionAuditEvents(ctx, uid) })
}

// DeleteSignal implements application.RetentionRepo (step 7 of §2.3, the
// last): it removes the signal row and, in the same transaction, the match
// the signal referenced. See DeleteMatches for why the parent match is
// removed here and not at step 3 (FK risk_signals.match_id → matches.id). A
// signal already gone is 0, never an error — the retention run is resumable
// (a re-scan skips deleted rows).
func (r *RetentionRepo) DeleteSignal(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	const op = "retention.delete_signal"

	uid, err := toUUID(signalID)
	if err != nil {
		return 0, application.ValidationError(op, err)
	}
	q := r.q.WithTx(tx)
	matchID, err := q.GetSignalMatchID(ctx, uid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil // the signal is already gone (resumable)
	}
	if err != nil {
		return 0, mapDBError(op, err)
	}
	n, err := q.DeleteRetentionSignal(ctx, uid)
	if err != nil {
		return 0, mapDBError(op, err)
	}
	if n > 0 && matchID.Valid {
		if _, err := q.DeleteRetentionMatch(ctx, matchID); err != nil {
			return 0, mapDBError(op, err)
		}
	}
	return int(n), nil
}

// deleteBySignal runs one signal-scoped deletion on the caller's transaction
// and returns the deleted row count. It keeps the per-table Delete* methods
// uniform (id parsing + error translation in one place).
func (r *RetentionRepo) deleteBySignal(ctx context.Context, op, signalID string, del func(uid pgtype.UUID) (int64, error)) (int, error) {
	uid, err := toUUID(signalID)
	if err != nil {
		return 0, application.ValidationError(op, err)
	}
	n, err := del(uid)
	if err != nil {
		return 0, mapDBError(op, err)
	}
	return int(n), nil
}

// retentionGuardMiss maps a guarded lifecycle update that matched no row to a
// conflict Error (the status gate rejected the transition), and any other
// driver error through the standard mapper.
func retentionGuardMiss(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ConflictError(op, err)
	}
	return mapDBError(op, err)
}

// retentionCountInt32 narrows one non-negative run counter to the int32 range
// of its column; a value the column cannot hold is a validation error (never a
// silent truncation), the same guard the other narrowings use
// (signaltriage.versionInt32, inventory_import.inventoryCounterToInt32).
func retentionCountInt32(op, name string, v int) (int32, error) {
	if v < 0 || v > math.MaxInt32 {
		return 0, application.Validationf(op, "%s count %d outside the int32 range", name, v)
	}
	return int32(v), nil
}

// retentionRunFromRow maps a stored retention_runs row onto the application
// model; a present dry_run jsonb is unmarshalled into the counts-only report
// (nil when the column is NULL).
func retentionRunFromRow(op string, row gen.RetentionRun) (application.RetentionRun, error) {
	run := application.RetentionRun{
		ID:             uuidString(row.ID),
		PolicyID:       row.PolicyID,
		Stage:          application.RetentionStage(row.Stage),
		Cutoff:         tsTime(row.Cutoff),
		PartitionKey:   row.PartitionKey,
		Status:         application.RetentionRunStatus(row.Status),
		ApprovedBy:     textValue(row.ApprovedBy),
		ApprovedAt:     tsTime(row.ApprovedAt),
		ApprovalReason: textValue(row.ApprovalReason),
		StartedAt:      tsTime(row.StartedAt),
		FinishedAt:     tsTime(row.FinishedAt),
		Pseudonymised:  int(row.PseudonymisedCount),
		Deleted:        int(row.DeletedCount),
		Failed:         int(row.FailedCount),
		LastError:      textValue(row.LastError),
	}
	if len(row.DryRun) > 0 {
		var counts application.RetentionCounts
		if err := json.Unmarshal(row.DryRun, &counts); err != nil {
			return application.RetentionRun{}, application.InfraError(op, err)
		}
		run.DryRun = &counts
	}
	return run, nil
}

// legalHoldFromRow maps a stored legal_holds row onto the application model.
func legalHoldFromRow(row gen.LegalHold) application.LegalHold {
	return application.LegalHold{
		ID:            uuidString(row.ID),
		AggregateType: row.AggregateType,
		AggregateID:   uuidString(row.AggregateID),
		Reason:        row.Reason,
		ActorID:       row.ActorID,
		CreatedAt:     tsTime(row.CreatedAt),
		ReleasedAt:    tsTime(row.ReleasedAt),
	}
}
