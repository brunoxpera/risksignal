package application

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the ExecuteRetention use case (ARCH-007 §2.2 step 3/§2.3,
// WP-6.05 / DEV-116): the deletion and pseudonymisation core the
// `retention.execute` worker job (WP-6.06) drives. It claims an approved run,
// processes its candidates in bounded batches (one transaction per batch),
// pseudonymises each candidate first and then deletes its non-shared
// dependents in the §2.3 referentially-safe order, appends one
// retention.executed audit event per batch (counts + the processed closed_at
// time range, no business content) and closes the run with the final counts —
// the retention report that survives the deletion.
//
// A legal hold blocks both the pseudonymisation and the deletion of its
// aggregate: the per-candidate hold re-check skips a held signal, so a hold
// set between the dry-run and the execution is honoured. A failing batch
// stops only that batch (a re-run re-scans the candidates and naturally skips
// already-deleted rows); the run is closed failed with the batch counter and
// the last error.

// ExecuteRetentionInput is the execution command the worker job invokes.
// BatchSize overrides the configured retention.batch_size (0 = configured).
type ExecuteRetentionInput struct {
	RunID         string
	BatchSize     int
	Actor         Actor
	CorrelationID string
}

// ExecuteRetentionResult reports the executed run: its terminal status and the
// accumulated pseudonymised/deleted/failed-batch counts.
type ExecuteRetentionResult struct {
	RunID         string
	Status        RetentionRunStatus
	Pseudonymised int
	Deleted       int
	FailedBatches int
}

// ExecuteRetention executes one approved retention run (ARCH-007 §2.2 step 3).
// The flow:
//
//  1. Authorize retention.manage (Admin) — deny-by-default, before any read
//     or transaction.
//  2. Load the run; only an approved run may be executed (else conflict).
//  3. Claim it (approved → executing).
//  4. Re-scan the candidates at the run's cutoff and process the non-held ones
//     in bounded batches, each in one transaction: pseudonymise-first, then (on
//     the delete stage) delete in the §2.3 order; one retention.executed audit
//     event per batch.
//  5. Close the run completed, or failed with the failed-batch count and the
//     last error.
func (s *Service) ExecuteRetention(ctx context.Context, in ExecuteRetentionInput) (ExecuteRetentionResult, error) {
	const op = "execute_retention"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return ExecuteRetentionResult{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return ExecuteRetentionResult{}, err
	}
	if s.retention == nil {
		return ExecuteRetentionResult{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.RunID == "" {
		return ExecuteRetentionResult{}, Validationf(op, "run_id must not be empty")
	}

	run, err := s.retention.GetRun(ctx, in.RunID)
	if err != nil {
		return ExecuteRetentionResult{}, err
	}
	if run.Status != RetentionStatusApproved {
		return ExecuteRetentionResult{}, ConflictError(op, errors.New(
			"run "+run.ID+" is "+string(run.Status)+", not approved — no deletion runs without an approved run"))
	}

	// Claim the run: the approved guard makes this the one execution of the
	// run (a second call matches zero rows → conflict).
	startedAt := s.clock.Now()
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.retention.StartRun(ctx, tx, in.RunID, startedAt)
		if err != nil {
			return err
		}
		run = row
		return nil
	})
	if err != nil {
		return ExecuteRetentionResult{}, err
	}

	// Re-scan the candidates on the run's cutoff (reads only): a hold set since
	// the dry-run is honoured, an already-deleted row is naturally absent
	// (resumable).
	candidates, err := s.retention.ScanRetentionCandidates(ctx, run.Cutoff)
	if err != nil {
		return ExecuteRetentionResult{}, err
	}
	due, _ := splitRetentionCandidates(candidates)

	batchSize := in.BatchSize
	if batchSize <= 0 {
		batchSize = s.retentionBatchSize
	}
	if batchSize <= 0 {
		batchSize = DefaultRetentionBatchSize
	}

	var totalPseudo, totalDeleted, failedBatches int
	var lastError string
	correlationID := correlationOrNew(in.CorrelationID)

	for start := 0; start < len(due); start += batchSize {
		end := start + batchSize
		if end > len(due) {
			end = len(due)
		}
		batch := due[start:end]

		var batchPseudo, batchDeleted int
		err := s.runTx(ctx, func(tx Tx) error {
			batchPseudo, batchDeleted = 0, 0
			from, to := batchTimeRange(batch)
			for _, c := range batch {
				held, err := s.retention.HasActiveHold(ctx, AuditAggregateRiskSignal, c.SignalID)
				if err != nil {
					return err
				}
				if held {
					continue // a hold preserves the record as-is (blocks both stages)
				}
				if _, err := s.retention.PseudonymiseSignal(ctx, tx, c.SignalID); err != nil {
					return err
				}
				batchPseudo++
				if run.Stage == RetentionStageDelete {
					if err := s.deleteSignalInSafeOrder(ctx, tx, c.SignalID); err != nil {
						return err
					}
					batchDeleted++
				}
			}
			snap := newRetentionSnapshot(run)
			snap.From = from
			snap.To = to
			snap.Pseudonymised = batchPseudo
			snap.Deleted = batchDeleted
			after, err := json.Marshal(snap)
			if err != nil {
				return InfraError(op, err)
			}
			return s.appendRetentionAudit(ctx, tx, EventTypeRetentionExecuted, AuditAggregateRetention, run.ID, actor, correlationID, s.clock.Now(), after)
		})
		if err != nil {
			// A failing batch stops only that batch: record it and continue
			// with the next one (the ARCH-007 §2.2 step 3 rule).
			failedBatches++
			lastError = err.Error()
			continue
		}
		totalPseudo += batchPseudo
		totalDeleted += batchDeleted
	}

	counts := RetentionRunCounts{Pseudonymised: totalPseudo, Deleted: totalDeleted, Failed: failedBatches, LastError: lastError}
	finishedAt := s.clock.Now()
	status := RetentionStatusCompleted
	err = s.runTx(ctx, func(tx Tx) error {
		var row RetentionRun
		var err error
		if failedBatches > 0 {
			row, err = s.retention.FailRun(ctx, tx, run.ID, counts, finishedAt)
			status = RetentionStatusFailed
		} else {
			row, err = s.retention.CompleteRun(ctx, tx, run.ID, counts, finishedAt)
		}
		if err != nil {
			return err
		}
		run = row
		return nil
	})
	if err != nil {
		return ExecuteRetentionResult{}, err
	}
	return ExecuteRetentionResult{
		RunID:         run.ID,
		Status:        status,
		Pseudonymised: totalPseudo,
		Deleted:       totalDeleted,
		FailedBatches: failedBatches,
	}, nil
}

// deleteSignalInSafeOrder deletes one signal's non-shared dependents in the
// ARCH-007 §2.3 referentially-safe order, then the signal itself:
// sla_clocks → comments → matches → notifications → priority_factors →
// audit_events → risk_signals. Shared data (evidences, vulnerabilities,
// raw_records) is never touched — the port exposes no operation for it.
func (s *Service) deleteSignalInSafeOrder(ctx context.Context, tx Tx, signalID string) error {
	if _, err := s.retention.DeleteSlaClocks(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeleteComments(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeleteMatches(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeleteNotifications(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeletePriorityFactors(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeleteAuditEvents(ctx, tx, signalID); err != nil {
		return err
	}
	if _, err := s.retention.DeleteSignal(ctx, tx, signalID); err != nil {
		return err
	}
	return nil
}

// batchTimeRange returns the closed_at window of one batch as RFC 3339 strings
// ("" when the batch is empty). It is the only time information an executed
// batch's audit carries — never a signal id.
func batchTimeRange(batch []RetentionCandidate) (from, to string) {
	if len(batch) == 0 {
		return "", ""
	}
	minAt, maxAt := batch[0].ClosedAt, batch[0].ClosedAt
	for _, c := range batch[1:] {
		if c.ClosedAt.Before(minAt) {
			minAt = c.ClosedAt
		}
		if c.ClosedAt.After(maxAt) {
			maxAt = c.ClosedAt
		}
	}
	return minAt.UTC().Format(time.RFC3339), maxAt.UTC().Format(time.RFC3339)
}
