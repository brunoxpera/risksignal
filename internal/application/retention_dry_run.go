package application

import (
	"context"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the RunRetentionDryRun command (ARCH-007 §2.2 step 1,
// WP-6.05 / DEV-116): the governed read-only proposal behind
// `maintenance retention --dry-run` and the monthly scheduler. It scans the
// signals whose retention deadline has elapsed, counts them (held /
// to_pseudonymise / to_delete), and stores a counts-only `retention_runs` row
// (`status='dry_run'`). It changes no domain state and writes no audit row —
// the report row is the only write, and it is the operational record the
// approval and execution steps act on.
//
// The cutoff is derived from the injected clock and the configured retention
// period (retention.closed_signal_years, default 5; NFR-015: no wall clock,
// deterministic with a FakeClock).

// RunRetentionDryRunInput is the dry-run command. PolicyID defaults to the
// MVP policy (closed-signals-5y); Stage defaults to the delete stage;
// PartitionKey defaults to the cutoff's month bucket. Cutoff overrides the
// clock-derived retention cutoff (now − retention.closed_signal_years) when
// set — the operator's explicit proposal; nil keeps the deterministic
// clock-derived cutoff (NFR-015).
type RunRetentionDryRunInput struct {
	PolicyID      string
	Stage         RetentionStage
	Cutoff        *time.Time
	PartitionKey  string
	Actor         Actor
	CorrelationID string
}

// RetentionDryRunResult is the stored dry-run report plus the operator view of
// the blocked candidates. Held carries the documented hold reasons for the
// review; it is never stored (the row keeps counts only). Run is the stored
// status='dry_run' row the command persisted — the wire report the HTTP layer
// renders.
type RetentionDryRunResult struct {
	RunID  string
	Status RetentionRunStatus
	Cutoff time.Time
	Counts RetentionCounts
	Held   []RetentionCandidate
	Run    RetentionRun
}

// RunRetentionDryRun scans the retention candidates and stores a counts-only
// dry-run report (ARCH-007 §2.2 step 1). The flow:
//
//  1. Authorize retention.manage (Admin) — deny-by-default, before any read
//     or transaction: a denial writes nothing and stores no run row.
//  2. Derive the cutoff from the injected clock and the configured retention
//     period.
//  3. Scan the closed signals due at the cutoff (with their active-hold flag).
//  4. Split into the actionable candidates and the held ones and count them.
//  5. Store the `retention_runs` row (status 'dry_run', counts-only report).
//
// No audit row is written (reads only); no domain state changes.
func (s *Service) RunRetentionDryRun(ctx context.Context, in RunRetentionDryRunInput) (RetentionDryRunResult, error) {
	const op = "run_retention_dry_run"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return RetentionDryRunResult{}, err
	}
	if _, err := signalActor(op, in.Actor); err != nil {
		return RetentionDryRunResult{}, err
	}
	if s.retention == nil {
		return RetentionDryRunResult{}, InfraError(op, errors.New("retention repository is not wired"))
	}

	policyID := in.PolicyID
	if policyID == "" {
		policyID = RetentionPolicyClosedSignals
	}
	stage := in.Stage
	if stage == "" {
		stage = RetentionStageDelete
	}
	if !stage.Valid() {
		return RetentionDryRunResult{}, Validationf(op, "invalid stage %q (want %q or %q)", stage, RetentionStagePseudonymise, RetentionStageDelete)
	}

	now := s.clock.Now()
	// The cutoff follows the run's stage: the pseudonymise stage uses
	// retention.pseudonymise_years, the delete stage
	// retention.closed_signal_years (the two coincide by default, ARCH-007
	// §2.4).
	years := s.retentionYears
	if stage == RetentionStagePseudonymise {
		years = s.retentionPseudonymiseYears
	}
	cutoff := now.AddDate(-years, 0, 0)
	// An explicit cutoff overrides the clock-derived retention deadline (the
	// operator's proposal, ARCH-007 §2.2); nil keeps it deterministic
	// (NFR-015: no wall clock).
	if in.Cutoff != nil {
		cutoff = in.Cutoff.UTC()
	}
	partitionKey := in.PartitionKey
	if partitionKey == "" {
		partitionKey = cutoff.UTC().Format("2006-01")
	}

	candidates, err := s.retention.ScanRetentionCandidates(ctx, cutoff)
	if err != nil {
		return RetentionDryRunResult{}, err
	}
	due, held := splitRetentionCandidates(candidates)
	counts := RetentionCounts{Candidates: len(due), Held: len(held)}
	switch stage {
	case RetentionStagePseudonymise:
		counts.ToPseudonymise = len(due)
	case RetentionStageDelete:
		counts.ToDelete = len(due)
	}

	var stored RetentionRun
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.retention.InsertRun(ctx, tx, RetentionRunRecord{
			PolicyID:     policyID,
			Stage:        stage,
			Cutoff:       cutoff,
			PartitionKey: partitionKey,
			Counts:       counts,
		})
		if err != nil {
			return err
		}
		stored = row
		return nil
	})
	if err != nil {
		return RetentionDryRunResult{}, err
	}
	return RetentionDryRunResult{
		RunID:  stored.ID,
		Status: stored.Status,
		Cutoff: cutoff,
		Counts: counts,
		Held:   held,
		Run:    stored,
	}, nil
}

// splitRetentionCandidates partitions the scan result into the actionable due
// signals and the hold-blocked ones, preserving the scan order.
func splitRetentionCandidates(candidates []RetentionCandidate) (due, held []RetentionCandidate) {
	for _, c := range candidates {
		if c.Held {
			held = append(held, c)
			continue
		}
		due = append(due, c)
	}
	return due, held
}
