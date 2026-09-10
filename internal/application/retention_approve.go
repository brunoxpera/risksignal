package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// This file owns the ApproveRetentionRun command (ARCH-007 §2.2 step 2,
// WP-6.05 / DEV-116): the four-eyes approval (or rejection) of a stored
// dry-run. The Product Owner (settings.approve) reviews the report and
// approves with a mandatory reason, flipping dry_run → approved and recording
// approved_by/approved_at/approval_reason; a rejection flips it to rejected.
// Only an approved run may be executed. No deletion runs without an approved
// run.
//
// The four-eyes gate reuses settings.approve (Product Owner) — a deliberate
// ARCH-007 decision (a dedicated retention.approve was declined). The two
// gates are distinct: retention.manage (Admin) drives the dry-run, the
// execution, the holds and the pseudonymisation; settings.approve (PO)
// authorises the deletion.

// ApproveRetentionRunInput is the approval command. Reason is mandatory and
// non-blank; Reject records a refusal instead of an approval (same gate, same
// reason requirement).
type ApproveRetentionRunInput struct {
	RunID         string
	Reason        string
	Reject        bool
	Actor         Actor
	CorrelationID string
}

// ApproveRetentionRunResult reports the decision: the run identity, its new
// status and the approving principal and instant.
type ApproveRetentionRunResult struct {
	RunID      string
	Status     RetentionRunStatus
	ApprovedBy string
	ApprovedAt time.Time
}

// ApproveRetentionRun approves (or rejects) one stored dry-run (ARCH-007 §2.2
// step 2). The flow:
//
//  1. Authorize settings.approve (Product Owner) — deny-by-default, before any
//     read or transaction: a denial writes nothing and approves nothing.
//  2. Validate the mandatory non-blank reason.
//  3. Load the run; only a dry_run run can be decided (else conflict).
//  4. In one transaction, flip the run and append the retention.approved /
//     retention.rejected audit event — atomically.
func (s *Service) ApproveRetentionRun(ctx context.Context, in ApproveRetentionRunInput) (ApproveRetentionRunResult, error) {
	const op = "approve_retention_run"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionSettingsApprove, domain.ScopeAll, ""); err != nil {
		return ApproveRetentionRunResult{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return ApproveRetentionRunResult{}, err
	}
	if s.retention == nil {
		return ApproveRetentionRunResult{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.RunID == "" {
		return ApproveRetentionRunResult{}, Validationf(op, "run_id must not be empty")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return ApproveRetentionRunResult{}, Validationf(op, "a reason is mandatory")
	}

	current, err := s.retention.GetRun(ctx, in.RunID)
	if err != nil {
		return ApproveRetentionRunResult{}, err
	}
	if current.Status != RetentionStatusDryRun {
		return ApproveRetentionRunResult{}, ConflictError(op, errors.New(
			"run "+current.ID+" is "+string(current.Status)+", not dry_run"))
	}

	now := s.clock.Now()
	correlationID := correlationOrNew(in.CorrelationID)
	action := EventTypeRetentionApproved
	if in.Reject {
		action = EventTypeRetentionRejected
	}

	var decided RetentionRun
	err = s.runTx(ctx, func(tx Tx) error {
		var row RetentionRun
		var err error
		if in.Reject {
			row, err = s.retention.RejectRun(ctx, tx, in.RunID, in.Reason, now)
		} else {
			row, err = s.retention.ApproveRun(ctx, tx, in.RunID, actor.ID, in.Reason, now)
		}
		if err != nil {
			return err
		}
		decided = row
		snap := newRetentionSnapshot(row)
		snap.Reason = in.Reason
		after, err := json.Marshal(snap)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendRetentionAudit(ctx, tx, action, AuditAggregateRetention, row.ID, actor, correlationID, now, after); err != nil {
			return err
		}
		// An approval triggers exactly one retention.execute job, on the same
		// transaction as the approval flip (the ARCH-007 §2.2 trigger: a
		// released maintenance plan executes the approved run). A rejected run
		// runs nothing. The dedupe key (policy_id + cutoff + batch, §14.1)
		// makes a retried approval a no-op — the run and its job commit or roll
		// back together (ARCH-001 §5).
		if in.Reject {
			return nil
		}
		payload, err := json.Marshal(RetentionExecutePayload{
			EventID:       uuid.New(),
			Type:          EventTypeRetentionExecute,
			RunID:         row.ID,
			PolicyID:      row.PolicyID,
			Cutoff:        row.Cutoff.UTC().Format(time.RFC3339),
			PartitionKey:  row.PartitionKey,
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		return s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeRetentionExecute,
			Payload:     payload,
			DedupeKey:   retentionExecuteDedupeKey(row.PolicyID, row.Cutoff, row.PartitionKey),
			AvailableAt: now,
			CreatedAt:   now,
		})
	})
	if err != nil {
		return ApproveRetentionRunResult{}, err
	}
	return ApproveRetentionRunResult{
		RunID:      decided.ID,
		Status:     decided.Status,
		ApprovedBy: decided.ApprovedBy,
		ApprovedAt: decided.ApprovedAt,
	}, nil
}
