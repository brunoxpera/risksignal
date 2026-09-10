package application

import (
	"context"
	"encoding/json"
	"time"
)

// This file owns the audit vocabulary and the shared append helper of the I6
// retention and pseudonymisation acts (ARCH-007 §2.2/§3, WP-6.05 / DEV-116).
// Every retention command writes exactly one audit event on its command
// transaction (ch. 5.1, ch. 13.2); the snapshots are minimised (ch. 13.5):
// counts, identities and instants only — never business content.

// Retention audit actions (ARCH-007 §2.2/§3, concept ch. 13.2).
const (
	// EventTypeRetentionApproved is the audit action of the four-eyes approval
	// of a dry-run run.
	EventTypeRetentionApproved = "retention.approved"
	// EventTypeRetentionRejected is the audit action of a refused approval.
	EventTypeRetentionRejected = "retention.rejected"
	// EventTypeRetentionExecuted is the audit action of one executed batch
	// (counts + the processed time range, no business content).
	EventTypeRetentionExecuted = "retention.executed"
	// EventTypeRetentionHoldCreated is the audit action of a legal hold.
	EventTypeRetentionHoldCreated = "retention.hold_created"
	// EventTypeRetentionHoldReleased is the audit action of a legal-hold
	// release.
	EventTypeRetentionHoldReleased = "retention.hold_released"
	// EventTypeRetentionPseudonymised is the audit action of a pseudonymisation
	// act (standalone or run-driven).
	EventTypeRetentionPseudonymised = "retention.pseudonymised"
)

// retentionSnapshot is the minimised audit snapshot of a run-lifecycle act
// (approve/reject/execute): the run identity, the stage and the counts-only
// report — never a signal id or any business content. The Instants carry the
// processed time range (closed_at window) of an executed batch.
type retentionSnapshot struct {
	RunID          string `json:"run_id"`
	PolicyID       string `json:"policy_id"`
	Stage          string `json:"stage"`
	Status         string `json:"status"`
	PartitionKey   string `json:"partition_key,omitempty"`
	Cutoff         string `json:"cutoff,omitempty"`
	Candidates     int    `json:"candidates,omitempty"`
	Held           int    `json:"held,omitempty"`
	ToPseudonymise int    `json:"to_pseudonymise,omitempty"`
	ToDelete       int    `json:"to_delete,omitempty"`
	Pseudonymised  int    `json:"pseudonymised,omitempty"`
	Deleted        int    `json:"deleted,omitempty"`
	Failed         int    `json:"failed,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// legalHoldSnapshot is the minimised audit snapshot of a legal-hold act: the
// hold identity, the held aggregate and the documented reason.
type legalHoldSnapshot struct {
	HoldID        string `json:"hold_id"`
	AggregateType string `json:"aggregate_type"`
	AggregateID   string `json:"aggregate_id"`
	Reason        string `json:"reason,omitempty"`
	ReleasedAt    string `json:"released_at,omitempty"`
}

// pseudonymiseSnapshot is the minimised audit snapshot of a pseudonymisation
// act: the pseudonymised identity and the per-target redaction counts.
type pseudonymiseSnapshot struct {
	UserID                  string `json:"user_id"`
	DisplayNamesCleared     int    `json:"display_names_cleared,omitempty"`
	CommentBodiesRedacted   int    `json:"comment_bodies_redacted,omitempty"`
	OverrideReasonsRedacted int    `json:"override_reasons_redacted,omitempty"`
	SnapshotReasonsRedacted int    `json:"snapshot_reasons_redacted,omitempty"`
	Reason                  string `json:"reason,omitempty"`
}

// newRetentionSnapshot projects one run onto its minimised audit snapshot.
func newRetentionSnapshot(r RetentionRun) retentionSnapshot {
	snap := retentionSnapshot{
		RunID:         r.ID,
		PolicyID:      r.PolicyID,
		Stage:         string(r.Stage),
		Status:        string(r.Status),
		PartitionKey:  r.PartitionKey,
		Pseudonymised: r.Pseudonymised,
		Deleted:       r.Deleted,
		Failed:        r.Failed,
	}
	if !r.Cutoff.IsZero() {
		snap.Cutoff = r.Cutoff.UTC().Format(time.RFC3339)
	}
	if r.DryRun != nil {
		snap.Candidates = r.DryRun.Candidates
		snap.Held = r.DryRun.Held
		snap.ToPseudonymise = r.DryRun.ToPseudonymise
		snap.ToDelete = r.DryRun.ToDelete
	}
	return snap
}

// appendRetentionAudit appends one retention audit event on the caller's
// transaction — atomic with the state change it records (ch. 5.1, ch. 13.2).
// after is a minimised snapshot (ch. 13.5); before is always nil.
func (s *Service) appendRetentionAudit(ctx context.Context, tx Tx, action, aggregateType, aggregateID string, actor Actor, correlationID string, now time.Time, after json.RawMessage) error {
	return s.audit.Append(ctx, tx, AuditEvent{
		AggregateType:    aggregateType,
		AggregateID:      aggregateID,
		ActorType:        actor.Type,
		ActorID:          actor.ID,
		ActorDisplayName: actor.DisplayName,
		Action:           action,
		OccurredAt:       now,
		Before:           nil,
		After:            after,
		CorrelationID:    correlationID,
	})
}
