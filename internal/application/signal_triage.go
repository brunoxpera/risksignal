package application

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// This file owns the I4 triage and SLA use cases of ARCH-004 §2/§3/§4
// (WP-4.04a / DEV-075): the guarded commands that move a signal through the
// ch. 6.3 state machine, assign an owner, append a comment, acknowledge a
// signal, override/revert its priority and pause/resume an SLA clock. Every
// command follows the house shape — validate, load the aggregate, apply the
// domain rule, then inside one transaction persist the guarded write, append
// the audit event and enqueue the outbox event (one command, one transaction,
// ch. 5.1). The persistence deps are the ports of ports.go; the concrete
// adapter is the DEV-073 postgres repository. The permission gate on these
// commands (signals.triage/signals.override) lands with I5a; I4 records the
// actor, it does not authorise it (ARCH-004 §10).

// Outbox type discriminators and audit action vocabulary of the I4 triage and
// SLA commands (ARCH-004 §2/§3/§4, ch. 13.2). Each command writes one audit
// event with the same action string and one outbox event of the same type on
// its transaction.
const (
	// EventTypeSignalTransitioned records a ch. 6.3 state change.
	EventTypeSignalTransitioned = "signal.transitioned"
	// EventTypeSignalOwnerAssigned records an owner assignment.
	EventTypeSignalOwnerAssigned = "signal.owner_assigned"
	// EventTypeSignalCommented records an appended comment.
	EventTypeSignalCommented = "signal.commented"
	// EventTypeSignalAcknowledged records the explicit acknowledgement
	// (new → in_review).
	EventTypeSignalAcknowledged = "signal.acknowledged"
	// EventTypeSignalPriorityOverridden records a manual priority override
	// (ADR-015 mirror).
	EventTypeSignalPriorityOverridden = "signal.priority_overridden"
	// EventTypeSignalPriorityReverted records the revert of a manual
	// priority override.
	EventTypeSignalPriorityReverted = "signal.priority_reverted"
	// EventTypeSignalSLAPaused records an SLA clock pause.
	EventTypeSignalSLAPaused = "signal.sla_paused"
	// EventTypeSignalSLAResumed records an SLA clock resume.
	EventTypeSignalSLAResumed = "signal.sla_resumed"
)

// TransitionSignalInput is the TransitionSignal command (ARCH-004 §2): move a
// signal along the ch. 6.3 matrix under the optimistic lock. Reason is
// mandatory for the guarded edges — entering a closed state or reopening one
// (domain.TransitionRequiresReason) — and is recorded in the audit snapshot;
// it is ignored (and may be empty) on the unguarded edges.
type TransitionSignalInput struct {
	SignalID        string
	To              domain.SignalStatus
	Reason          string
	ExpectedVersion int
	Actor           Actor
	CorrelationID   string
}

// AssignOwnerInput is the AssignOwner command (ARCH-004 §2.1): set the
// opaque owner principal under the optimistic lock. Owner == "" clears the
// assignment. User resolution is I5a; I4 records the id as given.
type AssignOwnerInput struct {
	SignalID        string
	Owner           string
	ExpectedVersion int
	Actor           Actor
	CorrelationID   string
}

// AddCommentInput is the AddComment command (ARCH-004 §2.2): append one
// comment to a signal's timeline. The comment is never edited or deleted and
// its insert, its audit event and its outbox event commit together.
type AddCommentInput struct {
	SignalID      string
	Body          string
	Actor         Actor
	CorrelationID string
}

// AcknowledgeSignalInput is the AcknowledgeSignal command (ARCH-004 §4.3):
// the explicit acknowledgement of a new signal — new → in_review, under the
// optimistic lock. Merely opening the detail view is not an acknowledgement
// (ch. 9.4).
type AcknowledgeSignalInput struct {
	SignalID        string
	ExpectedVersion int
	Actor           Actor
	CorrelationID   string
}

// OverridePriorityInput is the OverridePriority command (ARCH-004 §3,
// ADR-015 mirror): replace the effective priority, preserving the computed
// value in auto_priority. Reason and Actor are mandatory and are stamped with
// the injected clock instant.
type OverridePriorityInput struct {
	SignalID        string
	Priority        domain.Priority
	Reason          string
	ExpectedVersion int
	Actor           Actor
	CorrelationID   string
}

// RevertPriorityInput is the RevertPriority command (ARCH-004 §3): restore
// the computed priority from auto_priority and clear the override columns.
type RevertPriorityInput struct {
	SignalID        string
	ExpectedVersion int
	Actor           Actor
	CorrelationID   string
}

// PauseSlaInput is the PauseSla command (ARCH-004 §4.3): pause one SLA clock
// (Target) of a signal. Reason and Actor are mandatory (audited); the clock
// must not already be paused and must not be fulfilled.
type PauseSlaInput struct {
	SignalID      string
	Target        domain.SLATarget
	Reason        string
	Actor         Actor
	CorrelationID string
}

// ResumeSlaInput is the ResumeSla command (ARCH-004 §4.3): resume one paused
// SLA clock, accumulating the elapsed pause into paused_seconds. Reason and
// Actor are mandatory (audited).
type ResumeSlaInput struct {
	SignalID      string
	Target        domain.SLATarget
	Reason        string
	Actor         Actor
	CorrelationID string
}

// signalCommandPayload is the outbox payload of one I4 triage/SLA command
// (ARCH-004 §2/§3/§4): the event envelope of the house style (event_id, type,
// signal_id, occurred_at, correlation_id) plus the identity-level detail of
// the command. It carries identities and enums only — never the free-text
// reason or comment body (ch. 3.3, TR-013); those live in the audit event and
// the comments table.
type signalCommandPayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	SignalID      string    `json:"signal_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`

	Version      int    `json:"version,omitempty"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Priority     string `json:"priority,omitempty"`
	AutoPriority string `json:"auto_priority,omitempty"`
	Target       string `json:"target,omitempty"`
	CommentID    string `json:"comment_id,omitempty"`
}

// TransitionSignal moves a signal along the ch. 6.3 state machine (ARCH-004
// §2): it validates the edge (domain.Transition), enforces the mandatory
// reason of the closed-entry and reopen edges, then — inside one transaction
// — writes the guarded status change (optimistic lock; a stale version is a
// conflict), stamps or clears closed_at, appends the audit event and enqueues
// the outbox event. The updated signal is returned.
func (s *Service) TransitionSignal(ctx context.Context, in TransitionSignalInput) (domain.RiskSignal, error) {
	const op = "transition_signal"

	if in.SignalID == "" {
		return domain.RiskSignal{}, Validationf(op, "signal_id must not be empty")
	}
	if !in.To.Valid() {
		return domain.RiskSignal{}, Validationf(op, "invalid target status %q", in.To)
	}
	if in.ExpectedVersion < 1 {
		return domain.RiskSignal{}, Validationf(op, "expected_version %d must be >= 1", in.ExpectedVersion)
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	// Off-matrix edges are a state conflict (TR-001); a guarded edge without
	// its reason is a client validation error.
	if err := domain.Transition(current.Status, in.To); err != nil {
		return domain.RiskSignal{}, ConflictError(op, err)
	}
	if domain.TransitionRequiresReason(current.Status, in.To) && strings.TrimSpace(in.Reason) == "" {
		return domain.RiskSignal{}, Validationf(op, "a reason is mandatory for the transition %s -> %s", current.Status, in.To)
	}

	before, err := signalStateSnapshot(current, "")
	if err != nil {
		return domain.RiskSignal{}, InfraError(op, err)
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()
	var closedAt *time.Time
	if in.To.IsClosed() {
		at := now
		closedAt = &at // entering a closed state starts the retention countdown
	}

	var updated domain.RiskSignal
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.Transition(ctx, tx, in.SignalID, in.To, closedAt, in.ExpectedVersion)
		if err != nil {
			return err
		}
		updated = row
		after, err := signalStateSnapshot(row, in.Reason)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalTransitioned, row.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalTransitioned, row.ID, correlationID, now, signalCommandPayload{
			Version: row.Version,
			From:    string(current.Status),
			To:      string(in.To),
		})
	})
	if err != nil {
		return domain.RiskSignal{}, err
	}
	return updated, nil
}

// AssignOwner sets the signal's owner (ARCH-004 §2.1) under the optimistic
// lock; Owner == "" clears it. State change, audit event and outbox event
// commit together; a stale version is a conflict.
func (s *Service) AssignOwner(ctx context.Context, in AssignOwnerInput) (domain.RiskSignal, error) {
	const op = "assign_owner"

	if in.SignalID == "" {
		return domain.RiskSignal{}, Validationf(op, "signal_id must not be empty")
	}
	if in.ExpectedVersion < 1 {
		return domain.RiskSignal{}, Validationf(op, "expected_version %d must be >= 1", in.ExpectedVersion)
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	before, err := signalStateSnapshot(current, "")
	if err != nil {
		return domain.RiskSignal{}, InfraError(op, err)
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var updated domain.RiskSignal
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.AssignOwner(ctx, tx, in.SignalID, in.Owner, in.ExpectedVersion)
		if err != nil {
			return err
		}
		updated = row
		after, err := signalStateSnapshot(row, "")
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalOwnerAssigned, row.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalOwnerAssigned, row.ID, correlationID, now, signalCommandPayload{
			Version: row.Version,
			Owner:   row.Owner,
		})
	})
	if err != nil {
		return domain.RiskSignal{}, err
	}
	return updated, nil
}

// AddComment appends one comment to the signal's timeline (ARCH-004 §2.2):
// the signal is loaded (existence), then the append, its audit event and its
// outbox event commit in one transaction. Comments are append-only and carry
// no optimistic lock of their own.
func (s *Service) AddComment(ctx context.Context, in AddCommentInput) (domain.Comment, error) {
	const op = "add_comment"

	if in.SignalID == "" {
		return domain.Comment{}, Validationf(op, "signal_id must not be empty")
	}
	if strings.TrimSpace(in.Body) == "" {
		return domain.Comment{}, Validationf(op, "comment body must not be empty")
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.Comment{}, err
	}

	if _, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID); err != nil {
		return domain.Comment{}, err
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var stored domain.Comment
	err = s.runTx(ctx, func(tx Tx) error {
		comment, err := s.comments.Add(ctx, tx, in.SignalID, actor.ID, in.Body, now)
		if err != nil {
			return err
		}
		stored = comment
		after, err := commentSnapshot(comment)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalCommented, in.SignalID, actor, correlationID, now, nil, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalCommented, in.SignalID, correlationID, now, signalCommandPayload{
			CommentID: comment.ID,
		})
	})
	if err != nil {
		return domain.Comment{}, err
	}
	return stored, nil
}

// AcknowledgeSignal is the explicit acknowledgement of a new signal
// (ARCH-004 §4.3): new → in_review under the optimistic lock. It is a
// dedicated command, not a view side effect (ch. 9.4). The status change, its
// audit event and its outbox event commit together; a signal that is not new
// is a conflict.
func (s *Service) AcknowledgeSignal(ctx context.Context, in AcknowledgeSignalInput) (domain.RiskSignal, error) {
	const op = "acknowledge_signal"

	if in.SignalID == "" {
		return domain.RiskSignal{}, Validationf(op, "signal_id must not be empty")
	}
	if in.ExpectedVersion < 1 {
		return domain.RiskSignal{}, Validationf(op, "expected_version %d must be >= 1", in.ExpectedVersion)
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	if err := domain.Transition(current.Status, domain.SignalStatusInReview); err != nil {
		return domain.RiskSignal{}, ConflictError(op, err)
	}
	before, err := signalStateSnapshot(current, "")
	if err != nil {
		return domain.RiskSignal{}, InfraError(op, err)
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var updated domain.RiskSignal
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.Transition(ctx, tx, in.SignalID, domain.SignalStatusInReview, nil, in.ExpectedVersion)
		if err != nil {
			return err
		}
		updated = row
		after, err := signalStateSnapshot(row, "")
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalAcknowledged, row.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalAcknowledged, row.ID, correlationID, now, signalCommandPayload{
			Version: row.Version,
			From:    string(current.Status),
			To:      string(domain.SignalStatusInReview),
		})
	})
	if err != nil {
		return domain.RiskSignal{}, err
	}
	return updated, nil
}

// OverridePriority replaces a signal's effective priority (ARCH-004 §3,
// ADR-015 mirror): the domain command (domain.RiskSignal.Override) validates
// the mandatory reason/actor and the not-already-overridden precondition and
// moves the computed value into auto_priority; the persistence then writes
// the effective priority, the preserved auto value and the override
// reason/actor/time in one guarded write, alongside the audit and the outbox
// event. A stale version is a conflict.
func (s *Service) OverridePriority(ctx context.Context, in OverridePriorityInput) (domain.RiskSignal, error) {
	const op = "override_priority"

	if in.SignalID == "" {
		return domain.RiskSignal{}, Validationf(op, "signal_id must not be empty")
	}
	if !in.Priority.Valid() {
		return domain.RiskSignal{}, Validationf(op, "invalid priority %q", in.Priority)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return domain.RiskSignal{}, Validationf(op, "override reason must not be empty")
	}
	if in.ExpectedVersion < 1 {
		return domain.RiskSignal{}, Validationf(op, "expected_version %d must be >= 1", in.ExpectedVersion)
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	now := s.clock.Now()
	// Domain guard before the write: an invalid override (already overridden,
	// blank reason/actor) is a client validation error and opens no
	// transaction.
	if _, err := current.Override(in.Priority, in.Reason, actor.ID, now); err != nil {
		return domain.RiskSignal{}, ValidationError(op, err)
	}
	auto := current.Priority // the computed value the override preserves (ADR-015)
	before, err := signalStateSnapshot(current, "")
	if err != nil {
		return domain.RiskSignal{}, InfraError(op, err)
	}
	correlationID := correlationOrNew(in.CorrelationID)

	var updated domain.RiskSignal
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.OverridePriority(ctx, tx, in.SignalID, in.Priority, auto, in.Reason, actor.ID, now, in.ExpectedVersion)
		if err != nil {
			return err
		}
		updated = row
		after, err := signalStateSnapshot(row, in.Reason)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalPriorityOverridden, row.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalPriorityOverridden, row.ID, correlationID, now, signalCommandPayload{
			Version:      row.Version,
			Priority:     string(row.Priority),
			AutoPriority: string(auto),
		})
	})
	if err != nil {
		return domain.RiskSignal{}, err
	}
	return updated, nil
}

// RevertPriority restores a signal's computed priority (ARCH-004 §3): the
// domain command (domain.RiskSignal.Revert) validates the active-override
// precondition and restores priority = auto_priority, clearing the four
// override columns; the persistence writes that in one guarded write
// alongside the audit and the outbox event. A signal without an active
// override is a validation error; a stale version is a conflict.
func (s *Service) RevertPriority(ctx context.Context, in RevertPriorityInput) (domain.RiskSignal, error) {
	const op = "revert_priority"

	if in.SignalID == "" {
		return domain.RiskSignal{}, Validationf(op, "signal_id must not be empty")
	}
	if in.ExpectedVersion < 1 {
		return domain.RiskSignal{}, Validationf(op, "expected_version %d must be >= 1", in.ExpectedVersion)
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	if _, err := current.Revert(); err != nil {
		return domain.RiskSignal{}, ValidationError(op, err)
	}
	before, err := signalStateSnapshot(current, "")
	if err != nil {
		return domain.RiskSignal{}, InfraError(op, err)
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var updated domain.RiskSignal
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.RevertPriority(ctx, tx, in.SignalID, in.ExpectedVersion)
		if err != nil {
			return err
		}
		updated = row
		after, err := signalStateSnapshot(row, "")
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalPriorityReverted, row.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalPriorityReverted, row.ID, correlationID, now, signalCommandPayload{
			Version:  row.Version,
			Priority: string(row.Priority),
		})
	})
	if err != nil {
		return domain.RiskSignal{}, err
	}
	return updated, nil
}

// PauseSla pauses one SLA clock of a signal (ARCH-004 §4.3). Reason and Actor
// are mandatory; the clock must be open and not already paused. The guarded
// write, the audit event and the outbox event commit in one transaction; a
// clock that is already paused, fulfilled or missing is a conflict. The port
// exposes no clock read, so the guarded statement is the splice of the
// domain precondition (domain.SlaClock.Pause) and its persistence; the
// adapter applies the same preconditions in SQL.
func (s *Service) PauseSla(ctx context.Context, in PauseSlaInput) (domain.SlaClock, error) {
	const op = "pause_sla"

	if in.SignalID == "" {
		return domain.SlaClock{}, Validationf(op, "signal_id must not be empty")
	}
	if !in.Target.Valid() {
		return domain.SlaClock{}, Validationf(op, "invalid SLA target %q", in.Target)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return domain.SlaClock{}, Validationf(op, "pause reason must not be empty")
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.SlaClock{}, err
	}
	if _, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID); err != nil {
		return domain.SlaClock{}, err
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var paused domain.SlaClock
	err = s.runTx(ctx, func(tx Tx) error {
		clock, err := s.slaClocks.Pause(ctx, tx, in.SignalID, in.Target, now)
		if err != nil {
			return err
		}
		paused = clock
		after, err := slaClockSnapshot(clock, in.Reason)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalSLAPaused, in.SignalID, actor, correlationID, now, nil, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalSLAPaused, in.SignalID, correlationID, now, signalCommandPayload{
			Target: string(in.Target),
		})
	})
	if err != nil {
		return domain.SlaClock{}, err
	}
	return paused, nil
}

// ResumeSla resumes one paused SLA clock (ARCH-004 §4.3), accumulating the
// elapsed pause into paused_seconds. Reason and Actor are mandatory. The
// guarded write, the audit event and the outbox event commit in one
// transaction; a clock that is not paused (or missing) is a conflict. See
// PauseSla for why the domain precondition and its persistence splice into
// the guarded statement.
func (s *Service) ResumeSla(ctx context.Context, in ResumeSlaInput) (domain.SlaClock, error) {
	const op = "resume_sla"

	if in.SignalID == "" {
		return domain.SlaClock{}, Validationf(op, "signal_id must not be empty")
	}
	if !in.Target.Valid() {
		return domain.SlaClock{}, Validationf(op, "invalid SLA target %q", in.Target)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return domain.SlaClock{}, Validationf(op, "resume reason must not be empty")
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return domain.SlaClock{}, err
	}
	if _, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID); err != nil {
		return domain.SlaClock{}, err
	}
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var resumed domain.SlaClock
	err = s.runTx(ctx, func(tx Tx) error {
		clock, err := s.slaClocks.Resume(ctx, tx, in.SignalID, in.Target, now)
		if err != nil {
			return err
		}
		resumed = clock
		after, err := slaClockSnapshot(clock, in.Reason)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalSLAResumed, in.SignalID, actor, correlationID, now, nil, after); err != nil {
			return err
		}
		return s.appendSignalOutbox(ctx, tx, EventTypeSignalSLAResumed, in.SignalID, correlationID, now, signalCommandPayload{
			Target: string(in.Target),
		})
	})
	if err != nil {
		return domain.SlaClock{}, err
	}
	return resumed, nil
}

// appendSignalAudit appends the audit event of one triage/SLA command on the
// caller's transaction — atomic with the state change (ch. 5.1, ch. 13.2).
// before/after are minimised state snapshots (ch. 13.5): status, priority,
// owner, version, the auto_priority mirror and the documented reason — no
// secrets, no comment bodies.
func (s *Service) appendSignalAudit(ctx context.Context, tx Tx, action, signalID string, actor Actor, correlationID string, now time.Time, before, after json.RawMessage) error {
	return s.audit.Append(ctx, tx, AuditEvent{
		AggregateType:    AuditAggregateRiskSignal,
		AggregateID:      signalID,
		ActorType:        actor.Type,
		ActorID:          actor.ID,
		ActorDisplayName: actor.DisplayName,
		Action:           action,
		OccurredAt:       now,
		Before:           before,
		After:            after,
		CorrelationID:    correlationID,
	})
}

// appendSignalOutbox enqueues the outbox event of one triage/SLA command on
// the caller's transaction (ch. 5.1) — the fault seam of the command: a
// failing append rolls the state change and the audit event back with it. The
// dedupe key namespaces the event type and carries a per-command event id, so
// every command writes exactly one row (the optimistic lock and the domain
// guards already make a command at-most-once; the key keeps the UQ from ever
// colliding across commands).
func (s *Service) appendSignalOutbox(ctx context.Context, tx Tx, evtType, signalID, correlationID string, now time.Time, p signalCommandPayload) error {
	p.EventID = uuid.New()
	p.Type = evtType
	p.SignalID = signalID
	p.OccurredAt = now
	p.CorrelationID = correlationID
	payload, err := json.Marshal(p)
	if err != nil {
		return InfraError("signal_command", err)
	}
	return s.outbox.Append(ctx, tx, OutboxEvent{
		Type:        evtType,
		Payload:     payload,
		DedupeKey:   evtType + ":" + signalID + ":" + p.EventID,
		AvailableAt: now,
		CreatedAt:   now,
	})
}

// signalStateSnapshot is the minimised before/after state snapshot of a
// signal triage command (ch. 13.5): the identity, status, effective priority,
// owner, optimistic-lock version and the auto_priority override mirror, plus
// the documented reason of the command (empty on snapshots that carry none).
func signalStateSnapshot(s domain.RiskSignal, reason string) (json.RawMessage, error) {
	snap := struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		Priority     string `json:"priority"`
		Owner        string `json:"owner,omitempty"`
		Version      int    `json:"version"`
		AutoPriority string `json:"auto_priority,omitempty"`
		Reason       string `json:"reason,omitempty"`
	}{
		ID:       s.ID,
		Status:   string(s.Status),
		Priority: string(s.Priority),
		Owner:    s.Owner,
		Version:  s.Version,
		Reason:   reason,
	}
	if s.AutoPriority != nil {
		snap.AutoPriority = string(*s.AutoPriority)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// commentSnapshot is the minimised audit snapshot of an appended comment: the
// comment id and its author — never the body (ch. 13.5, ch. 3.3).
func commentSnapshot(c domain.Comment) (json.RawMessage, error) {
	b, err := json.Marshal(struct {
		CommentID string `json:"comment_id"`
		SignalID  string `json:"signal_id"`
		ActorID   string `json:"actor_id"`
	}{CommentID: c.ID, SignalID: c.SignalID, ActorID: c.ActorID})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// slaClockSnapshot is the minimised audit snapshot of an SLA clock pause /
// resume: the target, the frozen deadline, the accumulated pause seconds, the
// current pause start and the fulfilment instant, plus the documented reason.
func slaClockSnapshot(c domain.SlaClock, reason string) (json.RawMessage, error) {
	var pausedAt, fulfilledAt *time.Time
	if c.Paused() {
		at := c.PausedAt
		pausedAt = &at
	}
	if c.Fulfilled() {
		at := c.FulfilledAt
		fulfilledAt = &at
	}
	b, err := json.Marshal(struct {
		Target        string     `json:"target"`
		DeadlineAt    time.Time  `json:"deadline_at"`
		PausedSeconds int64      `json:"paused_seconds"`
		PausedAt      *time.Time `json:"paused_at,omitempty"`
		FulfilledAt   *time.Time `json:"fulfilled_at,omitempty"`
		Reason        string     `json:"reason,omitempty"`
	}{
		Target:        string(c.Target),
		DeadlineAt:    c.DeadlineAt,
		PausedSeconds: c.PausedSeconds,
		PausedAt:      pausedAt,
		FulfilledAt:   fulfilledAt,
		Reason:        reason,
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// signalActor resolves the audit principal of a triage/SLA command: an empty
// Type defaults to the I1b system principal (user actors arrive with I5a);
// an empty id is a client validation error — the actor of an audited command
// is mandatory. I4 records the actor; the permission gate lands with I5a
// (ARCH-004 §10).
func signalActor(op string, a Actor) (Actor, error) {
	if a.Type == "" {
		a.Type = ActorTypeSystem
	}
	if a.ID == "" {
		return Actor{}, Validationf(op, "actor id must not be empty")
	}
	return a, nil
}

// correlationOrNew keeps a caller-supplied correlation id, generating one
// when absent (ARCH-001 §1 audit_events.correlation_id links the audit row
// and the outbox row of the command).
func correlationOrNew(id string) string {
	if id == "" {
		return uuid.New()
	}
	return id
}
