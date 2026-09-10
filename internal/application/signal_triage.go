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
	// EventTypeSignalSLAClockCreated records a clock the priority-upgrade
	// treatment created (a missing stricter clock, ARCH-004 §4.3).
	EventTypeSignalSLAClockCreated = "signal.sla_clock_created"
	// EventTypeSignalSLAClockTightened records a clock the priority-upgrade
	// treatment tightened — the audit carries the old→new deadline so the
	// already-elapsed processing time stays visible (ch. 9.4, ARCH-004 §4.3).
	EventTypeSignalSLAClockTightened = "signal.sla_clock_tightened"
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

	// The priority-recompute detail (ARCH-004 §5, DEV-077): the
	// vulnerability the recompute read, and the rule version/input hash the
	// recomputed priority was derived under. Carried by the
	// signal.reopen_proposed proposal — identity/enum only, never free text.
	CveID       string `json:"cve_id,omitempty"`
	RuleVersion string `json:"rule_version,omitempty"`
	InputHash   string `json:"input_hash,omitempty"`
}

// TransitionSignal moves a signal along the ch. 6.3 state machine (ARCH-004
// §2): it validates the edge (domain.Transition), enforces the mandatory
// reason of the closed-entry and reopen edges, then — inside one transaction
// — writes the guarded status change (optimistic lock; a stale version is a
// conflict), stamps or clears closed_at, appends the audit event and enqueues
// the outbox event. The updated signal is returned.
func (s *Service) TransitionSignal(ctx context.Context, in TransitionSignalInput) (domain.RiskSignal, error) {
	const op = "transition_signal"

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}
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
	// The signals.triage gate runs after the load (the object is known) and
	// before the guarded write: a Systemverantwortliche may triage only an
	// assigned signal (owner_id = principal.id); the Analyst's all-scope
	// passes unconditionally (ARCH-005 §5). A denial writes nothing.
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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
		// The ch. 6.3 status change implies an SLA clock treatment
		// (ARCH-004 §4.3): fulfil the target(s) the new status completes, or
		// reset the clocks on a reopen. It runs on this very transaction, so
		// a rolled-back transition rolls its clock treatment back with it.
		if err := s.applyTransitionClocks(ctx, tx, current.Status, row, in.To, now); err != nil {
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

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}
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
	// signals.triage, object-scoped: only the signal's current owner may
	// (re)assign it under the assigned scope (ARCH-005 §5).
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.Comment{}, err
	}
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

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.Comment{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.RiskSignal{}, err
	}
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
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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
		// The explicit acknowledgement fulfils the acknowledgement clock
		// (ARCH-004 §4.3). The call is idempotent and never fabricates a
		// clock: a missing clock (e.g. a priority with no acknowledgement
		// target) or an already-fulfilled one is a no-op. It commits with
		// the status change.
		if _, _, err := s.slaClocks.Fulfil(ctx, tx, row.ID, domain.SLATargetAcknowledgement, now); err != nil {
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

	// C-4 carry-over: the signals.override gate sits at the top, so a
	// non-Analyst (e.g. an Administrator) is denied before the
	// expected_version/domain checks run (ARCH-005 §5).
	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionSignalsOverride, domain.ScopeAll, ""); err != nil {
		return domain.RiskSignal{}, err
	}
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
		// The ARCH-004 §4.3 priority-upgrade clock treatment: create the
		// clocks the new priority defines but the signal lacks, and tighten
		// the existing ones whose new deadline is earlier — audited per
		// mutation. It runs on this transaction, so a rolled-back override
		// rolls its clock treatment back with it. A downgrade (P1→P3) only
		// ever creates-or-tightens too, so it never lengthens a deadline.
		if err := s.applyUpgradeClocks(ctx, tx, row.ID, row.Priority, actor, correlationID, now); err != nil {
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

	// C-4 carry-over: revert is the inverse of the override decision
	// authority, so it shares signals.override (ARCH-005 §5). The gate sits
	// at the top, before the expected_version/domain checks.
	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionSignalsOverride, domain.ScopeAll, ""); err != nil {
		return domain.RiskSignal{}, err
	}
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

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.SlaClock{}, err
	}
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
	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.SlaClock{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return domain.SlaClock{}, err
	}
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
	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return domain.SlaClock{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsTriage, domain.ScopeAssigned, current.Owner); err != nil {
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

// definedAt reports whether the injected SLA time profile defines a clock
// for the (priority, target) pair — a positive duration means defined
// (ARCH-004 §4.2/§4.3). It guards every fulfil and reset the triage commands
// issue: a target without a defined duration has no clock and is never
// touched (never created, never fulfilled, never reset).
func (s *Service) definedAt(priority domain.Priority, target domain.SLATarget) bool {
	return s.slaProfile.Duration(priority, target) > 0
}

// applyTransitionClocks is the ARCH-004 §4.3 clock treatment of one ch. 6.3
// status change, run on the transition's transaction:
//
//   - → action_planned / accepted / resolved fulfils the assessment and the
//     decision clock — a qualified impact assessment is documented and a
//     disposition is decided (the common fast path co-fulfils both);
//   - → not_affected fulfils the assessment clock alone;
//   - a reopen (a closed state → in_review) resets every clock defined at
//     the signal's current priority;
//   - every other target (new / in_review entry) leaves the clocks alone.
//
// Each fulfil is guarded by the injected profile, so e.g. P3's missing
// decision clock is a no-op, and the reset touches only defined targets. The
// priority is the signal's effective priority, which a status change never
// alters.
func (s *Service) applyTransitionClocks(ctx context.Context, tx Tx, from domain.SignalStatus, signal domain.RiskSignal, to domain.SignalStatus, now time.Time) error {
	switch to {
	case domain.SignalStatusActionPlanned, domain.SignalStatusAccepted, domain.SignalStatusResolved:
		if err := s.fulfilClock(ctx, tx, signal, domain.SLATargetAssessment, now); err != nil {
			return err
		}
		return s.fulfilClock(ctx, tx, signal, domain.SLATargetDecision, now)
	case domain.SignalStatusNotAffected:
		return s.fulfilClock(ctx, tx, signal, domain.SLATargetAssessment, now)
	case domain.SignalStatusInReview:
		if domain.IsReopen(from, to) {
			return s.resetClocks(ctx, tx, signal, now)
		}
	}
	return nil
}

// fulfilClock fulfils one SLA clock of a signal when the injected profile
// defines it at the signal's priority (ARCH-004 §4.3). The port's Fulfil is
// idempotent and never creates a clock: an already-fulfilled or missing
// clock is a no-op (changed = false), and a target the profile does not
// define is skipped before the call.
func (s *Service) fulfilClock(ctx context.Context, tx Tx, signal domain.RiskSignal, target domain.SLATarget, at time.Time) error {
	if !s.definedAt(signal.Priority, target) {
		return nil
	}
	if _, _, err := s.slaClocks.Fulfil(ctx, tx, signal.ID, target, at); err != nil {
		return err
	}
	return nil
}

// resetClocks restarts every SLA clock the profile defines at the signal's
// priority on a reopen (ARCH-004 §4.3): started_at = now, deadline_at = now +
// duration, fulfilled_at cleared and the pause counters zeroed. Targets the
// profile does not define have no clock and are never touched. It runs on
// the reopen's transaction, so a rolled-back reopen resets nothing.
func (s *Service) resetClocks(ctx context.Context, tx Tx, signal domain.RiskSignal, now time.Time) error {
	for _, target := range s.slaProfile.Targets(signal.Priority) {
		deadline := now.Add(s.slaProfile.Duration(signal.Priority, target))
		if _, err := s.slaClocks.Reset(ctx, tx, signal.ID, target, now, deadline); err != nil {
			return err
		}
	}
	return nil
}

// createClocks creates every SLA clock the injected profile defines at the
// signal's priority (ARCH-004 §4.3 Create): started_at = now, deadline_at =
// now + duration. It is the clock treatment of the CreateSignal commit — run
// on the very transaction as the signal, its audit event and its outbox
// event, so a rolled-back create leaves no clock behind — and it is the other
// half of the lifecycle DEV-076's fulfil/reset act on. Only targets with a
// defined duration are created (P3/P4 get no notification clock, P3/P4 no
// decision clock); the natural-key upsert keeps a re-run idempotent. The
// signal.created audit event documents the creation, so no per-clock audit
// row is written on this path — the create command's own audit event is its
// evidence, matching the DEV-076 fulfil/reset treatment that rides its
// transition's audit event.
func (s *Service) createClocks(ctx context.Context, tx Tx, signalID string, priority domain.Priority, now time.Time) error {
	const op = "sla_clocks.create"
	for _, target := range s.slaProfile.Targets(priority) {
		clock, err := domain.NewSlaClock(uuid.New(), signalID, target, priority, s.slaProfile, now)
		if err != nil {
			return InfraError(op, err)
		}
		if _, err := s.slaClocks.Upsert(ctx, tx, clock); err != nil {
			return err
		}
	}
	return nil
}

// applyUpgradeClocks applies the ARCH-004 §4.3 clock treatment of a priority
// change to `priority`: the manual OverridePriority path drives it today and
// RecomputePriority reuses it when a recompute-driven change must tighten
// clocks. For every target the injected profile defines at the new priority:
//
//   - a target without a clock is created fresh from the upgrade instant
//     (Upsert at now);
//   - a target whose existing clock would shorten to an earlier deadline
//     (now + duration(new_P, target) < the stored deadline_at) is tightened
//     to the new value, keeping started_at — the already-elapsed processing
//     time stays visible (ch. 9.4).
//
// A target the new priority does not define is left untouched, and a deadline
// that is not earlier is left untouched: an upgrade never lengthens a window.
// Every mutation writes one audit row on the caller's transaction — the
// create its new deadline, the tighten its old→new deadline — so a rolled-back
// command rolls its clock treatment back with it. The treatment is idempotent:
// a re-run finds the created clock (whose deadline is now later than the
// upgrade instant's target) or the already-tightened deadline, and writes
// nothing more.
func (s *Service) applyUpgradeClocks(ctx context.Context, tx Tx, signalID string, priority domain.Priority, actor Actor, correlationID string, now time.Time) error {
	const op = "sla_clocks.upgrade"
	for _, target := range s.slaProfile.Targets(priority) {
		existing, ok, err := s.slaClocks.Get(ctx, tx, signalID, target)
		if err != nil {
			return err
		}
		if !ok {
			created, err := domain.NewSlaClock(uuid.New(), signalID, target, priority, s.slaProfile, now)
			if err != nil {
				return InfraError(op, err)
			}
			stored, err := s.slaClocks.Upsert(ctx, tx, created)
			if err != nil {
				return err
			}
			after, err := slaClockMutationSnapshot(stored, time.Time{})
			if err != nil {
				return InfraError(op, err)
			}
			if err := s.appendSignalAudit(ctx, tx, EventTypeSignalSLAClockCreated, signalID, actor, correlationID, now, nil, after); err != nil {
				return err
			}
			continue
		}
		newDeadline := now.Add(s.slaProfile.Duration(priority, target))
		tightened, changed, err := s.slaClocks.Tighten(ctx, tx, signalID, target, newDeadline)
		if err != nil {
			return err
		}
		if !changed {
			continue // fulfilled, or the stored deadline is already at least as early
		}
		after, err := slaClockMutationSnapshot(tightened, existing.DeadlineAt)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalSLAClockTightened, signalID, actor, correlationID, now, nil, after); err != nil {
			return err
		}
	}
	return nil
}

// slaClockMutationSnapshot is the minimised audit snapshot of one SLA clock
// mutation of the priority-upgrade treatment (ch. 13.5): the target, the
// resulting started_at/deadline_at and — on a tighten — the replaced (old)
// deadline. Identities and timestamps only, never free text.
func slaClockMutationSnapshot(c domain.SlaClock, oldDeadline time.Time) (json.RawMessage, error) {
	snap := struct {
		Target      string     `json:"target"`
		StartedAt   time.Time  `json:"started_at"`
		DeadlineAt  time.Time  `json:"deadline_at"`
		OldDeadline *time.Time `json:"old_deadline_at,omitempty"`
	}{
		Target:     string(c.Target),
		StartedAt:  c.StartedAt,
		DeadlineAt: c.DeadlineAt,
	}
	if !oldDeadline.IsZero() {
		od := oldDeadline
		snap.OldDeadline = &od
	}
	return json.Marshal(snap)
}

// signalActor resolves the audit principal of a triage/SLA command (ARCH-005
// §6). I5a stops guessing a default: the actor type must be one of system,
// user or service — the composition roots now supply the authenticated
// principal (Type = "user", ID = users.id, DisplayName = snapshot) — and an
// empty id is a client validation error (the actor of an audited command is
// mandatory). The permission gate itself runs earlier in the command
// (authz.go); this resolves the identity that is stamped into the audit row.
func signalActor(op string, a Actor) (Actor, error) {
	if !validActorType(a.Type) {
		return Actor{}, Validationf(op, "actor type %q must be one of %q, %q, %q", a.Type, ActorTypeSystem, ActorTypeUser, ActorTypeService)
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
