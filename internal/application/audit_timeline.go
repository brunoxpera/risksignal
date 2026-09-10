package application

// This file implements the ListAuditEvents read use case of ARCH-006 §3.1
// (DEV-110): the signal audit timeline the web adapter renders on the signal
// detail page. It is a pure read over the append-only audit_events table
// through the AuditRepo read path (ListByAggregate); the events are ordered
// by occurred_at then id (the port contract) and the use case opens no
// transaction.
//
// The read is object-scoped by the audit.read matrix (ARCH-005 §3/§5,
// §12.2): the Analyst holds audit.read at the `own` scope and the
// Systemverantwortliche at the `assigned` scope — both restrict the read to
// the principal's owned signals (the owner filter), while the Administrator,
// the Auditor and the Product Owner hold `all`. The use case therefore
// loads the target signal to resolve its owner and runs the standard
// authorizeObject check (deny-by-default): a scoped principal that does not
// own the signal is denied with a ForbiddenError (403) before the timeline is
// read. An unknown signal id is a not-found Error.

import (
	"context"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// ListAuditEventsInput is the signal-timeline read (ARCH-006 §3.1, DEV-110):
// the signal id and the authenticated principal. audit.read gates the read
// per the matrix and an `own`/`assigned` grant restricts it to the
// principal's owned signal (the object-scope check against the signal owner).
type ListAuditEventsInput struct {
	SignalID string
	Actor    Actor
}

// ListAuditEventsResult is one signal's audit timeline, ordered by
// occurred_at then id (the AuditRepo.ListByAggregate contract). A signal
// without audit events yields an empty slice, never an error.
type ListAuditEventsResult struct {
	Events []AuditEvent
}

// ListAuditEvents returns the audit timeline of one signal (ARCH-006 §3.1,
// DEV-110). An unknown id is a not-found error. A user principal without
// audit.read, or with an `own`/`assigned` grant on a signal it does not own,
// is denied with a ForbiddenError (403) before the timeline is returned
// (ARCH-005 §5).
func (s *Service) ListAuditEvents(ctx context.Context, in ListAuditEventsInput) (ListAuditEventsResult, error) {
	const op = "list_audit_events"

	if in.SignalID == "" {
		return ListAuditEventsResult{}, Validationf(op, "signal id must not be empty")
	}
	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return ListAuditEventsResult{}, err
	}
	// Membership first (a role-less user is denied before the load), then the
	// object-scope check on the loaded signal's owner.
	scope := principal.GrantedScope(domain.PermissionAuditRead)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return ListAuditEventsResult{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionAuditRead)
	}
	// The signal load doubles as the existence check and the owner lookup the
	// object scope needs (audit rows carry no owner of their own).
	sig, err := s.signals.GetByID(ctx, in.SignalID)
	if err != nil {
		return ListAuditEventsResult{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionAuditRead, scope, sig.Owner); err != nil {
		return ListAuditEventsResult{}, err
	}

	events, err := s.audit.ListByAggregate(ctx, AuditAggregateRiskSignal, in.SignalID)
	if err != nil {
		return ListAuditEventsResult{}, err
	}
	return ListAuditEventsResult{Events: events}, nil
}
