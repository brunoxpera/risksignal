package application

import (
	"context"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// GetSignalInput is the single-signal read (ARCH-001 §4 getSignal) with the
// authenticated principal: signals.read is gated per the matrix and an
// `assigned`/`own` grant restricts the read to the principal's owned signal
// (ARCH-005 §5).
type GetSignalInput struct {
	SignalID string
	Actor    Actor
}

// GetSignal returns the readable detail view of one signal — the signal
// joined with its match, vulnerability, component and asset (ARCH-001 §4
// getSignal). An unknown id is a not-found error (the HTTP layer maps it to
// a 404 ProblemDetails). A user principal without signals.read, or with an
// `assigned`/`own` grant on a signal it does not own, is denied with a
// ForbiddenError (403) before the view is returned (ARCH-005 §5).
func (s *Service) GetSignal(ctx context.Context, in GetSignalInput) (Signal, error) {
	const op = "get_signal"

	if in.SignalID == "" {
		return Signal{}, Validationf(op, "signal id must not be empty")
	}
	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return Signal{}, err
	}
	// Membership first (a role-less user is denied before the load), then the
	// object-scope check on the loaded signal's owner.
	scope := principal.GrantedScope(domain.PermissionSignalsRead)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return Signal{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionSignalsRead)
	}
	sig, err := s.signals.GetByID(ctx, in.SignalID)
	if err != nil {
		return Signal{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionSignalsRead, scope, sig.Owner); err != nil {
		return Signal{}, err
	}
	return sig, nil
}
