package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the I5a use-case authorisation seam of ARCH-005 §5
// (WP-5a.06): the deny-by-default gate every user-invokable use case runs
// before any write and before opening a transaction. The application layer is
// the gate of record — the check lives inside the command, so no alternate
// adapter (CLI, future web, a direct in-process call) can bypass it. The pure
// decision is domain.Authorize (DEV-087); this file resolves the principal and
// wraps that decision into the application error vocabulary.
//
// The gate applies to *user* principals only. Internal system and service
// actors (the matching pipeline's CreateSignal, source fetch/normalize,
// sla.evaluate, priority.recompute, the demo seed) run inside the trusted
// worker/CLI process and are not user-authorised (ARCH-005 §5): they are not
// user-invokable, so a gated use case invoked by one is a trusted internal
// call and proceeds. A user-invokable use case invoked by a user actor is
// authorised at the concrete use case.

// principalFor resolves the audit actor of a gated use case into a Principal.
// A non-user actor (system/service) is a trusted internal principal and
// resolves to the zero Principal (the gate is a no-op for it); a user actor is
// resolved through resolvePrincipal, which denies a deactivated or unknown
// principal. It performs no object check — that is authorizeObject's job,
// once the object owner is known.
func (s *Service) principalFor(ctx context.Context, op string, a Actor) (domain.Principal, error) {
	if a.Type != ActorTypeUser {
		return domain.Principal{}, nil
	}
	return s.resolvePrincipal(ctx, op, a)
}

// resolvePrincipal resolves the authenticated user actor into a Principal
// enriched with the *current* authorisation state (ARCH-005 §5):
//
//   - the internal users.id is looked up through UserRepo (an unknown id
//     denies);
//   - the roles are re-read from user_roles at authorise time — never taken
//     from the token — so a role change takes effect on the next command;
//   - deactivated_at is re-read and a deactivated principal denies (it still
//     resolves in the audit trail, but holds no rights, ADR-014).
//
// A denial is a ForbiddenError (403); a repository failure is an InfraError.
// No transaction is opened and nothing is written on either path.
func (s *Service) resolvePrincipal(ctx context.Context, op string, a Actor) (domain.Principal, error) {
	if a.ID == "" {
		return domain.Principal{}, Forbiddenf(op, "user actor id must not be empty")
	}
	if s.users == nil {
		return domain.Principal{}, InfraError(op, errors.New("authorizer: user repository is not wired"))
	}
	u, err := s.users.GetUserByID(ctx, a.ID)
	if err != nil {
		if kind, _ := ErrorKindOf(err); kind == KindNotFound {
			return domain.Principal{}, Forbiddenf(op, "unknown principal %q", a.ID)
		}
		return domain.Principal{}, InfraError(op, fmt.Errorf("resolve principal %q: %w", a.ID, err))
	}
	if !u.DeactivatedAt.IsZero() {
		return domain.Principal{}, Forbiddenf(op, "principal %q is deactivated", a.ID)
	}
	roles, err := s.users.RolesByUserID(ctx, a.ID)
	if err != nil {
		return domain.Principal{}, InfraError(op, fmt.Errorf("resolve roles of principal %q: %w", a.ID, err))
	}
	return domain.Principal{
		Identity:      domain.Identity{DisplayName: u.DisplayName},
		InternalID:    u.ID,
		Roles:         roles,
		DeactivatedAt: u.DeactivatedAt,
	}, nil
}

// authorizeObject applies the pure domain.Authorize decision for perm at
// scope to the resolved principal, with ownerID the owner of the concrete
// object the use case acts on ("" for a non-object-bound command). A non-user
// principal (the zero Principal) is not user-authorised and passes — the
// gate exists for user principals only. A denial is a ForbiddenError (403);
// it is raised before any write and before opening a transaction.
func (s *Service) authorizeObject(op string, p domain.Principal, perm domain.Permission, scope domain.Scope, ownerID string) error {
	if p.InternalID == "" {
		return nil // a non-user principal is not user-authorised (ARCH-005 §5)
	}
	ok, err := domain.Authorize(p.Roles, perm, scope, ownerID, p.InternalID)
	if err != nil {
		return InfraError(op, err)
	}
	if !ok {
		return Forbiddenf(op, "principal %q is not permitted %s", p.InternalID, perm)
	}
	return nil
}

// RoutePrincipal resolves an authenticated identity into the domain.Principal
// the HTTP route-level permission gate consults (ARCH-005 §5). It performs the
// same authorise-time re-read the in-use-case authoriser performs — the
// internal users.id by subject and the current roles from user_roles (never
// from the token) — and denies a missing subject, an unknown user or a
// deactivated principal (deny-by-default). It is the defense-in-depth
// pre-gate: it decides no permission and no object scope, and the use case
// remains the gate of record.
func (s *Service) RoutePrincipal(ctx context.Context, id domain.Identity) (domain.Principal, error) {
	const op = "route_principal"
	actor, err := s.ResolveActor(ctx, id)
	if err != nil {
		return domain.Principal{}, err
	}
	return s.resolvePrincipal(ctx, op, actor)
}

// authorize is the one-shot form of the seam: resolve the actor, then apply
// the object-aware decision. A non-user actor is a no-op (see principalFor).
func (s *Service) authorize(ctx context.Context, op string, a Actor, perm domain.Permission, scope domain.Scope, ownerID string) (domain.Principal, error) {
	p, err := s.principalFor(ctx, op, a)
	if err != nil {
		return domain.Principal{}, err
	}
	if err := s.authorizeObject(op, p, perm, scope, ownerID); err != nil {
		return domain.Principal{}, err
	}
	return p, nil
}
