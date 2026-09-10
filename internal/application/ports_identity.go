package application

import (
	"context"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// UserIdentity is the authorise-time snapshot of one internal user (ARCH-005
// §1/§5): the stable internal id (users.id — the value audit_events.actor_id
// stores for user actors), the display name denormalised into audit rows, and
// the deactivation instant (the zero value means active). It is the
// application-level projection of the users row: the postgres adapter maps
// gen.User onto it, so the application layer never imports the generated
// package (.go-arch-lint.yml).
type UserIdentity struct {
	// ID is the stable internal users.id.
	ID string
	// DisplayName is snapshotted into the audit row of a user command.
	DisplayName string
	// DeactivatedAt is the deactivation instant; the zero value means the
	// user is active. A deactivated user still resolves (ADR-014) but holds
	// no rights.
	DeactivatedAt time.Time
}

// UserRepo is the I5a identity read port of the authorizer (ARCH-005 §1/§5,
// WP-5a.06): resolvePrincipal re-reads a user's deactivation state and its
// *current* roles at authorise time — never from the token — so a
// deactivation or a role change takes effect on the next command,
// independent of token lifetime. The DEV-089 postgres *repo.UserRepo
// implements it; the adapter maps its stored rows onto UserIdentity and
// []domain.Role.
//
// It is a read-only port: the login/create, role-grant and deactivation
// writes (also on the DEV-089 repository) serve the identity lifecycle and
// are not part of the authoriser's seam.
type UserRepo interface {
	// GetUserByID reads one user by its stable internal id. An unknown id is
	// a not-found Error (the authorizer denies it); a deactivated user still
	// resolves (the caller reads DeactivatedAt to decide the state).
	GetUserByID(ctx context.Context, id string) (UserIdentity, error)

	// RolesByUserID returns the user's current roles (re-read at authorise
	// time). A user holding no roles yields an empty slice, never an error —
	// zero roles means deny-by-default on everything (ARCH-005 §3).
	RolesByUserID(ctx context.Context, userID string) ([]domain.Role, error)
}
