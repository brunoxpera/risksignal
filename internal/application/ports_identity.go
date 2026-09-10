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
	// SubjectID is the issuer-qualified external OIDC subject
	// (users.subject_id, "<issuer>::<sub>") — the login key the authenticated
	// adapters resolve an Identity on (ARCH-005 §2) and the value
	// audit.reveal_identity returns as the revealed subject id (ADR-014).
	SubjectID string
	// DisplayName is snapshotted into the audit row of a user command.
	DisplayName string
	// DeactivatedAt is the deactivation instant; the zero value means the
	// user is active. A deactivated user still resolves (ADR-014) but holds
	// no rights.
	DeactivatedAt time.Time
}

// UserRecord is the administration read model of one internal user (ARCH-005
// §1, ARCH-006 §3.3): the identity fields of the users row plus its current
// roles and the lifecycle instants the I5b admin screens render. It is the
// application-level projection the UserAdminRepo returns — the postgres
// adapter maps the generated row onto it, so the application never imports
// the generated package. DeactivatedAt/LastLoginAt are the zero time when
// NULL (zero DeactivatedAt ⇒ active), the same nullability convention as
// UserIdentity.
type UserRecord struct {
	ID          string // stable internal users.id
	SubjectID   string // issuer-qualified external OIDC subject
	DisplayName string
	Email       string // optional notification recipient; "" when none
	Roles       []domain.Role

	DeactivatedAt time.Time // zero = active (deactivate, never delete — ADR-014)
	LastLoginAt   time.Time // zero = never logged in
	CreatedAt     time.Time
}

// UserAdminRepo is the I5b user/role administration write port (ARCH-006 §3.3,
// ARCH-005 §1): the administration list read and the role grant/revoke and
// deactivation writes the I5b admin use cases (WP-5b.03) orchestrate. It is a
// distinct port from the authorizer's read-only UserRepo because these are the
// administration mutations, not the authorise-time reads: the DEV-089 postgres
// *repo.UserRepo implements both (its grant/revoke/deactivate writes already
// live there, unwrapped as use cases). Every write method runs on the caller's
// transaction, so a role grant/revoke/deactivation and its audit event commit
// or roll back together (one command, one transaction — ch. 5.1). The
// admin use cases never re-implement the SQL-guarded idempotency: GrantRole
// stores nothing for a held role and RevokeRole deletes nothing for an unheld
// one, so the use case diffs the current roles and audits only real changes.
type UserAdminRepo interface {
	// ListUsers returns every user, active and deactivated alike (ADR-014:
	// deactivated users are shown, not hidden), ordered by display_name then
	// id, each with its current roles. An empty table yields an empty slice,
	// never an error. The use case paginates the result.
	ListUsers(ctx context.Context) ([]UserRecord, error)

	// GetUser reads one user with its current roles by its stable internal id
	// — the load the admin writes take before a mutation and the re-read that
	// returns the changed user. A missing id is a not-found Error (the admin
	// read maps it to a 404); a deactivated user still resolves.
	GetUser(ctx context.Context, id string) (UserRecord, error)

	// GrantRole grants one role to one user; grantedAt is the injected clock
	// and grantedBy records the origin (the admin's internal id). Idempotent —
	// a held role stores nothing.
	GrantRole(ctx context.Context, tx Tx, userID string, role domain.Role, grantedAt time.Time, grantedBy string) error

	// RevokeRole removes one role from one user. Idempotent — revoking an
	// unheld role deletes nothing.
	RevokeRole(ctx context.Context, tx Tx, userID string, role domain.Role) error

	// DeactivateUser soft-deactivates one user (ADR-014: deactivate, never
	// delete) at the injected instant. The write is guarded on
	// deactivated_at IS NULL; an already-deactivated (or unknown) user matches
	// zero rows and surfaces as a conflict Error (the caller pre-loads the user
	// to distinguish not-found from already-deactivated).
	DeactivateUser(ctx context.Context, tx Tx, userID string, now time.Time) error
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

	// GetUserBySubject reads one user by its issuer-qualified external
	// subject_id — the resolution the authenticated adapters (the reveal
	// endpoint and the CLI identity-lookup) run to turn a verified identity
	// into the internal users.id the authoriser and the audit actor key on
	// (ARCH-005 §2). It is a pure read: a login creates the row, request-time
	// resolution never does. An unknown subject is a not-found Error (the
	// caller fails closed); a deactivated user still resolves.
	GetUserBySubject(ctx context.Context, subjectID string) (UserIdentity, error)
}
