package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// UserRepo is the postgres implementation of the I5a identity persistence
// (users.sql + user_roles.sql, ARCH-005 §1/§5, WP-5a.03 / DEV-089): the
// first-login create-or-read by subject, the by-id read, the deactivation and
// the last-login touch, plus the role grant/revoke and the per-user role
// read.
//
// It returns the raw generated rows (gen.User / gen.UserRole) and applies no
// domain mapping: the authorizer's `resolvePrincipal` — and the mapping onto
// domain.Principal it performs — lives in the application layer (WP-5a.06),
// not in this adapter. The adapter only persists/reads and translates driver
// errors (dbmap.go). The write methods receive the application transaction
// handle and rebind (Queries.WithTx) so the write runs on exactly the
// transaction the caller opened (ARCH-001 §2); the reads run on the
// pool-scoped query set. Every instant comes from the injected clock.
type UserRepo struct {
	q *gen.Queries
}

// NewUserRepo binds the repository to one query set.
func NewUserRepo(q *gen.Queries) *UserRepo { return &UserRepo{q: q} }

// UpsertBySubject implements the first-login create-or-read (ARCH-005 §1/§2):
// the verified token's subject resolves the internal user, inserting the row
// on the first login or refreshing display_name/email and the last-login
// instant on a later login. subject_id is the UQ login key, so a repeated
// login returns the same stable id — never a second row. now is the injected
// login instant (UpsertUserBySubject stamps last_login_at, created_at and
// updated_at from it). email may be empty (it is optional and never the login
// key). The stored raw row is returned.
func (r *UserRepo) UpsertBySubject(ctx context.Context, tx application.Tx, subjectID, displayName, email string, now time.Time) (gen.User, error) {
	const op = "user.upsert_by_subject"

	if subjectID == "" {
		return gen.User{}, application.Validationf(op, "subject_id is mandatory")
	}
	if displayName == "" {
		return gen.User{}, application.Validationf(op, "display_name is mandatory")
	}
	if now.IsZero() {
		return gen.User{}, application.Validationf(op, "login instant must not be zero")
	}
	row, err := r.q.WithTx(tx).UpsertUserBySubject(ctx, gen.UpsertUserBySubjectParams{
		SubjectID:   subjectID,
		DisplayName: displayName,
		Email:       toTextOpt(email),
		Now:         toTS(now),
	})
	if err != nil {
		return gen.User{}, mapDBError(op, err)
	}
	return row, nil
}

// GetByID reads one user by its stable internal id — the authorizer's
// deactivated_at re-check at authorise time (ARCH-005 §5) and the
// audit.reveal_identity resolution read (ADR-014). A missing id is a not-found
// Error; a deactivated user still resolves (the caller reads DeactivatedAt to
// decide the state). The stored raw row is returned.
func (r *UserRepo) GetByID(ctx context.Context, id string) (gen.User, error) {
	const op = "user.get_by_id"

	uid, err := toUUID(id)
	if err != nil {
		return gen.User{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetUserByID(ctx, uid)
	if err != nil {
		return gen.User{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return row, nil
}

// Deactivate soft-deactivates one user (ARCH-005 §1, ADR-014): deactivated_at
// and updated_at are stamped from the injected clock. The statement's
// `deactivated_at IS NULL` guard makes the transition idempotent — an
// already-deactivated (or unknown) user matches zero rows, reported as a
// conflict Error (the guard did not apply; the caller decides whether a
// repeated deactivation is a no-op), exactly as the SLA-clock guarded writes
// report a zero-row guard. The stored raw row is returned when a row changed.
func (r *UserRepo) Deactivate(ctx context.Context, tx application.Tx, id string, now time.Time) (gen.User, error) {
	const op = "user.deactivate"

	uid, err := toUUID(id)
	if err != nil {
		return gen.User{}, application.ValidationError(op, err)
	}
	if now.IsZero() {
		return gen.User{}, application.Validationf(op, "deactivation instant must not be zero")
	}
	row, err := r.q.WithTx(tx).DeactivateUser(ctx, gen.DeactivateUserParams{
		Now: toTS(now),
		ID:  uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return gen.User{}, application.ConflictError(op, fmt.Errorf("user %s: guard did not match (already deactivated or missing)", id))
		}
		return gen.User{}, mapDBError(op, err)
	}
	return row, nil
}

// TouchLastLogin stamps the last successful login/session/token resolution on
// an existing user (ARCH-005 §1): last_login_at and updated_at come from the
// injected clock. It is the already-resolved counterpart of UpsertBySubject
// (a session/token refresh does not re-run the create-or-read). An unknown id
// is a not-found Error. The stored raw row is returned.
func (r *UserRepo) TouchLastLogin(ctx context.Context, tx application.Tx, id string, now time.Time) (gen.User, error) {
	const op = "user.touch_last_login"

	uid, err := toUUID(id)
	if err != nil {
		return gen.User{}, application.ValidationError(op, err)
	}
	if now.IsZero() {
		return gen.User{}, application.Validationf(op, "login instant must not be zero")
	}
	row, err := r.q.WithTx(tx).TouchLastLogin(ctx, gen.TouchLastLoginParams{
		Now: toTS(now),
		ID:  uid,
	})
	if err != nil {
		return gen.User{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return row, nil
}

// List returns every user, active and deactivated alike, ordered by
// display_name (then id) — the administration read the I5b users screen binds.
// An empty table yields an empty slice, never an error.
func (r *UserRepo) List(ctx context.Context) ([]gen.User, error) {
	const op = "user.list"

	rows, err := r.q.ListUsers(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	return rows, nil
}

// GrantRole grants one role to one user (ARCH-005 §1): the first-login claim
// sync and the admin grant path share it. grantedAt is the injected clock;
// grantedBy records the origin (an admin's internal id, or 'claim'; an empty
// value stores NULL). The grant is idempotent — a held role stores nothing
// (ON CONFLICT DO NOTHING), so the caller can grant unconditionally.
func (r *UserRepo) GrantRole(ctx context.Context, tx application.Tx, userID string, role domain.Role, grantedAt time.Time, grantedBy string) error {
	const op = "user.grant_role"

	uid, err := toUUID(userID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if !role.Valid() {
		return application.Validationf(op, "invalid role %q", role)
	}
	if grantedAt.IsZero() {
		return application.Validationf(op, "grant instant must not be zero")
	}
	if err := r.q.WithTx(tx).GrantRole(ctx, gen.GrantRoleParams{
		UserID:    uid,
		Role:      string(role),
		GrantedAt: toTS(grantedAt),
		GrantedBy: toTextOpt(grantedBy),
	}); err != nil {
		return mapDBError(op, err)
	}
	return nil
}

// RevokeRole removes one role from one user (ARCH-005 §1): the admin revoke
// path. It is idempotent — revoking a role the user does not hold deletes
// zero rows and is not an error.
func (r *UserRepo) RevokeRole(ctx context.Context, tx application.Tx, userID string, role domain.Role) error {
	const op = "user.revoke_role"

	uid, err := toUUID(userID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if !role.Valid() {
		return application.Validationf(op, "invalid role %q", role)
	}
	if err := r.q.WithTx(tx).RevokeRole(ctx, gen.RevokeRoleParams{
		UserID: uid,
		Role:   string(role),
	}); err != nil {
		return mapDBError(op, err)
	}
	return nil
}

// ListRolesByUser returns one user's current roles ordered by role — the
// authorizer's authorise-time re-read (ARCH-005 §5) and the admin detail
// read. A user holding no roles yields an empty slice, never an error (zero
// roles ⇒ deny-by-default). The raw generated rows are returned.
func (r *UserRepo) ListRolesByUser(ctx context.Context, userID string) ([]gen.UserRole, error) {
	const op = "user.list_roles_by_user"

	uid, err := toUUID(userID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	rows, err := r.q.ListRolesByUser(ctx, uid)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	return rows, nil
}
