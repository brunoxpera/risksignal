package repo

// UserAdminRepo half of UserRepo (ARCH-006 §3.3, WP-5b.03 port; adapter glue
// lands in WP-5b.05 / DEV-101).
//
// The I5b user/role administration use cases (ListUsers, GetUser, GrantRole,
// RevokeRole, DeactivateUser) run over application.UserAdminRepo, a distinct
// port from the authorizer's read-only application.UserRepo because they are
// the administration reads/writes, not the authorise-time reads. The DEV-089
// *repo.UserRepo implements both: its role grant/revoke and deactivation
// writes already live in user.go (GrantRole/RevokeRole/Deactivate); this file
// adds the administration read models (ListUsers/GetUser, with each user's
// current roles) and the port-shaped DeactivateUser wrapper, mapping the
// stored rows onto application.UserRecord so the application layer never
// imports the generated package.
//
// The list read follows the UserAdminRepo contract ("every user, ordered by
// display_name then id, each with its current roles"): it returns the whole
// user table ordered by display_name/id and joins each user's roles with the
// existing ListRolesByUser query (the current schema has no roles-in-list
// query, and the internal user table is small — the administration read is
// not a hot path). A role value the domain vocabulary does not know is
// skipped (an unknown role grants nothing — fail closed), the same rule as
// the authorizer's RolesByUserID.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// compile-time check that UserRepo satisfies the administration port too.
var _ application.UserAdminRepo = (*UserRepo)(nil)

// ListUsers implements application.UserAdminRepo: every user, active and
// deactivated alike (ADR-014), ordered by display_name then id, each with its
// current roles. An empty table yields an empty slice, never an error.
func (r *UserRepo) ListUsers(ctx context.Context) ([]application.UserRecord, error) {
	const op = "user.list_admin"

	rows, err := r.q.ListUsers(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.UserRecord, 0, len(rows))
	for _, row := range rows {
		roles, err := r.adminRoles(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, userRecordFrom(row, roles))
	}
	return out, nil
}

// GetUser implements application.UserAdminRepo: one user with its current
// roles by its stable internal id — the load the admin writes take before a
// mutation and the re-read that returns the changed user. A missing id is a
// not-found Error; a deactivated user still resolves (the caller reads
// DeactivatedAt to decide the state).
func (r *UserRepo) GetUser(ctx context.Context, id string) (application.UserRecord, error) {
	const op = "user.get_admin"

	uid, err := toUUID(id)
	if err != nil {
		return application.UserRecord{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetUserByID(ctx, uid)
	if err != nil {
		return application.UserRecord{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	roles, err := r.adminRoles(ctx, uid)
	if err != nil {
		return application.UserRecord{}, err
	}
	return userRecordFrom(row, roles), nil
}

// DeactivateUser implements application.UserAdminRepo: the soft deactivation
// (ADR-014: deactivate, never delete) at the injected instant, on the
// caller's transaction. It reuses the guarded Deactivate write — an
// already-deactivated (or unknown) user matches zero rows and surfaces as a
// conflict Error (the use case pre-loads the user to distinguish not-found
// from already-deactivated).
func (r *UserRepo) DeactivateUser(ctx context.Context, tx application.Tx, userID string, now time.Time) error {
	_, err := r.Deactivate(ctx, tx, userID, now)
	return err
}

// adminRoles reads one user's current roles, mapping the stored role rows
// onto domain.Role. An unknown role value is skipped (fail closed), like the
// authorizer's RolesByUserID.
func (r *UserRepo) adminRoles(ctx context.Context, uid pgtype.UUID) ([]domain.Role, error) {
	const op = "user.list_admin_roles"

	rows, err := r.q.ListRolesByUser(ctx, uid)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	roles := make([]domain.Role, 0, len(rows))
	for _, row := range rows {
		role, err := domain.ParseRole(row.Role)
		if err != nil {
			continue // unknown role grants nothing (fail closed)
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// userRecordFrom maps a stored users row plus its roles onto the
// administration read model (deactivated_at/last_login_at NULL ⇒ the zero
// instant; email NULL ⇒ "").
func userRecordFrom(row gen.User, roles []domain.Role) application.UserRecord {
	return application.UserRecord{
		ID:            uuidString(row.ID),
		SubjectID:     row.SubjectID,
		DisplayName:   row.DisplayName,
		Email:         textValue(row.Email),
		Roles:         roles,
		DeactivatedAt: tsTime(row.DeactivatedAt),
		LastLoginAt:   tsTime(row.LastLoginAt),
		CreatedAt:     tsTime(row.CreatedAt),
	}
}
