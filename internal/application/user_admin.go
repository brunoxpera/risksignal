package application

// This file implements the I5b user/role administration use cases of
// ARCH-006 §3.3 (WP-5b.03): ListUsers, ListRoles, GrantRole, RevokeRole and
// DeactivateUser. They are thin, permission-gated orchestration over the
// existing users/user_roles tables (the DEV-089 repository) — no new
// business logic: the role catalogue is the domain matrix, the SQL-guarded
// idempotency stays in the writes, and every change writes its audit event
// (users.role_granted / users.role_revoked / users.deactivated, concept ch.
// 13.2). All five are gated on users.roles.manage (deny-by-default); a denied
// call opens no transaction and writes no audit row. Deactivation is
// deactivate-never-delete (ADR-014): the internal id stays permanently
// referenceable so the audit trail stays resolvable.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Audit vocabulary of the user/role administration (concept ch. 13.2).
const (
	// AuditAggregateUser is the aggregate type of a user/role audit row; the
	// aggregate id is the user's internal id.
	AuditAggregateUser = "user"
	// AuditActionUserRoleGranted records one role grant.
	AuditActionUserRoleGranted = "users.role_granted"
	// AuditActionUserRoleRevoked records one role revocation.
	AuditActionUserRoleRevoked = "users.role_revoked"
	// AuditActionUserDeactivated records one user deactivation.
	AuditActionUserDeactivated = "users.deactivated"
)

// errUserAdminNotWired is the programming error of the admin use cases invoked
// without the UserAdminRepo port.
var errUserAdminNotWired = errors.New("application: user-admin repository is not wired")

// ListUsersInput is the user-list query (ARCH-006 §3.3, GET /users): a page
// size and an opaque cursor. Limit 0 means the default (20); limits above
// maxListLimit are rejected.
type ListUsersInput struct {
	Limit  int
	Cursor string
	Actor  Actor
}

// ListUsersResult is one page of the user list. NextCursor is empty on the
// last page.
type ListUsersResult struct {
	Users      []UserRecord
	NextCursor string
}

// ListUsers returns one cursor-paginated page of internal users with their
// current roles (ARCH-006 §3.3). users.roles.manage gates the read
// (deny-by-default). The list is ordered by display_name then id (the
// UserAdminRepo.ListUsers contract) and paginated in the use case.
func (s *Service) ListUsers(ctx context.Context, in ListUsersInput) (ListUsersResult, error) {
	const op = "list_users"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionUsersRolesManage, domain.ScopeAll, ""); err != nil {
		return ListUsersResult{}, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 0 || limit > maxListLimit {
		return ListUsersResult{}, Validationf(op, "limit %d outside [1,%d] (0 means the default %d)", in.Limit, maxListLimit, defaultListLimit)
	}
	offset, err := decodeCursor(op, in.Cursor)
	if err != nil {
		return ListUsersResult{}, err
	}
	if s.userAdmin == nil {
		return ListUsersResult{}, InfraError(op, errUserAdminNotWired)
	}
	users, err := s.userAdmin.ListUsers(ctx)
	if err != nil {
		return ListUsersResult{}, err
	}
	if offset >= len(users) {
		users = nil
	} else {
		users = users[offset:]
	}
	res := ListUsersResult{}
	if len(users) > limit {
		res.Users = users[:limit]
		res.NextCursor = encodeCursor(offset + limit)
	} else {
		res.Users = users
	}
	return res, nil
}

// ListRolesInput is the role-catalogue read (ARCH-006 §3.3, GET /roles).
type ListRolesInput struct {
	Actor Actor
}

// PermissionGrant is one permission→scope grant of a role (ARCH-005 §3).
type PermissionGrant struct {
	Permission domain.Permission
	Scope      domain.Scope
}

// RoleDescriptor is one role of the catalogue with its permission grants
// (ARCH-006 §3.3).
type RoleDescriptor struct {
	Role        domain.Role
	Permissions []PermissionGrant
}

// ListRoles returns the fixed role catalogue with each role's permission→scope
// grants (ARCH-006 §3.3). The catalogue is the domain matrix from code (no
// table — ARCH-005 §1), rendered in canonical role and permission order.
// users.roles.manage gates the read.
func (s *Service) ListRoles(ctx context.Context, in ListRolesInput) ([]RoleDescriptor, error) {
	const op = "list_roles"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionUsersRolesManage, domain.ScopeAll, ""); err != nil {
		return nil, err
	}
	roles := domain.AllRoles()
	out := make([]RoleDescriptor, 0, len(roles))
	for _, r := range roles {
		grants := r.Permissions()
		perms := make([]PermissionGrant, 0, len(grants))
		for _, p := range domain.AllPermissions() {
			if scope, ok := grants[p]; ok {
				perms = append(perms, PermissionGrant{Permission: p, Scope: scope})
			}
		}
		out = append(out, RoleDescriptor{Role: r, Permissions: perms})
	}
	return out, nil
}

// GrantRoleInput is the role-grant command (ARCH-006 §3.3, PATCH
// /users/{id}/roles).
type GrantRoleInput struct {
	UserID        string
	Role          domain.Role
	Actor         Actor
	CorrelationID string
}

// GrantRole grants one role to one user and audits it (ARCH-006 §3.3): the
// grant and its users.role_granted audit event commit in one transaction. It
// is idempotent (a held role is not re-granted and writes no audit row). A
// missing user is a not-found error (404); a deactivated user is a conflict
// (409). users.roles.manage gates the call.
func (s *Service) GrantRole(ctx context.Context, in GrantRoleInput) (UserRecord, error) {
	return s.changeRoles(ctx, "grant_role", in.UserID, nil, []domain.Role{in.Role}, in.Actor, in.CorrelationID)
}

// RevokeRoleInput is the role-revocation command (ARCH-006 §3.3, PATCH
// /users/{id}/roles).
type RevokeRoleInput struct {
	UserID        string
	Role          domain.Role
	Actor         Actor
	CorrelationID string
}

// RevokeRole removes one role from one user and audits it (ARCH-006 §3.3): the
// revocation and its users.role_revoked audit event commit in one transaction.
// It is idempotent (an unheld role is not re-revoked and writes no audit row).
// A missing user is a not-found error (404); a deactivated user is a conflict
// (409). users.roles.manage gates the call.
func (s *Service) RevokeRole(ctx context.Context, in RevokeRoleInput) (UserRecord, error) {
	return s.changeRoles(ctx, "revoke_role", in.UserID, []domain.Role{in.Role}, nil, in.Actor, in.CorrelationID)
}

// changeRoles is the shared grant/revoke orchestration: it authorizes
// users.roles.manage, validates the role, loads the target user (404 on a
// missing id, 409 on a deactivated one), diffs the current roles — only real
// changes are written and audited (the SQL-granted idempotency of the writes)
// — and, when something changed, writes the role change(s) and their audit
// events in one transaction. It returns the user's roles after the change.
func (s *Service) changeRoles(ctx context.Context, op, userID string, revoke, grant []domain.Role, actorIn Actor, correlationID string) (UserRecord, error) {
	if _, err := s.authorize(ctx, op, actorIn, domain.PermissionUsersRolesManage, domain.ScopeAll, ""); err != nil {
		return UserRecord{}, err
	}
	actor, err := signalActor(op, actorIn)
	if err != nil {
		return UserRecord{}, err
	}
	if userID == "" {
		return UserRecord{}, Validationf(op, "user id must not be empty")
	}
	for _, r := range append(append([]domain.Role(nil), grant...), revoke...) {
		if !r.Valid() {
			return UserRecord{}, Validationf(op, "invalid role %q", r)
		}
	}
	if s.userAdmin == nil {
		return UserRecord{}, InfraError(op, errUserAdminNotWired)
	}

	user, err := s.userAdmin.GetUser(ctx, userID)
	if err != nil {
		return UserRecord{}, err
	}
	if !user.DeactivatedAt.IsZero() {
		return UserRecord{}, ConflictError(op, errors.New("user is deactivated"))
	}

	held := make(map[domain.Role]bool, len(user.Roles))
	for _, r := range user.Roles {
		held[r] = true
	}
	toGrant := diffRoles(grant, held, false)
	toRevoke := diffRoles(revoke, held, true)
	if len(toGrant) == 0 && len(toRevoke) == 0 {
		// Nothing changed: no transaction, no audit row (a re-grant is not a
		// change — the SQL writes are idempotent by design).
		return user, nil
	}

	corr := correlationOrNew(correlationID)
	now := s.clock.Now()
	err = s.runTx(ctx, func(tx Tx) error {
		for _, r := range toGrant {
			if err := s.userAdmin.GrantRole(ctx, tx, userID, r, now, actor.ID); err != nil {
				return err
			}
			if err := s.appendUserAudit(ctx, tx, AuditActionUserRoleGranted, userID, actor, corr, now, userRoleSnapshot{UserID: userID, Role: string(r)}); err != nil {
				return err
			}
		}
		for _, r := range toRevoke {
			if err := s.userAdmin.RevokeRole(ctx, tx, userID, r); err != nil {
				return err
			}
			if err := s.appendUserAudit(ctx, tx, AuditActionUserRoleRevoked, userID, actor, corr, now, userRoleSnapshot{UserID: userID, Role: string(r)}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return UserRecord{}, err
	}
	return s.userAdmin.GetUser(ctx, userID)
}

// diffRoles returns the roles of want that are (want=true) or are not
// (want=false) currently held, preserving the caller's order and deduplicating.
func diffRoles(want []domain.Role, held map[domain.Role]bool, wantHeld bool) []domain.Role {
	seen := make(map[domain.Role]bool, len(want))
	var out []domain.Role
	for _, r := range want {
		if seen[r] || held[r] != wantHeld {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// DeactivateUserInput is the deactivation command (ARCH-006 §3.3, POST
// /users/{id}/deactivate).
type DeactivateUserInput struct {
	UserID        string
	Actor         Actor
	CorrelationID string
}

// DeactivateUser soft-deactivates one user and audits it (ARCH-006 §3.3,
// ADR-014): the guarded deactivation and its users.deactivated audit event
// commit in one transaction; nothing is ever deleted. A missing user is a
// not-found error (404); an already-deactivated user is a conflict (409).
// users.roles.manage gates the call.
func (s *Service) DeactivateUser(ctx context.Context, in DeactivateUserInput) (UserRecord, error) {
	const op = "deactivate_user"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionUsersRolesManage, domain.ScopeAll, ""); err != nil {
		return UserRecord{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return UserRecord{}, err
	}
	if in.UserID == "" {
		return UserRecord{}, Validationf(op, "user id must not be empty")
	}
	if s.userAdmin == nil {
		return UserRecord{}, InfraError(op, errUserAdminNotWired)
	}

	user, err := s.userAdmin.GetUser(ctx, in.UserID)
	if err != nil {
		return UserRecord{}, err
	}
	if !user.DeactivatedAt.IsZero() {
		return UserRecord{}, ConflictError(op, errors.New("user is already deactivated"))
	}

	corr := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()
	err = s.runTx(ctx, func(tx Tx) error {
		if err := s.userAdmin.DeactivateUser(ctx, tx, in.UserID, now); err != nil {
			return err
		}
		return s.appendUserAudit(ctx, tx, AuditActionUserDeactivated, in.UserID, actor, corr, now, userDeactivatedSnapshot{UserID: in.UserID, DeactivatedAt: now})
	})
	if err != nil {
		return UserRecord{}, err
	}
	return s.userAdmin.GetUser(ctx, in.UserID)
}

// userRoleSnapshot is the minimised after snapshot of a role-grant/revoke
// audit row (concept ch. 13.5: the change only, no secrets).
type userRoleSnapshot struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// userDeactivatedSnapshot is the minimised after snapshot of a users.deactivated
// audit row.
type userDeactivatedSnapshot struct {
	UserID        string    `json:"user_id"`
	DeactivatedAt time.Time `json:"deactivated_at"`
}

// appendUserAudit appends the audit event of one user/role administration
// change on the caller's transaction (concept ch. 13.2): aggregate "user",
// the actor resolved by the composition root, the minimised after snapshot.
func (s *Service) appendUserAudit(ctx context.Context, tx Tx, action, userID string, actor Actor, correlationID string, now time.Time, after any) error {
	payload, err := json.Marshal(after)
	if err != nil {
		return InfraError("user_admin", err)
	}
	return s.audit.Append(ctx, tx, AuditEvent{
		AggregateType:    AuditAggregateUser,
		AggregateID:      userID,
		ActorType:        actor.Type,
		ActorID:          actor.ID,
		ActorDisplayName: actor.DisplayName,
		Action:           action,
		OccurredAt:       now,
		Before:           nil,
		After:            payload,
		CorrelationID:    correlationID,
	})
}
