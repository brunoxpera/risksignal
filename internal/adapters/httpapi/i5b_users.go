// HTTP handlers of the user/role administration (ARCH-006 §3.3, WP-5b.05):
// the generated operations GET /api/v1/users, GET /api/v1/roles,
// PATCH /api/v1/users/{id}/roles and POST /api/v1/users/{id}/deactivate. They
// translate the wire request onto the application admin use cases (the gate of
// record, gated on users.roles.manage) and map their outcome onto the typed
// response objects. The role catalogue, the audit events and the
// deactivate-never-delete semantics stay entirely in the use cases.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// UserAdmin is the application surface of the user/role administration the
// handler delegates to (application.Service).
type UserAdmin interface {
	ActorResolver
	ListUsers(ctx context.Context, in application.ListUsersInput) (application.ListUsersResult, error)
	ListRoles(ctx context.Context, in application.ListRolesInput) ([]application.RoleDescriptor, error)
	GrantRole(ctx context.Context, in application.GrantRoleInput) (application.UserRecord, error)
	RevokeRole(ctx context.Context, in application.RevokeRoleInput) (application.UserRecord, error)
	DeactivateUser(ctx context.Context, in application.DeactivateUserInput) (application.UserRecord, error)
}

// userAdminHandler implements the four admin operations.
type userAdminHandler struct {
	admin  UserAdmin
	logger *slog.Logger
}

// ListUsers implements GET /api/v1/users (ARCH-006 §3.3): the cursor-paginated
// user list with each user's roles.
func (h *userAdminHandler) ListUsers(ctx context.Context, request gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	if h.admin == nil {
		return gen.ListUsers500JSONResponse(h.internalProblem(ctx, errors.New("user admin handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.admin)
	if err != nil {
		return h.listError(ctx, err)
	}
	in := application.ListUsersInput{Actor: actor}
	if request.Params.Limit != nil {
		in.Limit = *request.Params.Limit
	}
	if request.Params.Cursor != nil {
		in.Cursor = *request.Params.Cursor
	}
	page, err := h.admin.ListUsers(ctx, in)
	if err != nil {
		return h.listError(ctx, err)
	}
	data := make([]gen.User, 0, len(page.Users))
	for _, u := range page.Users {
		data = append(data, toGenUser(u))
	}
	var nextCursor *string
	if page.NextCursor != "" {
		nextCursor = &page.NextCursor
	}
	return gen.ListUsers200JSONResponse(gen.UserList{Data: data, NextCursor: nextCursor}), nil
}

// ListRoles implements GET /api/v1/roles (ARCH-006 §3.3): the fixed role
// catalogue with each role's permission→scope grants.
func (h *userAdminHandler) ListRoles(ctx context.Context, _ gen.ListRolesRequestObject) (gen.ListRolesResponseObject, error) {
	if h.admin == nil {
		return gen.ListRoles500JSONResponse(h.internalProblem(ctx, errors.New("user admin handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.admin)
	if err != nil {
		return h.rolesError(ctx, err)
	}
	roles, err := h.admin.ListRoles(ctx, application.ListRolesInput{Actor: actor})
	if err != nil {
		return h.rolesError(ctx, err)
	}
	return gen.ListRoles200JSONResponse(toGenRoleList(roles)), nil
}

// UpdateUserRoles implements PATCH /api/v1/users/{id}/roles (ARCH-006 §3.3):
// grant and/or revoke roles on one user, each change audited by its use case.
// Every supplied role is validated before any write (a malformed body is a
// 400 with nothing changed); a missing user is a 404 and a deactivated user a
// 409, both raised by the use case before it writes.
func (h *userAdminHandler) UpdateUserRoles(ctx context.Context, request gen.UpdateUserRolesRequestObject) (gen.UpdateUserRolesResponseObject, error) {
	if h.admin == nil {
		return gen.UpdateUserRoles500JSONResponse(h.internalProblem(ctx, errors.New("user admin handler is not wired"))), nil
	}
	if request.Body == nil {
		return gen.UpdateUserRoles400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a role-change body is required")), nil
	}
	grant := request.Body.Grant
	revoke := request.Body.Revoke
	if len(grant) == 0 && len(revoke) == 0 {
		return gen.UpdateUserRoles400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "at least one role to grant or revoke is required")), nil
	}
	for _, r := range grant {
		if !domain.Role(r).Valid() {
			return gen.UpdateUserRoles400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "invalid role "+string(r))), nil
		}
	}
	for _, r := range revoke {
		if !domain.Role(r).Valid() {
			return gen.UpdateUserRoles400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "invalid role "+string(r))), nil
		}
	}
	actor, err := resolveActor(ctx, h.admin)
	if err != nil {
		return h.rolesChangeError(ctx, err)
	}
	corr := correlationIDFromContext(ctx)
	var user application.UserRecord
	for _, r := range grant {
		user, err = h.admin.GrantRole(ctx, application.GrantRoleInput{UserID: request.Id, Role: domain.Role(r), Actor: actor, CorrelationID: corr})
		if err != nil {
			return h.rolesChangeError(ctx, err)
		}
	}
	for _, r := range revoke {
		user, err = h.admin.RevokeRole(ctx, application.RevokeRoleInput{UserID: request.Id, Role: domain.Role(r), Actor: actor, CorrelationID: corr})
		if err != nil {
			return h.rolesChangeError(ctx, err)
		}
	}
	return gen.UpdateUserRoles200JSONResponse(toGenUser(user)), nil
}

// DeactivateUser implements POST /api/v1/users/{id}/deactivate (ARCH-006
// §3.3, ADR-014): soft-deactivate one user (never deleted). A missing user is
// a 404 and an already-deactivated user a 409.
func (h *userAdminHandler) DeactivateUser(ctx context.Context, request gen.DeactivateUserRequestObject) (gen.DeactivateUserResponseObject, error) {
	if h.admin == nil {
		return gen.DeactivateUser500JSONResponse(h.internalProblem(ctx, errors.New("user admin handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.admin)
	if err != nil {
		return h.deactivateError(ctx, err)
	}
	user, err := h.admin.DeactivateUser(ctx, application.DeactivateUserInput{UserID: request.Id, Actor: actor, CorrelationID: correlationIDFromContext(ctx)})
	if err != nil {
		return h.deactivateError(ctx, err)
	}
	return gen.DeactivateUser200JSONResponse(toGenUser(user)), nil
}

func (h *userAdminHandler) listError(ctx context.Context, err error) (gen.ListUsersResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.ListUsers400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.ListUsers403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.ListUsers500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

func (h *userAdminHandler) rolesError(ctx context.Context, err error) (gen.ListRolesResponseObject, error) {
	status, title, detail := actorProblem(err)
	if status == http.StatusForbidden {
		return gen.ListRoles403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	}
	return gen.ListRoles500JSONResponse(h.internalProblem(ctx, err)), nil
}

func (h *userAdminHandler) rolesChangeError(ctx context.Context, err error) (gen.UpdateUserRolesResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.UpdateUserRoles400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.UpdateUserRoles403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusNotFound:
		return gen.UpdateUserRoles404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleUserNotFound, detail)), nil
	case http.StatusConflict:
		return gen.UpdateUserRoles409JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.UpdateUserRoles500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

func (h *userAdminHandler) deactivateError(ctx context.Context, err error) (gen.DeactivateUserResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.DeactivateUser400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.DeactivateUser403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusNotFound:
		return gen.DeactivateUser404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleUserNotFound, detail)), nil
	case http.StatusConflict:
		return gen.DeactivateUser409JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.DeactivateUser500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

// internalProblem logs err with its correlation id and returns the generic
// internal-error problem detail (no detail field).
func (h *userAdminHandler) internalProblem(ctx context.Context, err error) gen.ProblemDetails {
	h.logger.ErrorContext(ctx, "user admin request failed", slog.Any("error", err))
	return problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")
}

// toGenUser maps the application user read model onto the generated User — the
// wire contract. A zero DeactivatedAt/LastLoginAt is the wire null; an empty
// email is the wire null; empty roles encode as [].
func toGenUser(u application.UserRecord) gen.User {
	roles := make([]gen.Role, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, gen.Role(r))
	}
	var email *string
	if u.Email != "" {
		e := u.Email
		email = &e
	}
	var deactivatedAt, lastLoginAt *time.Time
	if !u.DeactivatedAt.IsZero() {
		d := u.DeactivatedAt
		deactivatedAt = &d
	}
	if !u.LastLoginAt.IsZero() {
		l := u.LastLoginAt
		lastLoginAt = &l
	}
	return gen.User{
		Id:            u.ID,
		SubjectId:     u.SubjectID,
		DisplayName:   u.DisplayName,
		Email:         email,
		Roles:         roles,
		DeactivatedAt: deactivatedAt,
		LastLoginAt:   lastLoginAt,
		CreatedAt:     u.CreatedAt,
	}
}

// toGenRoleList maps the application role catalogue onto the generated
// RoleList — the wire contract.
func toGenRoleList(roles []application.RoleDescriptor) gen.RoleList {
	data := make([]gen.RoleDescriptor, 0, len(roles))
	for _, rd := range roles {
		perms := make([]gen.PermissionGrant, 0, len(rd.Permissions))
		for _, p := range rd.Permissions {
			perms = append(perms, gen.PermissionGrant{Permission: string(p.Permission), Scope: gen.Scope(p.Scope)})
		}
		data = append(data, gen.RoleDescriptor{Role: gen.Role(rd.Role), Permissions: perms})
	}
	return gen.RoleList{Data: data}
}
