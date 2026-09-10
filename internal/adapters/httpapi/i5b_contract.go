// Not-yet-wired implementations of the I5b contract operations (WP-5b.01).
//
// WP-5b.01 lands the OpenAPI document and its regenerated oapi-codegen
// surface only: the eight-command signal command vocabulary, the staged
// inventory-import resources, the assets read resources and the user/role
// administration resources. The generated strict server interface now
// declares those operations, so the composed handler must satisfy them or
// the build fails (ADR-011: contract drift becomes a compile error). The
// thin stubs below answer the generic 500 problem detail until the
// adapter work packages bind them to their application use cases
// (WP-5b.04 signal commands, WP-5b.05 inventory/assets/users). They hold
// no business logic, authorise nothing and write nothing — exactly like
// the composition root that does not yet serve an operation.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
)

// i5bContractHandlers carries the I5b operations that have no application
// binding yet. logger records the not-wired hits (the client only ever sees
// the generic 500 problem detail, concept ch. 5.2).
type i5bContractHandlers struct {
	logger *slog.Logger
}

// notWired answers the generic internal-error problem detail of an
// operation the composition root does not serve yet (mirrors the nil-seam
// behaviour of the signal command and audit reveal handlers).
func (h i5bContractHandlers) notWired(ctx context.Context, operation string) {
	h.logger.WarnContext(ctx, "i5b contract operation is not wired yet", slog.String("operation", operation))
}

// CreateInventoryImport implements POST /api/v1/inventory/imports (WP-5b.05).
func (h i5bContractHandlers) CreateInventoryImport(ctx context.Context, _ gen.CreateInventoryImportRequestObject) (gen.CreateInventoryImportResponseObject, error) {
	h.notWired(ctx, "createInventoryImport")
	return gen.CreateInventoryImport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// GetInventoryImport implements GET /api/v1/inventory/imports/{id} (WP-5b.05).
func (h i5bContractHandlers) GetInventoryImport(ctx context.Context, _ gen.GetInventoryImportRequestObject) (gen.GetInventoryImportResponseObject, error) {
	h.notWired(ctx, "getInventoryImport")
	return gen.GetInventoryImport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// CommitInventoryImport implements POST /api/v1/inventory/imports/{id}/commit (WP-5b.05).
func (h i5bContractHandlers) CommitInventoryImport(ctx context.Context, _ gen.CommitInventoryImportRequestObject) (gen.CommitInventoryImportResponseObject, error) {
	h.notWired(ctx, "commitInventoryImport")
	return gen.CommitInventoryImport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// ListAssets implements GET /api/v1/assets (WP-5b.05).
func (h i5bContractHandlers) ListAssets(ctx context.Context, _ gen.ListAssetsRequestObject) (gen.ListAssetsResponseObject, error) {
	h.notWired(ctx, "listAssets")
	return gen.ListAssets500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// GetAssetComponents implements GET /api/v1/assets/{id}/components (WP-5b.05).
func (h i5bContractHandlers) GetAssetComponents(ctx context.Context, _ gen.GetAssetComponentsRequestObject) (gen.GetAssetComponentsResponseObject, error) {
	h.notWired(ctx, "getAssetComponents")
	return gen.GetAssetComponents500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// ListUsers implements GET /api/v1/users (WP-5b.05).
func (h i5bContractHandlers) ListUsers(ctx context.Context, _ gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	h.notWired(ctx, "listUsers")
	return gen.ListUsers500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// ListRoles implements GET /api/v1/roles (WP-5b.05).
func (h i5bContractHandlers) ListRoles(ctx context.Context, _ gen.ListRolesRequestObject) (gen.ListRolesResponseObject, error) {
	h.notWired(ctx, "listRoles")
	return gen.ListRoles500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// UpdateUserRoles implements PATCH /api/v1/users/{id}/roles (WP-5b.05).
func (h i5bContractHandlers) UpdateUserRoles(ctx context.Context, _ gen.UpdateUserRolesRequestObject) (gen.UpdateUserRolesResponseObject, error) {
	h.notWired(ctx, "updateUserRoles")
	return gen.UpdateUserRoles500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// DeactivateUser implements POST /api/v1/users/{id}/deactivate (WP-5b.05).
func (h i5bContractHandlers) DeactivateUser(ctx context.Context, _ gen.DeactivateUserRequestObject) (gen.DeactivateUserResponseObject, error) {
	h.notWired(ctx, "deactivateUser")
	return gen.DeactivateUser500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}
