// Not-yet-wired implementations of the I6 contract operations (WP-6.01).
//
// WP-6.01 lands the OpenAPI `Exports` resources and the retention/legal-hold
// schemas, plus the regenerated oapi-codegen surface only. The generated
// strict server interface now declares the three export operations, so the
// composed handler must satisfy them or the build fails (ADR-011: contract
// drift becomes a compile error). The thin stubs below answer the generic 500
// problem detail until the adapter work packages bind them to their
// application use cases (WP-6.04 export use cases, WP-6.07 HTTP endpoints).
// They hold no business logic, authorise nothing and write nothing — exactly
// like the composition root that does not yet serve an operation.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
)

// i6ContractHandlers carries the I6 operations that have no application
// binding yet. logger records the not-wired hits (the client only ever sees
// the generic 500 problem detail, concept ch. 5.2).
type i6ContractHandlers struct {
	logger *slog.Logger
}

// notWired answers the generic internal-error problem detail of an operation
// the composition root does not serve yet (mirrors the nil-seam behaviour of
// the other not-yet-bound handlers).
func (h i6ContractHandlers) notWired(ctx context.Context, operation string) {
	h.logger.WarnContext(ctx, "i6 contract operation is not wired yet", slog.String("operation", operation))
}

// CreateExport implements POST /api/v1/exports (WP-6.07).
func (h i6ContractHandlers) CreateExport(ctx context.Context, _ gen.CreateExportRequestObject) (gen.CreateExportResponseObject, error) {
	h.notWired(ctx, "createExport")
	return gen.CreateExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// GetExport implements GET /api/v1/exports/{id} (WP-6.07).
func (h i6ContractHandlers) GetExport(ctx context.Context, _ gen.GetExportRequestObject) (gen.GetExportResponseObject, error) {
	h.notWired(ctx, "getExport")
	return gen.GetExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}

// DownloadExport implements GET /api/v1/exports/{id}/download (WP-6.07).
func (h i6ContractHandlers) DownloadExport(ctx context.Context, _ gen.DownloadExportRequestObject) (gen.DownloadExportResponseObject, error) {
	h.notWired(ctx, "downloadExport")
	return gen.DownloadExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
}
