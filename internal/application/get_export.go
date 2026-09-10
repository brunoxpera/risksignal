package application

import (
	"context"
	"errors"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the GetExport read (ARCH-007 §1.1/§1.2, WP-6.04 / DEV-115):
// the status read behind GET /exports/{id}. It returns the frozen filter plus
// the generation stamps, object-scoped to the creator for a
// Systemverantwortliche.

// GetExportInput is the single-export read (ARCH-007 §1.1) with the
// authenticated principal: exports.create is gated per the matrix and an
// `assigned` grant restricts the read to the principal's own export (the one
// it created, exports.created_by = principal.id).
type GetExportInput struct {
	ExportID string
	Actor    Actor
}

// GetExport returns one export job — its status, frozen filter and the
// generation stamps (ARCH-007 §1.1). An unknown id is a not-found error (the
// HTTP layer maps it to 404). A user principal without exports.create, or one
// whose `assigned` grant does not own the export, is denied with a
// ForbiddenError (403) before the row is returned (ARCH-005 §5).
func (s *Service) GetExport(ctx context.Context, in GetExportInput) (Export, error) {
	const op = "get_export"

	if in.ExportID == "" {
		return Export{}, Validationf(op, "export id must not be empty")
	}
	if s.exports == nil {
		return Export{}, InfraError(op, errors.New("export repository is not wired"))
	}
	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return Export{}, err
	}
	row, err := s.exports.GetByID(ctx, in.ExportID)
	if err != nil {
		return Export{}, err
	}
	// exports.create, object-scoped to the creator (assigned): an all-scope
	// role reads any export, an assigned-scope role only the one it created.
	if err := s.authorizeObject(op, principal, domain.PermissionExportsCreate, domain.ScopeAssigned, row.CreatedBy); err != nil {
		return Export{}, err
	}
	return row, nil
}
