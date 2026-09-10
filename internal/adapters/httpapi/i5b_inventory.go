// HTTP handlers of the staged inventory import (ARCH-006 §2.1, WP-5b.05): the
// generated operations POST /api/v1/inventory/imports,
// GET /api/v1/inventory/imports/{id} and
// POST /api/v1/inventory/imports/{id}/commit. They translate the wire request
// onto the application.InventoryImport use cases (the gate of record, gated on
// inventory.manage) and map their outcome onto the typed response objects.
// The upload itself is bounded by application.InventoryMaxBytes (413 on
// exceed); the staging/commit orchestration — parse, preview, persist, run
// the I3 commit, stamp the counters — stays entirely in the use cases.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// InventoryImports is the application surface of the staged inventory import
// the handler delegates to (application.Service). Depending on the narrow
// interface keeps the handler testable with an in-memory fake.
type InventoryImports interface {
	ActorResolver
	StageInventoryImport(ctx context.Context, in application.StageInventoryImportInput) (application.InventoryImport, error)
	GetInventoryImport(ctx context.Context, in application.GetInventoryImportInput) (application.InventoryImport, error)
	CommitStagedInventory(ctx context.Context, in application.CommitStagedInventoryInput) (application.InventoryImport, error)
}

// inventoryImportHandler implements the three inventory-import operations.
type inventoryImportHandler struct {
	imports InventoryImports
	logger  *slog.Logger
}

// CreateInventoryImport implements POST /api/v1/inventory/imports (ARCH-006
// §2.1): read the bounded CSV body, delegate to StageInventoryImport and answer
// the staged record. An oversized body is the typed 413; a body the chain
// cannot read is a 400.
func (h *inventoryImportHandler) CreateInventoryImport(ctx context.Context, request gen.CreateInventoryImportRequestObject) (gen.CreateInventoryImportResponseObject, error) {
	if h.imports == nil {
		return gen.CreateInventoryImport500JSONResponse(h.internalProblem(ctx, errors.New("inventory import handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.imports)
	if err != nil {
		return h.createError(ctx, err)
	}
	file, err := readInventoryUpload(request.Body)
	if err != nil {
		if errors.Is(err, errUploadTooLarge) {
			return gen.CreateInventoryImport413JSONResponse(problemFromContext(ctx, http.StatusRequestEntityTooLarge, titlePayloadTooLarge,
				"the uploaded CSV exceeds the inventory import limit")), nil
		}
		return gen.CreateInventoryImport400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
			"the request body could not be read")), nil
	}
	staged, err := h.imports.StageInventoryImport(ctx, application.StageInventoryImportInput{
		File:          file,
		Actor:         actor,
		CorrelationID: correlationIDFromContext(ctx),
	})
	if err != nil {
		return h.createError(ctx, err)
	}
	return gen.CreateInventoryImport200JSONResponse(toGenInventoryImport(staged)), nil
}

// GetInventoryImport implements GET /api/v1/inventory/imports/{id} (ARCH-006
// §2.1): read one staged record. An unknown id is the typed 404.
func (h *inventoryImportHandler) GetInventoryImport(ctx context.Context, request gen.GetInventoryImportRequestObject) (gen.GetInventoryImportResponseObject, error) {
	if h.imports == nil {
		return gen.GetInventoryImport500JSONResponse(h.internalProblem(ctx, errors.New("inventory import handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.imports)
	if err != nil {
		return h.getError(ctx, err)
	}
	rec, err := h.imports.GetInventoryImport(ctx, application.GetInventoryImportInput{ID: request.Id, Actor: actor})
	if err != nil {
		return h.getError(ctx, err)
	}
	return gen.GetInventoryImport200JSONResponse(toGenInventoryImport(rec)), nil
}

// CommitInventoryImport implements POST /api/v1/inventory/imports/{id}/commit
// (ARCH-006 §2.1): run the existing I3 commit over the stored bytes and mark
// the record committed (idempotent). An unknown id is 404, a failed record a
// 409.
func (h *inventoryImportHandler) CommitInventoryImport(ctx context.Context, request gen.CommitInventoryImportRequestObject) (gen.CommitInventoryImportResponseObject, error) {
	if h.imports == nil {
		return gen.CommitInventoryImport500JSONResponse(h.internalProblem(ctx, errors.New("inventory import handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.imports)
	if err != nil {
		return h.commitError(ctx, err)
	}
	rec, err := h.imports.CommitStagedInventory(ctx, application.CommitStagedInventoryInput{ID: request.Id, Actor: actor})
	if err != nil {
		return h.commitError(ctx, err)
	}
	return gen.CommitInventoryImport200JSONResponse(toGenInventoryImport(rec)), nil
}

func (h *inventoryImportHandler) createError(ctx context.Context, err error) (gen.CreateInventoryImportResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusForbidden:
		return gen.CreateInventoryImport403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusBadRequest:
		return gen.CreateInventoryImport400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.CreateInventoryImport500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

func (h *inventoryImportHandler) getError(ctx context.Context, err error) (gen.GetInventoryImportResponseObject, error) {
	status, title, detail := actorProblem(err)
	if status == http.StatusInternalServerError {
		return gen.GetInventoryImport500JSONResponse(h.internalProblem(ctx, err)), nil
	}
	if status == http.StatusBadRequest {
		return gen.GetInventoryImport400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	}
	if status == http.StatusForbidden {
		return gen.GetInventoryImport403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	}
	if status == http.StatusNotFound {
		return gen.GetInventoryImport404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleInventoryImportNotFound, detail)), nil
	}
	return gen.GetInventoryImport500JSONResponse(h.internalProblem(ctx, err)), nil
}

func (h *inventoryImportHandler) commitError(ctx context.Context, err error) (gen.CommitInventoryImportResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.CommitInventoryImport400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.CommitInventoryImport403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusNotFound:
		return gen.CommitInventoryImport404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleInventoryImportNotFound, detail)), nil
	case http.StatusConflict:
		return gen.CommitInventoryImport409JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.CommitInventoryImport500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

// internalProblem logs err with its correlation id and returns the generic
// internal-error problem detail — no detail field, the cause never reaches the
// client (concept ch. 5.2).
func (h *inventoryImportHandler) internalProblem(ctx context.Context, err error) gen.ProblemDetails {
	h.logger.ErrorContext(ctx, "inventory import request failed", slog.Any("error", err))
	return problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")
}

// toGenInventoryImport maps the application staged-import view onto the
// generated InventoryImport — the wire contract, never hand-rolled. The
// positioned errors/warnings and the preview tallies are rendered in full; a
// zero CommittedAt is the wire null.
func toGenInventoryImport(v application.InventoryImport) gen.InventoryImport {
	problems := make([]gen.InventoryImportProblem, 0, len(v.Problems))
	for _, p := range v.Problems {
		problems = append(problems, gen.InventoryImportProblem{Line: p.Line, Column: p.Column, Reason: p.Reason, Input: p.Input})
	}
	warnings := make([]gen.InventoryImportWarning, 0, len(v.Warnings))
	for _, w := range v.Warnings {
		warnings = append(warnings, gen.InventoryImportWarning{Line: w.Line, Field: w.Field, Value: w.Value, Reason: w.Reason})
	}
	var committedAt *time.Time
	if !v.CommittedAt.IsZero() {
		c := v.CommittedAt
		committedAt = &c
	}
	return gen.InventoryImport{
		Id:          v.ID,
		Status:      gen.InventoryImportStatus(v.Status),
		CreatedAt:   v.CreatedAt,
		CommittedAt: committedAt,
		Preview: gen.InventoryImportPreview{
			Rows:                v.Rows,
			Errors:              v.ErrorCount,
			Warnings:            v.WarningCount,
			AssetsCreated:       v.AssetsCreated,
			AssetsUpdated:       v.AssetsUpdated,
			AssetsUnchanged:     v.AssetsUnchanged,
			ComponentsCreated:   v.ComponentsCreated,
			ComponentsUpdated:   v.ComponentsUpdated,
			ComponentsUnchanged: v.ComponentsUnchanged,
		},
		Problems: problems,
		Warnings: warnings,
	}
}
