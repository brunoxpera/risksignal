// HTTP boundary of the I6 operations surface (ARCH-007 §1.1/§2.1/§2.2,
// WP-6.07 / DEV-119): the asynchronous export resources (POST /exports,
// GET /exports/{id}, GET /exports/{id}/download), the governed retention-run
// surface (POST /retention/runs dry-run, GET /retention/runs,
// GET /retention/runs/{id}, POST /retention/runs/{id}/approve) and the
// legal-hold surface (POST /legal-holds, GET /legal-holds,
// POST /legal-holds/{id}/release).
//
// The handlers are thin translations (like the I5b adapters): they resolve the
// authenticated identity into an audit actor, map the wire request onto the
// matching application.*Input, call the use case — the gate of record, which
// authorises exports.create / retention.manage / settings.approve and stamps
// the actor — and map the application error classes back onto the generated
// response objects. They decide no rights and no business rules; the per-route
// PermissionGate is defense-in-depth only (ARCH-005 §5). The materialisation
// and the deletion run in the worker jobs (WP-6.06); these endpoints only
// schedule (export.create), propose (retention dry-run), approve (four-eyes)
// and stream/download or read the operational record.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// ExportAPI is the export application surface the export handler delegates
// to: the three DEV-115 use cases plus the shared identity→actor resolution.
// Depending on this narrow interface (not the whole service) keeps the handler
// testable with an in-memory fake; the signatures mirror *application.Service
// so the composition root passes the real service unchanged.
type ExportAPI interface {
	ActorResolver
	CreateExport(ctx context.Context, in application.CreateExportInput) (application.CreateExportResult, error)
	GetExport(ctx context.Context, in application.GetExportInput) (application.Export, error)
	DownloadExport(ctx context.Context, in application.DownloadExportInput) (application.DownloadExportResult, error)
}

// RetentionAPI is the retention-run application surface the retention handler
// delegates to: the dry-run, the report reads, the four-eyes approval (each
// authorises internally) plus the actor resolution.
type RetentionAPI interface {
	ActorResolver
	RunRetentionDryRun(ctx context.Context, in application.RunRetentionDryRunInput) (application.RetentionDryRunResult, error)
	ListRetentionRuns(ctx context.Context, in application.ListRetentionRunsInput) ([]application.RetentionRun, error)
	GetRetentionRun(ctx context.Context, in application.GetRetentionRunInput) (application.RetentionRun, error)
	ApproveRetentionRun(ctx context.Context, in application.ApproveRetentionRunInput) (application.ApproveRetentionRunResult, error)
}

// LegalHoldAPI is the legal-hold application surface the legal-hold handler
// delegates to: the create/release/list use cases plus the actor resolution.
type LegalHoldAPI interface {
	ActorResolver
	CreateLegalHold(ctx context.Context, in application.CreateLegalHoldInput) (application.LegalHold, error)
	ReleaseLegalHold(ctx context.Context, in application.ReleaseLegalHoldInput) (application.LegalHold, error)
	ListLegalHolds(ctx context.Context, in application.ListLegalHoldsInput) ([]application.LegalHold, error)
}

// exportHandler implements the three export operations of the generated strict
// interface. A nil exports leaves every operation answering the generic 500 (a
// composition root that does not serve them).
type exportHandler struct {
	exports ExportAPI
	logger  *slog.Logger
}

// retentionHandler implements the four retention-run operations.
type retentionHandler struct {
	retention RetentionAPI
	logger    *slog.Logger
}

// legalHoldHandler implements the three legal-hold operations.
type legalHoldHandler struct {
	holds  LegalHoldAPI
	logger *slog.Logger
}

// ---------------------------------------------------------------------------
// Exports

// CreateExport implements gen.StrictServerInterface (POST /api/v1/exports,
// ARCH-007 §1.1). It maps the frozen filter + format onto CreateExportInput
// (the use case validates the filter and authorises exports.create) and
// answers the created ExportRecord (status pending).
func (h exportHandler) CreateExport(ctx context.Context, request gen.CreateExportRequestObject) (gen.CreateExportResponseObject, error) {
	if h.exports == nil {
		return gen.CreateExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	if request.Body == nil {
		return gen.CreateExport400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a body is required")), nil
	}
	actor, err := resolveActor(ctx, h.exports)
	if err != nil {
		status, title, detail := actorProblem(err)
		return createExportProblem(ctx, status, title, detail), nil
	}
	res, err := h.exports.CreateExport(ctx, application.CreateExportInput{
		Filter: fromGenExportFilter(request.Body.Filter),
		Format: export.Format(request.Body.Format),
		Actor:  actor,
	})
	if err != nil {
		status, title, detail := statusProblem(err, "")
		return createExportProblem(ctx, status, title, detail), nil
	}
	return gen.CreateExport200JSONResponse(toGenExportRecord(res.Export)), nil
}

// GetExport implements gen.StrictServerInterface (GET /api/v1/exports/{id},
// ARCH-007 §1.1): the status read of one export, object-scoped to the creator
// by the use case.
func (h exportHandler) GetExport(ctx context.Context, request gen.GetExportRequestObject) (gen.GetExportResponseObject, error) {
	if h.exports == nil {
		return gen.GetExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.exports)
	if err != nil {
		status, title, detail := actorProblem(err)
		return getExportProblem(ctx, status, title, detail), nil
	}
	row, err := h.exports.GetExport(ctx, application.GetExportInput{ExportID: request.Id, Actor: actor})
	if err != nil {
		status, title, detail := statusProblem(err, titleExportNotFound)
		return getExportProblem(ctx, status, title, detail), nil
	}
	return gen.GetExport200JSONResponse(toGenExportRecord(row)), nil
}

// DownloadExport implements gen.StrictServerInterface (GET
// /api/v1/exports/{id}/download, ARCH-007 §1.1): the time-limited stream of a
// materialised artifact. An expired artifact answers the declared 410 (Gone);
// an export that is not completed yet answers 409 (Conflict) — the use case
// checks both against the injected clock before opening the artifact. The
// response content type is the stored format's (the use case computes it:
// text/csv; charset=utf-8 or application/json; charset=utf-8), never a
// hardcoded application/octet-stream.
func (h exportHandler) DownloadExport(ctx context.Context, request gen.DownloadExportRequestObject) (gen.DownloadExportResponseObject, error) {
	if h.exports == nil {
		return gen.DownloadExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.exports)
	if err != nil {
		status, title, detail := actorProblem(err)
		return downloadExportProblem(ctx, status, title, detail), nil
	}
	res, err := h.exports.DownloadExport(ctx, application.DownloadExportInput{ExportID: request.Id, Actor: actor})
	if err != nil {
		if errors.Is(err, application.ErrExportExpired) {
			return gen.DownloadExport410JSONResponse(problemFromContext(ctx, http.StatusGone, titleExportExpired, errorCause(err))), nil
		}
		status, title, detail := statusProblem(err, titleExportNotFound)
		return downloadExportProblem(ctx, status, title, detail), nil
	}
	filename := res.Filename
	return gen.DownloadExport200AsteriskResponse{
		Body:          res.Reader,
		ContentType:   res.ContentType,
		Headers:       gen.DownloadExport200ResponseHeaders{ContentDisposition: &filename},
		ContentLength: res.SizeBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// Retention runs

// CreateRetentionRun implements gen.StrictServerInterface (POST
// /api/v1/retention/runs, ARCH-007 §2.2 step 1): the mandatory dry-run
// proposal. It maps the optional policy/stage/cutoff onto the dry-run input
// (the use case authorises retention.manage and derives the cutoff from the
// injected clock when none is given) and answers the stored counts-only report.
func (h retentionHandler) CreateRetentionRun(ctx context.Context, request gen.CreateRetentionRunRequestObject) (gen.CreateRetentionRunResponseObject, error) {
	if h.retention == nil {
		return gen.CreateRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.retention)
	if err != nil {
		status, title, detail := actorProblem(err)
		return createRetentionRunProblem(ctx, status, title, detail), nil
	}
	in := application.RunRetentionDryRunInput{Actor: actor}
	if request.Body != nil {
		if request.Body.PolicyId != nil {
			in.PolicyID = *request.Body.PolicyId
		}
		if request.Body.Stage != nil {
			in.Stage = application.RetentionStage(*request.Body.Stage)
		}
		in.Cutoff = request.Body.Cutoff
	}
	res, err := h.retention.RunRetentionDryRun(ctx, in)
	if err != nil {
		status, title, detail := statusProblem(err, "")
		return createRetentionRunProblem(ctx, status, title, detail), nil
	}
	return gen.CreateRetentionRun200JSONResponse(toGenRetentionRun(res.Run)), nil
}

// ListRetentionRuns implements gen.StrictServerInterface (GET
// /api/v1/retention/runs, ARCH-007 §2.2 step 4): the operator report read.
func (h retentionHandler) ListRetentionRuns(ctx context.Context, _ gen.ListRetentionRunsRequestObject) (gen.ListRetentionRunsResponseObject, error) {
	if h.retention == nil {
		return gen.ListRetentionRuns500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.retention)
	if err != nil {
		status, title, detail := actorProblem(err)
		return listRetentionRunsProblem(ctx, status, title, detail), nil
	}
	runs, err := h.retention.ListRetentionRuns(ctx, application.ListRetentionRunsInput{Actor: actor})
	if err != nil {
		status, title, detail := statusProblem(err, "")
		return listRetentionRunsProblem(ctx, status, title, detail), nil
	}
	data := make([]gen.RetentionRun, 0, len(runs))
	for _, r := range runs {
		data = append(data, toGenRetentionRun(r))
	}
	return gen.ListRetentionRuns200JSONResponse(gen.RetentionRunList{Data: data, NextCursor: nil}), nil
}

// GetRetentionRun implements gen.StrictServerInterface (GET
// /api/v1/retention/runs/{id}, ARCH-007 §2.2 step 4).
func (h retentionHandler) GetRetentionRun(ctx context.Context, request gen.GetRetentionRunRequestObject) (gen.GetRetentionRunResponseObject, error) {
	if h.retention == nil {
		return gen.GetRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.retention)
	if err != nil {
		status, title, detail := actorProblem(err)
		return getRetentionRunProblem(ctx, status, title, detail), nil
	}
	run, err := h.retention.GetRetentionRun(ctx, application.GetRetentionRunInput{RunID: request.Id, Actor: actor})
	if err != nil {
		status, title, detail := statusProblem(err, titleRetentionRunNotFound)
		return getRetentionRunProblem(ctx, status, title, detail), nil
	}
	return gen.GetRetentionRun200JSONResponse(toGenRetentionRun(run)), nil
}

// ApproveRetentionRun implements gen.StrictServerInterface (POST
// /api/v1/retention/runs/{id}/approve, ARCH-007 §2.2 step 2): the four-eyes
// approval (settings.approve, Product Owner). A run not in dry_run is a
// conflict (409); an unknown run a 404.
func (h retentionHandler) ApproveRetentionRun(ctx context.Context, request gen.ApproveRetentionRunRequestObject) (gen.ApproveRetentionRunResponseObject, error) {
	if h.retention == nil {
		return gen.ApproveRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	if request.Body == nil {
		return gen.ApproveRetentionRun400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a body is required")), nil
	}
	actor, err := resolveActor(ctx, h.retention)
	if err != nil {
		status, title, detail := actorProblem(err)
		return approveRetentionRunProblem(ctx, status, title, detail), nil
	}
	res, err := h.retention.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{
		RunID:  request.Id,
		Reason: request.Body.Reason,
		Actor:  actor,
	})
	if err != nil {
		status, title, detail := statusProblem(err, titleRetentionRunNotFound)
		return approveRetentionRunProblem(ctx, status, title, detail), nil
	}
	// The approval use case returns the deciding principal and instant; the
	// report row is read back so the wire carries the full run (the approval
	// flipped exactly this run, so the read cannot disagree).
	run, err := h.retention.GetRetentionRun(ctx, application.GetRetentionRunInput{RunID: res.RunID, Actor: actor})
	if err != nil {
		return gen.ApproveRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	return gen.ApproveRetentionRun200JSONResponse(toGenRetentionRun(run)), nil
}

// ---------------------------------------------------------------------------
// Legal holds

// CreateLegalHold implements gen.StrictServerInterface (POST /api/v1/legal-holds,
// ARCH-007 §2.1): set one documented hold (retention.manage).
func (h legalHoldHandler) CreateLegalHold(ctx context.Context, request gen.CreateLegalHoldRequestObject) (gen.CreateLegalHoldResponseObject, error) {
	if h.holds == nil {
		return gen.CreateLegalHold500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	if request.Body == nil {
		return gen.CreateLegalHold400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a body is required")), nil
	}
	actor, err := resolveActor(ctx, h.holds)
	if err != nil {
		status, title, detail := actorProblem(err)
		return createLegalHoldProblem(ctx, status, title, detail), nil
	}
	aggregateType := ""
	if request.Body.AggregateType != nil {
		aggregateType = *request.Body.AggregateType
	}
	hold, err := h.holds.CreateLegalHold(ctx, application.CreateLegalHoldInput{
		AggregateType: aggregateType,
		AggregateID:   request.Body.AggregateId,
		Reason:        request.Body.Reason,
		Actor:         actor,
	})
	if err != nil {
		status, title, detail := statusProblem(err, "")
		return createLegalHoldProblem(ctx, status, title, detail), nil
	}
	return gen.CreateLegalHold200JSONResponse(toGenLegalHold(hold)), nil
}

// ListLegalHolds implements gen.StrictServerInterface (GET /api/v1/legal-holds,
// ARCH-007 §2.1).
func (h legalHoldHandler) ListLegalHolds(ctx context.Context, _ gen.ListLegalHoldsRequestObject) (gen.ListLegalHoldsResponseObject, error) {
	if h.holds == nil {
		return gen.ListLegalHolds500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	actor, err := resolveActor(ctx, h.holds)
	if err != nil {
		status, title, detail := actorProblem(err)
		return listLegalHoldsProblem(ctx, status, title, detail), nil
	}
	holds, err := h.holds.ListLegalHolds(ctx, application.ListLegalHoldsInput{Actor: actor})
	if err != nil {
		status, title, detail := statusProblem(err, "")
		return listLegalHoldsProblem(ctx, status, title, detail), nil
	}
	data := make([]gen.LegalHold, 0, len(holds))
	for _, hold := range holds {
		data = append(data, toGenLegalHold(hold))
	}
	return gen.ListLegalHolds200JSONResponse(gen.LegalHoldList{Data: data, NextCursor: nil}), nil
}

// ReleaseLegalHold implements gen.StrictServerInterface (POST
// /api/v1/legal-holds/{id}/release, ARCH-007 §2.1): the set-once, audited
// release (retention.manage).
func (h legalHoldHandler) ReleaseLegalHold(ctx context.Context, request gen.ReleaseLegalHoldRequestObject) (gen.ReleaseLegalHoldResponseObject, error) {
	if h.holds == nil {
		return gen.ReleaseLegalHold500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	if request.Body == nil {
		return gen.ReleaseLegalHold400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a body is required")), nil
	}
	actor, err := resolveActor(ctx, h.holds)
	if err != nil {
		status, title, detail := actorProblem(err)
		return releaseLegalHoldProblem(ctx, status, title, detail), nil
	}
	hold, err := h.holds.ReleaseLegalHold(ctx, application.ReleaseLegalHoldInput{
		HoldID: request.Id,
		Reason: request.Body.Reason,
		Actor:  actor,
	})
	if err != nil {
		status, title, detail := statusProblem(err, titleLegalHoldNotFound)
		return releaseLegalHoldProblem(ctx, status, title, detail), nil
	}
	return gen.ReleaseLegalHold200JSONResponse(toGenLegalHold(hold)), nil
}

// ---------------------------------------------------------------------------
// Per-operation problem builders (a 4xx/5xx maps onto the typed response
// object of the operation; the operation's declared set decides the shape).

func createExportProblem(ctx context.Context, status int, title, detail string) gen.CreateExportResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.CreateExport400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.CreateExport403JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.CreateExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func getExportProblem(ctx context.Context, status int, title, detail string) gen.GetExportResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.GetExport400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.GetExport403JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusNotFound:
		return gen.GetExport404JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.GetExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func downloadExportProblem(ctx context.Context, status int, title, detail string) gen.DownloadExportResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.DownloadExport400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.DownloadExport403JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusNotFound:
		return gen.DownloadExport404JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusConflict:
		return gen.DownloadExport409JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusGone:
		return gen.DownloadExport410JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.DownloadExport500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func createRetentionRunProblem(ctx context.Context, status int, title, detail string) gen.CreateRetentionRunResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.CreateRetentionRun400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.CreateRetentionRun403JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.CreateRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func listRetentionRunsProblem(ctx context.Context, status int, title, detail string) gen.ListRetentionRunsResponseObject {
	switch status {
	case http.StatusForbidden:
		return gen.ListRetentionRuns403JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.ListRetentionRuns500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func getRetentionRunProblem(ctx context.Context, status int, title, detail string) gen.GetRetentionRunResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.GetRetentionRun400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.GetRetentionRun403JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusNotFound:
		return gen.GetRetentionRun404JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.GetRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func approveRetentionRunProblem(ctx context.Context, status int, title, detail string) gen.ApproveRetentionRunResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.ApproveRetentionRun400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.ApproveRetentionRun403JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusNotFound:
		return gen.ApproveRetentionRun404JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusConflict:
		return gen.ApproveRetentionRun409JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.ApproveRetentionRun500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func createLegalHoldProblem(ctx context.Context, status int, title, detail string) gen.CreateLegalHoldResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.CreateLegalHold400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.CreateLegalHold403JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.CreateLegalHold500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func listLegalHoldsProblem(ctx context.Context, status int, title, detail string) gen.ListLegalHoldsResponseObject {
	switch status {
	case http.StatusForbidden:
		return gen.ListLegalHolds403JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.ListLegalHolds500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

func releaseLegalHoldProblem(ctx context.Context, status int, title, detail string) gen.ReleaseLegalHoldResponseObject {
	switch status {
	case http.StatusBadRequest:
		return gen.ReleaseLegalHold400JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusForbidden:
		return gen.ReleaseLegalHold403JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusNotFound:
		return gen.ReleaseLegalHold404JSONResponse(problemFromContext(ctx, status, title, detail))
	case http.StatusConflict:
		return gen.ReleaseLegalHold409JSONResponse(problemFromContext(ctx, status, title, detail))
	default:
		return gen.ReleaseLegalHold500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, ""))
	}
}

// ---------------------------------------------------------------------------
// Wire mappings (application models → generated contract types).

// toGenExportRecord maps a stored export row onto the ExportRecord schema (the
// generation stamps are nullable and only present once completed).
func toGenExportRecord(e application.Export) gen.ExportRecord {
	rec := gen.ExportRecord{
		Id:        e.ID,
		Status:    gen.ExportStatus(e.Status),
		Filter:    toGenExportFilter(e.Filter),
		CreatedAt: e.CreatedAt,
	}
	if e.Status == application.ExportStatusCompleted {
		rowCount := e.RowCount
		sizeBytes := int(e.SizeBytes)
		checksum := e.Checksum
		schemaVersion := e.SchemaVersion
		ruleVersion := e.RuleVersion
		rec.RowCount = &rowCount
		rec.SizeBytes = &sizeBytes
		rec.Checksum = &checksum
		rec.SchemaVersion = &schemaVersion
		rec.RuleVersion = &ruleVersion
		if !e.ExpiresAt.IsZero() {
			expiresAt := e.ExpiresAt
			rec.ExpiresAt = &expiresAt
		}
	}
	return rec
}

// fromGenExportFilter maps the wire filter onto the application filter (the
// use case validates the vocabulary; an out-of-vocabulary value is a 400).
func fromGenExportFilter(f gen.ExportFilter) application.ExportFilter {
	out := application.ExportFilter{}
	if f.Priority != nil {
		p := domain.Priority(*f.Priority)
		out.Priority = &p
	}
	if f.Status != nil {
		s := domain.SignalStatus(*f.Status)
		out.Status = &s
	}
	if f.AssetType != nil {
		a := domain.AssetType(*f.AssetType)
		out.AssetType = &a
	}
	if f.AssetId != nil {
		out.AssetID = *f.AssetId
	}
	if f.Product != nil {
		out.Product = *f.Product
	}
	if f.Cve != nil {
		out.Cve = *f.Cve
	}
	if f.OwnerId != nil {
		out.OwnerID = f.OwnerId
	}
	if f.SourceId != nil {
		out.SourceID = *f.SourceId
	}
	if f.CreatedFrom != nil {
		out.CreatedFrom = f.CreatedFrom
	}
	if f.CreatedTo != nil {
		out.CreatedTo = f.CreatedTo
	}
	if f.SlaState != nil {
		s := application.ExportSLAState(*f.SlaState)
		out.SLAState = &s
	}
	if f.FreeText != nil {
		out.FreeText = *f.FreeText
	}
	return out
}

// toGenExportFilter maps the stored application filter onto the wire filter.
func toGenExportFilter(f application.ExportFilter) gen.ExportFilter {
	out := gen.ExportFilter{}
	if f.Priority != nil {
		p := gen.Priority(*f.Priority)
		out.Priority = &p
	}
	if f.Status != nil {
		s := gen.SignalStatus(*f.Status)
		out.Status = &s
	}
	if f.AssetType != nil {
		a := gen.AssetType(*f.AssetType)
		out.AssetType = &a
	}
	if f.AssetID != "" {
		out.AssetId = stringPtr(f.AssetID)
	}
	if f.Product != "" {
		out.Product = stringPtr(f.Product)
	}
	if f.Cve != "" {
		out.Cve = stringPtr(f.Cve)
	}
	if f.OwnerID != nil {
		out.OwnerId = f.OwnerID
	}
	if f.SourceID != "" {
		out.SourceId = stringPtr(f.SourceID)
	}
	if f.CreatedFrom != nil {
		out.CreatedFrom = f.CreatedFrom
	}
	if f.CreatedTo != nil {
		out.CreatedTo = f.CreatedTo
	}
	if f.SLAState != nil {
		s := string(*f.SLAState)
		out.SlaState = &s
	}
	if f.FreeText != "" {
		out.FreeText = stringPtr(f.FreeText)
	}
	return out
}

// toGenRetentionRun maps a stored retention run onto the RetentionRun schema
// (the approval/execution stamps are nullable).
func toGenRetentionRun(r application.RetentionRun) gen.RetentionRun {
	run := gen.RetentionRun{
		Id:                 r.ID,
		PolicyId:           r.PolicyID,
		Stage:              gen.RetentionStage(r.Stage),
		Cutoff:             r.Cutoff,
		PartitionKey:       r.PartitionKey,
		Status:             gen.RetentionRunStatus(r.Status),
		PseudonymisedCount: r.Pseudonymised,
		DeletedCount:       r.Deleted,
		FailedCount:        r.Failed,
	}
	if r.DryRun != nil {
		report := gen.RetentionDryRunReport{
			Candidates:     r.DryRun.Candidates,
			Held:           r.DryRun.Held,
			ToPseudonymise: r.DryRun.ToPseudonymise,
			ToDelete:       r.DryRun.ToDelete,
		}
		run.DryRun = &report
	}
	if r.ApprovedBy != "" {
		run.ApprovedBy = stringPtr(r.ApprovedBy)
	}
	if !r.ApprovedAt.IsZero() {
		at := r.ApprovedAt
		run.ApprovedAt = &at
	}
	if r.ApprovalReason != "" {
		run.ApprovalReason = stringPtr(r.ApprovalReason)
	}
	if !r.StartedAt.IsZero() {
		at := r.StartedAt
		run.StartedAt = &at
	}
	if !r.FinishedAt.IsZero() {
		at := r.FinishedAt
		run.FinishedAt = &at
	}
	if r.LastError != "" {
		run.LastError = stringPtr(r.LastError)
	}
	return run
}

// toGenLegalHold maps a stored legal hold onto the LegalHold schema.
func toGenLegalHold(h application.LegalHold) gen.LegalHold {
	hold := gen.LegalHold{
		Id:            h.ID,
		AggregateType: h.AggregateType,
		AggregateId:   h.AggregateID,
		Reason:        h.Reason,
		ActorId:       h.ActorID,
		CreatedAt:     h.CreatedAt,
	}
	if !h.ReleasedAt.IsZero() {
		at := h.ReleasedAt
		hold.ReleasedAt = &at
	}
	return hold
}

// stringPtr returns a pointer to a copy of s (the generated nullable fields
// are pointers; the mapped values are stable copies).
func stringPtr(s string) *string { return &s }
