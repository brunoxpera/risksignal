package httpapi

// Handler tests of the I6 operations (ARCH-007 §1.1/§2.1/§2.2, WP-6.07 /
// DEV-119): the export resources, the retention-run surface and the legal
// holds, served by an in-memory fake of the three application surfaces. The
// suite pins the wire contract — the deployed types and the RFC 9457 problem
// details of the declared error classes (happy/denied/not-found/conflict/expired)
// — and the delegation (the resolved actor and the input fields reach the use
// case unchanged).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeI6 is an in-memory implementation of the three I6 surfaces. Each method
// serves the configured outcome and records what the handler delegated.
type fakeI6 struct {
	actor    application.Actor
	actorErr error

	created     application.CreateExportResult
	createErr   error
	got         application.Export
	getErr      error
	download    application.DownloadExportResult
	downloadErr error

	dryRun    application.RetentionDryRunResult
	dryRunErr error
	runs      []application.RetentionRun
	listErr   error
	run       application.RetentionRun
	getRunErr error
	approved  application.ApproveRetentionRunResult
	approveEr error

	hold         application.LegalHold
	holdErr      error
	released     application.LegalHold
	releaseErr   error
	holds        []application.LegalHold
	listHoldsErr error

	lastCreate     application.CreateExportInput
	lastGet        application.GetExportInput
	lastDownload   application.DownloadExportInput
	lastDryRun     application.RunRetentionDryRunInput
	lastApprove    application.ApproveRetentionRunInput
	lastCreateHold application.CreateLegalHoldInput
	lastRelease    application.ReleaseLegalHoldInput
}

var _ ExportAPI = (*fakeI6)(nil)
var _ RetentionAPI = (*fakeI6)(nil)
var _ LegalHoldAPI = (*fakeI6)(nil)

func (f *fakeI6) ResolveActor(_ context.Context, _ domain.Identity) (application.Actor, error) {
	return f.actor, f.actorErr
}

func (f *fakeI6) CreateExport(_ context.Context, in application.CreateExportInput) (application.CreateExportResult, error) {
	f.lastCreate = in
	return f.created, f.createErr
}

func (f *fakeI6) GetExport(_ context.Context, in application.GetExportInput) (application.Export, error) {
	f.lastGet = in
	return f.got, f.getErr
}

func (f *fakeI6) DownloadExport(_ context.Context, in application.DownloadExportInput) (application.DownloadExportResult, error) {
	f.lastDownload = in
	return f.download, f.downloadErr
}

func (f *fakeI6) RunRetentionDryRun(_ context.Context, in application.RunRetentionDryRunInput) (application.RetentionDryRunResult, error) {
	f.lastDryRun = in
	return f.dryRun, f.dryRunErr
}

func (f *fakeI6) ListRetentionRuns(_ context.Context, _ application.ListRetentionRunsInput) ([]application.RetentionRun, error) {
	return f.runs, f.listErr
}

func (f *fakeI6) GetRetentionRun(_ context.Context, _ application.GetRetentionRunInput) (application.RetentionRun, error) {
	return f.run, f.getRunErr
}

func (f *fakeI6) ApproveRetentionRun(_ context.Context, in application.ApproveRetentionRunInput) (application.ApproveRetentionRunResult, error) {
	f.lastApprove = in
	return f.approved, f.approveEr
}

func (f *fakeI6) CreateLegalHold(_ context.Context, in application.CreateLegalHoldInput) (application.LegalHold, error) {
	f.lastCreateHold = in
	return f.hold, f.holdErr
}

func (f *fakeI6) ReleaseLegalHold(_ context.Context, in application.ReleaseLegalHoldInput) (application.LegalHold, error) {
	f.lastRelease = in
	return f.released, f.releaseErr
}

func (f *fakeI6) ListLegalHolds(_ context.Context, _ application.ListLegalHoldsInput) ([]application.LegalHold, error) {
	return f.holds, f.listHoldsErr
}

// newI6API builds the API route table with the given I6 surface and injects
// the authenticated identity (mirrors the composition root's mount path).
func newI6API(t *testing.T, f *fakeI6, id domain.Identity, withIdentity bool) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(&fakeSignals{}, nil, nil, logger,
		APISurfaces{Exports: f, Retention: f, LegalHolds: f}))
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if withIdentity {
				r = r.WithContext(WithIdentity(r.Context(), id))
			}
			next.ServeHTTP(w, r)
		})
	}
	return NewHandlerWithAuth(mux, logger, auth)
}

var i6Identity = domain.Identity{SubjectID: "local::administrator"}

// ---------------------------------------------------------------------------
// Exports

func TestExportCreateHappy(t *testing.T) {
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	created := application.Export{ID: "exp-1", Status: application.ExportStatusPending, Format: export.FormatCSV, CreatedAt: at}
	f := &fakeI6{
		actor:   application.Actor{Type: application.ActorTypeUser, ID: "u-1", DisplayName: "Admin"},
		created: application.CreateExportResult{ExportID: "exp-1", Status: application.ExportStatusPending, CreatedAt: at, Export: created},
	}
	h := newI6API(t, f, i6Identity, true)

	body := `{"filter":{"priority":"P1"},"format":"csv"}`
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/exports", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"exp-1"`) || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("create body = %s, want the pending ExportRecord", rec.Body.String())
	}
	if f.lastCreate.Format != export.FormatCSV || f.lastCreate.Filter.Priority == nil || *f.lastCreate.Filter.Priority != domain.PriorityP1 {
		t.Fatalf("delegated input = %+v, want csv + P1", f.lastCreate)
	}
	if f.lastCreate.Actor.ID != "u-1" {
		t.Fatalf("delegated actor = %+v, want the resolved user", f.lastCreate.Actor)
	}
}

func TestExportCreateDenied(t *testing.T) {
	f := &fakeI6{actorErr: application.ForbiddenError("resolve", errors.New("no exports.create"))}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/exports", strings.NewReader(`{"filter":{},"format":"csv"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExportCreateInvalidFilter(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.createErr = application.Validationf("create_export", "invalid priority")
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/exports", strings.NewReader(`{"filter":{},"format":"csv"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExportGetNotFound(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.getErr = application.NotFoundError("get_export", errors.New("no export"))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/exports/exp-404", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExportDownloadExpired(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.downloadErr = application.ConflictError("download_export", fmt.Errorf("export exp-1 expired at 2026-09-01T00:00:00Z: %w", application.ErrExportExpired))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/exports/exp-1/download", nil))
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExportDownloadNotCompleted(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.downloadErr = application.ConflictError("download_export", errors.New("export exp-1 is pending, not completed"))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/exports/exp-1/download", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExportDownloadStreams(t *testing.T) {
	for _, tc := range []struct {
		name        string
		filename    string
		contentType string
	}{
		{"csv", "export-exp-1.csv", "text/csv; charset=utf-8"},
		{"json", "export-exp-1.json", "application/json; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
			f.download = application.DownloadExportResult{
				Reader:      io.NopCloser(strings.NewReader("a,b\n1,2\n")),
				Filename:    tc.filename,
				ContentType: tc.contentType,
				SizeBytes:   8,
			}
			h := newI6API(t, f, i6Identity, true)
			rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/exports/exp-1/download", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			// The handler must emit the application-computed content type, not a
			// hardcoded application/octet-stream (DEV-139).
			if got := rec.Header().Get("Content-Type"); got != tc.contentType {
				t.Fatalf("Content-Type = %q, want %q", got, tc.contentType)
			}
			if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, tc.filename) {
				t.Fatalf("Content-Disposition = %q, want the attachment filename", got)
			}
			if rec.Body.String() != "a,b\n1,2\n" {
				t.Fatalf("body = %q, want the streamed artifact", rec.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Retention runs

func TestRetentionDryRunHappy(t *testing.T) {
	cutoff := time.Date(2021, 9, 10, 0, 0, 0, 0, time.UTC)
	counts := application.RetentionCounts{Candidates: 3, Held: 1, ToDelete: 3}
	f := &fakeI6{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"},
		dryRun: application.RetentionDryRunResult{
			RunID: "run-1", Status: application.RetentionStatusDryRun, Cutoff: cutoff, Counts: counts,
			Run: application.RetentionRun{
				ID: "run-1", PolicyID: application.RetentionPolicyClosedSignals, Stage: application.RetentionStageDelete,
				Cutoff: cutoff, PartitionKey: "2021-09", Status: application.RetentionStatusDryRun, DryRun: &counts,
			},
		},
	}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/retention/runs", strings.NewReader(`{"stage":"delete"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"run-1"`) || !strings.Contains(rec.Body.String(), `"held":1`) {
		t.Fatalf("body = %s, want the dry-run report", rec.Body.String())
	}
	if f.lastDryRun.Stage != application.RetentionStageDelete {
		t.Fatalf("delegated stage = %q, want delete", f.lastDryRun.Stage)
	}
}

func TestRetentionDryRunDenied(t *testing.T) {
	f := &fakeI6{actorErr: application.ForbiddenError("resolve", errors.New("no retention.manage"))}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/retention/runs", strings.NewReader(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRetentionRunList(t *testing.T) {
	f := &fakeI6{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"},
		runs: []application.RetentionRun{
			{ID: "run-1", PolicyID: application.RetentionPolicyClosedSignals, Stage: application.RetentionStageDelete, Status: application.RetentionStatusDryRun},
		},
	}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/retention/runs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"run-1"`) || !strings.Contains(rec.Body.String(), `"data":[`) {
		t.Fatalf("body = %s, want the run list", rec.Body.String())
	}
}

func TestRetentionRunGetNotFound(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.getRunErr = application.NotFoundError("get_retention_run", errors.New("no run"))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/retention/runs/run-404", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRetentionApproveConflict(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "po-1"}}
	f.approveEr = application.ConflictError("approve_retention_run", errors.New("run is approved, not dry_run"))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/retention/runs/run-1/approve", strings.NewReader(`{"reason":"reviewed"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if f.lastApprove.RunID != "run-1" || f.lastApprove.Reason != "reviewed" {
		t.Fatalf("delegated approve = %+v, want run-1/reviewed", f.lastApprove)
	}
}

func TestRetentionApproveMissingBody(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "po-1"}}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/retention/runs/run-1/approve", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Legal holds

func TestLegalHoldCreateHappy(t *testing.T) {
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	f := &fakeI6{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"},
		hold: application.LegalHold{
			ID: "hold-1", AggregateType: application.AuditAggregateRiskSignal, AggregateID: "sig-1", Reason: "litigation", ActorID: "u-1", CreatedAt: at,
		},
	}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/legal-holds", strings.NewReader(`{"aggregate_id":"sig-1","reason":"litigation"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if f.lastCreateHold.AggregateID != "sig-1" || f.lastCreateHold.Reason != "litigation" {
		t.Fatalf("delegated create-hold = %+v, want sig-1/litigation", f.lastCreateHold)
	}
}

func TestLegalHoldCreateInvalid(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.holdErr = application.Validationf("create_legal_hold", "a reason is mandatory")
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/legal-holds", strings.NewReader(`{"aggregate_id":"sig-1","reason":""}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestLegalHoldList(t *testing.T) {
	f := &fakeI6{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"},
		holds: []application.LegalHold{
			{ID: "hold-1", AggregateType: application.AuditAggregateRiskSignal, AggregateID: "sig-1", Reason: "litigation"},
		},
	}
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/legal-holds", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"hold-1"`) {
		t.Fatalf("body = %s, want the hold list", rec.Body.String())
	}
}

func TestLegalHoldReleaseNotFound(t *testing.T) {
	f := &fakeI6{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}
	f.releaseErr = application.NotFoundError("release_legal_hold", errors.New("no hold"))
	h := newI6API(t, f, i6Identity, true)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/legal-holds/hold-404/release", strings.NewReader(`{"reason":"done"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestI6NoIdentityForbidden: without an authenticated identity every I6
// command answers the declared 403 (fail closed, no fallback identity).
func TestI6NoIdentityForbidden(t *testing.T) {
	f := &fakeI6{}
	h := newI6API(t, f, domain.Identity{}, false)
	rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/exports", strings.NewReader(`{"filter":{},"format":"csv"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}
