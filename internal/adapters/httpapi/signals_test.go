package httpapi

// Handler tests of the I1b signal reads (WP-1b.08, ARCH-001 §4): the
// generated routes GET /api/v1/signals and GET /api/v1/signals/{signal_id}
// behind the full WP-1a.06 middleware chain, served by an in-memory fake of
// the application read surface. The suite pins the wire contract — the
// SignalList envelope with its sort order, the single Signal, and RFC 9457
// problem details carrying the correlation id for the 400/404/500 cases —
// and the delegation to the use cases (filters, limit, cursor and id all
// reach application.ListSignals/GetSignal unchanged). The application
// error-class mapping (validation → 400, conflict → 409, not-found → 404,
// infra → 500 without leaking the cause) is covered through the fake.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fixedCreated is the timestamp of every sample signal, so the tests pin
// the exact RFC 3339 rendering of created_at.
var fixedCreated = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// sampleSignal returns a fully populated application signal view.
func sampleSignal(id string, priority domain.Priority) application.Signal {
	return application.Signal{
		ID:         id,
		MatchID:    "00000000-0000-0000-0000-0000000000b1",
		CveID:      "CVE-2024-0001",
		Priority:   priority,
		Status:     domain.SignalStatusNew,
		Confidence: domain.ConfidenceHigh,
		Method:     domain.MatchMethodExactIdentifier,
		Asset: application.SignalAsset{
			ID:          "00000000-0000-0000-0000-0000000000c1",
			Name:        "portal-1",
			Type:        domain.AssetTypeServerVM,
			Criticality: domain.CriticalityCritical,
			Exposure:    domain.ExposureInternet,
		},
		Product:   application.SignalProduct{Vendor: "acme", Product: "portal", Version: "2.4"},
		Summary:   "Sample signal " + id,
		CreatedAt: fixedCreated,
		Version:   1,
	}
}

// fakeSignals is an in-memory SignalsQuery: it serves the configured page,
// signal or error and records what the handler delegated, so tests can
// assert both the wire response and the use-case input.
type fakeSignals struct {
	page      application.ListSignalsResult
	listErr   error
	signal    application.Signal
	getErr    error
	listCalls int
	getCalls  int
	lastInput application.ListSignalsInput
	lastID    string
}

var _ SignalsQuery = (*fakeSignals)(nil)

func (f *fakeSignals) ListSignals(ctx context.Context, in application.ListSignalsInput) (application.ListSignalsResult, error) {
	f.listCalls++
	f.lastInput = in
	return f.page, f.listErr
}

func (f *fakeSignals) GetSignal(ctx context.Context, in application.GetSignalInput) (application.Signal, error) {
	f.getCalls++
	f.lastID = in.SignalID
	return f.signal, f.getErr
}

// newSignalAPI builds the I1b signal route table exactly like the
// composition root (cmd/risksignal-server): RegisterSignalRoutes on a fresh
// ServeMux, wrapped in the WP-1a.06 middleware chain of NewHandler. The
// tests therefore exercise the real mount path, and the correlation
// middleware populates the request context whose id the ProblemDetails
// assertions rely on.
func newSignalAPI(t *testing.T, query SignalsQuery) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterSignalRoutes(mux, NewSignalsHandler(query, logger))
	return NewHandler(mux, logger)
}

// doRequest runs one request through h and returns the recorder.
func doRequest(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// getWithRequestID runs a GET with the given correlation id header set.
func getWithRequestID(t *testing.T, h http.Handler, target, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set(HeaderRequestID, requestID)
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) gen.ProblemDetails {
	t.Helper()
	var p gen.ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem details from %q: %v", rec.Body.String(), err)
	}
	return p
}

// TestListSignalsReturnsSortedEnvelope drives the listSignals happy path
// through the whole chain: the SignalList envelope is on the wire with the
// signals in the use case's order (priority ascending — the repository
// enforces the ARCH-001 §4 sort, the handler preserves it), next_cursor is
// null on the last page and the correlation id is echoed back.
func TestListSignalsReturnsSortedEnvelope(t *testing.T) {
	p1 := sampleSignal("00000000-0000-0000-0000-0000000000a1", domain.PriorityP1)
	p2 := sampleSignal("00000000-0000-0000-0000-0000000000a2", domain.PriorityP2)
	fake := &fakeSignals{page: application.ListSignalsResult{Signals: []application.Signal{p1, p2}}}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals", "list-request-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := rec.Header().Get(HeaderRequestID); got != "list-request-1" {
		t.Errorf("X-Request-ID echo = %q, want %q", got, "list-request-1")
	}

	var body gen.SignalList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Data) != 2 {
		t.Fatalf("data has %d signals, want 2", len(body.Data))
	}
	// The envelope keeps the use-case order: P1 before P2 (stable sort).
	if body.Data[0].Id != p1.ID || body.Data[1].Id != p2.ID {
		t.Errorf("data order = [%s, %s], want [%s, %s] (priority ascending)",
			body.Data[0].Id, body.Data[1].Id, p1.ID, p2.ID)
	}
	if body.Data[0].Priority != gen.P1 || body.Data[1].Priority != gen.P2 {
		t.Errorf("priority order = [%s, %s], want [P1, P2]", body.Data[0].Priority, body.Data[1].Priority)
	}
	if body.NextCursor != nil {
		t.Errorf("next_cursor = %q, want null on the last page", *body.NextCursor)
	}

	// The delegation happened with an open filter and page defaults: the
	// use case turns limit 0 into the default page size.
	if fake.listCalls != 1 {
		t.Fatalf("ListSignals called %d times, want 1", fake.listCalls)
	}
	if fake.lastInput.Limit != 0 || fake.lastInput.Cursor != "" ||
		fake.lastInput.Priority != nil || fake.lastInput.Status != nil {
		t.Errorf("ListSignalsInput = %+v, want an open filter with default page", fake.lastInput)
	}
}

// TestListSignalsForwardsFiltersLimitCursor asserts the query parameters
// reach the use case unchanged: priority/status as the domain filter, limit
// and cursor verbatim.
func TestListSignalsForwardsFiltersLimitCursor(t *testing.T) {
	fake := &fakeSignals{page: application.ListSignalsResult{Signals: []application.Signal{sampleSignal("00000000-0000-0000-0000-0000000000a1", domain.PriorityP1)}}}
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals?priority=P3&status=new&limit=5&cursor=page-cursor-7")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if fake.listCalls != 1 {
		t.Fatalf("ListSignals called %d times, want 1", fake.listCalls)
	}
	in := fake.lastInput
	if in.Limit != 5 {
		t.Errorf("limit = %d, want 5", in.Limit)
	}
	if in.Cursor != "page-cursor-7" {
		t.Errorf("cursor = %q, want %q (opaque, passed through)", in.Cursor, "page-cursor-7")
	}
	if in.Priority == nil || *in.Priority != domain.PriorityP3 {
		t.Errorf("priority filter = %v, want P3", in.Priority)
	}
	if in.Status == nil || *in.Status != domain.SignalStatusNew {
		t.Errorf("status filter = %v, want new", in.Status)
	}
}

// TestListSignalsCarriesNextCursor asserts a further page is signalled with
// the opaque next_cursor of the use case result, verbatim.
func TestListSignalsCarriesNextCursor(t *testing.T) {
	next := "page-cursor-8"
	fake := &fakeSignals{page: application.ListSignalsResult{
		Signals:    []application.Signal{sampleSignal("00000000-0000-0000-0000-0000000000a1", domain.PriorityP1)},
		NextCursor: next,
	}}
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals")
	var body gen.SignalList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.NextCursor == nil || *body.NextCursor != next {
		t.Errorf("next_cursor = %v, want %q", body.NextCursor, next)
	}
}

// TestListSignalsEmptyPageIsEmptyArray asserts an empty page renders as
// {"data": [], "next_cursor": null} — never "data": null, which the array
// schema rejects.
func TestListSignalsEmptyPageIsEmptyArray(t *testing.T) {
	fake := &fakeSignals{} // no signals, no next cursor
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Errorf("body = %s, want an empty data array", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"next_cursor":null`) {
		t.Errorf("body = %s, want next_cursor null", rec.Body.String())
	}
}

// TestGetSignalReturnsSignal drives the getSignal happy path: the single
// Signal renders with every joined field under its snake_case wire name —
// identifiers as strings, the enums, the nested asset and product, the
// RFC 3339 UTC created_at and the version.
func TestGetSignalReturnsSignal(t *testing.T) {
	sig := sampleSignal("00000000-0000-0000-0000-0000000000a1", domain.PriorityP1)
	fake := &fakeSignals{signal: sig}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals/"+sig.ID, "get-request-2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if fake.getCalls != 1 || fake.lastID != sig.ID {
		t.Errorf("GetSignal called %d times with id %q, want once with %q", fake.getCalls, fake.lastID, sig.ID)
	}

	var body gen.Signal
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Id != sig.ID || body.MatchId != sig.MatchID || body.CveId != sig.CveID {
		t.Errorf("ids = (%s, %s, %s), want the sample ids", body.Id, body.MatchId, body.CveId)
	}
	if body.Priority != gen.P1 || body.Status != gen.New {
		t.Errorf("priority/status = (%s, %s), want (P1, new)", body.Priority, body.Status)
	}
	if body.Confidence != gen.ConfidenceHigh || body.Method != gen.ExactIdentifier {
		t.Errorf("confidence/method = (%s, %s), want (high, exact_identifier)", body.Confidence, body.Method)
	}
	if body.Asset == nil || body.Asset.Id != sig.Asset.ID || body.Asset.Name != "portal-1" ||
		body.Asset.Type != "server_vm" || body.Asset.Criticality != gen.CriticalityCritical ||
		body.Asset.Exposure != gen.ExposureInternet {
		t.Errorf("asset = %+v, want the sample asset on the wire", body.Asset)
	}
	if body.Product.Vendor != "acme" || body.Product.Product != "portal" || body.Product.Version != "2.4" {
		t.Errorf("product = %+v, want the sample product", body.Product)
	}
	if body.Summary != sig.Summary || body.Version != 1 {
		t.Errorf("summary/version = (%q, %d), want the sample values", body.Summary, body.Version)
	}
	if !body.CreatedAt.Equal(fixedCreated) {
		t.Errorf("created_at = %v, want %v (RFC 3339 UTC)", body.CreatedAt, fixedCreated)
	}
}

// TestGetSignalUnknownIDRenders404ProblemDetails asserts the getSignal 404
// contract: an unknown — but well-formed — signal id answers RFC 9457
// problem details whose required fields are present, whose detail names the
// requested id and whose correlation_id matches the echoed X-Request-ID.
func TestGetSignalUnknownIDRenders404ProblemDetails(t *testing.T) {
	const unknown = "00000000-0000-0000-0000-00000000dead"
	fake := &fakeSignals{getErr: application.NotFoundError("get_signal", errors.New("no rows in result set"))}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals/"+unknown, "not-found-3")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(HeaderRequestID); got != "not-found-3" {
		t.Errorf("X-Request-ID echo = %q, want %q", got, "not-found-3")
	}

	p := decodeProblem(t, rec)
	if p.Type != "about:blank" || p.Title != "Signal not found" || p.Status != http.StatusNotFound {
		t.Errorf("problem = (%q, %q, %d), want (about:blank, %q, 404)", p.Type, p.Title, p.Status, "Signal not found")
	}
	if p.CorrelationId != "not-found-3" {
		t.Errorf("correlation_id = %q, want the echoed request id %q", p.CorrelationId, "not-found-3")
	}
	if p.Detail == nil || !strings.Contains(*p.Detail, unknown) {
		t.Errorf("detail = %v, want it to name the unknown signal id", p.Detail)
	}
	if p.Instance == nil || *p.Instance != "/api/v1/signals/"+unknown {
		t.Errorf("instance = %v, want the request path", p.Instance)
	}
	// The repository cause stays internal: it must not leak into the body.
	if p.Detail != nil && strings.Contains(*p.Detail, "no rows") {
		t.Errorf("detail = %q, leaks the repository error", *p.Detail)
	}
}

// TestListSignalsRejectsInvalidPriority asserts an out-of-vocabulary
// priority filter is refused at the API boundary with a 400 problem detail
// and never reaches the use case.
func TestListSignalsRejectsInvalidPriority(t *testing.T) {
	fake := &fakeSignals{}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals?priority=P9", "bad-priority-4")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Invalid request" || p.Status != http.StatusBadRequest {
		t.Errorf("problem = (%q, %d), want (Invalid request, 400)", p.Title, p.Status)
	}
	if p.CorrelationId != "bad-priority-4" {
		t.Errorf("correlation_id = %q, want %q", p.CorrelationId, "bad-priority-4")
	}
	if fake.listCalls != 0 {
		t.Errorf("ListSignals called %d times, want 0 (refused at the boundary)", fake.listCalls)
	}
}

// TestListSignalsRejectsInvalidStatus asserts the same for a status outside
// the ch. 6.3 vocabulary (the full lifecycle is on the wire since I4).
func TestListSignalsRejectsInvalidStatus(t *testing.T) {
	fake := &fakeSignals{}
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals?status=archived")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Invalid request" || p.Detail == nil || !strings.Contains(*p.Detail, "archived") {
		t.Errorf("problem = (%q, %v), want Invalid request naming the bad status", p.Title, p.Detail)
	}
	if fake.listCalls != 0 {
		t.Errorf("ListSignals called %d times, want 0", fake.listCalls)
	}
}

// TestListSignalsRejectsInvalidLimit asserts a limit beyond the cap answers
// 400 through the application validation mapping, with the client-facing
// cause (no application-error envelope) in the detail.
func TestListSignalsRejectsInvalidLimit(t *testing.T) {
	fake := &fakeSignals{listErr: application.Validationf("list_signals", "limit %d outside [1,100] (0 means the default 20)", 101)}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals?limit=101", "bad-limit-5")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Invalid request" || p.CorrelationId != "bad-limit-5" {
		t.Errorf("problem = (%q, %q), want (Invalid request, bad-limit-5)", p.Title, p.CorrelationId)
	}
	if p.Detail == nil || *p.Detail != "limit 101 outside [1,100] (0 means the default 20)" {
		t.Errorf("detail = %v, want the client-facing cause without the application envelope", p.Detail)
	}
	// The use case was reached with the offending value.
	if fake.listCalls != 1 || fake.lastInput.Limit != 101 {
		t.Errorf("ListSignals called %d times with limit %d, want once with 101", fake.listCalls, fake.lastInput.Limit)
	}
}

// TestListSignalsMalformedLimitParamRenders400 asserts a query value the
// generated parameter binding cannot parse (?limit=abc) is a client mistake
// answered as a problem detail — the binding-error handler of
// RegisterSignalRoutes replaces the generated plain-text default.
func TestListSignalsMalformedLimitParamRenders400(t *testing.T) {
	fake := &fakeSignals{}
	h := newSignalAPI(t, fake)

	rec := getWithRequestID(t, h, "/api/v1/signals?limit=abc", "bad-param-6")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Invalid request" || p.Status != http.StatusBadRequest || p.CorrelationId != "bad-param-6" {
		t.Errorf("problem = (%q, %d, %q), want (Invalid request, 400, bad-param-6)", p.Title, p.Status, p.CorrelationId)
	}
	if p.Detail == nil || !strings.Contains(*p.Detail, "limit") {
		t.Errorf("detail = %v, want it to name the offending parameter", p.Detail)
	}
	if fake.listCalls != 0 {
		t.Errorf("ListSignals called %d times, want 0", fake.listCalls)
	}
}

// TestGetSignalMalformedIDRenders400 asserts a signal id that fails
// application validation (a non-uuid reaches the repository, which reports
// it as a caller mistake) maps to a 400 problem detail.
func TestGetSignalMalformedIDRenders400(t *testing.T) {
	fake := &fakeSignals{getErr: application.Validationf("get_signal", "invalid signal id %q", "not-a-uuid")}
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals/not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Invalid request" || p.Detail == nil || *p.Detail != `invalid signal id "not-a-uuid"` {
		t.Errorf("problem = (%q, %v), want Invalid request with the validation cause", p.Title, p.Detail)
	}
}

// TestListSignalsConflictRenders409 asserts the conflict class of the
// application error table maps to 409. Read endpoints cannot produce a
// conflict today — the row exists because the class mapping is complete per
// concept ch. 5.2 and grows operative with the I4 command endpoints.
func TestListSignalsConflictRenders409(t *testing.T) {
	fake := &fakeSignals{listErr: application.ConflictError("list_signals", errors.New("duplicate"))}
	h := newSignalAPI(t, fake)

	rec := doRequest(t, h, http.MethodGet, "/api/v1/signals")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body: %s)", rec.Code, rec.Body.String())
	}
	if p := decodeProblem(t, rec); p.Title != "Conflict" || p.Status != http.StatusConflict {
		t.Errorf("problem = (%q, %d), want (Conflict, 409)", p.Title, p.Status)
	}
}

// TestGetSignalInfraErrorIsGeneric500 asserts the internal-error contract:
// an infrastructure failure answers a 500 problem detail without a detail
// field — the cause goes only to the structured log, never to the client.
func TestGetSignalInfraErrorIsGeneric500(t *testing.T) {
	logger, logBuf := testLogger(t)
	fake := &fakeSignals{getErr: errors.New("database connection refused")}
	mux := http.NewServeMux()
	RegisterSignalRoutes(mux, NewSignalsHandler(fake, logger))
	h := NewHandler(mux, logger)

	rec := getWithRequestID(t, h, "/api/v1/signals/00000000-0000-0000-0000-0000000000a1", "infra-7")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	p := decodeProblem(t, rec)
	if p.Title != "Internal server error" || p.Status != http.StatusInternalServerError {
		t.Errorf("problem = (%q, %d), want (Internal server error, 500)", p.Title, p.Status)
	}
	if p.Detail != nil {
		t.Errorf("detail = %q, must not leak the internal cause", *p.Detail)
	}
	if p.CorrelationId != "infra-7" {
		t.Errorf("correlation_id = %q, want %q", p.CorrelationId, "infra-7")
	}
	// The cause is in the log — linked to the same correlation id — but
	// nowhere on the wire.
	if !strings.Contains(logBuf.String(), "database connection refused") {
		t.Errorf("log = %q, want the internal error recorded", logBuf.String())
	}
}

// TestSignalRoutesRejectNonGET asserts the method-scoped generated routes
// answer 405 for other verbs instead of falling through to the mux.
func TestSignalRoutesRejectNonGET(t *testing.T) {
	fake := &fakeSignals{}
	h := newSignalAPI(t, fake)

	for _, target := range []string{"/api/v1/signals", "/api/v1/signals/00000000-0000-0000-0000-0000000000a1"} {
		rec := doRequest(t, h, http.MethodPost, target)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s status = %d, want 405", target, rec.Code)
		}
	}
	if fake.listCalls != 0 || fake.getCalls != 0 {
		t.Errorf("use cases called for non-GET requests (list %d, get %d)", fake.listCalls, fake.getCalls)
	}
}
