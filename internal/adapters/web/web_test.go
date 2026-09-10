package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"io"
	"log/slog"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fixedTime is the injected clock instant of the tests.
var fixedTime = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeService is an in-memory Service + ActorResolver (no database).
type fakeService struct {
	signals    []application.Signal
	assets     []application.Asset
	components []application.Component
	users      []application.UserRecord
	roles      []application.RoleDescriptor

	// signal is returned by GetSignal (version can be bumped to simulate a
	// stale-version conflict re-render).
	signal application.Signal

	getErr    error
	listErr   error
	ackErr    error
	transErr  error
	commitErr error
	revokeErr error
	deactErr  error

	lastListSignals application.ListSignalsInput
	lastListAssets  application.ListAssetsInput
}

func (f *fakeService) ResolveActor(_ context.Context, _ domain.Identity) (application.Actor, error) {
	return application.Actor{Type: application.ActorTypeUser, ID: "u-1", DisplayName: "Test Analyst"}, nil
}

func (f *fakeService) ListSignals(_ context.Context, in application.ListSignalsInput) (application.ListSignalsResult, error) {
	f.lastListSignals = in
	if f.listErr != nil {
		return application.ListSignalsResult{}, f.listErr
	}
	return application.ListSignalsResult{Signals: f.signals}, nil
}

func (f *fakeService) GetSignal(_ context.Context, _ application.GetSignalInput) (application.Signal, error) {
	if f.getErr != nil {
		return application.Signal{}, f.getErr
	}
	return f.signal, nil
}

func (f *fakeService) ListAssets(_ context.Context, in application.ListAssetsInput) (application.ListAssetsResult, error) {
	f.lastListAssets = in
	return application.ListAssetsResult{Assets: f.assets}, nil
}

func (f *fakeService) GetAssetComponents(_ context.Context, _ application.GetAssetComponentsInput) (application.AssetComponents, error) {
	return application.AssetComponents{Components: f.components}, nil
}

func (f *fakeService) ListUsers(_ context.Context, _ application.ListUsersInput) (application.ListUsersResult, error) {
	return application.ListUsersResult{Users: f.users}, nil
}

func (f *fakeService) ListRoles(_ context.Context, _ application.ListRolesInput) ([]application.RoleDescriptor, error) {
	return f.roles, nil
}

func (f *fakeService) GrantRole(_ context.Context, _ application.GrantRoleInput) (application.UserRecord, error) {
	return application.UserRecord{}, nil
}

func (f *fakeService) RevokeRole(_ context.Context, _ application.RevokeRoleInput) (application.UserRecord, error) {
	if f.revokeErr != nil {
		return application.UserRecord{}, f.revokeErr
	}
	return application.UserRecord{}, nil
}

func (f *fakeService) DeactivateUser(_ context.Context, _ application.DeactivateUserInput) (application.UserRecord, error) {
	if f.deactErr != nil {
		return application.UserRecord{}, f.deactErr
	}
	return application.UserRecord{}, nil
}

func (f *fakeService) StageInventoryImport(_ context.Context, _ application.StageInventoryImportInput) (application.InventoryImport, error) {
	return application.InventoryImport{ID: "imp-1", Status: application.InventoryImportPending, Rows: 3}, nil
}

func (f *fakeService) GetInventoryImport(_ context.Context, in application.GetInventoryImportInput) (application.InventoryImport, error) {
	return application.InventoryImport{ID: in.ID, Status: application.InventoryImportPending, Rows: 3}, nil
}

func (f *fakeService) CommitStagedInventory(_ context.Context, in application.CommitStagedInventoryInput) (application.InventoryImport, error) {
	if f.commitErr != nil {
		return application.InventoryImport{}, f.commitErr
	}
	return application.InventoryImport{ID: in.ID, Status: application.InventoryImportCommitted}, nil
}

func (f *fakeService) AcknowledgeSignal(_ context.Context, _ application.AcknowledgeSignalInput) (domain.RiskSignal, error) {
	if f.ackErr != nil {
		return domain.RiskSignal{}, f.ackErr
	}
	return domain.RiskSignal{}, nil
}

func (f *fakeService) TransitionSignal(_ context.Context, _ application.TransitionSignalInput) (domain.RiskSignal, error) {
	if f.transErr != nil {
		return domain.RiskSignal{}, f.transErr
	}
	return domain.RiskSignal{}, nil
}

func (f *fakeService) AssignOwner(_ context.Context, _ application.AssignOwnerInput) (domain.RiskSignal, error) {
	return domain.RiskSignal{}, nil
}

func (f *fakeService) AddComment(_ context.Context, _ application.AddCommentInput) (domain.Comment, error) {
	return domain.Comment{}, nil
}

func (f *fakeService) OverridePriority(_ context.Context, _ application.OverridePriorityInput) (domain.RiskSignal, error) {
	return domain.RiskSignal{}, nil
}

func (f *fakeService) RevertPriority(_ context.Context, _ application.RevertPriorityInput) (domain.RiskSignal, error) {
	return domain.RiskSignal{}, nil
}

func (f *fakeService) PauseSla(_ context.Context, _ application.PauseSlaInput) (domain.SlaClock, error) {
	return domain.SlaClock{}, nil
}

func (f *fakeService) ResumeSla(_ context.Context, _ application.ResumeSlaInput) (domain.SlaClock, error) {
	return domain.SlaClock{}, nil
}

// fakeRoles is the RolesReader of the tests.
type fakeRoles struct{ roles []domain.Role }

func (f fakeRoles) RolesByUserID(_ context.Context, _ string) ([]domain.Role, error) {
	return f.roles, nil
}

// testMounter registers without a permission gate (the gate is the httpapi
// PermissionGate in production).
type testMounter struct{}

func (testMounter) Mount(mux *http.ServeMux, pattern string, _ domain.Permission, h http.Handler) {
	mux.Handle(pattern, h)
}

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// newTestWeb builds the adapter over the fakes and returns the served handler.
func newTestWeb(t *testing.T, svc *fakeService, roles []domain.Role) http.Handler {
	t.Helper()
	// The tests load the real templates/assets from the repository web/ tree
	// on disk, so they exercise what production serves without importing the
	// embedded FS package (which the architecture gate reserves for the
	// composition root).
	fsys := os.DirFS("../../../web")
	w, err := New(Options{
		Service:   svc,
		Roles:     fakeRoles{roles: roles},
		Logger:    testLogger,
		Clock:     fixedClock{t: fixedTime},
		Templates: fsys,
		Assets:    fsys,
		Identity: func(context.Context) (domain.Identity, bool) {
			return domain.Identity{SubjectID: "s-1", DisplayName: "Test Analyst"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	w.Register(mux, testMounter{})
	return mux
}

// allRoles is the role set that sees every navigation entry.
func allRoles() []domain.Role {
	return []domain.Role{domain.RoleAdministrator, domain.RoleSecurityAnalyst}
}

// defaultSignal is a P1, high-confidence signal with a deadline.
func defaultSignal() application.Signal {
	due := fixedTime.Add(90 * time.Minute)
	return application.Signal{
		ID: "s1", CveID: "CVE-2026-0001", Priority: domain.PriorityP1, Status: domain.SignalStatusNew,
		Confidence: domain.ConfidenceHigh, Method: domain.MatchMethodExactIdentifier,
		Asset:   application.SignalAsset{ID: "a1", Name: "web-01", Type: domain.AssetTypeServerVM, Criticality: domain.CriticalityHigh},
		Product: application.SignalProduct{Vendor: "acme", Product: "widget", Version: "1.2.3"},
		Owner:   "u-1", CreatedAt: fixedTime.Add(-time.Hour), Version: 2, DueAt: &due,
	}
}

func sampleFake() *fakeService {
	return &fakeService{
		signals: []application.Signal{defaultSignal()},
		signal:  defaultSignal(),
		assets: []application.Asset{
			{ID: "a1", Name: "web-01", Type: domain.AssetTypeServerVM, Environment: domain.EnvironmentProduction, Criticality: domain.CriticalityHigh, Exposure: domain.ExposureInternet, Owner: "u-1", Source: "csv"},
		},
		components: []application.Component{{Vendor: "acme", Product: "widget", Version: "1.2.3"}},
		users: []application.UserRecord{
			{ID: "u-1", DisplayName: "Test Analyst", Email: "t@example.com", Roles: []domain.Role{domain.RoleSecurityAnalyst}},
		},
		roles: []application.RoleDescriptor{
			{Role: domain.RoleSecurityAnalyst, Permissions: []application.PermissionGrant{{Permission: domain.PermissionSignalsRead, Scope: domain.ScopeAll}}},
		},
	}
}

// get performs an authenticated GET.
func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// csrfFrom extracts the CSRF cookie value a GET set (minting it if needed).
func csrfFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "_risksignal_csrf" {
			return c.Value
		}
	}
	t.Fatalf("no CSRF cookie in response")
	return ""
}

// postForm performs an authenticated POST with the CSRF cookie + field.
func postForm(t *testing.T, h http.Handler, target, csrf string, form map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	vals := url.Values{}
	for k, v := range form {
		vals.Set(k, v)
	}
	vals.Set("csrf_token", csrf)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{ //nolint:gosec // test request cookie; the server sets the real attributes
		Name: "_risksignal_csrf", Value: csrf, SameSite: http.SameSiteLaxMode,
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEveryViewRenders(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	cases := []struct {
		path string
		want string
	}{
		{"/", "Dashboard"},
		{"/signals", "Signal triage"},
		{"/signals/s1", "Actions"},
		{"/sources", "Source monitor"},
		{"/inventory", "Assets"},
		{"/inventory/imports", "Stage an import"},
		{"/admin/users", "Users"},
		{"/admin/roles", "Role catalogue"},
	}
	for _, tc := range cases {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("GET %s body missing %q", tc.path, tc.want)
		}
	}
}

func TestStaticAssetsServed(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	rec := get(t, h, "/assets/app.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/app.css = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ":focus") {
		t.Errorf("stylesheet must contain a visible :focus rule")
	}
	if rec := get(t, h, "/assets/app.js"); rec.Code != http.StatusOK {
		t.Errorf("GET /assets/app.js = %d, want 200", rec.Code)
	}
}

func TestCSRFRejected(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	// Fetch to obtain a cookie, then POST without the field.
	_ = get(t, h, "/signals/s1")
	req := httptest.NewRequest(http.MethodPost, "/signals/s1/acknowledge", strings.NewReader("expected_version=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CSRF") {
		t.Errorf("body should mention the CSRF failure")
	}
}

func TestAcknowledgeHappyPath(t *testing.T) {
	h := newTestWeb(t, sampleFake(), allRoles())
	rec := get(t, h, "/signals/s1")
	csrf := csrfFrom(t, rec)
	rec = postForm(t, h, "/signals/s1/acknowledge", csrf, map[string]string{"expected_version": "2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("acknowledge = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "acknowledged") {
		t.Errorf("success flash missing")
	}
}

func TestStaleVersionRerenders409(t *testing.T) {
	svc := sampleFake()
	svc.ackErr = application.ConflictError("acknowledge_signal", errors.New("version mismatch"))
	h := newTestWeb(t, svc, allRoles())
	rec := get(t, h, "/signals/s1")
	csrf := csrfFrom(t, rec)
	rec = postForm(t, h, "/signals/s1/acknowledge", csrf, map[string]string{"expected_version": "1"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale acknowledge = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "changed by another user") {
		t.Errorf("409 must carry the visible conflict notice")
	}
	if !strings.Contains(rec.Body.String(), `data-version="2"`) {
		t.Errorf("409 must re-render with the fresh version")
	}
}
