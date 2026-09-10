package httpapi

// Handler tests of the I5b operations (ARCH-006 §2/§3.3, WP-5b.05): the
// staged inventory import, the asset reads and the user/role administration,
// behind the middleware chain plus an identity-injecting layer and served by
// an in-memory fake of the three application surfaces. The suite pins the wire
// contract — the deployed types and the RFC 9457 problem details of the
// declared error classes — the delegation (the resolved actor and the input
// fields reach the use case unchanged) and the per-route permission binding.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeI5B is an in-memory implementation of the three I5b surfaces. Each
// method serves the configured outcome and records what the handler
// delegated.
type fakeI5B struct {
	actor    application.Actor
	actorErr error

	staged     application.InventoryImport
	stageErr   error
	got        application.InventoryImport
	getErr     error
	committed  application.InventoryImport
	commitErr  error
	assetsPage application.ListAssetsResult
	listErr    error
	detail     application.AssetComponents
	detailErr  error
	usersPage  application.ListUsersResult
	usersErr   error
	roles      []application.RoleDescriptor
	rolesErr   error
	changed    application.UserRecord
	grantErr   error
	revokeErr  error
	deactErr   error

	lastStage      application.StageInventoryImportInput
	lastGet        application.GetInventoryImportInput
	lastCommit     application.CommitStagedInventoryInput
	lastListAssets application.ListAssetsInput
	lastDetail     application.GetAssetComponentsInput
	lastListUsers  application.ListUsersInput
	lastGrant      application.GrantRoleInput
	lastRevoke     application.RevokeRoleInput
	lastDeactivate application.DeactivateUserInput

	grantCalls int
	revokeCall int
}

var _ InventoryImports = (*fakeI5B)(nil)
var _ AssetsRead = (*fakeI5B)(nil)
var _ UserAdmin = (*fakeI5B)(nil)

func (f *fakeI5B) ResolveActor(_ context.Context, _ domain.Identity) (application.Actor, error) {
	return f.actor, f.actorErr
}

func (f *fakeI5B) StageInventoryImport(_ context.Context, in application.StageInventoryImportInput) (application.InventoryImport, error) {
	f.lastStage = in
	return f.staged, f.stageErr
}

func (f *fakeI5B) GetInventoryImport(_ context.Context, in application.GetInventoryImportInput) (application.InventoryImport, error) {
	f.lastGet = in
	return f.got, f.getErr
}

func (f *fakeI5B) CommitStagedInventory(_ context.Context, in application.CommitStagedInventoryInput) (application.InventoryImport, error) {
	f.lastCommit = in
	return f.committed, f.commitErr
}

func (f *fakeI5B) ListAssets(_ context.Context, in application.ListAssetsInput) (application.ListAssetsResult, error) {
	f.lastListAssets = in
	return f.assetsPage, f.listErr
}

func (f *fakeI5B) GetAssetComponents(_ context.Context, in application.GetAssetComponentsInput) (application.AssetComponents, error) {
	f.lastDetail = in
	return f.detail, f.detailErr
}

func (f *fakeI5B) ListUsers(_ context.Context, in application.ListUsersInput) (application.ListUsersResult, error) {
	f.lastListUsers = in
	return f.usersPage, f.usersErr
}

func (f *fakeI5B) ListRoles(_ context.Context, _ application.ListRolesInput) ([]application.RoleDescriptor, error) {
	return f.roles, f.rolesErr
}

func (f *fakeI5B) GrantRole(_ context.Context, in application.GrantRoleInput) (application.UserRecord, error) {
	f.grantCalls++
	f.lastGrant = in
	return f.changed, f.grantErr
}

func (f *fakeI5B) RevokeRole(_ context.Context, in application.RevokeRoleInput) (application.UserRecord, error) {
	f.revokeCall++
	f.lastRevoke = in
	return f.changed, f.revokeErr
}

func (f *fakeI5B) DeactivateUser(_ context.Context, in application.DeactivateUserInput) (application.UserRecord, error) {
	f.lastDeactivate = in
	return f.changed, f.deactErr
}

// newI5BAPI builds the API route table with the given I5b surface and injects
// the authenticated identity (mirrors the composition root's mount path).
func newI5BAPI(t *testing.T, f *fakeI5B, id domain.Identity, withIdentity bool) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(&fakeSignals{}, nil, nil, logger, I5BAPI{Inventory: f, Assets: f, Users: f}))
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

func decodeProblemBody(t *testing.T, rec *httptest.ResponseRecorder) gen.ProblemDetails {
	t.Helper()
	var p gen.ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v (body %s)", err, rec.Body.String())
	}
	return p
}

// ---------------------------------------------------------------------------
// Inventory import

func TestInventoryImportStagedFlow(t *testing.T) {
	csv := "source,external_id,type,name,environment,criticality,exposure\ninv,a1,server_vm,Alpha,production,critical,internet\n"
	committedAt := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	f := &fakeI5B{
		actor:     application.Actor{Type: application.ActorTypeUser, ID: "u-1", DisplayName: "Admin"},
		staged:    application.InventoryImport{ID: "imp-1", Status: application.InventoryImportPending, Rows: 1, WarningCount: 1},
		got:       application.InventoryImport{ID: "imp-1", Status: application.InventoryImportPending, Rows: 1},
		committed: application.InventoryImport{ID: "imp-1", Status: application.InventoryImportCommitted, Rows: 1, CommittedAt: committedAt},
	}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)

	// POST: upload → 200 staged record; the bytes and the correlation id
	// reach the use case.
	upload := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports", strings.NewReader(csv))
	upload.Header.Set("Content-Type", "text/csv")
	upload.Header.Set(HeaderRequestID, "corr-123")
	rec := do(h, upload)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var staged gen.InventoryImport
	if err := json.Unmarshal(rec.Body.Bytes(), &staged); err != nil {
		t.Fatalf("decode staged: %v", err)
	}
	if staged.Id != "imp-1" || staged.Status != gen.Pending || staged.Preview.Rows != 1 || staged.Preview.Warnings != 1 {
		t.Fatalf("staged = %+v, want imp-1/pending/1 row/1 warning", staged)
	}
	if string(f.lastStage.File) != csv || f.lastStage.Actor.ID != "u-1" || f.lastStage.CorrelationID != "corr-123" {
		t.Fatalf("delegated stage = %+v, want the CSV, actor u-1 and corr-123", f.lastStage)
	}

	// GET: the staged record by id.
	rec = do(h, httptest.NewRequest(http.MethodGet, "/api/v1/inventory/imports/imp-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if f.lastGet.ID != "imp-1" || f.lastGet.Actor.ID != "u-1" {
		t.Fatalf("delegated get = %+v, want imp-1 actor u-1", f.lastGet)
	}

	// commit: → 200 committed record with committed_at.
	rec = do(h, httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports/imp-1/commit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("commit status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var committed gen.InventoryImport
	if err := json.Unmarshal(rec.Body.Bytes(), &committed); err != nil {
		t.Fatalf("decode committed: %v", err)
	}
	if committed.Status != gen.Committed || committed.CommittedAt == nil {
		t.Fatalf("committed = %+v, want committed with committed_at", committed)
	}
	if f.lastCommit.ID != "imp-1" {
		t.Fatalf("delegated commit = %+v, want imp-1", f.lastCommit)
	}
}

func TestInventoryImportErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		err    error
		want   int
	}{
		{"get not found", http.MethodGet, "/api/v1/inventory/imports/missing", application.NotFoundError("op", errors.New("gone")), http.StatusNotFound},
		{"get forbidden", http.MethodGet, "/api/v1/inventory/imports/imp-1", application.Forbiddenf("op", "denied"), http.StatusForbidden},
		{"get internal", http.MethodGet, "/api/v1/inventory/imports/imp-1", application.InfraError("op", errors.New("boom")), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}, getErr: tc.err}
			h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
			rec := do(h, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if p := decodeProblemBody(t, rec); p.Status != tc.want || p.CorrelationId == "" {
				t.Fatalf("problem = %+v, want status %d and a correlation id", p, tc.want)
			}
		})
	}

	// Commit conflict (a failed record) is the typed 409.
	f := &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}, commitErr: application.ConflictError("op", errors.New("failed"))}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports/imp-1/commit", nil)); rec.Code != http.StatusConflict {
		t.Fatalf("commit conflict status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestInventoryImportUploadBodyLimit(t *testing.T) {
	f := &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}, staged: application.InventoryImport{ID: "imp-1", Status: application.InventoryImportPending}}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)

	// A body beyond the chain limit, with no declared length: MaxBytesReader
	// cuts it off and the handler answers the typed 413 problem detail.
	const oversize = int(MaxBodyBytes) + 1024
	body := io.LimitReader(strings.NewReader(strings.Repeat("a", oversize)), int64(oversize))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports", body)
	req.ContentLength = -1
	rec := do(h, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload status = %d, want 413 (body %s)", rec.Code, rec.Body.String())
	}
	if p := decodeProblemBody(t, rec); p.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("problem = %+v, want status 413", p)
	}
	if f.lastStage.File != nil {
		t.Fatal("the oversized upload reached the use case")
	}
}

// ---------------------------------------------------------------------------
// Assets

func TestAssetsListAndDetail(t *testing.T) {
	detailID := "asset-1"
	f := &fakeI5B{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "u-9"},
		assetsPage: application.ListAssetsResult{Assets: []application.Asset{
			{ID: "asset-1", ExternalID: "a1", Source: "inv", Type: domain.AssetTypeServerVM, Name: "Alpha",
				Environment: domain.EnvironmentProduction, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet, Owner: "u-9"},
		}, NextCursor: "cur-2"},
		detail: application.AssetComponents{
			Asset: application.Asset{ID: detailID, ExternalID: "a1", Source: "inv", Type: domain.AssetTypeServerVM, Name: "Alpha"},
			Components: []application.Component{
				{ID: "c-1", AssetID: detailID, Vendor: "acme", Product: "widget", Version: "1.0", NaturalKey: "k"},
			},
		},
	}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)

	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/assets?type=server_vm&limit=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var page gen.AssetList
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode asset list: %v", err)
	}
	if len(page.Data) != 1 || page.Data[0].Id != "asset-1" || page.Data[0].Owner == nil || *page.Data[0].Owner != "u-9" {
		t.Fatalf("asset list = %+v, want asset-1 owned by u-9", page)
	}
	if page.NextCursor == nil || *page.NextCursor != "cur-2" {
		t.Fatalf("next_cursor = %v, want cur-2", page.NextCursor)
	}
	if f.lastListAssets.Type == nil || *f.lastListAssets.Type != domain.AssetTypeServerVM || f.lastListAssets.Limit != 1 {
		t.Fatalf("delegated list = %+v, want type=server_vm limit=1", f.lastListAssets)
	}

	rec = do(h, httptest.NewRequest(http.MethodGet, "/api/v1/assets/asset-1/components", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var detail gen.AssetComponents
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode asset components: %v", err)
	}
	if detail.Asset.Id != "asset-1" || len(detail.Components) != 1 || detail.Components[0].Product != "widget" {
		t.Fatalf("asset components = %+v, want asset-1 with one widget component", detail)
	}
	if f.lastDetail.AssetID != "asset-1" {
		t.Fatalf("delegated detail = %+v, want asset-1", f.lastDetail)
	}
}

func TestAssetsErrorMapping(t *testing.T) {
	// Invalid enum filter → 400 without reaching the use case.
	f := &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-9"}}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/assets?type=not_a_type", nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if f.lastListAssets.Type != nil {
		t.Fatal("an invalid filter reached the use case")
	}

	// Detail not found → 404; forbidden → 403.
	f = &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-9"}, detailErr: application.NotFoundError("op", errors.New("gone"))}
	h = newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/assets/missing/components", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("detail not found status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}

	f = &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-9"}, listErr: application.Forbiddenf("op", "denied")}
	h = newI5BAPI(t, f, domain.Identity{SubjectID: "local::system-responsible"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("list forbidden status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// User/role administration

func TestUserAdminListAndRoles(t *testing.T) {
	f := &fakeI5B{
		actor:     application.Actor{Type: application.ActorTypeUser, ID: "admin-1"},
		usersPage: application.ListUsersResult{Users: []application.UserRecord{{ID: "u-1", SubjectID: "local::x", DisplayName: "X", Roles: []domain.Role{domain.RoleSecurityAnalyst}}}},
		roles:     []application.RoleDescriptor{{Role: domain.RoleAdministrator, Permissions: []application.PermissionGrant{{Permission: domain.PermissionUsersRolesManage, Scope: domain.ScopeAll}}}},
		changed:   application.UserRecord{ID: "u-2", SubjectID: "local::y", DisplayName: "Y", Roles: []domain.Role{domain.RoleAuditor}},
	}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)

	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=5", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list users status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var users gen.UserList
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	if len(users.Data) != 1 || users.Data[0].Id != "u-1" || len(users.Data[0].Roles) != 1 {
		t.Fatalf("users = %+v, want u-1 with one role", users)
	}
	if f.lastListUsers.Limit != 5 || f.lastListUsers.Actor.ID != "admin-1" {
		t.Fatalf("delegated list users = %+v, want limit 5 actor admin-1", f.lastListUsers)
	}

	rec = do(h, httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list roles status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var roles gen.RoleList
	if err := json.Unmarshal(rec.Body.Bytes(), &roles); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	if len(roles.Data) != 1 || roles.Data[0].Role != "administrator" || len(roles.Data[0].Permissions) != 1 {
		t.Fatalf("roles = %+v, want administrator with one grant", roles)
	}
}

func TestUserAdminGrantRevokeDeactivate(t *testing.T) {
	f := &fakeI5B{
		actor:   application.Actor{Type: application.ActorTypeUser, ID: "admin-1"},
		changed: application.UserRecord{ID: "u-2", SubjectID: "local::y", DisplayName: "Y", DeactivatedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)},
	}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)

	// Grant then revoke in one PATCH.
	body := `{"grant":["auditor"],"revoke":["security_analyst"]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/u-2/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestID, "corr-77")
	rec := do(h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch roles status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if f.grantCalls != 1 || f.lastGrant.Role != domain.RoleAuditor || f.lastGrant.UserID != "u-2" || f.lastGrant.Actor.ID != "admin-1" || f.lastGrant.CorrelationID != "corr-77" {
		t.Fatalf("delegated grant = %+v (calls %d), want auditor on u-2 by admin-1", f.lastGrant, f.grantCalls)
	}
	if f.revokeCall != 1 || f.lastRevoke.Role != domain.RoleSecurityAnalyst || f.lastRevoke.UserID != "u-2" {
		t.Fatalf("delegated revoke = %+v (calls %d), want security_analyst on u-2", f.lastRevoke, f.revokeCall)
	}

	// Deactivate → 200 with the deactivated user.
	rec = do(h, httptest.NewRequest(http.MethodPost, "/api/v1/users/u-2/deactivate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var user gen.User
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatalf("decode user: %v", err)
	}
	if user.Id != "u-2" || user.DeactivatedAt == nil {
		t.Fatalf("deactivated user = %+v, want u-2 deactivated", user)
	}
	if f.lastDeactivate.UserID != "u-2" || f.lastDeactivate.Actor.ID != "admin-1" {
		t.Fatalf("delegated deactivate = %+v, want u-2 by admin-1", f.lastDeactivate)
	}
}

func TestUserAdminErrorMapping(t *testing.T) {
	// Empty grant+revoke → 400 without reaching the use case.
	f := &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "admin-1"}}
	h := newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/u-2/roles", strings.NewReader(`{"grant":[],"revoke":[]}`))
	req.Header.Set("Content-Type", "application/json")
	if rec := do(h, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty roles status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if f.grantCalls != 0 || f.revokeCall != 0 {
		t.Fatal("an empty role change reached the use case")
	}

	// Invalid role → 400.
	f = &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "admin-1"}}
	h = newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/u-2/roles", strings.NewReader(`{"grant":["nonsense"],"revoke":[]}`))
	req.Header.Set("Content-Type", "application/json")
	if rec := do(h, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid role status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}

	// Deactivate not found → 404, conflict → 409.
	f = &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "admin-1"}, deactErr: application.NotFoundError("op", errors.New("gone"))}
	h = newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/users/missing/deactivate", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("deactivate not found status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	f = &fakeI5B{actor: application.Actor{Type: application.ActorTypeUser, ID: "admin-1"}, deactErr: application.ConflictError("op", errors.New("already deactivated"))}
	h = newI5BAPI(t, f, domain.Identity{SubjectID: "local::administrator"}, true)
	if rec := do(h, httptest.NewRequest(http.MethodPost, "/api/v1/users/u-2/deactivate", nil)); rec.Code != http.StatusConflict {
		t.Fatalf("deactivate conflict status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestI5BMissingIdentityFailsClosed pins the fail-closed rule: a request with
// no authenticated identity is a 403 on every I5b operation, never a fallback
// identity, and never reaches the use case.
func TestI5BMissingIdentityFailsClosed(t *testing.T) {
	f := &fakeI5B{}
	h := newI5BAPI(t, f, domain.Identity{}, false)

	reqs := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports", strings.NewReader("x")),
		httptest.NewRequest(http.MethodGet, "/api/v1/inventory/imports/imp-1", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/users", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/users/u-2/deactivate", nil),
	}
	for _, req := range reqs {
		rec := do(h, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403 (body %s)", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	}
	if f.lastStage.File != nil || f.lastGet.ID != "" || f.lastDeactivate.UserID != "" {
		t.Fatal("an unauthenticated request reached a use case")
	}
}

// TestI5BRoutePermissionsBound proves the per-route declarations: with a
// denying checker every I5b route answers 403 before the handler runs, and
// the declaration table carries the required permission of each route.
func TestI5BRoutePermissionsBound(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(&fakeChecker{allowed: false}, logger)
	want := map[string]domain.Permission{
		"POST /api/v1/inventory/imports":             domain.PermissionInventoryManage,
		"GET /api/v1/inventory/imports/{id}":         domain.PermissionInventoryManage,
		"POST /api/v1/inventory/imports/{id}/commit": domain.PermissionInventoryManage,
		"GET /api/v1/assets":                         domain.PermissionInventoryRead,
		"GET /api/v1/assets/{id}/components":         domain.PermissionInventoryRead,
		"GET /api/v1/users":                          domain.PermissionUsersRolesManage,
		"GET /api/v1/roles":                          domain.PermissionUsersRolesManage,
		"PATCH /api/v1/users/{id}/roles":             domain.PermissionUsersRolesManage,
		"POST /api/v1/users/{id}/deactivate":         domain.PermissionUsersRolesManage,
	}
	for pattern, perm := range want {
		gate.Declare(pattern, perm)
	}

	mux := http.NewServeMux()
	RegisterAPIRoutes(gate.Decorate(mux), NewAPIHandler(&fakeSignals{}, nil, nil, logger, I5BAPI{}))
	h := NewHandlerWithAuth(mux, logger, func(next http.Handler) http.Handler { return next })

	reqs := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports", strings.NewReader("x")),
		httptest.NewRequest(http.MethodGet, "/api/v1/inventory/imports/imp-1", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/inventory/imports/imp-1/commit", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/assets/asset-1/components", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/users", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil),
		httptest.NewRequest(http.MethodPatch, "/api/v1/users/u-2/roles", strings.NewReader(`{"grant":["auditor"],"revoke":[]}`)),
		httptest.NewRequest(http.MethodPost, "/api/v1/users/u-2/deactivate", nil),
	}
	for _, req := range reqs {
		rec := do(h, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403 (the gate must deny)", req.Method, req.URL.Path, rec.Code)
		}
	}
	decls := gate.Declarations()
	for pattern, perm := range want {
		if decls[pattern] != perm {
			t.Errorf("declaration %q = %q, want %q", pattern, decls[pattern], perm)
		}
	}
}
