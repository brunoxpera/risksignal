package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeChecker is a PermissionChecker with a fixed verdict that records the
// permissions it was asked about.
type fakeChecker struct {
	allowed bool
	got     []domain.Permission
}

func (c *fakeChecker) HasPermission(_ context.Context, perm domain.Permission) bool {
	c.got = append(c.got, perm)
	return c.allowed
}

// fakePrincipalResolver is a PrincipalResolver with a fixed principal (or
// error) that records the identity it was asked to resolve.
type fakePrincipalResolver struct {
	principal domain.Principal
	err       error
	gotID     domain.Identity
	calls     int
}

func (f *fakePrincipalResolver) RoutePrincipal(_ context.Context, id domain.Identity) (domain.Principal, error) {
	f.calls++
	f.gotID = id
	return f.principal, f.err
}

// testIdentity is the authenticated identity the gate/checker tests place in
// the request context (the auth middleware does this in the live chain).
var testIdentity = domain.Identity{SubjectID: "local::analyst", DisplayName: "Analyst"}

// authed returns req with testIdentity in its context.
func authed(req *http.Request) *http.Request {
	return req.WithContext(WithIdentity(req.Context(), testIdentity))
}

func TestPermissionGateDeniesWith403(t *testing.T) {
	logger, _ := testLogger(t)
	checker := &fakeChecker{allowed: false}
	gate := NewPermissionGate(checker, logger)

	called := false
	mux := http.NewServeMux()
	gate.Mount(mux, "GET /api/v1/signals", domain.PermissionSignalsRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := do(mux, authed(httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if called {
		t.Error("the handler ran despite the denied permission")
	}
	if p := decodeProblem(t, rec); p.Status != http.StatusForbidden || p.Title != titleForbidden {
		t.Errorf("problem = %+v, want 403 %q", p, titleForbidden)
	}
	if len(checker.got) != 1 || checker.got[0] != domain.PermissionSignalsRead {
		t.Errorf("checker saw %v, want [%s]", checker.got, domain.PermissionSignalsRead)
	}
}

func TestPermissionGateAllowsWithPermission(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(&fakeChecker{allowed: true}, logger)

	called := false
	mux := http.NewServeMux()
	gate.Mount(mux, "GET /api/v1/signals", domain.PermissionSignalsRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := do(mux, authed(httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if !called {
		t.Error("the handler did not run despite the granted permission")
	}
}

// TestPermissionGateUnauthenticatedIs401: a protected route reached without an
// authenticated identity is unauthenticated — the gate answers 401, not 403
// (the live auth middleware answers this before the gate; this is the gate's
// own defensive contract).
func TestPermissionGateUnauthenticatedIs401(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAdministrator}}},
		logger), logger)

	called := false
	mux := http.NewServeMux()
	gate.Mount(mux, "GET /api/v1/signals", domain.PermissionSignalsRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := do(mux, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if called {
		t.Error("the handler ran on an unauthenticated request")
	}
	if p := decodeProblem(t, rec); p.Status != http.StatusUnauthorized || p.Title != titleUnauthorized {
		t.Errorf("problem = %+v, want 401 %q", p, titleUnauthorized)
	}
}

// TestPermissionGateForbiddenRoleIs403: an authenticated principal whose roles
// do not grant the declared permission is forbidden by the real checker at the
// route check, before the handler runs.
func TestPermissionGateForbiddenRoleIs403(t *testing.T) {
	logger, _ := testLogger(t)
	// The Auditor holds signals.read but not signals.triage (ARCH-005 §12.2).
	gate := NewPermissionGate(NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAuditor}}},
		logger), logger)

	called := false
	mux := http.NewServeMux()
	gate.Mount(mux, "POST /api/v1/signals/{signal_id}/commands", domain.PermissionSignalsTriage, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := do(mux, authed(httptest.NewRequest(http.MethodPost, "/api/v1/signals/sig-1/commands", nil)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if called {
		t.Error("the handler ran despite the missing permission")
	}
}

// TestPermissionGateGrantedRolePassesThrough: an authenticated principal whose
// roles grant the declared permission reaches the use case (the gate of
// record).
func TestPermissionGateGrantedRolePassesThrough(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAuditor}}},
		logger), logger)

	called := false
	mux := http.NewServeMux()
	gate.Mount(mux, "GET /api/v1/signals", domain.PermissionSignalsRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := do(mux, authed(httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if !called {
		t.Error("the handler did not run despite the granted permission")
	}
}

// TestPermissionGatePublicRouteNeverBlocked: an empty declaration is a public
// route the gate never consults, even with a denying checker.
func TestPermissionGatePublicRouteNeverBlocked(t *testing.T) {
	logger, _ := testLogger(t)
	checker := &fakeChecker{allowed: false}
	gate := NewPermissionGate(checker, logger)

	mux := http.NewServeMux()
	gate.Mount(mux, "GET /version", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := do(mux, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(checker.got) != 0 {
		t.Errorf("the gate consulted the checker for a public route: %v", checker.got)
	}
}

// TestPermissionGateNilCheckerDefers proves the defense-in-depth semantics:
// with no checker wired the declaration binds but the decision stays with the
// use case (WP-5a.06).
func TestPermissionGateNilCheckerDefers(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(nil, logger)

	mux := http.NewServeMux()
	gate.Mount(mux, "GET /api/v1/signals", domain.PermissionSignalsRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if rec := do(mux, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil checker defers to the use case)", rec.Code)
	}
	if perm := gate.Declarations()["GET /api/v1/signals"]; perm != domain.PermissionSignalsRead {
		t.Errorf("declaration = %q, want %q (the declaration must still bind)", perm, domain.PermissionSignalsRead)
	}
}

// TestPermissionGateBindsGeneratedRoute covers the generated-registration path
// (Decorate): a route mounted through the decorator is gated by its declared
// permission.
func TestPermissionGateBindsGeneratedRoute(t *testing.T) {
	logger, _ := testLogger(t)
	gate := NewPermissionGate(&fakeChecker{allowed: false}, logger)
	gate.Declare("GET /api/v1/signals", domain.PermissionSignalsRead)

	real := http.NewServeMux()
	decorated := gate.Decorate(real)
	decorated.HandleFunc("GET /api/v1/signals", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if rec := do(decorated, authed(httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := gate.Declarations()["GET /api/v1/signals"]; got != domain.PermissionSignalsRead {
		t.Errorf("declaration = %q, want %q", got, domain.PermissionSignalsRead)
	}
}

// --- IdentityPermissionChecker (the production checker) --------------------

// checkerCtx returns a context carrying the test identity.
func checkerCtx() context.Context {
	return WithIdentity(context.Background(), testIdentity)
}

func TestIdentityPermissionCheckerAllowsGrantedRole(t *testing.T) {
	logger, _ := testLogger(t)
	c := NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAdministrator}}},
		logger)
	if !c.HasPermission(checkerCtx(), domain.PermissionUsersRolesManage) {
		t.Fatal("administrator should hold users.roles.manage at the route check")
	}
}

func TestIdentityPermissionCheckerDeniesForbiddenRole(t *testing.T) {
	logger, _ := testLogger(t)
	// The Auditor holds signals.read but not signals.triage (ARCH-005 §12.2).
	c := NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAuditor}}},
		logger)
	if c.HasPermission(checkerCtx(), domain.PermissionSignalsTriage) {
		t.Fatal("auditor must not hold signals.triage at the route check")
	}
}

// TestIdentityPermissionCheckerAllowsObjectScopedGrant pins the locked design
// decision: the route check is scope-agnostic — an object-scoped grant (the
// Systemverantwortliche's assigned signals.read) passes here, because object
// scope is decided by the use case (the gate of record).
func TestIdentityPermissionCheckerAllowsObjectScopedGrant(t *testing.T) {
	logger, _ := testLogger(t)
	c := NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleSystemResponsible}}},
		logger)
	if !c.HasPermission(checkerCtx(), domain.PermissionSignalsRead) {
		t.Fatal("an assigned-scope signals.read grant must pass the coarse route check")
	}
}

func TestIdentityPermissionCheckerNoIdentityDenies(t *testing.T) {
	logger, _ := testLogger(t)
	c := NewIdentityPermissionChecker(
		&fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAdministrator}}},
		logger)
	if c.HasPermission(context.Background(), domain.PermissionSignalsRead) {
		t.Fatal("a request without an identity must deny")
	}
}

func TestIdentityPermissionCheckerResolverErrorDenies(t *testing.T) {
	logger, _ := testLogger(t)
	c := NewIdentityPermissionChecker(
		&fakePrincipalResolver{err: errors.New("unknown subject")},
		logger)
	if c.HasPermission(checkerCtx(), domain.PermissionSignalsRead) {
		t.Fatal("an unresolvable principal must deny (fail closed)")
	}
}

func TestIdentityPermissionCheckerResolvesTheContextIdentity(t *testing.T) {
	logger, _ := testLogger(t)
	fr := &fakePrincipalResolver{principal: domain.Principal{InternalID: "u-1", Roles: []domain.Role{domain.RoleAuditor}}}
	c := NewIdentityPermissionChecker(fr, logger)
	c.HasPermission(checkerCtx(), domain.PermissionSignalsRead)
	if fr.calls != 1 || fr.gotID != testIdentity {
		t.Fatalf("resolver saw identity %+v (calls %d), want %+v once", fr.gotID, fr.calls, testIdentity)
	}
}

// TestIdentityPermissionCheckerConstructionGuards asserts the constructor
// refuses a nil seam or logger (a startup-time misconfiguration).
func TestIdentityPermissionCheckerConstructionGuards(t *testing.T) {
	logger, _ := testLogger(t)
	t.Run("nil resolver", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("nil resolver did not panic")
			}
		}()
		NewIdentityPermissionChecker(nil, logger)
	})
	t.Run("nil logger", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("nil logger did not panic")
			}
		}()
		NewIdentityPermissionChecker(&fakePrincipalResolver{}, nil)
	})
}
