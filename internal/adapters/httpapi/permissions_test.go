package httpapi

import (
	"context"
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

	rec := do(mux, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
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

	rec := do(mux, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
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

	if rec := do(decorated, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := gate.Declarations()["GET /api/v1/signals"]; got != domain.PermissionSignalsRead {
		t.Errorf("declaration = %q, want %q", got, domain.PermissionSignalsRead)
	}
}
