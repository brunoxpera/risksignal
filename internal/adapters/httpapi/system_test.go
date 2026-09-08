package httpapi

// Unit tests of the WP-1a.07 System endpoints (concept ch. 10.2, 16.3):
// liveness always answers 200, readiness answers 200 only when every probe
// passes and 503 with a distinct reason per failing check, and the version
// endpoint reports the injected build metadata. The probes are fakes here —
// the real database and migration probes are wired at the composition root
// (cmd/risksignal-server) and covered there.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/platform/buildinfo"
)

func doGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestLiveAlwaysOK asserts the liveness contract: the process answers 200
// no matter what, because liveness has no dependencies (external sources are
// deliberately not a criterion, concept ch. 16.3).
func TestLiveAlwaysOK(t *testing.T) {
	rec := doGet(t, LiveHandler(), "/health/live")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status field = %q, want %q", body.Status, "ok")
	}
}

// TestReadyAllGreen asserts that readiness answers 200 with every check
// reported "ok" when all probes pass.
func TestReadyAllGreen(t *testing.T) {
	passing := func(name string) Probe {
		return Probe{Name: name, Check: func(ctx context.Context) error { return nil }}
	}
	h := ReadyHandler([]Probe{passing("database"), passing("migrations"), passing("config")})

	rec := doGet(t, h, "/health/ready")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var body readyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status field = %q, want %q", body.Status, "ready")
	}
	for _, name := range []string{"database", "migrations", "config"} {
		if got := body.Checks[name]; got != checkOK {
			t.Errorf("checks[%s] = %q, want %q", name, got, checkOK)
		}
	}
	if len(body.Checks) != 3 {
		t.Errorf("checks has %d entries, want 3 (%v)", len(body.Checks), body.Checks)
	}
}

// TestReady503WithDistinctReasons asserts the not-ready contract: 503 with
// the reason of every failing check under its stable name, and the passing
// checks still reported "ok" — an operator can tell a dead database apart
// from pending migrations apart from an invalid configuration.
func TestReady503WithDistinctReasons(t *testing.T) {
	h := ReadyHandler([]Probe{
		{Name: "database", Check: func(ctx context.Context) error {
			return errors.New("unreachable: connection refused")
		}},
		{Name: "migrations", Check: func(ctx context.Context) error {
			return errors.New("1 pending migration(s)")
		}},
		{Name: "config", Check: func(ctx context.Context) error { return nil }},
	})

	rec := doGet(t, h, "/health/ready")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body readyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "not_ready" {
		t.Errorf("status field = %q, want %q", body.Status, "not_ready")
	}
	if got := body.Checks["database"]; got != "unreachable: connection refused" {
		t.Errorf("checks[database] = %q, want the database reason", got)
	}
	if got := body.Checks["migrations"]; got != "1 pending migration(s)" {
		t.Errorf("checks[migrations] = %q, want the migrations reason", got)
	}
	if got := body.Checks["config"]; got != checkOK {
		t.Errorf("checks[config] = %q, want %q", got, checkOK)
	}
	if len(body.Checks) != 3 {
		t.Errorf("checks has %d entries, want 3 (%v)", len(body.Checks), body.Checks)
	}
}

// TestReadyIgnoresAnonymousProbes asserts that a probe without a name or
// without a check cannot fail readiness and does not appear in the report.
func TestReadyIgnoresAnonymousProbes(t *testing.T) {
	h := ReadyHandler([]Probe{
		{Name: "", Check: func(ctx context.Context) error { return errors.New("nameless failure") }},
		{Name: "config", Check: nil},
	})
	rec := doGet(t, h, "/health/ready")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var body readyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Checks) != 0 {
		t.Errorf("checks = %v, want empty", body.Checks)
	}
}

// TestReadyBoundedByTimeout asserts that a probe which never returns cannot
// hang readiness: the handler gives each probe probeTimeout and reports the
// deadline as the failure reason.
func TestReadyBoundedByTimeout(t *testing.T) {
	oldTimeout := probeTimeout
	probeTimeout = 50 * time.Millisecond
	defer func() { probeTimeout = oldTimeout }()

	h := ReadyHandler([]Probe{
		{Name: "database", Check: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}},
	})
	rec := doGet(t, h, "/health/ready")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body readyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got := body.Checks["database"]; !strings.Contains(got, "deadline exceeded") {
		t.Errorf("checks[database] = %q, want a deadline-exceeded reason", got)
	}
}

// TestVersionReportsBuildInfo asserts that GET /version echoes the injected
// build metadata verbatim — the commit, version and build time that the
// Makefile build target bakes into the binary via -ldflags.
func TestVersionReportsBuildInfo(t *testing.T) {
	info := buildinfo.Info{Version: "1.2.3", Commit: "deadbeef", BuildTime: "2026-09-08T12:00:00Z"}
	h := VersionHandler(info)

	rec := doGet(t, h, "/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got buildinfo.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got != info {
		t.Errorf("body = %+v, want %+v", got, info)
	}
}

// TestVersionDefaultsWhenUnset asserts the development fallback: a binary
// built without ldflags reports version "dev" (buildinfo default), which is
// exactly what /version shows on plain go build/go run binaries.
func TestVersionDefaultsWhenUnset(t *testing.T) {
	info := buildinfo.Current() // test binaries are built without ldflags
	rec := doGet(t, VersionHandler(info), "/version")
	var got buildinfo.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Version != "dev" {
		t.Errorf("version = %q, want the buildinfo default %q", got.Version, "dev")
	}
	if got.Commit == "" || got.BuildTime == "" {
		t.Errorf("unset metadata must be non-empty, got %+v", got)
	}
}
