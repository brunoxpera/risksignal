package main

// Composition-root tests of the I6 observability wiring (ARCH-007 §5,
// WP-6.08 / DEV-120): the /metrics exposition is never part of the public
// handler (it is served on its own internal listener), a public request
// records the HTTP families on the shared registry, and the registry renders
// the §16.2 family set.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

func TestMetricsEndpointNotOnPublicHandler(t *testing.T) {
	cfg := testConfig("postgres://u:p@127.0.0.1:1/db")
	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	h, err := newHandler(cfg, pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics on the public handler = %d, want 404 (the exposition is internal-only)", rec.Code)
	}
}

func TestPublicRequestRecordsHTTPFamilies(t *testing.T) {
	cfg := testConfig("postgres://u:p@127.0.0.1:1/db")
	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	reg := observabilityRegistry()
	h, err := newHandler(cfg, pool, discardLogger(),
		httpapi.WithMiddleware(httpapi.TraceMiddleware(tracing.New(nil))),
		httpapi.WithMiddleware(httpapi.MetricsMiddleware(reg)))
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health/live = %d, want 200", rec.Code)
	}

	out := reg.Prometheus()
	for _, want := range []string{
		`http_requests_total{method="GET",path="/health/live"} 1`,
		`http_responses_by_status_total{method="GET",status="200"} 1`,
		"# TYPE source_run_duration_seconds summary",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics exposition lacks %q:\n%s", want, out)
		}
	}
	// The trace header is echoed on the response (W3C propagation).
	if rec.Header().Get("Traceparent") == "" {
		t.Error("no traceparent response header on a traced request")
	}
}
