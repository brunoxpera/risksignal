package httpapi

// Tests of the I6 observability surfaces (concept ch. 16.2/16.3, ARCH-007 §5,
// WP-6.08 / DEV-120): the Prometheus /metrics handler renders the §16.2
// families, the metrics middleware records the HTTP families for a served
// request, and the trace middleware echoes a W3C traceparent whose trace id is
// the correlation id.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

func TestMetricsHandlerRendersFamilies(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	reg.Counter(metrics.NameHTTPRequestsTotal, metrics.HelpHTTPRequestsTotal).With(metrics.Labels{"method": "GET", "path": "/health/live"}).Add(2)

	rec := do(MetricsHandler(reg), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q, want the Prometheus text exposition", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE http_requests_total counter",
		"# TYPE source_run_duration_seconds summary",
		"# TYPE jobs_dead_letters_total counter",
		"# TYPE signals_unassigned gauge",
		"# TYPE database_size_bytes gauge",
		"# TYPE notifications_failures_total counter",
		`http_requests_total{method="GET",path="/health/live"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body lacks %q:\n%s", want, body)
		}
	}
}

func TestMetricsMiddlewareRecordsRequestFamilies(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	handler := Chain(CorrelationID, MetricsMiddleware(reg))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	do(handler, httptest.NewRequest(http.MethodPost, "/api/v1/exports", nil))

	samples := reg.Snapshot()
	if !hasSample(samples, metrics.NameHTTPRequestsTotal, "path", "/api/v1/exports") {
		t.Fatalf("http_requests_total not recorded: %+v", samples)
	}
	if !hasSample(samples, metrics.NameHTTPResponsesByStatus, "status", "201") {
		t.Fatalf("http_responses_by_status_total not recorded: %+v", samples)
	}
	if !hasSample(samples, metrics.NameHTTPRequestDuration, "path", "/api/v1/exports") {
		t.Fatalf("http_request_duration_seconds not recorded: %+v", samples)
	}
}

func TestTraceMiddlewareEchoesCorrelationTraceID(t *testing.T) {
	const correlationID = "0123456789abcdef0123456789abcdef" // canonical: used verbatim as the trace id
	handler := Chain(CorrelationID, TraceMiddleware(tracing.New(nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.Header.Set(HeaderRequestID, correlationID)
	rec := do(handler, req)

	tp := rec.Header().Get("Traceparent")
	if tp == "" {
		t.Fatal("no traceparent response header")
	}
	traceID, ok := tracing.ParseTraceparent(tp)
	if !ok {
		t.Fatalf("traceparent %q is not well-formed", tp)
	}
	if want := tracing.TraceIDForCorrelation(correlationID); traceID != want {
		t.Fatalf("trace id = %q, want the correlation-derived %q", traceID, want)
	}
}

// TestTraceMiddlewareAdoptsInboundTraceparent: a valid inbound traceparent is
// propagated (its trace id becomes the request span's trace id).
func TestTraceMiddlewareAdoptsInboundTraceparent(t *testing.T) {
	inbound := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	handler := Chain(CorrelationID, TraceMiddleware(tracing.New(nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Header.Set(tracing.TraceparentHeader, inbound)
	rec := do(handler, req)

	traceID, ok := tracing.ParseTraceparent(rec.Header().Get("Traceparent"))
	if !ok || traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("inbound trace not propagated: %q -> %q (%v)", inbound, rec.Header().Get("Traceparent"), ok)
	}
}

// hasSample reports whether a metric name has a series carrying label=value.
func hasSample(samples []metrics.Sample, name, label, value string) bool {
	for _, s := range samples {
		if s.Name == name && s.Labels[label] == value {
			return true
		}
	}
	return false
}
