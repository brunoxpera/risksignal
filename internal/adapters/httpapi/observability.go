package httpapi

// The I6 observability surfaces of the HTTP adapter (concept ch. 16.2/16.3,
// ARCH-007 §5, WP-6.08 / DEV-120): the Prometheus /metrics handler, the
// request metrics middleware and the request trace middleware.
//
// The /metrics exposition is never part of the public API surface: the
// composition root serves it on a dedicated internal listener
// (observability.metrics_addr, never public), not on the mux behind the API
// middleware chain. The metrics and trace middlewares join the WP-1a.06 chain
// via WithMiddleware, just after the correlation middleware, so a request's
// metrics and its span carry the effective correlation id.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

// metricsShutdownGrace bounds the metrics listener shutdown on ctx cancel.
const metricsShutdownGrace = 5 * time.Second

// MetricsHandler serves the Prometheus text exposition of reg (concept
// ch. 16.2). It answers 200 with Content-Type text/plain (version 0.0.4) and
// the snapshot rendered by Registry.Prometheus.
func MetricsHandler(reg *metrics.Registry) http.Handler {
	if reg == nil {
		panic("httpapi: MetricsHandler: registry must not be nil")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := reg.Prometheus()
		w.Header().Set("Content-Type", metrics.ContentType())
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
}

// ServeMetrics runs the internal /metrics listener on addr until ctx is
// cancelled, then shuts it down within a grace period. It returns nil after a
// graceful shutdown and an error for a bind or serve failure. The listener
// must bind an internal-only address (config.Validate enforces loopback in
// local and a non-wildcard host outside) — the exposition is never public.
func ServeMetrics(ctx context.Context, addr string, reg *metrics.Registry, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", MetricsHandler(reg))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics: listen on %s: %w", addr, err)
	}
	if logger != nil {
		logger.Info("metrics listening", slog.String("addr", ln.Addr().String()))
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics: serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownGrace)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	}
}

// MetricsMiddleware records the §16.2 HTTP families (concept ch. 16.2) for
// every request that passes it: http_requests_total (method, path),
// http_request_duration_seconds (method, path — a summary), the
// http_responses_by_status_total counter (method, status) and the
// http_inflight gauge. Paths are the raw request paths; a private deployment
// scrapes a bounded route set.
func MetricsMiddleware(reg *metrics.Registry) Middleware {
	if reg == nil {
		panic("httpapi: MetricsMiddleware: registry must not be nil")
	}
	requests := reg.Counter(metrics.NameHTTPRequestsTotal, metrics.HelpHTTPRequestsTotal)
	durations := reg.Seconds(metrics.NameHTTPRequestDuration, metrics.HelpHTTPRequestDuration)
	responses := reg.Counter(metrics.NameHTTPResponsesByStatus, metrics.HelpHTTPResponsesByStatus)
	inflight := reg.Gauge(metrics.NameHTTPInflight, metrics.HelpHTTPInflight)

	var inflightCount int64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if path == "" {
				path = "/"
			}
			method := r.Method
			requests.With(metrics.Labels{"method": method, "path": path}).Inc()
			inflight.Set(float64(atomic.AddInt64(&inflightCount, 1)))

			rec := &statusRecorder{ResponseWriter: w}
			started := time.Now()
			next.ServeHTTP(rec, r)

			inflight.Set(float64(atomic.AddInt64(&inflightCount, -1)))
			durations.With(metrics.Labels{"method": method, "path": path}).Observe(time.Since(started).Seconds())
			responses.With(metrics.Labels{"method": method, "status": strconv.Itoa(rec.statusCode())}).Inc()
		})
	}
}

// TraceMiddleware opens the HTTP request span (ARCH-007 §5, WP-6.08). The
// trace id is the correlation id (via the tracer's correlation-id-as-trace-id
// mapping), an inbound valid W3C traceparent when one is propagated, or a
// fresh random id; the span's traceparent is echoed in the response header.
// With no exporter wired the span is recorded in-process only.
func TraceMiddleware(tr *tracing.Tracer) Middleware {
	if tr == nil {
		panic("httpapi: TraceMiddleware: tracer must not be nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if traceID, ok := tracing.ParseTraceparent(r.Header.Get(tracing.TraceparentHeader)); ok {
				ctx = tracing.WithTraceID(ctx, traceID)
			}
			ctx, span := tr.Start(ctx, "http.request")
			// Echo the trace context so a downstream proxy/caller can join the
			// trace (W3C trace context, response propagation).
			w.Header().Set("Traceparent", tracing.Traceparent(span))
			span.SetAttr("http.method", r.Method)
			span.SetAttr("http.path", sanitizeLogField(r.URL.Path))

			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r.WithContext(ctx))

			span.SetStatus(rec.statusCode())
			span.End()
		})
	}
}
