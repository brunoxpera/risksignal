package httpapi

import (
	"log/slog"
	"net/http"
	"time"
)

// AccessLog logs one structured record per completed request: method, path,
// status, duration and the correlation ID (concept ch. 16.1 "Strukturierte
// Logs", WP-1a.08). The record goes through the structured, redacting logger
// of internal/platform/logging, which attaches the uniform fields — service,
// version, environment and the correlation_id from the request context — and
// redacts anything that looks like a token, secret or payload. Request-
// derived values are sanitised before logging so a crafted path can never
// forge a record or break out of the log line.
func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(rec, r)
			logger.InfoContext(r.Context(), "access",
				slog.String("method", r.Method),
				slog.String("path", sanitizeLogField(r.URL.Path)),
				slog.Int("status", rec.statusCode()),
				// Rendered as a string ("311µs") so JSON and text records read
				// identically; slog.Duration would emit raw nanoseconds in JSON.
				slog.String("duration", time.Since(start).Round(time.Microsecond).String()),
			)
		})
	}
}
