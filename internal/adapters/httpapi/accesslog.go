package httpapi

import (
	"net/http"
	"time"
)

// AccessLog logs one line per completed request: method, path, status,
// duration and correlation ID (concept ch. 16.1 "Strukturierte Logs"). The
// line is deliberately minimal plain text — structured JSON, uniform fields
// and redaction are WP-1a.08; this link only guarantees that every request is
// traceable from day one. Request-derived values are sanitised before
// logging.
func AccessLog(logger Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(rec, r)
			logger.Printf("access method=%s path=%s status=%d duration=%s request_id=%s",
				r.Method,
				sanitizeLogField(r.URL.Path),
				rec.statusCode(),
				time.Since(start).Round(time.Microsecond),
				requestID(r),
			)
		})
	}
}

// requestID returns the correlation ID of the request, or "-" when the
// request did not pass through CorrelationID (only possible in hand-built
// test chains).
func requestID(r *http.Request) string {
	id, ok := RequestIDFromContext(r.Context())
	if !ok || id == "" {
		return "-"
	}
	return id
}
