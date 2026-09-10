package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
)

// HeaderRequestID is the correlation header name. A request may carry its own
// ID here; the server always echoes the effective ID back in this header.
const HeaderRequestID = "X-Request-ID"

// maxRequestIDLength bounds how long an inbound correlation ID may be before
// the server refuses to adopt it. 64 bytes is generous for UUIDs and proxy
// tokens while keeping downstream storage and logs bounded.
const maxRequestIDLength = 64

// CorrelationID is the outermost chain link (concept ch. 16.1: correlation
// IDs connect an API request to its job, audit event and notification). It
// adopts a valid inbound X-Request-ID, or generates one when the header is
// absent or invalid, stores the effective ID in the request context — via
// logging.WithCorrelationID, so structured log records pick it up as their
// uniform correlation_id field (WP-1a.08) — and echoes it back in the
// response header, on every response, including errors generated deeper in
// the chain.
func CorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		r = r.WithContext(logging.WithCorrelationID(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}

// RequestIDFromContext returns the correlation ID CorrelationID stored in the
// request context. The bool is false when the request never passed through
// CorrelationID (possible only in hand-built test chains).
func RequestIDFromContext(ctx context.Context) (string, bool) {
	return logging.CorrelationIDFrom(ctx)
}

// requestID returns the effective correlation ID of the request, or "-" when
// the request did not pass through CorrelationID (only possible in hand-built
// test chains).
func requestID(r *http.Request) string {
	id, ok := RequestIDFromContext(r.Context())
	if !ok || id == "" {
		return "-"
	}
	return id
}

// validRequestID reports whether s is safe to adopt as a correlation ID:
// non-empty, at most maxRequestIDLength bytes and restricted to the token
// characters [A-Za-z0-9._-]. Anything else (whitespace, control characters,
// header smuggling attempts) is rejected in favour of a generated ID.
func validRequestID(s string) bool {
	if s == "" || len(s) > maxRequestIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// newRequestID generates a fresh correlation ID: 128 bits from crypto/rand,
// hex-encoded. The ID is unguessable and needs no external dependency.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on supported platforms; if it ever
		// did, we must not fall back to guessable IDs — fail loudly.
		panic("httpapi: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
