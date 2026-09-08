package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// requestIDOf runs a single request through the correlation middleware and
// returns the echoed X-Request-ID response header.
func requestIDOf(t *testing.T, handler http.Handler, inbound string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if inbound != "" {
		req.Header.Set(HeaderRequestID, inbound)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Header().Get(HeaderRequestID)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the correlation ID from the context so tests can prove the
		// middleware stored what the header said.
		id, _ := RequestIDFromContext(r.Context())
		_, _ = w.Write([]byte(id))
	})
}

func TestCorrelationAdoptsValidInboundID(t *testing.T) {
	h := CorrelationID(okHandler())
	const inbound = "abc-123_DEF.456"

	got := requestIDOf(t, h, inbound)
	if got != inbound {
		t.Fatalf("X-Request-ID = %q, want the adopted inbound ID %q", got, inbound)
	}
}

func TestCorrelationGeneratesForInvalidInboundIDs(t *testing.T) {
	invalid := []string{
		"",                   // absent header is the empty string here
		"has spaces",         // whitespace is not a token character
		"newline\ninjection", // control characters must never be adopted
		"😀emoji",             // outside the token character set
		strings.Repeat("a", maxRequestIDLength+1), // too long
	}
	for _, inbound := range invalid {
		t.Run(strings.TrimPrefix(inbound, strings.Repeat("a", maxRequestIDLength+1)), func(t *testing.T) {
			h := CorrelationID(okHandler())
			got := requestIDOf(t, h, inbound)
			if got == "" {
				t.Fatal("X-Request-ID is empty, want a generated ID")
			}
			if inbound != "" && got == inbound {
				t.Fatalf("X-Request-ID = %q, want a generated ID instead of the rejected inbound value", got)
			}
			if !validRequestID(got) {
				t.Fatalf("X-Request-ID %q is not a valid correlation ID", got)
			}
		})
	}
}

func TestCorrelationGeneratedIDsDiffer(t *testing.T) {
	h := CorrelationID(okHandler())
	first := requestIDOf(t, h, "")
	second := requestIDOf(t, h, "")
	if first == second {
		t.Fatalf("two requests got the same generated ID %q", first)
	}
}

func TestCorrelationStoresIDInContext(t *testing.T) {
	var seen string
	h := CorrelationID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Error("RequestIDFromContext reports no correlation ID in the context")
		}
		seen = id
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Fatal("handler did not observe a correlation ID")
	}
	if seen != rec.Header().Get(HeaderRequestID) {
		t.Fatalf("context ID %q differs from echoed header ID %q", seen, rec.Header().Get(HeaderRequestID))
	}
}

func TestRequestIDFromContextAbsent(t *testing.T) {
	if _, ok := RequestIDFromContext(t.Context()); ok {
		t.Fatal("RequestIDFromContext on a plain context reports a present ID")
	}
}
