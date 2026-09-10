package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
)

// testLogger returns a structured local-mode logger writing to an in-memory
// buffer, so tests can assert on the access log and panic log records. Local
// mode renders text records — one line per record — which keeps the
// substring assertions below readable.
func testLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logging.New(logging.Options{
		Service:     "risksignal-server-test",
		Version:     "test",
		Environment: "local",
		Writer:      &buf,
	}), &buf
}

func TestChainAppliesOutermostFirst(t *testing.T) {
	var order []string
	tag := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	h := Chain(tag("first"), tag("second"), tag("third"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"first", "second", "third", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("execution order = %v, want %v", order, want)
	}
}

// TestSecurityHeadersPresent runs a request through the full WP-1a.06 chain
// and asserts the hardening headers of concept ch. 12.3 are on the response.
func TestSecurityHeadersPresent(t *testing.T) {
	logger, _ := testLogger(t)
	h := NewHandler(okHandler(), logger)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	for name, want := range headers {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

// TestNoCORSHeaderByDefault asserts that CORS stays off: even a cross-origin
// request gets no Access-Control-Allow-* header (concept ch. 12.3).
func TestNoCORSHeaderByDefault(t *testing.T) {
	logger, _ := testLogger(t)
	h := NewHandler(okHandler(), logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("header %s = %q, want it absent (CORS disabled by default)", name, got)
		}
	}
}

// TestRecoverPanicNeutral500 drives a panicking handler through the full
// chain: the client sees a neutral 500 carrying the correlation ID and
// nothing else — the panic value and stack live only in the log (concept
// ch. 5.2).
func TestRecoverPanicNeutral500(t *testing.T) {
	logger, buf := testLogger(t)
	h := NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom: secret internals")
	}), logger)

	const inbound = "panic-test-1"
	req := httptest.NewRequest(http.MethodGet, "/explode", nil)
	req.Header.Set(HeaderRequestID, inbound)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := rec.Header().Get(HeaderRequestID); got != inbound {
		t.Fatalf("X-Request-ID = %q, want the inbound %q echoed", got, inbound)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "internal server error") {
		t.Errorf("body %q is not a neutral error message", body)
	}
	if !strings.Contains(body, inbound) {
		t.Errorf("body %q does not carry the correlation ID %q", body, inbound)
	}
	for _, leaked := range []string{"boom", "goroutine", "runtime/", "recover.go", "secret internals"} {
		if strings.Contains(body, leaked) {
			t.Errorf("body %q leaks %q to the client", body, leaked)
		}
	}

	logged := buf.String()
	for _, want := range []string{
		"msg=panic", "level=ERROR",
		"correlation_id=" + inbound,
		`panic_value="boom: secret internals"`, "goroutine ",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log does not contain %q; log:\n%s", want, logged)
		}
	}
	if !strings.Contains(logged, "status=500") {
		t.Errorf("access log does not record the 500; log:\n%s", logged)
	}
}

// TestRecoverPanicReraisesAfterResponseStarted covers the case where the
// handler panics after the status is already on the wire: the middleware must
// not fake a 500 the client would never receive, but re-raise so net/http
// aborts the connection.
func TestRecoverPanicReraisesAfterResponseStarted(t *testing.T) {
	logger, _ := testLogger(t)
	h := NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		panic("late boom")
	}), logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/late", nil)

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		h.ServeHTTP(rec, req)
	}()
	if recovered == nil {
		t.Fatal("panic was swallowed after the response started, want it re-raised")
	}
	if recovered != "late boom" {
		t.Fatalf("re-raised value = %v, want the original panic value", recovered)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the already-written 200", rec.Code)
	}
}

// TestAccessLogOneLinePerRequest asserts one structured record per request
// with method, path, status, duration and correlation ID — including 404s
// from the as-yet empty ServeMux.
func TestAccessLogOneLinePerRequest(t *testing.T) {
	logger, buf := testLogger(t)
	mux := http.NewServeMux() // no routes yet: everything 404s
	h := NewHandler(mux, logger)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.Header.Set(HeaderRequestID, "access-test-7")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from the empty mux", rec.Code)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log has %d lines, want exactly 1 per request:\n%s", len(lines), buf.String())
	}
	line := lines[0]
	for _, want := range []string{
		"msg=access", "method=GET", "path=/some/path", "status=404", "duration=",
		"correlation_id=access-test-7", "service=risksignal-server-test",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("access log line %q does not contain %q", line, want)
		}
	}
}

// TestAccessLogSanitisesPath proves control characters in a decoded path
// cannot forge a second log line (concept ch. 12.3: log injection).
func TestAccessLogSanitisesPath(t *testing.T) {
	logger, buf := testLogger(t)
	h := NewHandler(okHandler(), logger)

	// %0A decodes to a newline in r.URL.Path.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a%0Ab", nil))

	line := strings.TrimSpace(buf.String())
	if strings.Contains(line, "\n") {
		t.Fatalf("log line contains a raw newline (injection); line: %q", line)
	}
	if !strings.Contains(line, "path=/a?b") {
		t.Errorf("log line %q does not contain the sanitised path /a?b", line)
	}
}

// TestLimitBodyRejectsDeclaredOversize drives a Content-Length beyond the
// limit through the full chain: the middleware answers 413 before the handler
// runs, with correlation ID and security headers intact.
func TestLimitBodyRejectsDeclaredOversize(t *testing.T) {
	logger, buf := testLogger(t)
	handlerCalled := false
	h := NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}), logger)

	const inbound = "body-limit-1"
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, MaxBodyBytes+1)))
	req.Header.Set(HeaderRequestID, inbound)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if handlerCalled {
		t.Error("handler ran although the declared body exceeds the limit")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if got := rec.Header().Get(HeaderRequestID); got != inbound {
		t.Errorf("X-Request-ID = %q, want %q on the 413", got, inbound)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("security headers missing on the 413 (X-Content-Type-Options = %q)", got)
	}
	if !strings.Contains(buf.String(), "status=413") {
		t.Errorf("access log does not record the 413; log:\n%s", buf.String())
	}
}

// TestLimitBodyCutsOffUndeclaredBody covers bodies whose size is not declared
// up front (chunked, ContentLength -1): MaxBytesReader caps the read, and the
// handler maps the MaxBytesError to 413 via IsBodyTooLarge.
func TestLimitBodyCutsOffUndeclaredBody(t *testing.T) {
	const limit = 1024
	var read int64
	h := Chain(LimitBody(limit))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		read = n
		if IsBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			http.Error(w, "body read error", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	tooBig := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 10*limit)))
	tooBig.ContentLength = -1 // client did not declare a length (chunked)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tooBig)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for an undeclared oversized body", rec.Code)
	}
	if read != limit {
		t.Fatalf("handler read %d bytes, want the reader to stop at the limit %d", read, limit)
	}
}

// TestLimitBodyAcceptsBodyUpToLimit is the boundary counterpart: a body of
// exactly the limit passes.
func TestLimitBodyAcceptsBodyUpToLimit(t *testing.T) {
	const limit = 1024
	h := Chain(LimitBody(limit))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unexpected read error: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "read %d bytes", n)
	}))

	exact := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, limit)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, exact)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a body of exactly the limit", rec.Code)
	}
	if got := rec.Body.String(); got != fmt.Sprintf("read %d bytes", limit) {
		t.Fatalf("body = %q, want the handler to have read all %d bytes", got, limit)
	}
}
