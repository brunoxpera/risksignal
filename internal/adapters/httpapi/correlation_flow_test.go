package httpapi

// Test of the request -> command correlation propagation (concept ch. 16.1,
// ARCH-007 §5, WP-6.08 / DEV-120): the request's effective correlation id (the
// X-Request-ID the middleware adopted or generated) is threaded into the
// command input, which carries it on to the audit row and the outbox payload
// — the same id the worker relay re-uses for the job's log scope and trace
// (see worker.TestRelayRecordsJobDispatchSpanAndCorrelation). Together they
// join request -> job -> audit on one correlation id.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

func TestRequestCorrelationIDReachesCommand(t *testing.T) {
	cmds := newFakeSignalCommands()
	h := newSignalCommandAPI(t, cmds, commandQuery(), domain.Identity{SubjectID: "local::security-analyst"}, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals/sig-1/commands",
		strings.NewReader(`{"command":"acknowledge","expected_version":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestID, "corr-req-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(HeaderRequestID); got != "corr-req-1" {
		t.Fatalf("response %s = %q, want the effective correlation id", HeaderRequestID, got)
	}
	if cmds.lastAck.CorrelationID != "corr-req-1" {
		t.Fatalf("command correlation id = %q, want the request's corr-req-1", cmds.lastAck.CorrelationID)
	}
}

// TestRequestCorrelationIDGeneratedWhenAbsent: an absent/invalid inbound id is
// replaced by a generated one that still reaches the command.
func TestRequestCorrelationIDGeneratedWhenAbsent(t *testing.T) {
	cmds := newFakeSignalCommands()
	h := newSignalCommandAPI(t, cmds, commandQuery(), domain.Identity{SubjectID: "local::security-analyst"}, true)

	rec := postSignalCommand(t, h, "sig-1", `{"command":"acknowledge","expected_version":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	effective := rec.Header().Get(HeaderRequestID)
	if effective == "" {
		t.Fatal("no effective correlation id on the response")
	}
	if cmds.lastAck.CorrelationID != effective {
		t.Fatalf("command correlation id = %q, want the effective %q", cmds.lastAck.CorrelationID, effective)
	}
}
