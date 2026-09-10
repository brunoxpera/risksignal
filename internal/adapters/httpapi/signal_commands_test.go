package httpapi

// Handler tests of the I5a reference triage endpoint (ARCH-005 §8, WP-5a.08):
// POST /api/v1/signals/{signal_id}/commands behind the WP-1a.06 middleware
// chain plus an identity-injecting authentication layer, served by an
// in-memory fake of the application command surface. The suite pins the wire
// contract — the SignalCommandResult 200 object, the RFC 9457 problem details
// of the declared 400/403/404/409/500 — and the delegation (the path id, the
// command fields and the resolved actor all reach the use case unchanged).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeSignalCommands is an in-memory SignalCommands: it serves the configured
// actor and command outcome and records what the handler delegated.
type fakeSignalCommands struct {
	actor    application.Actor
	actorErr error
	signal   domain.RiskSignal
	ackErr   error
	ovrErr   error

	lastIdentity domain.Identity
	lastAck      application.AcknowledgeSignalInput
	lastOverride application.OverridePriorityInput
	ackCalls     int
	ovrCalls     int
}

var _ SignalCommands = (*fakeSignalCommands)(nil)

func (f *fakeSignalCommands) ResolveActor(_ context.Context, id domain.Identity) (application.Actor, error) {
	f.lastIdentity = id
	return f.actor, f.actorErr
}

func (f *fakeSignalCommands) AcknowledgeSignal(_ context.Context, in application.AcknowledgeSignalInput) (domain.RiskSignal, error) {
	f.ackCalls++
	f.lastAck = in
	return f.signal, f.ackErr
}

func (f *fakeSignalCommands) OverridePriority(_ context.Context, in application.OverridePriorityInput) (domain.RiskSignal, error) {
	f.ovrCalls++
	f.lastOverride = in
	return f.signal, f.ovrErr
}

// newSignalCommandAPI builds the API route table with the given command
// surface and injects the authenticated identity (mirrors the composition
// root's mount path).
func newSignalCommandAPI(t *testing.T, cmds SignalCommands, id domain.Identity, withIdentity bool) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(&fakeSignals{}, nil, cmds, logger))
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if withIdentity {
				r = r.WithContext(WithIdentity(r.Context(), id))
			}
			next.ServeHTTP(w, r)
		})
	}
	return NewHandlerWithAuth(mux, logger, auth)
}

// postSignalCommand runs one command request with the given JSON body.
func postSignalCommand(t *testing.T, h http.Handler, signalID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals/"+signalID+"/commands", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSignalCommandAcknowledgeDelegation(t *testing.T) {
	cmds := &fakeSignalCommands{
		actor:  application.Actor{Type: application.ActorTypeUser, ID: "u-1", DisplayName: "Analyst"},
		signal: domain.RiskSignal{ID: "sig-1", Status: domain.SignalStatusInReview, Priority: domain.PriorityP1, Version: 2},
	}
	id := domain.Identity{SubjectID: "local::security-analyst"}
	h := newSignalCommandAPI(t, cmds, id, true)

	rec := postSignalCommand(t, h, "sig-1", `{"command":"acknowledge","expected_version":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got gen.SignalCommandResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got.Id != "sig-1" || got.Command != "acknowledge" || got.Status != gen.InReview || got.Priority != gen.P1 || got.Version != 2 {
		t.Fatalf("result = %+v, want the acknowledge outcome", got)
	}
	// Delegation: the identity resolved, the path id and the version reached
	// the use case, the actor is the resolved user actor.
	if cmds.lastIdentity != id {
		t.Fatalf("resolved identity = %+v, want %+v", cmds.lastIdentity, id)
	}
	if cmds.ackCalls != 1 || cmds.lastAck.SignalID != "sig-1" || cmds.lastAck.ExpectedVersion != 1 || cmds.lastAck.Actor.ID != "u-1" {
		t.Fatalf("delegated ack = %+v (calls %d), want signal sig-1 v1 actor u-1", cmds.lastAck, cmds.ackCalls)
	}
}

func TestSignalCommandOverrideDelegation(t *testing.T) {
	cmds := &fakeSignalCommands{
		actor:  application.Actor{Type: application.ActorTypeUser, ID: "u-1"},
		signal: domain.RiskSignal{ID: "sig-1", Status: domain.SignalStatusNew, Priority: domain.PriorityP3, Version: 2},
	}
	h := newSignalCommandAPI(t, cmds, domain.Identity{SubjectID: "local::security-analyst"}, true)

	rec := postSignalCommand(t, h, "sig-1", `{"command":"override_priority","expected_version":1,"priority":"P3","reason":"decommissioned"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if cmds.ovrCalls != 1 || cmds.lastOverride.Priority != domain.PriorityP3 || cmds.lastOverride.Reason != "decommissioned" {
		t.Fatalf("delegated override = %+v, want P3/decommissioned", cmds.lastOverride)
	}
}

func TestSignalCommandErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		body string
		err  error
		want int
	}{
		{"validation", `{"command":"acknowledge","expected_version":0}`, application.Validationf("op", "bad"), http.StatusBadRequest},
		{"forbidden", `{"command":"acknowledge","expected_version":1}`, application.Forbiddenf("op", "denied"), http.StatusForbidden},
		{"not found", `{"command":"acknowledge","expected_version":1}`, application.NotFoundError("op", errors.New("gone")), http.StatusNotFound},
		{"conflict", `{"command":"acknowledge","expected_version":1}`, application.ConflictError("op", errors.New("stale")), http.StatusConflict},
		{"internal", `{"command":"acknowledge","expected_version":1}`, application.InfraError("op", errors.New("boom")), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := &fakeSignalCommands{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}, ackErr: tc.err}
			h := newSignalCommandAPI(t, cmds, domain.Identity{SubjectID: "local::security-analyst"}, true)
			rec := postSignalCommand(t, h, "sig-1", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			var p gen.ProblemDetails
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if p.Status != tc.want || p.CorrelationId == "" {
				t.Fatalf("problem = %+v, want status %d and a correlation id", p, tc.want)
			}
		})
	}
}

func TestSignalCommandRejectsUnknownCommandAndMissingIdentity(t *testing.T) {
	cmds := &fakeSignalCommands{actor: application.Actor{Type: application.ActorTypeUser, ID: "u-1"}}

	// Unknown command: 400, no delegation.
	h := newSignalCommandAPI(t, cmds, domain.Identity{SubjectID: "local::security-analyst"}, true)
	if rec := postSignalCommand(t, h, "sig-1", `{"command":"nonsense","expected_version":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown command status = %d, want 400", rec.Code)
	}
	if cmds.ackCalls != 0 || cmds.ovrCalls != 0 {
		t.Fatalf("unknown command delegated a use case (ack %d, override %d)", cmds.ackCalls, cmds.ovrCalls)
	}

	// Missing identity: 403 (fail closed, no fallback identity).
	noID := newSignalCommandAPI(t, cmds, domain.Identity{}, false)
	if rec := postSignalCommand(t, noID, "sig-1", `{"command":"acknowledge","expected_version":1}`); rec.Code != http.StatusForbidden {
		t.Fatalf("missing identity status = %d, want 403", rec.Code)
	}
}
