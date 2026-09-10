package httpapi

// Handler tests of the governed audit.reveal_identity endpoint (ARCH-005 §7,
// WP-5a.07 / DEV-094, ADR-014): POST
// /api/v1/audit-events/{id}/reveal-actor behind the WP-1a.06 middleware chain
// plus an identity-injecting authentication layer, served by an in-memory
// fake of the application reveal surface. The suite pins the wire contract —
// the RevealedActor 200 object, the RFC 9457 problem details of the declared
// 400/403/404/500 — and the delegation (the path id, the body reason and the
// resolved actor all reach the use case unchanged).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeReveal is an in-memory AuditReveal: it serves the configured actor and
// reveal outcome and records what the handler delegated.
type fakeReveal struct {
	actor     application.Actor
	actorErr  error
	result    application.RevealAuditIdentityResult
	revealErr error

	resolveCalls int
	revealCalls  int
	lastIdentity domain.Identity
	lastInput    application.RevealAuditIdentityInput
}

var _ AuditReveal = (*fakeReveal)(nil)

func (f *fakeReveal) ResolveActor(_ context.Context, id domain.Identity) (application.Actor, error) {
	f.resolveCalls++
	f.lastIdentity = id
	return f.actor, f.actorErr
}

func (f *fakeReveal) RevealAuditIdentity(_ context.Context, in application.RevealAuditIdentityInput) (application.RevealAuditIdentityResult, error) {
	f.revealCalls++
	f.lastInput = in
	return f.result, f.revealErr
}

// newAuditAPI builds the API route table with the given reveal surface and
// injects the authenticated identity, mirroring the composition root's mount
// path (RegisterAPIRoutes behind the middleware chain + auth).
func newAuditAPI(t *testing.T, reveal AuditReveal, id domain.Identity) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(&fakeSignals{}, reveal, logger))
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
	return NewHandlerWithAuth(mux, logger, auth)
}

// postReveal runs one reveal request with the given JSON body and request id.
func postReveal(t *testing.T, h http.Handler, target, body, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec
}

// TestRevealEndpointReturnsResolvedIdentity asserts the 200 wire object of a
// user reveal and that the path id, body reason and resolved actor reach the
// use case unchanged.
func TestRevealEndpointReturnsResolvedIdentity(t *testing.T) {
	identity := domain.Identity{SubjectID: "local::auditor", DisplayName: "Auditor"}
	fr := &fakeReveal{
		actor: application.Actor{Type: application.ActorTypeUser, ID: "uid-1", DisplayName: "Auditor"},
		result: application.RevealAuditIdentityResult{
			EventID:        "audit-1",
			EventActorType: application.ActorTypeUser,
			IsUser:         true,
			Label:          "Victim User",
			UserID:         "uid-victim",
			SubjectID:      "local::victim",
			DisplayName:    "Victim User",
		},
	}
	h := newAuditAPI(t, fr, identity)

	rec := postReveal(t, h, "/api/v1/audit-events/audit-1/reveal-actor", `{"reason":"subject access"}`, "reveal-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}
	var got gen.RevealedActor
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body)
	}
	if got.EventId != "audit-1" || got.ActorType != "user" || !got.IsUser || got.Label != "Victim User" {
		t.Fatalf("body = %+v, want the resolved user identity", got)
	}
	if got.UserId == nil || *got.UserId != "uid-victim" || got.SubjectId == nil || *got.SubjectId != "local::victim" {
		t.Fatalf("body = %+v, want user_id/subject_id populated", got)
	}
	if fr.resolveCalls != 1 || fr.revealCalls != 1 {
		t.Fatalf("delegation calls resolve=%d reveal=%d, want 1 each", fr.resolveCalls, fr.revealCalls)
	}
	if fr.lastIdentity.SubjectID != "local::auditor" {
		t.Fatalf("resolved identity = %+v, want the request identity", fr.lastIdentity)
	}
	if fr.lastInput.EventID != "audit-1" || fr.lastInput.Reason != "subject access" || fr.lastInput.Actor.ID != "uid-1" {
		t.Fatalf("reveal input = %+v, want the path id, body reason and resolved actor", fr.lastInput)
	}
}

// TestRevealEndpointSystemActorLabel asserts a non-user actor answers the
// label with the identity fields null.
func TestRevealEndpointSystemActorLabel(t *testing.T) {
	fr := &fakeReveal{
		actor:  application.Actor{Type: application.ActorTypeUser, ID: "uid-1"},
		result: application.RevealAuditIdentityResult{EventID: "audit-sys", EventActorType: application.ActorTypeSystem, IsUser: false, Label: "sla.evaluate"},
	}
	h := newAuditAPI(t, fr, domain.Identity{SubjectID: "local::auditor"})

	rec := postReveal(t, h, "/api/v1/audit-events/audit-sys/reveal-actor", `{"reason":"check"}`, "reveal-sys")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}
	var got gen.RevealedActor
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.IsUser || got.Label != "sla.evaluate" || got.UserId != nil || got.SubjectId != nil {
		t.Fatalf("body = %+v, want the system label with null identity", got)
	}
}

// TestRevealEndpointErrorMapping asserts the declared error responses map the
// application error classes and keep the RFC 9457 problem detail.
func TestRevealEndpointErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantTitle  string
	}{
		{"forbidden", application.Forbiddenf("reveal_audit_identity", "principal is not permitted"), http.StatusForbidden, titleForbidden},
		{"blank-reason", application.Validationf("reveal_audit_identity", "a reason is mandatory"), http.StatusBadRequest, titleInvalidRequest},
		{"not-found", application.NotFoundError("reveal_audit_identity", context.Canceled), http.StatusNotFound, titleAuditEventNotFound},
		{"infra", application.InfraError("reveal_audit_identity", context.Canceled), http.StatusInternalServerError, titleInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeReveal{
				actor:     application.Actor{Type: application.ActorTypeUser, ID: "uid-1"},
				revealErr: tc.err,
			}
			h := newAuditAPI(t, fr, domain.Identity{SubjectID: "local::auditor"})
			rec := postReveal(t, h, "/api/v1/audit-events/audit-1/reveal-actor", `{"reason":"x"}`, "reveal-err")
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Title != tc.wantTitle || p.Status != tc.wantStatus || p.CorrelationId != "reveal-err" {
				t.Fatalf("problem = %+v, want title %q status %d correlation reveal-err", p, tc.wantTitle, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusInternalServerError && p.Detail != nil {
				t.Fatalf("internal error leaked a detail: %q", *p.Detail)
			}
		})
	}
}

// TestRevealEndpointResolveActorForbidden asserts an unknown authenticated
// subject (a resolve failure) answers the declared 403 without reaching the
// reveal use case.
func TestRevealEndpointResolveActorForbidden(t *testing.T) {
	fr := &fakeReveal{actorErr: application.Forbiddenf("resolve_actor", "unknown subject")}
	h := newAuditAPI(t, fr, domain.Identity{SubjectID: "local::ghost"})

	rec := postReveal(t, h, "/api/v1/audit-events/audit-1/reveal-actor", `{"reason":"x"}`, "reveal-res")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body)
	}
	if fr.revealCalls != 0 {
		t.Fatalf("reveal use case called %d times, want 0 (resolution denied)", fr.revealCalls)
	}
}

// TestRevealEndpointMissingIdentityForbidden asserts a request without an
// authenticated identity fails closed as the declared 403.
func TestRevealEndpointMissingIdentityForbidden(t *testing.T) {
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(&fakeSignals{}, &fakeReveal{}, logger))
	h := NewHandler(mux, logger) // no identity middleware

	rec := postReveal(t, h, "/api/v1/audit-events/audit-1/reveal-actor", `{"reason":"x"}`, "reveal-anon")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body)
	}
}
