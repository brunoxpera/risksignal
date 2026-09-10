package httpapi

// Handler tests of the I5b signal command endpoint (ARCH-006 §1, WP-5b.04):
// POST /api/v1/signals/{signal_id}/commands behind the WP-1a.06 middleware
// chain plus an identity-injecting authentication layer, served by an
// in-memory fake of the application command surface. The suite pins the
// dispatch of all eight commands (each arm maps the request onto its
// application.*Input and resolves the actor once), the per-command
// required-field validation (a malformed command is a 400 before any use
// case), the wire contract (the SignalCommandResult 200 object with its
// nullable owner_id/target/auto_priority detail fields, the RFC 9457 problem
// details of the declared 400/403/404/409/500) and the error-class mapping.

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
// actor, per-command outcome and records what the handler delegated. A single
// err is returned by every command, so the error-class mapping is exercised
// uniformly; the calls map counts per-command delegations.
type fakeSignalCommands struct {
	actor    application.Actor
	actorErr error

	signal  domain.RiskSignal
	comment domain.Comment
	clock   domain.SlaClock
	err     error

	lastIdentity   domain.Identity
	lastAck        application.AcknowledgeSignalInput
	lastTransition application.TransitionSignalInput
	lastAssign     application.AssignOwnerInput
	lastComment    application.AddCommentInput
	lastOverride   application.OverridePriorityInput
	lastRevert     application.RevertPriorityInput
	lastPause      application.PauseSlaInput
	lastResume     application.ResumeSlaInput

	calls map[string]int
}

var _ SignalCommands = (*fakeSignalCommands)(nil)

func newFakeSignalCommands() *fakeSignalCommands {
	return &fakeSignalCommands{
		actor:   application.Actor{Type: application.ActorTypeUser, ID: "u-1", DisplayName: "Analyst"},
		signal:  domain.RiskSignal{ID: "sig-1", Status: domain.SignalStatusInReview, Priority: domain.PriorityP1, Version: 2},
		comment: domain.Comment{ID: "c-1", SignalID: "sig-1", ActorID: "u-1", Body: "note"},
		clock:   domain.SlaClock{ID: "clk-1", SignalID: "sig-1", Target: domain.SLATargetNotification},
		calls:   map[string]int{},
	}
}

func (f *fakeSignalCommands) totalCalls() int {
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

func (f *fakeSignalCommands) ResolveActor(_ context.Context, id domain.Identity) (application.Actor, error) {
	f.lastIdentity = id
	return f.actor, f.actorErr
}

func (f *fakeSignalCommands) AcknowledgeSignal(_ context.Context, in application.AcknowledgeSignalInput) (domain.RiskSignal, error) {
	f.calls["acknowledge"]++
	f.lastAck = in
	return f.signal, f.err
}

func (f *fakeSignalCommands) TransitionSignal(_ context.Context, in application.TransitionSignalInput) (domain.RiskSignal, error) {
	f.calls["change_status"]++
	f.lastTransition = in
	return f.signal, f.err
}

func (f *fakeSignalCommands) AssignOwner(_ context.Context, in application.AssignOwnerInput) (domain.RiskSignal, error) {
	f.calls["assign_owner"]++
	f.lastAssign = in
	return f.signal, f.err
}

func (f *fakeSignalCommands) AddComment(_ context.Context, in application.AddCommentInput) (domain.Comment, error) {
	f.calls["add_comment"]++
	f.lastComment = in
	return f.comment, f.err
}

func (f *fakeSignalCommands) OverridePriority(_ context.Context, in application.OverridePriorityInput) (domain.RiskSignal, error) {
	f.calls["override_priority"]++
	f.lastOverride = in
	return f.signal, f.err
}

func (f *fakeSignalCommands) RevertPriority(_ context.Context, in application.RevertPriorityInput) (domain.RiskSignal, error) {
	f.calls["revert_priority"]++
	f.lastRevert = in
	return f.signal, f.err
}

func (f *fakeSignalCommands) PauseSla(_ context.Context, in application.PauseSlaInput) (domain.SlaClock, error) {
	f.calls["pause_sla"]++
	f.lastPause = in
	return f.clock, f.err
}

func (f *fakeSignalCommands) ResumeSla(_ context.Context, in application.ResumeSlaInput) (domain.SlaClock, error) {
	f.calls["resume_sla"]++
	f.lastResume = in
	return f.clock, f.err
}

// newSignalCommandAPI builds the API route table with the given command
// surface and read seam, and injects the authenticated identity (mirrors the
// composition root's mount path).
func newSignalCommandAPI(t *testing.T, cmds SignalCommands, query SignalsQuery, id domain.Identity, withIdentity bool) http.Handler {
	t.Helper()
	logger, _ := testLogger(t)
	mux := http.NewServeMux()
	RegisterAPIRoutes(mux, NewAPIHandler(query, nil, cmds, logger))
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

// commandQuery is the read seam the handler uses to render the post-command
// state of the non-signal commands; it carries a distinct version so the test
// proves the read-back is used.
func commandQuery() *fakeSignals {
	return &fakeSignals{signal: application.Signal{
		ID:       "sig-1",
		Status:   domain.SignalStatusInReview,
		Priority: domain.PriorityP1,
		Version:  5,
	}}
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

// TestSignalCommandDispatch exercises the happy path of every command: the
// wire result carries the post-command state and the command-specific detail
// field, the path id / command fields / resolved actor reach the matching
// application.*Input, and only that arm runs.
func TestSignalCommandDispatch(t *testing.T) {
	const sigID = "sig-1"
	analyst := domain.Identity{SubjectID: "local::security-analyst"}

	t.Run("acknowledge", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		query := commandQuery()
		h := newSignalCommandAPI(t, cmds, query, analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"acknowledge","expected_version":1}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "acknowledge", gen.InReview, gen.P1, 2)
		assertNilDetails(t, result)
		if cmds.lastIdentity != analyst {
			t.Fatalf("resolved identity = %+v, want %+v", cmds.lastIdentity, analyst)
		}
		if cmds.lastAck.SignalID != sigID || cmds.lastAck.ExpectedVersion != 1 || cmds.lastAck.Actor.ID != "u-1" {
			t.Fatalf("delegated ack = %+v, want sig-1 v1 actor u-1", cmds.lastAck)
		}
		if query.getCalls != 0 {
			t.Errorf("acknowledge read the signal (%d), want no read-back", query.getCalls)
		}
		if cmds.calls["acknowledge"] != 1 || cmds.totalCalls() != 1 {
			t.Fatalf("calls = %v, want exactly acknowledge", cmds.calls)
		}
	})

	t.Run("change_status", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.signal = domain.RiskSignal{ID: sigID, Status: domain.SignalStatusActionPlanned, Priority: domain.PriorityP1, Version: 3}
		h := newSignalCommandAPI(t, cmds, commandQuery(), analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"change_status","expected_version":1,"status":"action_planned","reason":"assessment done"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "change_status", gen.ActionPlanned, gen.P1, 3)
		assertNilDetails(t, result)
		if cmds.lastTransition.SignalID != sigID || cmds.lastTransition.To != domain.SignalStatusActionPlanned ||
			cmds.lastTransition.Reason != "assessment done" || cmds.lastTransition.ExpectedVersion != 1 ||
			cmds.lastTransition.Actor.ID != "u-1" {
			t.Fatalf("delegated transition = %+v, want action_planned/reason/v1", cmds.lastTransition)
		}
	})

	t.Run("assign_owner", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.signal = domain.RiskSignal{ID: sigID, Status: domain.SignalStatusInReview, Priority: domain.PriorityP1, Version: 2, Owner: "u-7"}
		h := newSignalCommandAPI(t, cmds, commandQuery(), analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"assign_owner","expected_version":1,"owner_id":"u-7"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "assign_owner", gen.InReview, gen.P1, 2)
		if result.OwnerId == nil || *result.OwnerId != "u-7" {
			t.Fatalf("owner_id = %v, want u-7", result.OwnerId)
		}
		if result.Target != nil || result.AutoPriority != nil {
			t.Fatalf("target/auto_priority = %v/%v, want null", result.Target, result.AutoPriority)
		}
		if cmds.lastAssign.Owner != "u-7" || cmds.lastAssign.ExpectedVersion != 1 || cmds.lastAssign.Actor.ID != "u-1" {
			t.Fatalf("delegated assign = %+v, want owner u-7 v1", cmds.lastAssign)
		}
	})

	t.Run("assign_owner clears to null", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.signal = domain.RiskSignal{ID: sigID, Status: domain.SignalStatusInReview, Priority: domain.PriorityP1, Version: 2}
		h := newSignalCommandAPI(t, cmds, commandQuery(), analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"assign_owner","expected_version":1,"owner_id":""}`)
		result := assertCommandOK(t, rec)
		if result.OwnerId != nil {
			t.Fatalf("owner_id = %v, want null for a cleared assignment", *result.OwnerId)
		}
		if cmds.lastAssign.Owner != "" {
			t.Fatalf("delegated assign owner = %q, want the empty string (clear)", cmds.lastAssign.Owner)
		}
	})

	t.Run("add_comment", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		query := commandQuery()
		h := newSignalCommandAPI(t, cmds, query, analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"add_comment","comment":"please check"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "add_comment", gen.InReview, gen.P1, 5)
		assertNilDetails(t, result)
		if cmds.lastComment.SignalID != sigID || cmds.lastComment.Body != "please check" || cmds.lastComment.Actor.ID != "u-1" {
			t.Fatalf("delegated comment = %+v, want body/actor", cmds.lastComment)
		}
		if query.getCalls != 1 {
			t.Fatalf("read-back calls = %d, want 1 (comment renders the signal state)", query.getCalls)
		}
	})

	t.Run("override_priority", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		auto := domain.PriorityP2
		cmds.signal = domain.RiskSignal{ID: sigID, Status: domain.SignalStatusInReview, Priority: domain.PriorityP3, Version: 4, AutoPriority: &auto}
		h := newSignalCommandAPI(t, cmds, commandQuery(), analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"override_priority","expected_version":1,"priority":"P3","reason":"decommissioned"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "override_priority", gen.InReview, gen.P3, 4)
		if result.AutoPriority == nil || *result.AutoPriority != gen.P2 {
			t.Fatalf("auto_priority = %v, want P2 (the preserved computed value)", result.AutoPriority)
		}
		if result.OwnerId != nil || result.Target != nil {
			t.Fatalf("owner/target = %v/%v, want null", result.OwnerId, result.Target)
		}
		if cmds.lastOverride.Priority != domain.PriorityP3 || cmds.lastOverride.Reason != "decommissioned" ||
			cmds.lastOverride.ExpectedVersion != 1 || cmds.lastOverride.Actor.ID != "u-1" {
			t.Fatalf("delegated override = %+v, want P3/decommissioned/v1", cmds.lastOverride)
		}
	})

	t.Run("revert_priority", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.signal = domain.RiskSignal{ID: sigID, Status: domain.SignalStatusInReview, Priority: domain.PriorityP2, Version: 5}
		h := newSignalCommandAPI(t, cmds, commandQuery(), analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"revert_priority","expected_version":1}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "revert_priority", gen.InReview, gen.P2, 5)
		if result.AutoPriority != nil {
			t.Fatalf("auto_priority = %v, want null after a revert", *result.AutoPriority)
		}
		if cmds.lastRevert.SignalID != sigID || cmds.lastRevert.ExpectedVersion != 1 || cmds.lastRevert.Actor.ID != "u-1" {
			t.Fatalf("delegated revert = %+v, want v1", cmds.lastRevert)
		}
	})

	t.Run("pause_sla", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.clock = domain.SlaClock{ID: "clk-1", SignalID: sigID, Target: domain.SLATargetNotification}
		query := commandQuery()
		h := newSignalCommandAPI(t, cmds, query, analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"pause_sla","target":"notification","reason":"hold"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "pause_sla", gen.InReview, gen.P1, 5)
		if result.Target == nil || *result.Target != gen.Notification {
			t.Fatalf("target = %v, want notification", result.Target)
		}
		if result.OwnerId != nil || result.AutoPriority != nil {
			t.Fatalf("owner/auto = %v/%v, want null", result.OwnerId, result.AutoPriority)
		}
		if cmds.lastPause.SignalID != sigID || cmds.lastPause.Target != domain.SLATargetNotification ||
			cmds.lastPause.Reason != "hold" || cmds.lastPause.Actor.ID != "u-1" {
			t.Fatalf("delegated pause = %+v, want notification/hold", cmds.lastPause)
		}
		if query.getCalls != 1 {
			t.Fatalf("read-back calls = %d, want 1", query.getCalls)
		}
	})

	t.Run("resume_sla", func(t *testing.T) {
		cmds := newFakeSignalCommands()
		cmds.clock = domain.SlaClock{ID: "clk-2", SignalID: sigID, Target: domain.SLATargetAcknowledgement}
		query := commandQuery()
		h := newSignalCommandAPI(t, cmds, query, analyst, true)

		rec := postSignalCommand(t, h, sigID, `{"command":"resume_sla","target":"acknowledgement","reason":"resume"}`)
		result := assertCommandOK(t, rec)
		assertResult(t, result, sigID, "resume_sla", gen.InReview, gen.P1, 5)
		if result.Target == nil || *result.Target != gen.Acknowledgement {
			t.Fatalf("target = %v, want acknowledgement", result.Target)
		}
		if cmds.lastResume.SignalID != sigID || cmds.lastResume.Target != domain.SLATargetAcknowledgement || cmds.lastResume.Reason != "resume" {
			t.Fatalf("delegated resume = %+v, want acknowledgement/resume", cmds.lastResume)
		}
	})
}

// TestSignalCommandMalformed pins the per-command required fields: a body
// missing a required field (or carrying expected_version where it is not
// allowed, or an unknown command) is a 400 before any use case runs and
// before the actor is resolved.
func TestSignalCommandMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"acknowledge without expected_version", `{"command":"acknowledge"}`},
		{"change_status without expected_version", `{"command":"change_status","status":"action_planned"}`},
		{"change_status without status", `{"command":"change_status","expected_version":1}`},
		{"assign_owner without owner_id", `{"command":"assign_owner","expected_version":1}`},
		{"add_comment without comment", `{"command":"add_comment"}`},
		{"add_comment with expected_version", `{"command":"add_comment","comment":"x","expected_version":1}`},
		{"override_priority without priority", `{"command":"override_priority","expected_version":1,"reason":"r"}`},
		{"override_priority without reason", `{"command":"override_priority","expected_version":1,"priority":"P3"}`},
		{"revert_priority without expected_version", `{"command":"revert_priority"}`},
		{"pause_sla without target", `{"command":"pause_sla","reason":"r"}`},
		{"pause_sla without reason", `{"command":"pause_sla","target":"notification"}`},
		{"pause_sla with expected_version", `{"command":"pause_sla","target":"notification","reason":"r","expected_version":1}`},
		{"resume_sla without target", `{"command":"resume_sla","reason":"r"}`},
		{"resume_sla without reason", `{"command":"resume_sla","target":"notification"}`},
		{"resume_sla with expected_version", `{"command":"resume_sla","target":"notification","reason":"r","expected_version":1}`},
		{"unknown command", `{"command":"nonsense"}`},
		{"missing command", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := newFakeSignalCommands()
			query := commandQuery()
			h := newSignalCommandAPI(t, cmds, query, domain.Identity{SubjectID: "local::security-analyst"}, true)

			rec := postSignalCommand(t, h, "sig-1", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			var p gen.ProblemDetails
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if p.Status != http.StatusBadRequest || p.CorrelationId == "" {
				t.Fatalf("problem = %+v, want status 400 and a correlation id", p)
			}
			if cmds.totalCalls() != 0 {
				t.Fatalf("malformed command delegated a use case: %v", cmds.calls)
			}
			if cmds.lastIdentity != (domain.Identity{}) {
				t.Fatalf("malformed command resolved an actor: %+v", cmds.lastIdentity)
			}
			if query.getCalls != 0 {
				t.Fatalf("malformed command read the signal: %d", query.getCalls)
			}
		})
	}
}

// validCommandBodies is one well-formed body per command, used by the
// error-class mapping suite.
var validCommandBodies = map[string]string{
	"acknowledge":       `{"command":"acknowledge","expected_version":1}`,
	"change_status":     `{"command":"change_status","expected_version":1,"status":"action_planned"}`,
	"assign_owner":      `{"command":"assign_owner","expected_version":1,"owner_id":"u-7"}`,
	"add_comment":       `{"command":"add_comment","comment":"note"}`,
	"override_priority": `{"command":"override_priority","expected_version":1,"priority":"P3","reason":"reason"}`,
	"revert_priority":   `{"command":"revert_priority","expected_version":1}`,
	"pause_sla":         `{"command":"pause_sla","target":"notification","reason":"reason"}`,
	"resume_sla":        `{"command":"resume_sla","target":"notification","reason":"reason"}`,
}

var commandOrder = []string{
	"acknowledge", "change_status", "assign_owner", "add_comment",
	"override_priority", "revert_priority", "pause_sla", "resume_sla",
}

// TestSignalCommandErrorClasses maps every use-case error class onto its
// declared response for every command (validation→400, forbidden→403,
// not-found→404, conflict→409, else→500).
func TestSignalCommandErrorClasses(t *testing.T) {
	classes := []struct {
		name string
		err  error
		want int
	}{
		{"validation", application.Validationf("op", "bad"), http.StatusBadRequest},
		{"forbidden", application.Forbiddenf("op", "denied"), http.StatusForbidden},
		{"not found", application.NotFoundError("op", errors.New("gone")), http.StatusNotFound},
		{"conflict", application.ConflictError("op", errors.New("stale")), http.StatusConflict},
		{"internal", application.InfraError("op", errors.New("boom")), http.StatusInternalServerError},
	}
	for _, command := range commandOrder {
		command := command
		body := validCommandBodies[command]
		t.Run(command, func(t *testing.T) {
			for _, tc := range classes {
				t.Run(tc.name, func(t *testing.T) {
					cmds := newFakeSignalCommands()
					cmds.err = tc.err
					h := newSignalCommandAPI(t, cmds, commandQuery(), domain.Identity{SubjectID: "local::security-analyst"}, true)

					rec := postSignalCommand(t, h, "sig-1", body)
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
					if tc.want == http.StatusInternalServerError && p.Detail != nil {
						t.Fatalf("internal error leaked a detail: %q", *p.Detail)
					}
				})
			}
		})
	}
}

// TestSignalCommandRejectsUnknownCommandAndMissingIdentity pins the two
// edge behaviours the dispatch keeps: an unknown command is a 400 without a
// delegation, and a missing identity fails closed as a 403.
func TestSignalCommandRejectsUnknownCommandAndMissingIdentity(t *testing.T) {
	cmds := newFakeSignalCommands()
	query := commandQuery()

	h := newSignalCommandAPI(t, cmds, query, domain.Identity{SubjectID: "local::security-analyst"}, true)
	if rec := postSignalCommand(t, h, "sig-1", `{"command":"nonsense","expected_version":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown command status = %d, want 400", rec.Code)
	}
	if cmds.totalCalls() != 0 {
		t.Fatalf("unknown command delegated a use case: %v", cmds.calls)
	}

	noID := newSignalCommandAPI(t, cmds, query, domain.Identity{}, false)
	if rec := postSignalCommand(t, noID, "sig-1", `{"command":"acknowledge","expected_version":1}`); rec.Code != http.StatusForbidden {
		t.Fatalf("missing identity status = %d, want 403", rec.Code)
	}
}

// assertCommandOK decodes a 200 response into the generated result type.
func assertCommandOK(t *testing.T, rec *httptest.ResponseRecorder) gen.SignalCommandResult {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var result gen.SignalCommandResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result
}

// assertResult asserts the base fields every command's result carries.
func assertResult(t *testing.T, result gen.SignalCommandResult, id, command string, status gen.SignalStatus, priority gen.Priority, version int) {
	t.Helper()
	if result.Id != id || result.Command != command || result.Status != status || result.Priority != priority || result.Version != version {
		t.Fatalf("result = %+v, want (%s, %s, %s, %s, v%d)", result, id, command, status, priority, version)
	}
}

// assertNilDetails asserts the three nullable detail fields are null.
func assertNilDetails(t *testing.T, result gen.SignalCommandResult) {
	t.Helper()
	if result.OwnerId != nil || result.Target != nil || result.AutoPriority != nil {
		t.Fatalf("detail fields = (%v, %v, %v), want all null", result.OwnerId, result.Target, result.AutoPriority)
	}
}
