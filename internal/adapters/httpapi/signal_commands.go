// HTTP boundary of the I5b signal command endpoint (ARCH-006 §1, WP-5b.04):
// the generated operation POST /api/v1/signals/{signal_id}/commands carrying
// the full eight-command vocabulary — acknowledge, change_status,
// assign_owner, add_comment, override_priority, revert_priority, pause_sla
// and resume_sla — of which acknowledge and override_priority were the I5a
// reference pair (ARCH-005 §8).
//
// The handler is a thin dispatcher (ARCH-006 §1.3): it resolves the
// authenticated identity placed in the request context by the I5a
// authentication middleware into an audit actor, enforces the per-command
// required fields the OpenAPI if/then declares declaratively (so a malformed
// command is a 400 at the binding layer — the document alone is not
// enforced), maps the generated request onto the matching application.*Input
// and delegates to the use case — the gate of record, which authorises
// signals.triage / signals.override and stamps the actor — then maps the
// outcome onto the generated response types. It decides no rights and no
// business rules; the finer signals.override gate stays inside the use case.
//
// Every command that ends on a domain.RiskSignal renders it directly. The
// three commands whose use case returns a non-signal aggregate — add_comment
// (domain.Comment), pause_sla/resume_sla (domain.SlaClock) — read the
// signal's post-command state back through the read seam, because the wire
// result (gen.SignalCommandResult) always carries status/priority/version;
// the read is signals.read and never changes state. Secrets and identities
// are never logged.

package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// SignalCommands is the application surface the command handler delegates to:
// the identity → actor resolution the authenticated adapters share, plus the
// eight I5b triage/SLA commands of *application.Service (each authorises
// internally via resolvePrincipal+authorize, ARCH-005 §5). Depending on this
// narrow interface (not the whole service) keeps the handler testable with an
// in-memory fake; the signatures mirror the use cases so the composition root
// passes the real service unchanged.
type SignalCommands interface {
	// ResolveActor maps the authenticated request identity onto the audit
	// actor of the command (users.id for a user principal).
	ResolveActor(ctx context.Context, id domain.Identity) (application.Actor, error)
	// AcknowledgeSignal moves a new signal to in_review (signals.triage).
	AcknowledgeSignal(ctx context.Context, in application.AcknowledgeSignalInput) (domain.RiskSignal, error)
	// TransitionSignal moves a signal along the status matrix (signals.triage).
	TransitionSignal(ctx context.Context, in application.TransitionSignalInput) (domain.RiskSignal, error)
	// AssignOwner sets or clears a signal's owner (signals.triage).
	AssignOwner(ctx context.Context, in application.AssignOwnerInput) (domain.RiskSignal, error)
	// AddComment appends one comment to a signal's timeline (signals.triage).
	AddComment(ctx context.Context, in application.AddCommentInput) (domain.Comment, error)
	// OverridePriority replaces a signal's effective priority (signals.override).
	OverridePriority(ctx context.Context, in application.OverridePriorityInput) (domain.RiskSignal, error)
	// RevertPriority restores a signal's computed priority (signals.override).
	RevertPriority(ctx context.Context, in application.RevertPriorityInput) (domain.RiskSignal, error)
	// PauseSla pauses one SLA clock of a signal (signals.triage).
	PauseSla(ctx context.Context, in application.PauseSlaInput) (domain.SlaClock, error)
	// ResumeSla resumes one paused SLA clock of a signal (signals.triage).
	ResumeSla(ctx context.Context, in application.ResumeSlaInput) (domain.SlaClock, error)
}

// signalCommandHandler implements the signalCommand operation of the generated
// strict interface. commands is the application command surface (nil leaves
// the operation answering a 500 — a composition root that does not serve it);
// query is the read seam used to render the post-command state of the
// commands whose use case returns a non-signal aggregate; logger receives
// unexpected internal errors (the client only ever sees the generic 500
// problem detail, concept ch. 5.2).
type signalCommandHandler struct {
	commands SignalCommands
	query    SignalsQuery
	logger   *slog.Logger
}

// signalCommandState is the post-command signal state the wire result
// renders (gen.SignalCommandResult always carries id/status/priority/version).
type signalCommandState struct {
	id       string
	status   domain.SignalStatus
	priority domain.Priority
	version  int
}

// SignalCommand implements the I5b command operation (ARCH-006 §1): it reads
// the authenticated identity from the request context, resolves it to the
// audit actor, enforces the per-command required fields, dispatches to the
// matching use case and answers the typed 200 object. A denial is the typed
// 403; a validation mistake the typed 400; an unknown signal the typed 404; a
// stale version / illegal transition the typed 409; anything else is logged
// and answered as the generic 500 without the cause.
func (h signalCommandHandler) SignalCommand(ctx context.Context, request gen.SignalCommandRequestObject) (gen.SignalCommandResponseObject, error) {
	if h.commands == nil {
		h.logger.ErrorContext(ctx, "signal command handler is not wired")
		return gen.SignalCommand500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	if request.Body == nil {
		return gen.SignalCommand400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, "a command body is required")), nil
	}
	// The authentication middleware places the identity in the context; a
	// missing one is an unauthenticated request (fail closed, no fallback
	// identity). It cannot occur behind the middleware chain — the 403 keeps
	// the declared response set.
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return gen.SignalCommand403JSONResponse(problemFromContext(ctx, http.StatusForbidden, titleForbidden, "authentication required")), nil
	}
	// Per-command required fields (the OpenAPI if/then is declarative only):
	// a malformed command never reaches a use case.
	if detail := validateSignalCommandBody(request.Body); detail != "" {
		return gen.SignalCommand400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, detail)), nil
	}
	actor, err := h.commands.ResolveActor(ctx, identity)
	if err != nil {
		return h.signalCommandError(ctx, err)
	}

	// expected_version is present exactly on the five version-guarded
	// commands (validation guarantees it), and absent on add_comment/
	// pause_sla/resume_sla — where it reaches no use case input (those
	// inputs carry no version field).
	expectedVersion := 0
	if request.Body.ExpectedVersion != nil {
		expectedVersion = *request.Body.ExpectedVersion
	}

	var (
		state  signalCommandState
		owner  *string
		target *domain.SLATarget
		auto   *domain.Priority
	)
	switch request.Body.Command {
	case gen.Acknowledge:
		sig, err := h.commands.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID:        request.SignalId,
			ExpectedVersion: expectedVersion,
			Actor:           actor,
			CorrelationID:   correlationIDFromContext(ctx),
		})
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		state = stateFromSignal(sig)

	case gen.ChangeStatus:
		sig, err := h.commands.TransitionSignal(ctx, application.TransitionSignalInput{
			SignalID:        request.SignalId,
			To:              optStatus(request.Body.Status),
			Reason:          optString(request.Body.Reason),
			ExpectedVersion: expectedVersion,
			Actor:           actor,
			CorrelationID:   correlationIDFromContext(ctx),
		})
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		state = stateFromSignal(sig)

	case gen.AssignOwner:
		sig, err := h.commands.AssignOwner(ctx, application.AssignOwnerInput{
			SignalID:        request.SignalId,
			Owner:           optString(request.Body.OwnerId),
			ExpectedVersion: expectedVersion,
			Actor:           actor,
			CorrelationID:   correlationIDFromContext(ctx),
		})
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		state = stateFromSignal(sig)
		owner = optionalString(sig.Owner)

	case gen.AddComment:
		if _, err := h.commands.AddComment(ctx, application.AddCommentInput{
			SignalID:      request.SignalId,
			Body:          optString(request.Body.Comment),
			Actor:         actor,
			CorrelationID: correlationIDFromContext(ctx),
		}); err != nil {
			return h.signalCommandError(ctx, err)
		}
		if state, err = h.postCommandState(ctx, request.SignalId, actor); err != nil {
			return h.signalCommandError(ctx, err)
		}

	case gen.OverridePriority:
		sig, err := h.commands.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID:        request.SignalId,
			Priority:        optPriority(request.Body.Priority),
			Reason:          optString(request.Body.Reason),
			ExpectedVersion: expectedVersion,
			Actor:           actor,
			CorrelationID:   correlationIDFromContext(ctx),
		})
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		state = stateFromSignal(sig)
		auto = sig.AutoPriority

	case gen.RevertPriority:
		sig, err := h.commands.RevertPriority(ctx, application.RevertPriorityInput{
			SignalID:        request.SignalId,
			ExpectedVersion: expectedVersion,
			Actor:           actor,
			CorrelationID:   correlationIDFromContext(ctx),
		})
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		state = stateFromSignal(sig)
		auto = sig.AutoPriority // nil after a revert: the override is cleared

	case gen.PauseSla, gen.ResumeSla:
		targetValue := optTarget(request.Body.Target)
		var (
			clock domain.SlaClock
			err   error
		)
		if request.Body.Command == gen.PauseSla {
			clock, err = h.commands.PauseSla(ctx, application.PauseSlaInput{
				SignalID:      request.SignalId,
				Target:        targetValue,
				Reason:        optString(request.Body.Reason),
				Actor:         actor,
				CorrelationID: correlationIDFromContext(ctx),
			})
		} else {
			clock, err = h.commands.ResumeSla(ctx, application.ResumeSlaInput{
				SignalID:      request.SignalId,
				Target:        targetValue,
				Reason:        optString(request.Body.Reason),
				Actor:         actor,
				CorrelationID: correlationIDFromContext(ctx),
			})
		}
		if err != nil {
			return h.signalCommandError(ctx, err)
		}
		if state, err = h.postCommandState(ctx, request.SignalId, actor); err != nil {
			return h.signalCommandError(ctx, err)
		}
		target = &clock.Target

	default:
		// Unreachable behind validateSignalCommandBody; kept so a future
		// command missing an arm fails closed as a 400, not a 500.
		return gen.SignalCommand400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
			"unknown command "+string(request.Body.Command))), nil
	}
	return gen.SignalCommand200JSONResponse(
		toGenSignalCommandResult(string(request.Body.Command), state, owner, target, auto)), nil
}

// validateSignalCommandBody enforces the per-command required fields the
// OpenAPI if/then declares declaratively (ARCH-006 §1.2): the version-guarded
// commands require expected_version, the append-only comment and the
// clock-state-guarded SLA pause/resume must not carry it, and every command
// requires its own fields. It returns the problem-detail text of the first
// violation, or "" when the body is well-formed. It checks presence only —
// enum membership and non-blank residual rules (e.g. a blank override reason,
// an off-matrix transition) stay in the use case/domain, the gate of record.
func validateSignalCommandBody(body *gen.SignalCommandRequest) string {
	switch body.Command {
	case gen.Acknowledge:
		if body.ExpectedVersion == nil {
			return "expected_version is required for acknowledge"
		}
	case gen.ChangeStatus:
		if body.ExpectedVersion == nil {
			return "expected_version is required for change_status"
		}
		if body.Status == nil {
			return "status is required for change_status"
		}
	case gen.AssignOwner:
		if body.ExpectedVersion == nil {
			return "expected_version is required for assign_owner"
		}
		if body.OwnerId == nil {
			return "owner_id is required for assign_owner (use an empty string to clear)"
		}
	case gen.AddComment:
		if body.Comment == nil {
			return "comment is required for add_comment"
		}
		if body.ExpectedVersion != nil {
			return "expected_version is not allowed for add_comment (append-only)"
		}
	case gen.OverridePriority:
		if body.ExpectedVersion == nil {
			return "expected_version is required for override_priority"
		}
		if body.Priority == nil {
			return "priority is required for override_priority"
		}
		if body.Reason == nil {
			return "reason is required for override_priority"
		}
	case gen.RevertPriority:
		if body.ExpectedVersion == nil {
			return "expected_version is required for revert_priority"
		}
	case gen.PauseSla, gen.ResumeSla:
		if body.Target == nil {
			return "target is required for " + string(body.Command)
		}
		if body.Reason == nil {
			return "reason is required for " + string(body.Command)
		}
		if body.ExpectedVersion != nil {
			return "expected_version is not allowed for " + string(body.Command) + " (clock-state guarded)"
		}
	default:
		return "unknown command " + string(body.Command)
	}
	return ""
}

// signalCommandError maps a use-case error onto the typed response objects of
// the operation: the application error classes are rendered here (400/403/404/
// 409), an undeclared class or a non-application error is an internal error —
// logged with its correlation id and answered as the generic 500 without the
// cause (concept ch. 5.2).
func (h signalCommandHandler) signalCommandError(ctx context.Context, err error) (gen.SignalCommandResponseObject, error) {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return gen.SignalCommand400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, errorCause(err))), nil
	case application.KindForbidden:
		return gen.SignalCommand403JSONResponse(problemFromContext(ctx, http.StatusForbidden, titleForbidden, errorCause(err))), nil
	case application.KindNotFound:
		return gen.SignalCommand404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleSignalNotFound, errorCause(err))), nil
	case application.KindConflict:
		return gen.SignalCommand409JSONResponse(problemFromContext(ctx, http.StatusConflict, titleConflict, errorCause(err))), nil
	default:
		h.logger.ErrorContext(ctx, "signal command failed", slog.Any("error", err))
		return gen.SignalCommand500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
}

// postCommandState reads the signal's post-command state for the commands
// whose use case returns a non-signal aggregate (add_comment, pause_sla,
// resume_sla), so the wire result still carries status/priority/version. It is
// a read through the existing signals.read seam and changes nothing.
func (h signalCommandHandler) postCommandState(ctx context.Context, signalID string, actor application.Actor) (signalCommandState, error) {
	view, err := h.query.GetSignal(ctx, application.GetSignalInput{SignalID: signalID, Actor: actor})
	if err != nil {
		return signalCommandState{}, err
	}
	return signalCommandState{id: view.ID, status: view.Status, priority: view.Priority, version: view.Version}, nil
}

// stateFromSignal is the post-command state of the signal-returning commands.
func stateFromSignal(sig domain.RiskSignal) signalCommandState {
	return signalCommandState{id: sig.ID, status: sig.Status, priority: sig.Priority, version: sig.Version}
}

// toGenSignalCommandResult maps the post-command state onto the generated
// response type — the wire contract, never hand-rolled. owner/target/auto are
// the nullable detail fields: set only by the command they belong to, null
// for every other command.
func toGenSignalCommandResult(command string, state signalCommandState, owner *string, target *domain.SLATarget, auto *domain.Priority) gen.SignalCommandResult {
	result := gen.SignalCommandResult{
		Id:       state.id,
		Command:  command,
		Status:   gen.SignalStatus(state.status),
		Priority: gen.Priority(state.priority),
		Version:  state.version,
		OwnerId:  owner,
	}
	if target != nil {
		t := gen.SLATarget(*target)
		result.Target = &t
	}
	if auto != nil {
		a := gen.Priority(*auto)
		result.AutoPriority = &a
	}
	return result
}

// optionalString returns nil for the empty string and a pointer to the value
// otherwise — the owner_id detail field is null when the assignment is cleared.
func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optString/optStatus/optPriority/optTarget dereference the optional request
// fields; validation guarantees presence for the values a command actually
// uses, and an absent value dereferences to the empty string.
func optString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func optStatus(p *gen.SignalStatus) domain.SignalStatus {
	if p == nil {
		return ""
	}
	return domain.SignalStatus(*p)
}

func optPriority(p *gen.Priority) domain.Priority {
	if p == nil {
		return ""
	}
	return domain.Priority(*p)
}

func optTarget(p *gen.SLATarget) domain.SLATarget {
	if p == nil {
		return ""
	}
	return domain.SLATarget(*p)
}
