// HTTP boundary of the I5a reference triage command (ARCH-005 §8, WP-5a.08):
// the generated operation POST /api/v1/signals/{signal_id}/commands.
//
// It is the API half of the API/CLI channel-parity proof (NFR-013): one
// reference operation (acknowledge + override) run identically through the
// API and the CLI must produce the same state, the same permission denials
// and the same audit evidence. The handler is a thin translation: it resolves
// the authenticated identity placed in the request context by the I5a
// authentication middleware into an audit actor (closing the DEV-093 "zero
// Actor" gap at this boundary), delegates to the application use case — the
// gate of record, which authorises signals.triage / signals.override and
// stamps the actor — and maps the outcome onto the generated response types.
//
// Only acknowledge and override_priority are part of I5a; the full triage
// command surface is I5b. Secrets and identities are never logged.

package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// SignalCommands is the application surface the reference command handler
// delegates to: the identity → actor resolution the authenticated adapters
// share, plus the two I5a triage commands. Depending on this narrow interface
// (not the whole service) keeps the handler testable with an in-memory fake.
type SignalCommands interface {
	// ResolveActor maps the authenticated request identity onto the audit
	// actor of the command (users.id for a user principal).
	ResolveActor(ctx context.Context, id domain.Identity) (application.Actor, error)
	// AcknowledgeSignal moves a new signal to in_review (signals.triage).
	AcknowledgeSignal(ctx context.Context, in application.AcknowledgeSignalInput) (domain.RiskSignal, error)
	// OverridePriority replaces a signal's effective priority (signals.override).
	OverridePriority(ctx context.Context, in application.OverridePriorityInput) (domain.RiskSignal, error)
}

// signalCommandHandler implements the signalCommand operation of the generated
// strict interface. commands is the application surface (nil leaves the
// operation answering a 500 — a composition root that does not serve it);
// logger receives unexpected internal errors (the client only ever sees the
// generic 500 problem detail, concept ch. 5.2).
type signalCommandHandler struct {
	commands SignalCommands
	logger   *slog.Logger
}

// SignalCommand implements the reference triage operation (ARCH-005 §8): it
// reads the authenticated identity from the request context, resolves it to
// the audit actor, dispatches to the use case and answers the typed 200
// object. A denial is the typed 403; a validation mistake the typed 400; an
// unknown signal the typed 404; a stale version / illegal transition the
// typed 409; anything else is logged and answered as the generic 500 without
// the cause.
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
	actor, err := h.commands.ResolveActor(ctx, identity)
	if err != nil {
		return h.signalCommandError(ctx, err)
	}

	// expected_version is optional in the generalised I5b request schema
	// (only the version-guarded commands require it); the two I5a reference
	// commands below are version-guarded, so a missing token reaches the use
	// case as 0 and is rejected there (WP-5b.04 owns the full dispatch).
	expectedVersion := 0
	if request.Body.ExpectedVersion != nil {
		expectedVersion = *request.Body.ExpectedVersion
	}

	var sig domain.RiskSignal
	switch request.Body.Command {
	case gen.Acknowledge:
		sig, err = h.commands.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID:        request.SignalId,
			ExpectedVersion: expectedVersion,
			Actor:           actor,
		})
	case gen.OverridePriority:
		priority := ""
		if request.Body.Priority != nil {
			priority = string(*request.Body.Priority)
		}
		reason := ""
		if request.Body.Reason != nil {
			reason = *request.Body.Reason
		}
		sig, err = h.commands.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID:        request.SignalId,
			Priority:        domain.Priority(priority),
			Reason:          reason,
			ExpectedVersion: expectedVersion,
			Actor:           actor,
		})
	default:
		return gen.SignalCommand400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
			"unknown command "+string(request.Body.Command))), nil
	}
	if err != nil {
		return h.signalCommandError(ctx, err)
	}
	return gen.SignalCommand200JSONResponse(toGenSignalCommandResult(string(request.Body.Command), sig)), nil
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

// toGenSignalCommandResult maps the post-command signal onto the generated
// response type — the wire contract, never hand-rolled.
func toGenSignalCommandResult(command string, sig domain.RiskSignal) gen.SignalCommandResult {
	return gen.SignalCommandResult{
		Id:       sig.ID,
		Command:  command,
		Status:   gen.SignalStatus(sig.Status),
		Priority: gen.Priority(sig.Priority),
		Version:  sig.Version,
	}
}
