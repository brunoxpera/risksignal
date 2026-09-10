// HTTP boundary of the governed audit.reveal_identity act (ARCH-005 §7,
// WP-5a.07 / DEV-094, ADR-014): the generated operation POST
// /api/v1/audit-events/{id}/reveal-actor.
//
// The handler is a thin translation: it resolves the authenticated identity
// (placed in the request context by the I5a authentication middleware) into
// an audit actor, delegates to application.RevealAuditIdentity — the gate of
// record, which authorises audit.reveal_identity, requires the reason and
// self-audits — and maps the outcome onto the generated response types (the
// wire contract, never hand-rolled). The per-route permission declaration
// binds audit.reveal_identity at registration (permissions.go); this handler
// adds no authorisation of its own. Secrets and identities are never logged.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// AuditReveal is the application surface the reveal handler delegates to:
// the RevealAuditIdentity use case and the identity → actor resolution the
// authenticated adapters share. Depending on this narrow interface (not the
// whole service) keeps the handler testable with an in-memory fake.
type AuditReveal interface {
	// ResolveActor maps the authenticated request identity onto the audit
	// actor of the command (users.id for a user principal).
	ResolveActor(ctx context.Context, id domain.Identity) (application.Actor, error)
	// RevealAuditIdentity runs the governed reveal.
	RevealAuditIdentity(ctx context.Context, in application.RevealAuditIdentityInput) (application.RevealAuditIdentityResult, error)
}

// auditRevealHandler implements the reveal operation of the generated strict
// interface. reveal is the application surface (nil leaves the operation
// answering a 500 — a composition root that does not serve it); logger
// receives unexpected internal errors (the client only ever sees the generic
// 500 problem detail, concept ch. 5.2).
type auditRevealHandler struct {
	reveal AuditReveal
	logger *slog.Logger
}

// RevealAuditEventActor implements the reveal operation (ADR-014). It reads
// the authenticated identity from the request context, resolves it to the
// audit actor, delegates to application.RevealAuditIdentity and answers the
// typed 200 object. A denial is the typed 403; a blank reason the typed 400;
// an unknown event the typed 404; anything else is logged and answered as the
// generic 500 without the cause.
func (h auditRevealHandler) RevealAuditEventActor(ctx context.Context, request gen.RevealAuditEventActorRequestObject) (gen.RevealAuditEventActorResponseObject, error) {
	if h.reveal == nil {
		h.logger.ErrorContext(ctx, "audit reveal handler is not wired")
		return gen.RevealAuditEventActor500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
	// The authentication middleware places the identity in the context; a
	// missing one is an unauthenticated request (fail closed, no fallback
	// identity). It cannot occur behind the middleware chain — the 403 keeps
	// the declared response set.
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return gen.RevealAuditEventActor403JSONResponse(problemFromContext(ctx, http.StatusForbidden, titleForbidden, "authentication required")), nil
	}
	actor, err := h.reveal.ResolveActor(ctx, identity)
	if err != nil {
		return h.revealError(ctx, err)
	}
	var reason string
	if request.Body != nil {
		reason = request.Body.Reason
	}
	res, err := h.reveal.RevealAuditIdentity(ctx, application.RevealAuditIdentityInput{
		EventID: request.Id,
		Reason:  reason,
		Actor:   actor,
	})
	if err != nil {
		return h.revealError(ctx, err)
	}
	return gen.RevealAuditEventActor200JSONResponse(toGenRevealedActor(res)), nil
}

// revealError maps a reveal error onto the typed response objects of the
// operation: the application error classes are rendered here (400/403/404),
// an undeclared class or a non-application error is an internal error —
// logged with its correlation id and answered as the generic 500 without the
// cause (concept ch. 5.2).
func (h auditRevealHandler) revealError(ctx context.Context, err error) (gen.RevealAuditEventActorResponseObject, error) {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return gen.RevealAuditEventActor400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, errorCause(err))), nil
	case application.KindForbidden:
		return gen.RevealAuditEventActor403JSONResponse(problemFromContext(ctx, http.StatusForbidden, titleForbidden, errorCause(err))), nil
	case application.KindNotFound:
		return gen.RevealAuditEventActor404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleAuditEventNotFound, errorCause(err))), nil
	default:
		h.logger.ErrorContext(ctx, "audit reveal failed", slog.Any("error", err))
		return gen.RevealAuditEventActor500JSONResponse(problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")), nil
	}
}

// toGenRevealedActor maps the application reveal result onto the generated
// RevealedActor: the identity fields are omitted (JSON null) for a non-user
// actor.
func toGenRevealedActor(r application.RevealAuditIdentityResult) gen.RevealedActor {
	out := gen.RevealedActor{
		EventId:   r.EventID,
		ActorType: r.EventActorType,
		IsUser:    r.IsUser,
		Label:     r.Label,
	}
	if r.UserID != "" {
		out.UserId = &r.UserID
	}
	if r.SubjectID != "" {
		out.SubjectId = &r.SubjectID
	}
	if r.DisplayName != "" {
		out.DisplayName = &r.DisplayName
	}
	return out
}
