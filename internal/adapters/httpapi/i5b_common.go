// Shared scaffolding of the I5b HTTP operations (ARCH-006 §2/§3,
// WP-5b.05): the staged inventory import, the asset reads and the user/role
// administration. The handlers are thin translations — they resolve the
// authenticated actor, map the wire request onto the application input, call
// the use case (the gate of record) and map the application error classes
// back onto the generated response objects. They decide no rights and no
// business rules; the per-route PermissionGate is defense-in-depth only
// (ARCH-005 §5).
package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// I5BAPI groups the application surfaces of the I5b operations. Each field is
// a narrow interface over *application.Service; a nil field leaves its
// operations answering the generic 500 (a composition root that does not
// serve them), exactly like a nil reveal leaves the reveal route answering
// 500.
type I5BAPI struct {
	Inventory InventoryImports
	Assets    AssetsRead
	Users     UserAdmin
}

// ActorResolver maps an authenticated request identity onto the audit actor
// of a command (application.Service.ResolveActor), the seam every
// authenticated adapter shares.
type ActorResolver interface {
	ResolveActor(ctx context.Context, id domain.Identity) (application.Actor, error)
}

// errNoIdentity marks a request whose context carries no authenticated
// identity: fail closed (403), there is never a fallback identity — the same
// rule as the reference command handler.
var errNoIdentity = errors.New("httpapi: no authenticated identity")

// errUploadTooLarge marks an inventory upload whose bytes exceed
// application.InventoryMaxBytes.
var errUploadTooLarge = errors.New("httpapi: inventory upload exceeds the limit")

// resolveActor resolves the authenticated actor of a request context through
// the given resolver. A context without an identity is errNoIdentity (a 403);
// an unknown subject fails the same way (ResolveActor returns forbidden).
func resolveActor(ctx context.Context, r ActorResolver) (application.Actor, error) {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return application.Actor{}, errNoIdentity
	}
	return r.ResolveActor(ctx, identity)
}

// actorProblem maps a resolveActor error onto (status, title, detail): a
// missing identity and an unknown subject are 403, anything else follows the
// application error classes (infrastructure ⇒ 500).
func actorProblem(err error) (int, string, string) {
	if errors.Is(err, errNoIdentity) {
		return http.StatusForbidden, titleForbidden, "authentication required"
	}
	return statusProblem(err, "")
}

// statusProblem maps an application error onto the (status, title, detail) of
// its class: validation→400, forbidden→403, not-found→404, conflict→409 and
// anything else→500 (no detail — the cause never reaches the client). The
// notFoundTitle names the resource the 404 refers to.
func statusProblem(err error, notFoundTitle string) (int, string, string) {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return http.StatusBadRequest, titleInvalidRequest, errorCause(err)
	case application.KindForbidden:
		return http.StatusForbidden, titleForbidden, errorCause(err)
	case application.KindNotFound:
		return http.StatusNotFound, notFoundTitle, errorCause(err)
	case application.KindConflict:
		return http.StatusConflict, titleConflict, errorCause(err)
	default:
		return http.StatusInternalServerError, titleInternalError, ""
	}
}

// correlationIDFromContext returns the request correlation id (the value the
// CorrelationID middleware stored), or "" when the request never passed
// through it.
func correlationIDFromContext(ctx context.Context) string {
	id, ok := RequestIDFromContext(ctx)
	if !ok {
		return ""
	}
	return id
}

// readInventoryUpload reads one inventory CSV body bounded by
// application.InventoryMaxBytes (ARCH-006 §2.1): a body that reaches the
// limit — whether cut off by the chain's MaxBytesReader (IsBodyTooLarge) or
// longer than the limit — is errUploadTooLarge (a 413), a read failure is the
// raw error (a 400).
func readInventoryUpload(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, application.InventoryMaxBytes+1))
	if err != nil {
		if IsBodyTooLarge(err) {
			return nil, errUploadTooLarge
		}
		return nil, err
	}
	if int64(len(data)) > application.InventoryMaxBytes {
		return nil, errUploadTooLarge
	}
	return data, nil
}
