// Composition of the generated strict server interface (ADR-011, ARCH-005
// §7). The OpenAPI document declares several operations; oapi-codegen emits a
// single monolithic gen.StrictServerInterface, so the HTTP handler is built
// from one small handler per domain — the signal reads (signals.go) and the
// audit identity reveal (audit.go) — composed into one implementation here.
// Splitting keeps each handler testable against its own narrow application
// seam while a missing or drifted operation still fails the build (the
// compile-time assertion below).
package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
)

// apiHandlers composes the per-domain strict-server implementations into the
// single gen.StrictServerInterface the generated registration mounts. The
// embedded method sets are disjoint (the signal reads and the audit reveal),
// so embedding yields the full interface without forwarding boilerplate.
type apiHandlers struct {
	*signalsHandler
	auditRevealHandler
}

// Compile-time proof that the composed handler implements every generated
// operation: a missing operation, a drifted signature or a declared response
// without a typed object fails the build (ADR-011).
var _ gen.StrictServerInterface = (*apiHandlers)(nil)

// NewAPIHandler returns the HTTP handler of the generated API surface as the
// gen.ServerInterface the route registration (signals_routes.go) mounts: the
// strict server wrapper around the composed StrictServerInterface. The
// wrapper's own error handlers keep every answer an RFC 9457 problem detail:
// a request the generated binding cannot parse answers 400, and an error a
// handler chooses not to render itself is mapped by writeError. A nil query
// is a programming error and panics here, at construction time, like
// application.NewService does; a nil reveal leaves the reveal route answering
// a 500 (a composition root that does not serve it).
func NewAPIHandler(query SignalsQuery, reveal AuditReveal, logger *slog.Logger) gen.ServerInterface {
	if query == nil {
		panic("httpapi: NewAPIHandler: query must not be nil")
	}
	if logger == nil {
		panic("httpapi: NewAPIHandler: logger must not be nil")
	}
	h := &apiHandlers{
		signalsHandler:     &signalsHandler{query: query, logger: logger},
		auditRevealHandler: auditRevealHandler{reveal: reveal, logger: logger},
	}
	return gen.NewStrictHandlerWithOptions(h, []gen.StrictMiddlewareFunc{recordRequestPath},
		gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest, err.Error())
			},
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				h.writeError(w, r, err)
			},
		})
}
