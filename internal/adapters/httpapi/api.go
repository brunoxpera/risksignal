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
// embedded method sets are disjoint (the signal reads, the audit reveal, the
// signal command and the I5b inventory/assets/admin operations), so embedding
// yields the full interface without forwarding boilerplate.
type apiHandlers struct {
	*signalsHandler
	auditRevealHandler
	signalCommandHandler
	*inventoryImportHandler
	*assetsHandler
	*userAdminHandler
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
//
// The optional i5b argument carries the staged-import, asset-read and
// user/role-admin surfaces (at most one value); when absent (or a field of it
// nil) that group answers the generic 500, like a nil reveal.
func NewAPIHandler(query SignalsQuery, reveal AuditReveal, commands SignalCommands, logger *slog.Logger, i5b ...I5BAPI) gen.ServerInterface {
	if query == nil {
		panic("httpapi: NewAPIHandler: query must not be nil")
	}
	if logger == nil {
		panic("httpapi: NewAPIHandler: logger must not be nil")
	}
	var surfaces I5BAPI
	if len(i5b) > 0 {
		surfaces = i5b[0]
	}
	h := &apiHandlers{
		signalsHandler:         &signalsHandler{query: query, logger: logger},
		auditRevealHandler:     auditRevealHandler{reveal: reveal, logger: logger},
		signalCommandHandler:   signalCommandHandler{commands: commands, query: query, logger: logger},
		inventoryImportHandler: &inventoryImportHandler{imports: surfaces.Inventory, logger: logger},
		assetsHandler:          &assetsHandler{assets: surfaces.Assets, logger: logger},
		userAdminHandler:       &userAdminHandler{admin: surfaces.Users, logger: logger},
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
