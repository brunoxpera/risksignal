// Route registration of the generated API (WP-1b.08, ADR-011): the I1b
// signal reads are mounted on the same http.ServeMux as the System
// endpoints, so the full WP-1a.06 middleware chain of httpapi.NewHandler —
// correlation id, access log, panic recovery, security headers, CSP, CORS
// off and the body limit — applies to them like to every other route. The
// composition root (cmd/risksignal-server) and the handler tests share this
// registration, so tests exercise the real mount path.
package httpapi

import (
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
)

// RegisterAPIRoutes mounts the generated API operations — the two I1b
// signal reads (GET /api/v1/signals, GET /api/v1/signals/{signal_id}) and
// the I5a governed identity reveal (POST
// /api/v1/audit-events/{id}/reveal-actor) — onto mux. api is the
// gen.ServerInterface serving them (see NewAPIHandler); gen.HandlerWithOptions
// registers every operation with its HTTP-method pattern and wires the
// generated parameter-binding wrapper in front of the handler.
//
// mux is a gen.ServeMux, so the composition root can pass a decorated router
// (httpapi.PermissionGate.Decorate) to bind the per-route permission gate at
// registration; a plain *http.ServeMux mounts the routes ungated.
//
// A binding failure of the generated wrapper (a malformed query value such
// as ?limit=abc, or a repeated parameter) is a client mistake; the default
// plain-text error handler is replaced so even those answer as RFC 9457
// problem details carrying the correlation id, like every other API error.
func RegisterAPIRoutes(mux gen.ServeMux, api gen.ServerInterface) {
	gen.HandlerWithOptions(api, gen.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest, err.Error())
		},
	})
}
