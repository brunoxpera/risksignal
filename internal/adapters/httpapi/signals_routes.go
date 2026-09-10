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

// RegisterSignalRoutes mounts the generated listSignals and getSignal
// routes — GET /api/v1/signals and GET /api/v1/signals/{signal_id}
// (ARCH-001 §4) — onto mux. api is the gen.ServerInterface implementation
// serving them (see NewSignalsHandler); gen.HandlerWithOptions registers the
// routes with their HTTP-method patterns and wires the generated
// parameter-binding wrapper in front of the handler.
//
// A binding failure of the generated wrapper (a malformed query value such
// as ?limit=abc, or a repeated parameter) is a client mistake; the default
// plain-text error handler is replaced so even those answer as RFC 9457
// problem details carrying the correlation id, like every other API error.
func RegisterSignalRoutes(mux *http.ServeMux, api gen.ServerInterface) {
	gen.HandlerWithOptions(api, gen.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest, err.Error())
		},
	})
}
