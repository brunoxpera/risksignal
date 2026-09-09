// Signal handlers of the I1b API (ARCH-001 §4, WP-1b.08): the generated
// StrictServerInterface implementation for GET /api/v1/signals (listSignals)
// and GET /api/v1/signals/{signal_id} (getSignal). The handlers are the HTTP
// boundary of the walking skeleton's read path: they translate the wire
// (query parameters, paths) into application use-case inputs (DEV-018), map
// the returned application views onto the generated response types — the
// wire contract, never hand-rolled — and map application errors onto
// RFC 9457 ProblemDetails carrying the request correlation id
// (problems.go). All ordering and pagination semantics stay in the use case
// and its repository; the handlers only delegate and translate.
//
// Since every declared response of the two reads now has a generated typed
// object (200/400/404/500, DEV-023), the handlers implement the generated
// StrictServerInterface (ARCH-001 §4 "strict server", ADR-011): each method
// returns the typed response object of its outcome instead of writing
// manually, so the response shapes on the wire are the contract's and a
// drift between document and handler becomes a compile error. The strict
// interface hands the handler only the request context — the correlation
// middleware has already stored the request id in it, and a strict
// middleware (recordRequestPath below) stores the request path — from which
// the problem details of problems.go read their correlation_id and instance.
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/xpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// SignalsQuery is the read surface of the application layer the signal
// handlers delegate to: the ListSignals and GetSignal use cases of
// *application.Service (DEV-018). Depending on the two-method interface
// instead of the whole service keeps the handlers testable with an
// in-memory fake — no database, no write-side repositories — while the
// composition root (cmd/risksignal-server) passes the real service.
type SignalsQuery interface {
	ListSignals(ctx context.Context, in application.ListSignalsInput) (application.ListSignalsResult, error)
	GetSignal(ctx context.Context, id string) (application.Signal, error)
}

// signalsHandler implements gen.StrictServerInterface for the two I1b signal
// reads. query is the application use-case surface; logger receives
// unexpected internal errors (the client only ever sees the generic 500
// problem detail, concept ch. 5.2).
type signalsHandler struct {
	query  SignalsQuery
	logger *slog.Logger
}

// Compile-time proof that the handler implements the generated strict
// interface: a missing operation, a drifted signature or a declared
// response without a typed object fails the build (ADR-011).
var _ gen.StrictServerInterface = (*signalsHandler)(nil)

// requestPathContextKey is the context key under which recordRequestPath
// stores the request path for the strict handlers.
type requestPathContextKey struct{}

// recordRequestPath is a strict-server middleware of the signal routes: it
// records the request path in the context so the strict handlers — which
// receive only the context, not the request — can carry it as the RFC 9457
// instance reference of their problem details.
func recordRequestPath(next gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		return next(context.WithValue(ctx, requestPathContextKey{}, r.URL.Path), w, r, request)
	}
}

// pathFromContext returns the request path recorded by recordRequestPath.
func pathFromContext(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(requestPathContextKey{}).(string)
	return p, ok
}

// NewSignalsHandler returns the HTTP handler of the I1b signal reads as the
// generated gen.ServerInterface the route registration (signals_routes.go)
// mounts: the strict server wrapper around the StrictServerInterface
// implementation above. The wrapper's own error handlers keep every answer
// an RFC 9457 problem detail: a request the generated binding cannot parse
// answers 400, and an error the handlers choose not to render themselves
// (the conflict class, which the read contract does not declare) is mapped
// by writeError exactly like before the strict migration. Nil dependencies
// are programming errors and panic here, at construction time, like
// application.NewService does.
func NewSignalsHandler(query SignalsQuery, logger *slog.Logger) gen.ServerInterface {
	if query == nil {
		panic("httpapi: NewSignalsHandler: query must not be nil")
	}
	if logger == nil {
		panic("httpapi: NewSignalsHandler: logger must not be nil")
	}
	h := &signalsHandler{query: query, logger: logger}
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

// ListSignals implements gen.StrictServerInterface (GET /api/v1/signals,
// ARCH-001 §4 listSignals). It validates the enum query parameters against
// the generated contract types — the parameter binding of the generated
// wrapper converts strings but does not check enum membership — maps them
// onto the use-case filter, delegates to application.ListSignals and
// answers the typed SignalList page object. Invalid enum filters are a
// client mistake and answer the typed 400 ProblemDetails object without
// reaching the use case; a validation error of the use case (limit outside
// the page bounds, malformed cursor) maps the same way; any other error is
// logged and answered as the typed 500 object.
func (h *signalsHandler) ListSignals(ctx context.Context, request gen.ListSignalsRequestObject) (gen.ListSignalsResponseObject, error) {
	params := request.Params
	in := application.ListSignalsInput{}

	if params.Priority != nil {
		if !params.Priority.Valid() {
			return gen.ListSignals400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid priority filter %q: expected one of P1, P2, P3, P4", *params.Priority))), nil
		}
		p := domain.Priority(*params.Priority)
		in.Priority = &p
	}
	if params.Status != nil {
		if !params.Status.Valid() {
			return gen.ListSignals400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid status filter %q: expected %q", *params.Status, gen.New))), nil
		}
		s := domain.SignalStatus(*params.Status)
		in.Status = &s
	}
	// limit and cursor need no handler-side validation: the use case owns
	// the page-size semantics (0 means the default 20, cap 100) and the
	// opaque cursor format is application-private, so their validation
	// errors surface through the same 400 mapping.
	if params.Limit != nil {
		in.Limit = *params.Limit
	}
	if params.Cursor != nil {
		in.Cursor = *params.Cursor
	}

	page, err := h.query.ListSignals(ctx, in)
	if err != nil {
		return h.listError(ctx, err)
	}

	// make(…, 0, …) keeps an empty page on the wire as "data": [] — a nil
	// slice would encode as null, which the array schema rejects.
	data := make([]gen.Signal, 0, len(page.Signals))
	for _, s := range page.Signals {
		data = append(data, toGenSignal(s))
	}
	var nextCursor *string
	if page.NextCursor != "" {
		nextCursor = &page.NextCursor
	}
	return gen.ListSignals200JSONResponse(gen.SignalList{Data: data, NextCursor: nextCursor}), nil
}

// GetSignal implements gen.StrictServerInterface (GET
// /api/v1/signals/{signal_id}, ARCH-001 §4 getSignal). An unknown signal id
// is a not-found application error and answers the typed 404 ProblemDetails
// object naming the id; a malformed id fails validation in the repository
// and answers the typed 400 object.
func (h *signalsHandler) GetSignal(ctx context.Context, request gen.GetSignalRequestObject) (gen.GetSignalResponseObject, error) {
	sig, err := h.query.GetSignal(ctx, request.SignalId)
	if err != nil {
		switch kind, _ := application.ErrorKindOf(err); kind {
		case application.KindNotFound:
			return gen.GetSignal404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleSignalNotFound,
				fmt.Sprintf("no signal exists for signal_id %q", request.SignalId))), nil
		case application.KindValidation:
			return gen.GetSignal400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, errorCause(err))), nil
		default:
			return h.getError(ctx, err)
		}
	}
	return gen.GetSignal200JSONResponse(toGenSignal(sig)), nil
}

// listError maps a ListSignals use-case error onto the typed response
// objects of the operation: a validation error is a client mistake (the
// typed 400), the conflict and not-found classes cannot be produced by the
// list read and escape to the response error handler of the strict wrapper
// (writeError) instead, and everything else is an internal error: logged
// with its correlation id and answered as the typed 500 object without the
// cause.
func (h *signalsHandler) listError(ctx context.Context, err error) (gen.ListSignalsResponseObject, error) {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return gen.ListSignals400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest, errorCause(err))), nil
	case application.KindConflict, application.KindNotFound:
		return nil, err
	default:
		return h.list500(ctx, err), nil
	}
}

// getError maps a GetSignal use-case error the handler does not render
// itself onto the typed response objects of the operation: the conflict
// class cannot be produced by the read and escapes to the response error
// handler of the strict wrapper (writeError); everything else is an
// internal error — logged and answered as the typed 500 object.
func (h *signalsHandler) getError(ctx context.Context, err error) (gen.GetSignalResponseObject, error) {
	if kind, _ := application.ErrorKindOf(err); kind == application.KindConflict {
		return nil, err
	}
	return gen.GetSignal500JSONResponse(h.internalProblem(ctx, err)), nil
}

// internalProblem logs err with its correlation id and returns the generic
// internal-error problem detail — no detail field, the cause never reaches
// the client (concept ch. 5.2).
func (h *signalsHandler) internalProblem(ctx context.Context, err error) gen.ProblemDetails {
	h.logger.ErrorContext(ctx, "signal read failed", slog.Any("error", err))
	return problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")
}

// list500 is internalProblem shaped for the ListSignals operation.
func (h *signalsHandler) list500(ctx context.Context, err error) gen.ListSignals500JSONResponse {
	return gen.ListSignals500JSONResponse(h.internalProblem(ctx, err))
}

// toGenSignal maps the application signal view onto the generated Signal —
// the response schema of ARCH-001 §4. The mapping is a pure field
// translation: identifiers stay strings, enums convert one to one and the
// timestamps pass through as RFC 3339 UTC, so the JSON on the wire is
// exactly the contract shape (snake_case tags on the generated types).
func toGenSignal(s application.Signal) gen.Signal {
	return gen.Signal{
		Id:         s.ID,
		MatchId:    s.MatchID,
		CveId:      s.CveID,
		Priority:   gen.Priority(s.Priority),
		Status:     gen.SignalStatus(s.Status),
		Confidence: gen.Confidence(s.Confidence),
		Method:     gen.MatchMethod(s.Method),
		Asset: &gen.SignalAsset{
			Id:          s.Asset.ID,
			Name:        s.Asset.Name,
			Type:        string(s.Asset.Type),
			Criticality: gen.Criticality(s.Asset.Criticality),
			Exposure:    gen.Exposure(s.Asset.Exposure),
		},
		Product: gen.SignalProduct{
			Vendor:  s.Product.Vendor,
			Product: s.Product.Product,
			Version: s.Product.Version,
		},
		Summary:   s.Summary,
		CreatedAt: s.CreatedAt,
		Version:   s.Version,
		DueAt:     s.DueAt,
	}
}
