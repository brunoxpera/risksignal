// Signal handlers of the I1b API (ARCH-001 §4, WP-1b.08): the generated
// ServerInterface implementation for GET /api/v1/signals (listSignals) and
// GET /api/v1/signals/{signal_id} (getSignal). The handlers are the HTTP
// boundary of the walking skeleton's read path: they translate the wire
// (query parameters, paths) into application use-case inputs (DEV-018), map
// the returned application views onto the generated response types — the
// wire contract, never hand-rolled — and map application errors onto
// RFC 9457 ProblemDetails carrying the request correlation id
// (problems.go). All ordering and pagination semantics stay in the use case
// and its repository; the handlers only delegate and translate.
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

// signalsHandler implements gen.ServerInterface for the two I1b signal
// reads. query is the application use-case surface; logger receives
// unexpected internal errors (the client only ever sees the generic 500
// problem detail, concept ch. 5.2).
type signalsHandler struct {
	query  SignalsQuery
	logger *slog.Logger
}

// Compile-time proof that the handler implements the generated interface:
// a missing operation or a drifted signature fails the build (ADR-011).
var _ gen.ServerInterface = (*signalsHandler)(nil)

// NewSignalsHandler returns the generated ServerInterface implementation of
// the I1b signal reads, delegating to the application use cases behind
// query. Nil dependencies are programming errors and panic here, at
// construction time, like application.NewService does.
func NewSignalsHandler(query SignalsQuery, logger *slog.Logger) gen.ServerInterface {
	if query == nil {
		panic("httpapi: NewSignalsHandler: query must not be nil")
	}
	if logger == nil {
		panic("httpapi: NewSignalsHandler: logger must not be nil")
	}
	return &signalsHandler{query: query, logger: logger}
}

// ListSignals implements gen.ServerInterface (GET /api/v1/signals,
// ARCH-001 §4 listSignals). It validates the enum query parameters against
// the generated contract types — the parameter binding of the generated
// wrapper converts strings but does not check enum membership — maps them
// onto the use-case filter, delegates to application.ListSignals and
// answers the SignalList page envelope. Invalid enum filters are a client
// mistake and answer 400 ProblemDetails without reaching the use case.
func (h *signalsHandler) ListSignals(w http.ResponseWriter, r *http.Request, params gen.ListSignalsParams) {
	in := application.ListSignalsInput{}

	if params.Priority != nil {
		if !params.Priority.Valid() {
			writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid priority filter %q: expected one of P1, P2, P3, P4", *params.Priority))
			return
		}
		p := domain.Priority(*params.Priority)
		in.Priority = &p
	}
	if params.Status != nil {
		if !params.Status.Valid() {
			writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid status filter %q: expected %q", *params.Status, gen.New))
			return
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

	page, err := h.query.ListSignals(r.Context(), in)
	if err != nil {
		h.writeError(w, r, err)
		return
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
	writeJSON(w, http.StatusOK, gen.SignalList{Data: data, NextCursor: nextCursor})
}

// GetSignal implements gen.ServerInterface (GET /api/v1/signals/{signal_id},
// ARCH-001 §4 getSignal). An unknown signal id is a not-found application
// error and answers 404 ProblemDetails naming the id; a malformed id fails
// validation in the repository and answers 400.
func (h *signalsHandler) GetSignal(w http.ResponseWriter, r *http.Request, signalId string) {
	sig, err := h.query.GetSignal(r.Context(), signalId)
	if err != nil {
		if kind, _ := application.ErrorKindOf(err); kind == application.KindNotFound {
			writeProblem(w, r, http.StatusNotFound, titleSignalNotFound,
				fmt.Sprintf("no signal exists for signal_id %q", signalId))
			return
		}
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenSignal(sig))
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
