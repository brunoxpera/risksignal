// RFC 9457 ProblemDetails rendering of the I1b API (ARCH-001 §4, ADR-011).
// Every API error of the signal handlers — a 400 for an invalid request, a
// 404 for an unknown signal, a 409 for a conflict and the generic 500 for
// anything unexpected — is answered as a problem detail carrying the
// request correlation id from the WP-1a.06 middleware chain, so a client
// can link the error back to the server logs (concept ch. 12.3).
package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/xpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/xpera/risksignal/internal/application"
)

// problemType is the type URI of every I1b problem detail: "about:blank",
// the RFC 9457 default for a problem without a more specific type URI. I1b
// defines no error taxonomy yet; the status code plus title carry the
// meaning, and a dedicated URI can grow on later iterations without
// changing the response shape.
const problemType = "about:blank"

// Problem-detail titles (RFC 9457: a short, human-readable summary of the
// problem type). They are stable per status so clients can match on them;
// the per-occurrence detail field carries the specifics.
const (
	titleInvalidRequest = "Invalid request"
	titleSignalNotFound = "Signal not found"
	titleConflict       = "Conflict"
	titleInternalError  = "Internal server error"
)

// writeProblem answers status with an RFC 9457 problem detail (ARCH-001 §4
// ProblemDetails schema): the required {type, title, status,
// correlation_id}, plus detail when given and the request path as the
// instance reference. The correlation id comes from the request context —
// the correlation middleware (correlation.go) sets it before any handler
// runs — and is echoed back in the X-Request-ID response header by the
// middleware itself.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	p := gen.ProblemDetails{
		Type:          problemType,
		Title:         title,
		Status:        status,
		CorrelationId: requestID(r),
	}
	if detail != "" {
		p.Detail = &detail
	}
	if r.URL.Path != "" {
		instance := r.URL.Path
		p.Instance = &instance
	}
	writeJSON(w, status, p)
}

// writeError maps an application error onto the problem detail of its class
// (concept ch. 5.2, DEV-018 error classes): a validation error is a client
// mistake (400), a missing row 404, a conflict 409 — and everything else,
// including errors without the application class, an internal error (500).
// Internal errors never leak their cause to the client: the detail is
// omitted and the full error goes to the structured log, where the
// correlation id links it to this request (the redacting logger of
// internal/platform/logging guards the record's content).
func (h *signalsHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	kind, _ := application.ErrorKindOf(err)
	switch kind {
	case application.KindValidation:
		writeProblem(w, r, http.StatusBadRequest, titleInvalidRequest, errorCause(err))
	case application.KindNotFound:
		writeProblem(w, r, http.StatusNotFound, titleSignalNotFound, errorCause(err))
	case application.KindConflict:
		writeProblem(w, r, http.StatusConflict, titleConflict, errorCause(err))
	default:
		h.logger.ErrorContext(r.Context(), "signal read failed", slog.Any("error", err))
		writeProblem(w, r, http.StatusInternalServerError, titleInternalError, "")
	}
}

// errorCause returns the wrapped cause of an application Error — the
// message without the "application: <op>: <kind>" envelope — so the
// ProblemDetails detail reads as a client-facing message instead of an
// internal error string. Errors without a cause (or without the application
// class) keep their full message.
func errorCause(err error) string {
	var appErr *application.Error
	if errors.As(err, &appErr) && appErr.Err != nil {
		return appErr.Err.Error()
	}
	return err.Error()
}
