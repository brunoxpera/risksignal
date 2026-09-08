package httpapi

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// RecoverPanic turns a handler panic into the neutral error response of
// concept ch. 5.2 ("Fehlersemantik"): an unexpected internal error answers
// with a generic 500 that carries the correlation ID, while the panic value
// and stack trace go only into the structured internal log — never to the
// client. The record is an ERROR record on the redacting logger, so a panic
// value that itself carries a secret is withheld from the log while the
// stack and the technical cause stay available (concept ch. 16.1: stack
// traces only for unexpected internal errors).
//
// When the handler already started writing, the status is on the wire and can
// no longer be changed; the panic is re-raised so net/http closes the
// connection and logs it, instead of delivering a truncated body as if the
// request had succeeded.
func RecoverPanic(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			defer func() {
				if v := recover(); v != nil {
					logger.ErrorContext(r.Context(), "panic",
						slog.String("panic_value", sanitizeLogField(fmt.Sprint(v))),
						slog.String("stack", sanitizeLogField(string(debug.Stack()))),
					)
					if rec.status != 0 {
						// Response already started: re-raise so net/http
						// aborts the connection instead of a half-written
						// response being taken for a success.
						panic(v)
					}
					http.Error(rec, "internal server error (correlation id "+requestID(r)+")",
						http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}
