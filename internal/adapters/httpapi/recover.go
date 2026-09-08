package httpapi

import (
	"fmt"
	"net/http"
	"runtime/debug"
)

// RecoverPanic turns a handler panic into the neutral error response of
// concept ch. 5.2 ("Fehlersemantik"): an unexpected internal error answers
// with a generic 500 that carries the correlation ID, while the panic value
// and stack trace go only into the internal log — never to the client.
//
// When the handler already started writing, the status is on the wire and can
// no longer be changed; the panic is re-raised so net/http closes the
// connection and logs it, instead of delivering a truncated body as if the
// request had succeeded.
func RecoverPanic(logger Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			defer func() {
				if v := recover(); v != nil {
					logger.Printf("panic request_id=%s value=%s\n%s",
						requestID(r),
						sanitizeLogField(fmt.Sprint(v)),
						debug.Stack(),
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
