package httpapi

import (
	"errors"
	"net/http"
)

// LimitBody caps the request body at maxBytes (concept ch. 12.3: strict input
// limits). A request that already declares a larger Content-Length is
// rejected up front with 413; every other body is wrapped in
// http.MaxBytesReader, which cuts off reads past the limit no matter what the
// client declared (chunked or misleading Content-Length).
//
// net/http no longer answers an exhausted MaxBytesReader by itself, so a
// handler that reads a body must map the resulting MaxBytesError to 413 —
// IsBodyTooLarge exists for exactly that. Rejecting on Content-Length first
// keeps endpoints that never read a body protected too, and makes the 413
// visible on the live server before any route exists.
func LimitBody(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// IsBodyTooLarge reports whether err is the MaxBytesError that LimitBody's
// reader returns once a request body exceeds the limit. Handlers that read
// request bodies use it to answer 413:
//
//	_, err := io.ReadAll(r.Body)
//	if httpapi.IsBodyTooLarge(err) {
//		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
//		return
//	}
func IsBodyTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}
