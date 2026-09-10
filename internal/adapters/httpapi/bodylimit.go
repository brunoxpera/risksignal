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
	return LimitBodyFor(maxBytes, nil)
}

// LimitBodyFor is LimitBody with a per-path override: a request whose path
// exactly matches an override key is capped at the override instead of
// maxBytes. It exists for bulk upload routes (the inventory-import CSV,
// bounded by the larger application.InventoryMaxBytes) mounted on the same mux
// as the default JSON endpoints. A nil/empty overrides map is LimitBody.
func LimitBodyFor(maxBytes int64, overrides map[string]int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := maxBytes
			if o, ok := overrides[r.URL.Path]; ok {
				limit = o
			}
			if r.ContentLength > limit {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
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
