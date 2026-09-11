package httpapi

import (
	"fmt"
	"net/http"
	"time"
)

// SecurityHeaders sets the baseline hardening headers required by concept
// ch. 12.3 ("Sicherheitskontrollen"): no MIME sniffing, no embedding by other
// sites and no referrer leakage. Headers are written before the next handler
// runs, so they are present on every response — including errors generated
// deeper in the chain.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ContentSecurityPolicy applies the restrictive policy of concept ch. 12.3:
// no content source is allowed (default-src 'none') and the response can
// never be embedded as a frame (frame-ancestors 'none'), which closes the
// clickjacking angle on top of X-Frame-Options.
func ContentSecurityPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// StrictTransportSecurity emits the HTTP Strict Transport Security header
// (concept ch. 12.3, ARCH-007 §7 control 4). maxAge is the max-age the client
// must honour; a non-positive maxAge disables the header (the online modes
// force it, plain-HTTP local development leaves it off — the flag is set at
// the composition root from the environment, HSTS()).
func StrictTransportSecurity(maxAge time.Duration) Middleware {
	if maxAge <= 0 {
		// No header: return the identity middleware. Returning a handler
		// that adds nothing keeps the chain shape stable.
		return func(next http.Handler) http.Handler { return next }
	}
	value := fmt.Sprintf("max-age=%d; includeSubDomains", int(maxAge.Seconds()))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", value)
			next.ServeHTTP(w, r)
		})
	}
}

// CORSDisabled pins cross-origin resource sharing to "off" (concept ch. 12.3:
// "CORS standardmässig deaktiviert und nur explizit freigegeben"). It emits
// no Access-Control-Allow-* header, so browsers keep enforcing the
// same-origin policy unchanged. If an explicit per-origin allowlist ever
// lands, it replaces this link in the chain and stays behind configuration.
func CORSDisabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// HSTS is the HandlerOption that sets the Strict-Transport-Security max-age of
// the chain (0 = off). The composition roots pass the online-mode value
// (demo/production force it, ARCH-007 §7 control 4); local mode passes 0.
func HSTS(maxAge time.Duration) HandlerOption {
	return func(c *handlerConfig) { c.hstsMaxAge = maxAge }
}
