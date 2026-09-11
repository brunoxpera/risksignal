// Package httpapi adapts inbound HTTP requests to the application layer
// (implementation concept ch. 3.2 "Repository-Struktur"). The generated API
// code of ADR-011 will land in httpapi/gen; this package holds the
// hand-written HTTP scaffolding.
//
// WP-1a.06 ("HTTP scaffolding and middleware chain") provides the middleware
// chain every request passes through. Routing stays on the standard library
// http.ServeMux (ADR-008 — no router framework), and the cross-cutting
// concerns of concept ch. 12.3 ("Sicherheitskontrollen") are composed here as
// an explicit chain: correlation ID, access log, panic recovery, security
// headers, a restrictive content security policy, CORS off by default and a
// body size limit.
package httpapi

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Middleware wraps an http.Handler with cross-cutting behaviour. It is the
// building block of the WP-1a.06 chain (ADR-008: middleware chaining as a
// small in-repository building block).
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares into one. They run in the given order, outermost
// first: Chain(a, b, c)(h) serves a(b(c(h))). An empty chain returns h
// unchanged.
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// MaxBodyBytes caps request bodies accepted by NewHandler (concept ch. 12.3:
// strict input limits). One MiB covers the JSON payloads of the planned API;
// the bulk-upload routes (the inventory-import CSV) raise their own limit
// through BodyLimitOverride.
const MaxBodyBytes int64 = 1 << 20 // 1 MiB

// HandlerOption customises the WP-1a.06 chain built by NewHandler and
// NewHandlerWithAuth.
type HandlerOption func(*handlerConfig)

// handlerConfig accumulates the optional chain overrides.
type handlerConfig struct {
	// bodyLimitOverrides raises (or lowers) the request-body cap of an exact
	// request path above the chain default (MaxBodyBytes).
	bodyLimitOverrides map[string]int64
	// extra holds middlewares inserted just after the correlation middleware
	// (see WithMiddleware) — the observability layers of the composition root.
	extra []Middleware
	// hstsMaxAge is the Strict-Transport-Security max-age of the chain
	// (0 = off); the online modes force it (HSTS, ARCH-007 §7 control 4).
	hstsMaxAge time.Duration
}

// WithMiddleware appends an extra middleware to the WP-1a.06 chain, inserted
// just after the correlation middleware (so it sees the effective correlation
// id and trace context) and before the access log. It is how the composition
// root adds the observability layers — metrics and trace — without changing
// the fixed chain order. A nil middleware is ignored.
func WithMiddleware(mw Middleware) HandlerOption {
	return func(c *handlerConfig) {
		if mw != nil {
			c.extra = append(c.extra, mw)
		}
	}
}

// BodyLimitOverride raises the request-body cap of one exact request path
// above the chain default MaxBodyBytes. It exists for the inventory-import
// upload, whose CSV is bounded by application.InventoryMaxBytes (16 MiB)
// rather than by the JSON default; every other path keeps the default limit.
func BodyLimitOverride(path string, maxBytes int64) HandlerOption {
	return func(c *handlerConfig) {
		if c.bodyLimitOverrides == nil {
			c.bodyLimitOverrides = make(map[string]int64)
		}
		c.bodyLimitOverrides[path] = maxBytes
	}
}

// NewHandler wraps h with the complete WP-1a.06 middleware chain, outermost
// first. Every request — matched or not — passes through the whole chain, so
// a 404 from an as-yet empty ServeMux still carries a correlation ID, the
// security headers and a structured access log record (WP-1a.08: the logger
// is a *log/slog.Logger from internal/platform/logging).
func NewHandler(h http.Handler, logger *slog.Logger, opts ...HandlerOption) http.Handler {
	cfg := newHandlerConfig(opts)
	mws := cfg.baseChain(logger)
	mws = append(mws, LimitBodyFor(MaxBodyBytes, cfg.bodyLimitOverrides))
	return Chain(mws...)(h)
}

// baseChain builds the fixed WP-1a.06 chain: correlation ID first (so the
// observability middlewares see the effective id), then the extra
// observability layers, then the access log, panic recovery, security
// headers, CSP and CORS. The per-route body limit and the optional auth
// middleware are appended by the callers.
func (cfg handlerConfig) baseChain(logger *slog.Logger) []Middleware {
	mws := make([]Middleware, 0, 6+len(cfg.extra))
	mws = append(mws, CorrelationID)
	mws = append(mws, cfg.extra...)
	mws = append(mws, AccessLog(logger), RecoverPanic(logger), SecurityHeaders, ContentSecurityPolicy, StrictTransportSecurity(cfg.hstsMaxAge), CORSDisabled)
	return mws
}

// newHandlerConfig folds the options into the chain configuration.
func newHandlerConfig(opts []HandlerOption) handlerConfig {
	var cfg handlerConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// NewHandlerWithAuth wraps h with the complete WP-1a.06 middleware chain plus
// the given authentication middleware (WP-5a.05) as the innermost layer, so
// an authentication failure (401) still carries the correlation id, the
// security headers and the access-log record of the chain.
func NewHandlerWithAuth(h http.Handler, logger *slog.Logger, auth Middleware, opts ...HandlerOption) http.Handler {
	cfg := newHandlerConfig(opts)
	mws := cfg.baseChain(logger)
	mws = append(mws, LimitBodyFor(MaxBodyBytes, cfg.bodyLimitOverrides), auth)
	return Chain(mws...)(h)
}

// statusRecorder records the first response status while writing through to
// the wrapped ResponseWriter. The access log needs the final status, and the
// panic recovery needs to know whether the handler already started answering.
type statusRecorder struct {
	http.ResponseWriter
	status int // 0 until the handler writes a status
}

// WriteHeader keeps the first status: later calls are superfluous (net/http
// would log and ignore them anyway) and must not overwrite what is already on
// the wire.
func (w *statusRecorder) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Write records the implicit 200 when the handler writes a body without an
// explicit status.
func (w *statusRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the real ResponseWriter, keeping
// optional interfaces (Flusher, Hijacker, ...) available through the chain.
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// statusCode returns the recorded status. When the handler wrote nothing the
// server answers 200 implicitly, so 200 is the honest value to log.
func (w *statusRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// sanitizeLogField neutralises log injection (concept ch. 12.3: "Log-Injektion
// werden neutralisiert"): control characters in request-derived values are
// replaced so a crafted path or panic value can never forge a log line.
func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
