// Authentication middleware of the I5a API surface (ARCH-005 §2, §5,
// WP-5a.05).
//
// The middleware resolves a request's credentials into an authenticated
// domain.Identity and places it in the request context. It authenticates
// ONLY: it never decides roles or permissions — the use case is the gate of
// record (WP-5a.06, ARCH-005 §5). A request it cannot authenticate is an
// anonymous request, answered with a 401 problem detail; there is never a
// fallback or default identity.
//
// Three credentials are recognised, in order:
//
//  1. the local dev principal, when auth.bypass_enabled is set — valid only
//     in local mode on a loopback bind, enforced at startup by
//     config.Validate (ARCH-005 §4);
//  2. a Bearer access token, verified through the TokenVerifier port (the
//     ARCH-005 §2 OIDC verifier is wired behind it by the composition root);
//  3. the browser session cookie, resolved through the SessionResolver port
//     (the server-side session store; nil disables the cookie path).
//
// The public exceptions of ARCH-005 §5 — /health/*, /version and the OIDC
// /auth/* establishment endpoints — carry no identity and never 401.
//
// Tokens are never logged (NFR-006/NFR-014); the redacting logger of
// internal/platform/logging drops Authorization headers.
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// issuerLocal is the pseudo-issuer of the local dev principal. The seeded
// local identities carry the subject "<issuer>::<name>" (migration 00009),
// so the bypass principal resolves to the seeded local-developer row.
const issuerLocal = "local"

// defaultBypassPrincipal is the seeded local multi-role user (ARCH-005 §4.2,
// config.Auth.BypassPrincipal default).
const defaultBypassPrincipal = "local-developer"

// ErrUnauthenticated is the sentinel every authentication failure wraps. The
// middleware maps it to a 401 problem detail; it is never returned to a
// client verbatim.
var ErrUnauthenticated = errors.New("httpapi: unauthenticated")

// identityContextKey is the unexported context key of the authenticated
// identity.
type identityContextKey struct{}

// WithIdentity returns a copy of ctx carrying the authenticated identity.
func WithIdentity(ctx context.Context, id domain.Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext returns the authenticated identity placed in ctx by the
// AuthenticationMiddleware, and whether one was present.
func IdentityFromContext(ctx context.Context) (domain.Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(domain.Identity)
	return id, ok
}

// TokenVerifier verifies a bearer access token and returns the authenticated
// identity (the ARCH-005 §2 TokenVerifier port). A failed verification is an
// error — never a fallback identity. The composition root adapts the OIDC
// adapter onto it.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (domain.Identity, error)
}

// SessionResolver resolves an opaque server-side session id (the browser
// session cookie value) into the authenticated identity (ARCH-005 §2). It is
// nil until the server-side session store lands; a nil resolver disables the
// cookie path.
type SessionResolver interface {
	Resolve(ctx context.Context, sessionID string) (domain.Identity, error)
}

// AuthOptions is the middleware's view of the auth configuration.
type AuthOptions struct {
	// BypassEnabled activates the local dev principal (config.Auth.
	// BypassEnabled). Valid only in local mode on a loopback bind — the
	// startup lock of config.Validate (ARCH-005 §4) is the enforcement.
	BypassEnabled bool
	// BypassPrincipal is the subject the bypass authenticates as
	// (config.Auth.BypassPrincipal, default local-developer).
	BypassPrincipal string
	// SessionCookieName is the browser session cookie (config.OIDC.
	// SessionCookieName). Empty disables the cookie path.
	SessionCookieName string
}

// IsPublicPath reports whether path is exempt from authentication (ARCH-005
// §5): the operational probes (/health/*), the build metadata (/version) and
// the OIDC establishment endpoints (/auth/*).
func IsPublicPath(path string) bool {
	switch {
	case path == "/version":
		return true
	case path == "/health" || strings.HasPrefix(path, "/health/"):
		return true
	case path == "/auth" || strings.HasPrefix(path, "/auth/"):
		return true
	default:
		return false
	}
}

// AuthenticationMiddleware resolves the request credentials into a
// domain.Identity in the request context (ARCH-005 §5). verifier verifies
// Bearer tokens; sessions resolves the browser session cookie (may be nil).
//
// When the bypass is disabled a verifier is required — without one no Bearer
// token could ever be authenticated — so a nil verifier is a construction
// error and panics (a misconfiguration, caught at startup, not at request
// time).
func AuthenticationMiddleware(verifier TokenVerifier, sessions SessionResolver, opts AuthOptions) Middleware {
	if verifier == nil && !opts.BypassEnabled {
		panic("httpapi: AuthenticationMiddleware: a TokenVerifier is required when auth.bypass_enabled is false")
	}
	cookieName := strings.TrimSpace(opts.SessionCookieName)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			id, err := authenticate(r.Context(), verifier, sessions, opts, cookieName, r)
			if err != nil {
				unauthorized(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// authenticate resolves one request's identity, or ErrUnauthenticated.
func authenticate(ctx context.Context, verifier TokenVerifier, sessions SessionResolver, opts AuthOptions, cookieName string, r *http.Request) (domain.Identity, error) {
	// 1. The local dev principal wins when the bypass is on: the process is
	//    guaranteed local + loopback-bound by config.Validate (ARCH-005 §4).
	if opts.BypassEnabled {
		return bypassIdentity(opts.BypassPrincipal), nil
	}
	// 2. A Bearer access token.
	if raw, ok := bearerToken(r); ok {
		if verifier == nil {
			return domain.Identity{}, ErrUnauthenticated
		}
		id, err := verifier.Verify(ctx, raw)
		if err != nil {
			return domain.Identity{}, ErrUnauthenticated
		}
		return id, nil
	}
	// 3. The browser session cookie.
	if cookieName != "" && sessions != nil {
		if c, err := r.Cookie(cookieName); err == nil && strings.TrimSpace(c.Value) != "" {
			id, err := sessions.Resolve(ctx, strings.TrimSpace(c.Value))
			if err != nil {
				return domain.Identity{}, ErrUnauthenticated
			}
			return id, nil
		}
	}
	return domain.Identity{}, ErrUnauthenticated
}

// bypassIdentity builds the local dev principal's identity (ARCH-005 §4.2):
// the issuer-qualified subject of the seeded local multi-role user
// ("local::<principal>"), which the use case resolves to the users row.
func bypassIdentity(principal string) domain.Identity {
	if principal = strings.TrimSpace(principal); principal == "" {
		principal = defaultBypassPrincipal
	}
	return domain.Identity{
		SubjectID:   issuerLocal + "::" + principal,
		DisplayName: principal,
	}
}

// bearerToken extracts a "Bearer <token>" Authorization header value.
func bearerToken(r *http.Request) (string, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return "", false
	}
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", false
	}
	return token, true
}

// unauthorized answers an unauthenticated request with a 401 problem detail
// and the RFC 6750 WWW-Authenticate challenge.
func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeProblem(w, r, http.StatusUnauthorized, titleUnauthorized, "authentication required")
}
