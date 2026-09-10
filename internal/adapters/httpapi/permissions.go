// Per-route permission declarations of the I5a API surface (ARCH-005 §5,
// WP-5a.05).
//
// The declaration table binds every protected route to the domain.Permission
// its callers must hold. It is bound at registration — Mount for a
// hand-registered route, Decorate for the generated route registration — and
// enforced as an early, defense-in-depth check before the handler runs.
//
// It is deliberately NOT the authorisation gate of record: the use case
// authorises (WP-5a.06, ARCH-005 §5), and this gate only rejects a request
// whose permission is obviously missing, using the PermissionChecker seam the
// composition root wires to the application's principal resolution. With no
// checker wired the declarations still bind (contract documentation) and the
// decision stays entirely with the use case.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// PermissionChecker reports whether the authenticated request may exercise
// perm (ARCH-005 §5). It is the defense-in-depth seam of the per-route
// declaration gate: the composition root wires it to the application's
// principal resolution (WP-5a.06). A nil checker leaves the decision entirely
// to the use case.
type PermissionChecker interface {
	HasPermission(ctx context.Context, perm domain.Permission) bool
}

// PrincipalResolver resolves an authenticated identity into the principal's
// current authorisation state for the route-level permission check
// (ARCH-005 §5). It is the narrow seam httpapi depends on; the composition
// root wires it to the application's principal resolution
// (application.Service.RoutePrincipal), so the route check re-reads the same
// roles the use case does — never the token — and denies an unknown or
// deactivated principal.
type PrincipalResolver interface {
	RoutePrincipal(ctx context.Context, id domain.Identity) (domain.Principal, error)
}

// IdentityPermissionChecker is the production PermissionChecker (ARCH-005 §5):
// it reads the request's authenticated identity from the context, resolves it
// into a domain.Principal and applies the pure domain.Authorize decision
// (deny-by-default).
//
// It is the coarse per-route pre-gate: it decides the permission only, at any
// scope — object scope is NOT decided here (an object-scoped grant passes; the
// use case decides the concrete object and remains the gate of record). A
// request with no identity, an unknown/deactivated principal or no granting
// role denies.
type IdentityPermissionChecker struct {
	principals PrincipalResolver
	logger     *slog.Logger
}

// NewIdentityPermissionChecker builds the checker. Both arguments are
// required; a nil one is a construction error (caught at startup).
func NewIdentityPermissionChecker(principals PrincipalResolver, logger *slog.Logger) *IdentityPermissionChecker {
	if principals == nil {
		panic("httpapi: NewIdentityPermissionChecker: principals must not be nil")
	}
	if logger == nil {
		panic("httpapi: NewIdentityPermissionChecker: logger must not be nil")
	}
	return &IdentityPermissionChecker{principals: principals, logger: logger}
}

// HasPermission reports whether the authenticated request may exercise perm at
// the route level (ARCH-005 §5).
func (c *IdentityPermissionChecker) HasPermission(ctx context.Context, perm domain.Permission) bool {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		return false // no identity: the gate answers 401
	}
	p, err := c.principals.RoutePrincipal(ctx, id)
	if err != nil {
		c.logger.WarnContext(ctx, "route permission check could not resolve principal",
			slog.String("permission", string(perm)), slog.Any("error", err))
		return false
	}
	// Scope-agnostic membership: ScopeOwn is the narrowest scope, so any grant
	// for perm is at least as broad; ownerID == the principal's own id
	// satisfies the object-scoped ownership clause. Object scope is not decided
	// here — the use case does (the gate of record).
	granted, err := domain.Authorize(p.Roles, perm, domain.ScopeOwn, p.InternalID, p.InternalID)
	if err != nil {
		c.logger.WarnContext(ctx, "route permission check failed",
			slog.String("permission", string(perm)), slog.Any("error", err))
		return false
	}
	return granted
}

// RoutePermissions is the per-route permission declaration table (ARCH-005
// §5): every protected route's required permission, keyed by its ServeMux
// pattern ("GET /api/v1/signals"). An empty permission declares a
// public/unauthenticated route; a pattern absent from the table is
// undeclared.
type RoutePermissions map[string]domain.Permission

// PermissionGate binds the per-route permission declarations at registration
// and enforces them as an early check.
type PermissionGate struct {
	checker PermissionChecker
	logger  *slog.Logger
	decls   RoutePermissions
}

// NewPermissionGate builds a gate. checker may be nil: the declarations still
// bind, but the early check stays inactive until the principal resolution is
// wired (WP-5a.06).
func NewPermissionGate(checker PermissionChecker, logger *slog.Logger) *PermissionGate {
	if logger == nil {
		panic("httpapi: NewPermissionGate: logger must not be nil")
	}
	return &PermissionGate{checker: checker, logger: logger, decls: RoutePermissions{}}
}

// Declare records the required permission of a route pattern. It is used for
// routes registered outside Mount (e.g. the generated operations mounted
// through Decorate); an empty perm declares a public route.
func (g *PermissionGate) Declare(pattern string, perm domain.Permission) {
	g.decls[pattern] = perm
}

// Mount declares pattern's required permission and registers h on mux behind
// the gate.
func (g *PermissionGate) Mount(mux *http.ServeMux, pattern string, perm domain.Permission, h http.Handler) {
	g.Declare(pattern, perm)
	mux.Handle(pattern, g.wrap(pattern, h))
}

// Decorate returns a gen.ServeMux that mounts every route registered through
// it behind the gate: the generated route registration (gen.HandlerWithOptions)
// binds each operation's declaration at mount time. Patterns must be declared
// (Declare) before the underlying registration runs.
func (g *PermissionGate) Decorate(mux gen.ServeMux) gen.ServeMux {
	return gateMux{mux: mux, gate: g}
}

// Declarations returns a copy of the bound declaration table (contract
// documentation and tests).
func (g *PermissionGate) Declarations() RoutePermissions {
	out := make(RoutePermissions, len(g.decls))
	for k, v := range g.decls {
		out[k] = v
	}
	return out
}

// wrap enforces the declaration recorded for pattern. A route with no
// required permission (or no checker to decide) passes through unmodified.
func (g *PermissionGate) wrap(pattern string, next http.Handler) http.Handler {
	perm := g.decls[pattern]
	if perm == "" || g.checker == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP-semantic split: a request that carries no authenticated identity
		// is unauthenticated (401); an authenticated identity that lacks the
		// declared permission is forbidden (403). In the live chain the auth
		// middleware already answers 401 before the gate — this is the gate's
		// own defensive contract with an unauthenticated request.
		if _, ok := IdentityFromContext(r.Context()); !ok {
			g.logger.WarnContext(r.Context(), "permission gate denied route: no identity",
				slog.String("pattern", pattern),
				slog.String("permission", string(perm)))
			unauthorized(w, r)
			return
		}
		if !g.checker.HasPermission(r.Context(), perm) {
			g.logger.WarnContext(r.Context(), "permission gate denied route",
				slog.String("pattern", pattern),
				slog.String("permission", string(perm)))
			writeProblem(w, r, http.StatusForbidden, titleForbidden, "permission "+string(perm)+" required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gateMux decorates a gen.ServeMux so the generated registration is gated.
type gateMux struct {
	mux  gen.ServeMux
	gate *PermissionGate
}

func (m gateMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.mux.HandleFunc(pattern, m.gate.wrap(pattern, http.HandlerFunc(h)).ServeHTTP)
}

func (m gateMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}

var _ gen.ServeMux = gateMux{}
