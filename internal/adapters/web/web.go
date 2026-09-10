// Package web is the server-rendered web adapter of the I5b iteration
// (ARCH-006 §3, ADR-004).
//
// It renders the central views (dashboard, triage, signal detail, source
// monitor, inventory and administration) with Go html/template over an
// embedded template tree, and calls the application service IN-PROCESS — never
// the HTTP API over a loopback request — so it runs the same use cases and the
// same in-command authoriser as the REST API and the CLI (ARCH-006 §6, NFR-013
// channel parity). There is no SPA, no client-side business logic and no
// business logic in the templates: the handlers translate the HTTP form/query
// onto the existing application inputs and map the returned error kinds back
// onto an HTML response.
//
// The adapter is mounted on the same http.ServeMux as the API, behind the I5a
// authentication middleware (the OIDC session cookie is the web principal
// source). Mutating form posts carry a per-session CSRF token (hidden field +
// SameSite cookie) validated before dispatch (ARCH-006 §3.2), and destructive
// forms additionally carry a target-scope confirmation token the server
// rejects the POST without (ARCH-006 §4 row 3).
package web

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// Clock is the injected clock of the web adapter (the countdown and the
// "%v" timestamps read it, never the wall clock — ch. 7.2).
type Clock interface {
	Now() time.Time
}

// Signals is the application surface of the signal reads.
type Signals interface {
	ListSignals(ctx context.Context, in application.ListSignalsInput) (application.ListSignalsResult, error)
	GetSignal(ctx context.Context, in application.GetSignalInput) (application.Signal, error)
}

// Assets is the application surface of the asset reads.
type Assets interface {
	ListAssets(ctx context.Context, in application.ListAssetsInput) (application.ListAssetsResult, error)
	GetAssetComponents(ctx context.Context, in application.GetAssetComponentsInput) (application.AssetComponents, error)
}

// Users is the application surface of the user/role administration.
type Users interface {
	ListUsers(ctx context.Context, in application.ListUsersInput) (application.ListUsersResult, error)
	ListRoles(ctx context.Context, in application.ListRolesInput) ([]application.RoleDescriptor, error)
	GrantRole(ctx context.Context, in application.GrantRoleInput) (application.UserRecord, error)
	RevokeRole(ctx context.Context, in application.RevokeRoleInput) (application.UserRecord, error)
	DeactivateUser(ctx context.Context, in application.DeactivateUserInput) (application.UserRecord, error)
}

// Imports is the application surface of the staged inventory import.
type Imports interface {
	StageInventoryImport(ctx context.Context, in application.StageInventoryImportInput) (application.InventoryImport, error)
	GetInventoryImport(ctx context.Context, in application.GetInventoryImportInput) (application.InventoryImport, error)
	CommitStagedInventory(ctx context.Context, in application.CommitStagedInventoryInput) (application.InventoryImport, error)
}

// Commands is the application surface of the eight triage/SLA commands.
type Commands interface {
	AcknowledgeSignal(ctx context.Context, in application.AcknowledgeSignalInput) (domain.RiskSignal, error)
	TransitionSignal(ctx context.Context, in application.TransitionSignalInput) (domain.RiskSignal, error)
	AssignOwner(ctx context.Context, in application.AssignOwnerInput) (domain.RiskSignal, error)
	AddComment(ctx context.Context, in application.AddCommentInput) (domain.Comment, error)
	OverridePriority(ctx context.Context, in application.OverridePriorityInput) (domain.RiskSignal, error)
	RevertPriority(ctx context.Context, in application.RevertPriorityInput) (domain.RiskSignal, error)
	PauseSla(ctx context.Context, in application.PauseSlaInput) (domain.SlaClock, error)
	ResumeSla(ctx context.Context, in application.ResumeSlaInput) (domain.SlaClock, error)
}

// ActorResolver maps an authenticated request identity onto the audit actor of
// a command (application.Service.ResolveActor).
type ActorResolver interface {
	ResolveActor(ctx context.Context, id domain.Identity) (application.Actor, error)
}

// RolesReader reads a user's current roles for the role-dependent navigation
// (ARCH-006 §3.1). It is the authoriser's read port (the DEV-089 *repo.UserRepo
// implements it) — the navigation is presentation only; the use cases remain
// the gate of record.
type RolesReader interface {
	RolesByUserID(ctx context.Context, userID string) ([]domain.Role, error)
}

// Service is the application surface the web adapter drives: the eight I5b
// read/admin/staged-import use cases, the eight triage/SLA commands and the
// actor resolution — one narrow view of *application.Service.
type Service interface {
	Signals
	Assets
	Users
	Imports
	Commands
	ActorResolver
}

// SourceMonitor is the OPTIONAL source-monitor read seam (ARCH-006 §3.1). The
// ARCH §3.1 route table names a "source monitor read", but I5b landed no
// application use case for it (the read lives in cmd/risksignal as CLI-local
// code). When this seam is nil the /sources view renders an explicit
// "not configured" state; wiring it is a follow-up (reported to the
// orchestrator). It is presentation-only: it returns pre-built rows.
type SourceMonitor interface {
	Sources(ctx context.Context, actor application.Actor) ([]SourceMonitorEntry, error)
}

// SourceMonitorEntry is one source's monitor row (see SourceMonitor).
type SourceMonitorEntry struct {
	ID             string
	Name           string
	Type           string
	Status         string
	LastRunAt      string
	DataAge        string
	ErrorCount     int
	OpenQuarantine int
	Degraded       bool
}

// Options are the construction inputs of the web adapter.
type Options struct {
	// Service is the application surface (required).
	Service Service
	// Roles reads a user's roles for the role-dependent navigation (required).
	Roles RolesReader
	// Logger is the structured logger (required).
	Logger *slog.Logger
	// Clock is the injected clock (required).
	Clock Clock
	// Identity resolves the authenticated identity from the request context
	// (required) — wired to httpapi.IdentityFromContext by the composition
	// root, so the web adapter does not depend on the httpapi package.
	Identity func(ctx context.Context) (domain.Identity, bool)
	// SourceMonitor is the optional source-monitor read seam (see its doc).
	SourceMonitor SourceMonitor
	// Templates is the template tree rooted at the repository web/ directory
	// (paths "templates/..."), supplied by the composition root from the
	// embedded web/templates FS (required).
	Templates fs.FS
	// Assets is the asset tree rooted at the repository web/ directory (paths
	// "assets/..."), supplied by the composition root from the embedded
	// web/assets FS (required).
	Assets fs.FS
	// CookieSecure sets the Secure flag on the CSRF cookie (production).
	CookieSecure bool
}

// Web is the constructed web adapter.
type Web struct {
	svc      Service
	roles    RolesReader
	monitor  SourceMonitor
	logger   *slog.Logger
	clock    Clock
	identity func(ctx context.Context) (domain.Identity, bool)
	secure   bool

	templates *templateSet
	assetsFS  fs.FS

	csrfCookieName string
}

// New constructs the web adapter and parses the templates once.
func New(opts Options) (*Web, error) {
	if opts.Service == nil {
		panic("web: New: Service must not be nil")
	}
	if opts.Roles == nil {
		panic("web: New: Roles must not be nil")
	}
	if opts.Logger == nil {
		panic("web: New: Logger must not be nil")
	}
	if opts.Clock == nil {
		panic("web: New: Clock must not be nil")
	}
	if opts.Identity == nil {
		panic("web: New: Identity must not be nil")
	}
	if opts.Templates == nil {
		panic("web: New: Templates must not be nil")
	}
	if opts.Assets == nil {
		panic("web: New: Assets must not be nil")
	}
	templates, err := loadTemplates(opts.Templates)
	if err != nil {
		return nil, err
	}
	return &Web{
		svc:            opts.Service,
		roles:          opts.Roles,
		monitor:        opts.SourceMonitor,
		logger:         opts.Logger,
		clock:          opts.Clock,
		identity:       opts.Identity,
		secure:         opts.CookieSecure,
		templates:      templates,
		assetsFS:       opts.Assets,
		csrfCookieName: "_risksignal_csrf",
	}, nil
}

// Mounter binds a route pattern to a required permission (satisfied by
// *httpapi.PermissionGate), so the web routes carry the same per-route
// declaration as the API.
type Mounter interface {
	Mount(mux *http.ServeMux, pattern string, perm domain.Permission, h http.Handler)
}

// Register mounts every web route on mux behind the mounter's per-route
// permission declaration (ARCH-006 §3.1). The whole mux is already wrapped in
// the I5a authentication middleware by the composition root.
func (w *Web) Register(mux *http.ServeMux, m Mounter) {
	// Static assets (public — the HTML that references them is authenticated).
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(w.assets()))))

	// Reads.
	m.Mount(mux, "GET /{$}", domain.PermissionSignalsRead, http.HandlerFunc(w.handleDashboard))
	m.Mount(mux, "GET /signals", domain.PermissionSignalsRead, http.HandlerFunc(w.handleTriage))
	m.Mount(mux, "GET /signals/_sla", domain.PermissionSignalsRead, http.HandlerFunc(w.handleSLAFragment))
	m.Mount(mux, "GET /signals/{id}", domain.PermissionSignalsRead, http.HandlerFunc(w.handleSignalDetail))
	m.Mount(mux, "GET /sources", domain.PermissionSourcesManage, http.HandlerFunc(w.handleSourceMonitor))
	m.Mount(mux, "GET /inventory", domain.PermissionInventoryRead, http.HandlerFunc(w.handleInventory))
	m.Mount(mux, "GET /inventory/imports", domain.PermissionInventoryManage, http.HandlerFunc(w.handleInventoryImport))
	m.Mount(mux, "GET /admin/users", domain.PermissionUsersRolesManage, http.HandlerFunc(w.handleAdminUsers))
	m.Mount(mux, "GET /admin/roles", domain.PermissionUsersRolesManage, http.HandlerFunc(w.handleAdminRoles))

	// Signal commands.
	m.Mount(mux, "POST /signals/{id}/acknowledge", domain.PermissionSignalsTriage, http.HandlerFunc(w.handleAcknowledge))
	m.Mount(mux, "POST /signals/{id}/transition", domain.PermissionSignalsTriage, http.HandlerFunc(w.handleTransition))
	m.Mount(mux, "POST /signals/{id}/assign", domain.PermissionSignalsTriage, http.HandlerFunc(w.handleAssign))
	m.Mount(mux, "POST /signals/{id}/comment", domain.PermissionSignalsTriage, http.HandlerFunc(w.handleComment))
	m.Mount(mux, "POST /signals/{id}/override", domain.PermissionSignalsOverride, http.HandlerFunc(w.handleOverride))
	m.Mount(mux, "POST /signals/{id}/revert", domain.PermissionSignalsOverride, http.HandlerFunc(w.handleRevert))
	m.Mount(mux, "POST /signals/{id}/pause-sla", domain.PermissionSignalsTriage, http.HandlerFunc(w.handlePauseSLA))
	m.Mount(mux, "POST /signals/{id}/resume-sla", domain.PermissionSignalsTriage, http.HandlerFunc(w.handleResumeSLA))

	// Inventory import + administration.
	m.Mount(mux, "POST /inventory/imports", domain.PermissionInventoryManage, http.HandlerFunc(w.handleStageImport))
	m.Mount(mux, "POST /inventory/imports/{id}/commit", domain.PermissionInventoryManage, http.HandlerFunc(w.handleCommitImport))
	m.Mount(mux, "POST /admin/users/{id}/roles/grant", domain.PermissionUsersRolesManage, http.HandlerFunc(w.handleGrantRole))
	m.Mount(mux, "POST /admin/users/{id}/roles/revoke", domain.PermissionUsersRolesManage, http.HandlerFunc(w.handleRevokeRole))
	m.Mount(mux, "POST /admin/users/{id}/deactivate", domain.PermissionUsersRolesManage, http.HandlerFunc(w.handleDeactivateUser))
}
