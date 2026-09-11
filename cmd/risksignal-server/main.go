// Command risksignal-server serves the RiskSignal REST API and web frontend.
//
// Process role per implementation concept ch. 4.1: REST API, web UI, OIDC
// sessions, synchronous use cases and health endpoints. WP-1a.02: it loads
// and validates its configuration on startup (defaults -> optional JSON
// config file -> RISKSIGNAL_* environment variables); an invalid
// configuration exits 1 without starting. WP-1a.06: it serves an
// http.ServeMux (ADR-008 — no router framework) wrapped in the httpapi
// middleware chain on http.addr, and shuts down gracefully on SIGINT/SIGTERM.
// WP-1a.07: it registers the System endpoints — GET /health/live, GET
// /health/ready and GET /version (concept ch. 10.2, 16.3) — and opens the
// database pool whose reachability the readiness endpoint reports. WP-1a.08:
// all process and request logging goes through the structured, redacting
// logger of internal/platform/logging (JSON in demo/production, text
// locally), carrying the uniform fields of concept ch. 16.1. WP-1b.08: the
// I1b signal reads of the generated API — GET /api/v1/signals and GET
// /api/v1/signals/{signal_id} (ARCH-001 §4, ADR-011) — are registered on
// the same mux as the System endpoints, behind the same middleware chain,
// and served by the application service built over the database pool.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/oidc"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/web"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/buildinfo"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
	"github.com/brunoxpera/risksignal/internal/platform/logging"
	webassets "github.com/brunoxpera/risksignal/web"
)

// shutdownGracePeriod is how long the server waits for in-flight requests
// after a shutdown signal before it gives up (WP-1a.06: clean shutdown with a
// grace period).
const shutdownGracePeriod = 10 * time.Second

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal-server: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())

	logger := logging.New(logging.Options{
		Service:     "risksignal-server",
		Version:     buildinfo.Current().Version,
		Environment: cfg.Env,
	})

	if err := serve(cfg, logger); err != nil {
		logger.Error("fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// serve runs the HTTP server on cfg.HTTP.Addr until a shutdown signal ends
// the process cleanly. It returns nil after a graceful shutdown, and an error
// for anything else (bind failure, serve failure, shutdown timeout).
func serve(cfg *config.Config, logger *slog.Logger) error {
	// The pool is lazy (postgres.NewPool, WP-1a.05/1a.07): pgx connects only
	// when a probe or query needs it, so a database that is down at startup
	// must not kill the server. Readiness reports the state instead — red
	// /health/ready, green /health/live (concept ch. 16.3) — and the pool
	// recovers on its own once the database is back.
	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("create database pool: %w", err)
	}
	defer pool.Close()

	handler, err := newHandler(cfg, pool, logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // slow-header protection
		IdleTimeout:       60 * time.Second,
		// net/http internals (e.g. panics that escape the chain) go through
		// the same redacting handler as everything else (WP-1a.08).
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	// Listen first so a bind failure is reported synchronously; "listening"
	// is only logged once the address is actually taken.
	ln, err := net.Listen("tcp", cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTP.Addr, err)
	}
	logger.Info("listening", slog.String("addr", ln.Addr().String()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil // Serve returned after Shutdown below
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining in-flight requests",
			slog.String("grace_period", shutdownGracePeriod.String()))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Info("shutdown complete")
		return nil
	}
}

// newHandler builds the route table of the server and wraps it in the
// WP-1a.06 middleware chain (correlation ID, access log, panic recovery,
// security headers, CSP, CORS off, body limit) plus the I5a authentication
// middleware (ARCH-005 §5). WP-1a.07 registers the System endpoints of
// concept ch. 10.2 on the ServeMux; WP-1b.08 registers the generated I1b
// signal reads of ARCH-001 §4 (GET /api/v1/signals and
// GET /api/v1/signals/{signal_id}) on the same mux behind the I5a per-route
// permission declaration (signals.read). WP-5b.06 mounts the server-rendered
// web adapter (ARCH-006 §3) on the same mux behind the same chain + auth
// middleware; any other path still 404s through the same chain, whose access
// log writes one structured record per request (WP-1a.08).
//
// The authentication middleware is built from the configuration: with the
// local bypass enabled it authenticates as the seeded dev principal (local
// mode + loopback bind, enforced by config.Validate); otherwise it verifies
// Bearer tokens through the OIDC verifier, and a misconfigured oidc.* fails
// here — before the process binds.
func newHandler(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) (http.Handler, error) {
	auth, err := buildAuthMiddleware(cfg, logger)
	if err != nil {
		return nil, err
	}

	svc := newSignalService(cfg, pool)

	mux := http.NewServeMux()
	// The per-route declaration gate runs the real checker (ARCH-005 §5): it
	// resolves the request's identity through the application's principal
	// resolution (the same authorise-time re-read the use case performs) and
	// applies the coarse permission decision. It is defense-in-depth — the
	// use-case authoriser remains the gate of record.
	gate := httpapi.NewPermissionGate(httpapi.NewIdentityPermissionChecker(svc, logger), logger)

	// Public routes (no identity): the operational probes, the build metadata.
	gate.Mount(mux, "GET /health/live", "", httpapi.LiveHandler())
	gate.Mount(mux, "GET /health/ready", "", httpapi.ReadyHandler(readinessProbes(cfg, pool)))
	gate.Mount(mux, "GET /version", "", httpapi.VersionHandler(buildinfo.Current()))

	// The I1b signal reads require signals.read, the I5a identity reveal
	// requires audit.reveal_identity (ARCH-005 §5, §7) and the I5a reference
	// command requires signals.triage/signals.override; each declaration is
	// bound at registration through the gate.
	gate.Declare("GET /api/v1/signals", domain.PermissionSignalsRead)
	gate.Declare("GET /api/v1/signals/{signal_id}", domain.PermissionSignalsRead)
	gate.Declare("POST /api/v1/audit-events/{id}/reveal-actor", domain.PermissionAuditRevealIdentity)
	// The I5a reference command endpoint (ARCH-005 §8) serves acknowledge
	// (signals.triage) and override_priority (signals.override); the
	// declaration documents the triage permission, the finer override gate
	// lives inside the use case (the gate of record).
	gate.Declare("POST /api/v1/signals/{signal_id}/commands", domain.PermissionSignalsTriage)
	// The I5b operations (ARCH-006 §2/§3.3) declare their per-route permission
	// here; the use case remains the gate of record. The staged inventory
	// import and the asset reads carry inventory.manage / inventory.read; the
	// user/role administration carries users.roles.manage.
	gate.Declare("POST /api/v1/inventory/imports", domain.PermissionInventoryManage)
	gate.Declare("GET /api/v1/inventory/imports/{id}", domain.PermissionInventoryManage)
	gate.Declare("POST /api/v1/inventory/imports/{id}/commit", domain.PermissionInventoryManage)
	gate.Declare("GET /api/v1/assets", domain.PermissionInventoryRead)
	gate.Declare("GET /api/v1/assets/{id}/components", domain.PermissionInventoryRead)
	gate.Declare("GET /api/v1/users", domain.PermissionUsersRolesManage)
	gate.Declare("GET /api/v1/roles", domain.PermissionUsersRolesManage)
	gate.Declare("PATCH /api/v1/users/{id}/roles", domain.PermissionUsersRolesManage)
	gate.Declare("POST /api/v1/users/{id}/deactivate", domain.PermissionUsersRolesManage)
	// The I6 operations (ARCH-007 §1.1/§2.1/§2.2) declare their per-route
	// permission here; the use case remains the gate of record. Exports carry
	// exports.create; the retention dry-run/reads/holds carry retention.manage
	// and the four-eyes deletion approval carries settings.approve (Product
	// Owner) — the ARCH-007 §9 reuse.
	gate.Declare("POST /api/v1/exports", domain.PermissionExportsCreate)
	gate.Declare("GET /api/v1/exports/{id}", domain.PermissionExportsCreate)
	gate.Declare("GET /api/v1/exports/{id}/download", domain.PermissionExportsCreate)
	gate.Declare("POST /api/v1/retention/runs", domain.PermissionRetentionManage)
	gate.Declare("GET /api/v1/retention/runs", domain.PermissionRetentionManage)
	gate.Declare("GET /api/v1/retention/runs/{id}", domain.PermissionRetentionManage)
	gate.Declare("POST /api/v1/retention/runs/{id}/approve", domain.PermissionSettingsApprove)
	gate.Declare("POST /api/v1/legal-holds", domain.PermissionRetentionManage)
	gate.Declare("GET /api/v1/legal-holds", domain.PermissionRetentionManage)
	gate.Declare("POST /api/v1/legal-holds/{id}/release", domain.PermissionRetentionManage)

	surfaces := httpapi.APISurfaces{
		Inventory:  svc,
		Assets:     svc,
		Users:      svc,
		Exports:    svc,
		Retention:  svc,
		LegalHolds: svc,
	}
	httpapi.RegisterAPIRoutes(gate.Decorate(mux), httpapi.NewAPIHandler(svc, svc, svc, logger, surfaces))

	// The server-rendered web adapter (ARCH-006 §3, WP-5b.06) is mounted on the
	// same mux behind the same middleware chain + I5a auth middleware: it calls
	// the application service in-process (no loopback API call), so it runs the
	// same use cases and the same in-command authoriser as the API. `gate`
	// carries the per-route permission declarations of the web routes.
	webUI, err := web.New(web.Options{
		Service:      svc,
		Roles:        repo.NewUserRepo(gen.New(pool)),
		Logger:       logger,
		Clock:        clock.RealClock{},
		Identity:     httpapi.IdentityFromContext,
		Templates:    webassets.Templates,
		Assets:       webassets.Assets,
		CookieSecure: cfg.Env == "production",
	})
	if err != nil {
		return nil, fmt.Errorf("web adapter: %w", err)
	}
	webUI.Register(mux, gate)

	// The inventory-import upload is bounded by InventoryMaxBytes (the I5b
	// staged CSV), not by the 1 MiB JSON default of the chain — for both the
	// API upload and the server-rendered web upload.
	return httpapi.NewHandlerWithAuth(mux, logger, auth,
		httpapi.BodyLimitOverride("POST /api/v1/inventory/imports", application.InventoryMaxBytes),
		httpapi.BodyLimitOverride("POST /inventory/imports", application.InventoryMaxBytes)), nil
}

// buildAuthMiddleware assembles the I5a authentication middleware from the
// configuration (ARCH-005 §2/§4/§5). With the local bypass enabled the dev
// principal is used and no OIDC verifier is required; otherwise the OIDC
// verifier is built from oidc.* — a misconfiguration (missing client id,
// unknown role mapping) is a startup error.
func buildAuthMiddleware(cfg *config.Config, logger *slog.Logger) (httpapi.Middleware, error) {
	opts := httpapi.AuthOptions{
		BypassEnabled:     cfg.Auth.BypassEnabled,
		BypassPrincipal:   cfg.Auth.BypassPrincipal,
		SessionCookieName: cfg.OIDC.SessionCookieName,
	}
	var verifier httpapi.TokenVerifier
	if !cfg.Auth.BypassEnabled {
		v, err := oidc.New(oidcAdapterConfig(cfg.OIDC))
		if err != nil {
			return nil, fmt.Errorf("oidc: %w", err)
		}
		verifier = oidcVerifier{v: v}
	}
	return httpapi.AuthenticationMiddleware(verifier, nil, opts), nil
}

// oidcAdapterConfig maps the platform oidc.* keys onto the OIDC adapter
// configuration (ARCH-005 §2). The role-mapping values are validated against
// the domain role vocabulary by the adapter's normalize step.
func oidcAdapterConfig(o config.OIDC) oidc.Config {
	var mappings map[string]domain.Role
	if len(o.RoleMappings) > 0 {
		mappings = make(map[string]domain.Role, len(o.RoleMappings))
		for claim, role := range o.RoleMappings {
			mappings[claim] = domain.Role(role)
		}
	}
	return oidc.Config{
		Issuer:       o.Issuer,
		ClientID:     o.ClientID,
		Audience:     o.Audience,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
		RolesClaim:   o.RolesClaim,
		RoleMappings: mappings,
	}
}

// oidcVerifier adapts *oidc.Verifier (which returns the OIDC Identity incl.
// the first-login role seed) onto the httpapi.TokenVerifier port
// (domain.Identity): the middleware authenticates only, so the role seed is
// intentionally dropped at this boundary — roles are re-read by the use case,
// never taken from the token (ARCH-005 §2/§5).
type oidcVerifier struct{ v *oidc.Verifier }

func (a oidcVerifier) Verify(ctx context.Context, rawToken string) (domain.Identity, error) {
	id, err := a.v.Verify(ctx, rawToken)
	if err != nil {
		return domain.Identity{}, err
	}
	return domain.Identity{SubjectID: id.SubjectID, DisplayName: id.DisplayName, Email: id.Email}, nil
}

// newSignalService assembles the application service behind the signal API
// (WP-1b.08, DEV-018): the server serves the read use cases, but the
// application service is one unit — every port of application.NewService is
// wired like in the other composition roots (cmd/risksignal demo), so the
// same service instance can grow the I4 command endpoints without a
// structural change. Construction touches no database: the pool connects
// lazily, so a stopped database keeps the server up and readiness reports
// it (the /api/v1 reads answer 500 problem details until the pool
// recovers).
func newSignalService(cfg *config.Config, pool *pgxpool.Pool) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          repo.NewOutboxRepo(q),
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		RawRecords:      repo.NewRawRecordRepo(q),
		Sources:         repo.NewSourceRepo(q),
		Quarantine:      repo.NewQuarantineRepo(q),
		Components:      repo.NewComponentRepo(q),
		Inventory:       repo.NewInventoryRepo(q),
		Users:           repo.NewUserRepo(q),
		// The I5b read/admin ports (ARCH-006 §2/§3.3, WP-5b.03/DEV-101): the
		// asset reads, the staged-import persistence (the DEV-099 review
		// follow-up adapter) and the user/role administration read models.
		Assets:           repo.NewAssetRepo(q),
		InventoryReader:  repo.NewInventoryRepo(q),
		InventoryImports: repo.NewInventoryImportRepo(q),
		UserAdmin:        repo.NewUserRepo(q),
		// The DEV-110 source-monitor read port (ARCH-006 §3.1): the
		// GET /sources projection of the latest run/data age/error
		// count/rate-limit flag/open quarantine count.
		SourceMonitor: repo.NewSourceMonitorRepo(q),
		// The I6 retention port (ARCH-007 §2/§3, WP-6.05 / DEV-116-117):
		// the candidate scan, the run lifecycle, the legal holds and the
		// in-place pseudonymisation/deletion primitives. DEV-117 wires the
		// postgres adapter so the retention use cases run end to end. The
		// export ports (Exports/ExportStore) back the POST /exports surface and
		// the time-limited download (WP-6.07); the retention period/batch/
		// pseudonymisation period come from the retention config (§10).
		Retention:                  repo.NewRetentionRepo(q),
		Exports:                    repo.NewExportRepo(q),
		ExportStore:                export.NewSpool(cfg.Export.Dir),
		RetentionClosedSignalYears: cfg.Retention.ClosedSignalYears,
		RetentionBatchSize:         cfg.Retention.BatchSize,
		RetentionPseudonymiseYears: cfg.Retention.PseudonymiseYears,
		// The I5a reference command endpoint (ARCH-005 §8) drives the I4
		// triage commands, so the server composition root wires the triage/
		// SLA/priority ports the use cases author and persist through.
		SignalTriage:  repo.NewSignalRepo(q),
		Comments:      repo.NewCommentRepo(q),
		SlaClocks:     repo.NewSlaClockRepo(q),
		PriorityRules: repo.NewPriorityRuleRepo(q),
		FactorSource:  repo.NewPriorityFactorRepo(q),
		Clock:         clock.RealClock{},
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// readinessProbes returns the readiness criteria of concept ch. 16.3 as the
// probe set of GET /health/ready: the database reachable through the pool,
// the schema migrations complete with verified checksums, and the mandatory
// configuration valid. External sources are deliberately not a criterion.
//
// Every probe returns an error whose text becomes the per-check reason in
// the readiness report, so reasons are operator-facing: they carry no
// credentials and no secret-bearing configuration content (the connection
// errors of pgx and migrate name host, user and database — never the
// password — and config validation already references keys only).
func readinessProbes(cfg *config.Config, pool *pgxpool.Pool) []httpapi.Probe {
	return []httpapi.Probe{
		{
			Name: "database",
			Check: func(ctx context.Context) error {
				return pool.Ping(ctx)
			},
		},
		{
			Name: "migrations",
			Check: func(ctx context.Context) error {
				// A dry run of the checksum-guarded runner (WP-1a.04,
				// ADR-010) is the read-only status check: it verifies that
				// every applied migration still matches its embedded file
				// and reports the pending ones. An error here means the
				// migration state cannot be trusted; pending migrations
				// mean the schema is behind this binary.
				runner, err := migrate.Open(ctx, cfg.Database.URL, migrations.FS)
				if err != nil {
					return fmt.Errorf("cannot inspect migration state: %w", err)
				}
				defer runner.Close()
				res, err := runner.Migrate(ctx, true)
				if err != nil {
					return fmt.Errorf("migration state not trustworthy: %w", err)
				}
				if len(res.Pending) > 0 {
					return fmt.Errorf("schema behind this binary: %d pending migration(s): %s",
						len(res.Pending), pendingNames(res.Pending))
				}
				return nil
			},
		},
		{
			Name: "config",
			Check: func(ctx context.Context) error {
				// Startup already refused an invalid configuration
				// (WP-1a.02); re-validating keeps the readiness contract
				// honest if a later work package ever adds reloading.
				if errs := config.Validate(cfg); len(errs) > 0 {
					return fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
				}
				return nil
			},
		},
	}
}

// pendingNames lists the pending migration file names, comma separated.
func pendingNames(pending []migrate.PendingMigration) string {
	names := make([]string, 0, len(pending))
	for _, p := range pending {
		names = append(names, p.Path)
	}
	return strings.Join(names, ", ")
}
