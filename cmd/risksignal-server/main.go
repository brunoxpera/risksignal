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

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/httpapi"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/buildinfo"
	"github.com/xpera/risksignal/internal/platform/clock"
	"github.com/xpera/risksignal/internal/platform/config"
	"github.com/xpera/risksignal/internal/platform/logging"
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

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           newHandler(cfg, pool, logger),
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
// security headers, CSP, CORS off, body limit). WP-1a.07 registers the
// System endpoints of concept ch. 10.2 on the ServeMux; WP-1b.08 registers
// the generated I1b signal reads of ARCH-001 §4 (GET /api/v1/signals and
// GET /api/v1/signals/{signal_id}) on the same mux — the application
// service over the database pool serves them, and the chain applies to
// them like to every other route. Every other path still 404s — through
// the same chain, whose access log writes one structured record per
// request (WP-1a.08).
func newHandler(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /health/live", httpapi.LiveHandler())
	mux.Handle("GET /health/ready", httpapi.ReadyHandler(readinessProbes(cfg, pool)))
	mux.Handle("GET /version", httpapi.VersionHandler(buildinfo.Current()))

	svc := newSignalService(pool)
	httpapi.RegisterSignalRoutes(mux, httpapi.NewSignalsHandler(svc, logger))
	return httpapi.NewHandler(mux, logger)
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
func newSignalService(pool *pgxpool.Pool) *application.Service {
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
		Clock:           clock.RealClock{},
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
