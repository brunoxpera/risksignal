// Command risksignal-worker runs the RiskSignal background worker.
//
// Process role per implementation concept ch. 4.1: source fetching,
// normalisation, matching, prioritisation, SLA escalation, retention, outbox
// and notifications. WP-1a.02: it loads and validates its configuration on
// startup (defaults -> optional JSON config file -> RISKSIGNAL_* environment
// variables) and prints a provenance summary; an invalid configuration exits
// 1 without starting. WP-1a.10 + WP-1b.06: it then runs the scheduler loop
// of internal/adapters/worker — a heartbeat and one scheduler run per
// worker.interval, where the run is the outbox relay drain of ARCH-001 §2:
// the loop claims the due outbox batch (lease-based, SKIP LOCKED),
// dispatches every row to the handler registered for its type and acks or
// dead-letters each row. WP-2.08 (DEV-042) extends the dispatch registry
// with the source.run job types of ARCH-002 §5 — source.fetch and
// source.normalize — driven through the application service on the same
// database pool (the signal.created sink of I1b stays registered). Worker
// health records the heartbeat and the last successful run (concept ch.
// 16.3) and time is read through the injectable clock port of
// internal/platform/clock (ch. 7.2, TR-009). SIGINT/SIGTERM shuts the loop
// down cleanly within a grace period. Further job types land in later work
// packages (ch. 14).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/adapters/sources/epss"
	"github.com/xpera/risksignal/internal/adapters/sources/kev"
	"github.com/xpera/risksignal/internal/adapters/sources/nvd"
	"github.com/xpera/risksignal/internal/adapters/worker"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/buildinfo"
	"github.com/xpera/risksignal/internal/platform/clock"
	"github.com/xpera/risksignal/internal/platform/config"
	"github.com/xpera/risksignal/internal/platform/logging"
)

// shutdownGracePeriod bounds the worker shutdown (WP-1a.10: clean shutdown
// with a grace period): after a shutdown signal the scheduler stops
// scheduling and the process waits up to this long for an in-flight
// scheduler run before it gives up — the same convention as
// cmd/risksignal-server.
const shutdownGracePeriod = 10 * time.Second

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal-worker: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())

	logger := logging.New(logging.Options{
		Service:     "risksignal-worker",
		Version:     buildinfo.Current().Version,
		Environment: cfg.Env,
	})

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run wires the scheduler (WP-1a.10) and blocks until SIGINT/SIGTERM ends
// the process cleanly. It returns nil after a graceful shutdown and an
// error for anything else (wiring failure, shutdown grace period exceeded).
func run(cfg *config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, cfg, logger)
}

// runWithContext runs the scheduler until ctx is cancelled, then shuts the
// process resources down cleanly. It is separated from run so the
// composition-root tests can drive the shutdown without sending signals to
// the test process.
func runWithContext(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// The pool backs the outbox relay store. It is lazy (postgres.NewPool,
	// WP-1a.05): a database that is down at startup must not stop the worker
	// — the heartbeat needs no database, the drain fails per cycle until the
	// pool recovers on its own, and the loop stays alive either way
	// (ch. 16.3).
	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("create database pool: %w", err)
	}
	defer pool.Close()

	// The outbox relay (WP-1b.06, ARCH-001 §2) executes one drain per
	// scheduler cycle. Its dispatch registry carries the I1b signal.created
	// sink — a no-op standing in for the I4 notification adapter, which
	// grows onto the same registry key in I4 (ch. 14.3
	// notification.deliver) — and, since WP-2.08 (DEV-042, ARCH-002 §5),
	// the source.run job types: source.fetch and source.normalize, driven
	// through the application service below.
	q := gen.New(pool)
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), logger)
	if err != nil {
		return fmt.Errorf("configure outbox relay: %w", err)
	}
	if err := relay.Register(application.EventTypeSignalCreated, worker.SignalCreatedSink(logger)); err != nil {
		return fmt.Errorf("configure outbox relay: %w", err)
	}

	// The source job handlers (ARCH-002 §5) run on the application service
	// — the same composition the server and CLI roots use, with the real
	// clock and postgres.WithTx as the transaction boundary — and on the
	// type-keyed adapter registry of the I2 HTTP sources. The adapters are
	// endpoint-less on purpose: the base URL of every fetch arrives through
	// the resolved sources row (ARCH-002 §1), so one adapter instance per
	// type serves every configured source of that type, and the standard
	// transports reach the public endpoints. The pool is lazy (WP-1a.05):
	// a database that is down at startup must not stop the worker — the
	// heartbeat needs no database and every database-touching step fails
	// per cycle until the pool recovers on its own.
	svc := application.NewService(application.ServiceDeps{
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
	adapters := map[application.SourceType]application.SourcePort{
		application.SourceTypeNVD:  nvd.New(nil),
		application.SourceTypeKEV:  kev.New(nil),
		application.SourceTypeEPSS: epss.New(nil, clock.RealClock{}),
	}
	sourceJobs, err := worker.NewSourceJobs(svc, repo.NewSourceRepo(q), adapters, logger)
	if err != nil {
		return fmt.Errorf("configure source jobs: %w", err)
	}
	if err := sourceJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure source jobs: %w", err)
	}

	health := worker.NewHealth()
	sched, err := worker.NewScheduler(cfg.Worker.Interval, clock.RealClock{}, logger, health, relay.Drain)
	if err != nil {
		return fmt.Errorf("configure scheduler: %w", err)
	}

	schedErr := make(chan error, 1)
	go func() { schedErr <- sched.Run(ctx) }()

	select {
	case err := <-schedErr:
		// The scheduler ended itself (a future fatal loop error); nothing
		// to drain.
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received; stopping scheduler",
			slog.String("grace_period", shutdownGracePeriod.String()))
		select {
		case err := <-schedErr:
			if err != nil {
				return err
			}
			logger.Info("shutdown complete")
			return nil
		case <-time.After(shutdownGracePeriod):
			return fmt.Errorf("graceful shutdown: scheduler still running after %s", shutdownGracePeriod)
		}
	}
}
