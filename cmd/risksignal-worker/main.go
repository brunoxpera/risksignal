// Command risksignal-worker runs the RiskSignal background worker.
//
// Process role per implementation concept ch. 4.1: source fetching,
// normalisation, matching, prioritisation, SLA escalation, retention, outbox
// and notifications. WP-1a.02: it loads and validates its configuration on
// startup (defaults -> optional JSON config file -> RISKSIGNAL_* environment
// variables) and prints a provenance summary; an invalid configuration exits
// 1 without starting. WP-1a.10: it then runs the scheduler loop of
// internal/adapters/worker — a heartbeat and one empty scheduler run per
// worker.interval (no job types yet), with worker health recording the
// heartbeat and the last successful run (concept ch. 16.3) and time read
// through the injectable clock port of internal/platform/clock (ch. 7.2,
// TR-009). SIGINT/SIGTERM shuts the loop down cleanly within a grace period.
// Job polling and dispatch land in later work packages (ch. 14).
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
	"github.com/xpera/risksignal/internal/adapters/worker"
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
	// The pool is opened for the job-processing work packages: no job type
	// exists yet (WP-1a.10), so nothing queries it, and it is lazy
	// (postgres.NewPool, WP-1a.05): a database that is down at startup must
	// not stop the worker — the heartbeat needs no database, and the pool
	// recovers on its own once the database is back.
	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("create database pool: %w", err)
	}
	defer pool.Close()

	health := worker.NewHealth()
	sched, err := worker.NewScheduler(cfg.Worker.Interval, clock.RealClock{}, logger, health)
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
