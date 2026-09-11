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

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/epss"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/kev"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/nvd"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/platform/buildinfo"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
	"github.com/brunoxpera/risksignal/internal/platform/logging"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// buildNotifyPort assembles the notification channel dispatcher from the
// resolved configuration (D-006): the in-app surface is always present; the
// SMTP relay (Mailpit in the local environment) and the signed webhook join
// it only when the operator configured and enabled a target. An
// enabled-but-incomplete channel is a wiring error — the config validation
// already rejects that, so this is the defensive backstop.
func buildNotifyPort(cfg *config.Config) (notify.NotifyPort, error) {
	ports := map[notify.NotifyChannel]notify.NotifyPort{
		notify.ChannelInApp: notify.NewInAppPort(),
	}
	if cfg.Notify.SMTP.Enabled {
		port, err := notify.NewSMTPPort(notify.NetSMTPMailer{Addr: cfg.Notify.SMTP.Addr}, cfg.Notify.SMTP.From, cfg.Notify.SMTP.To)
		if err != nil {
			return nil, err
		}
		ports[notify.ChannelSMTP] = port
	}
	if cfg.Notify.Webhook.Enabled {
		port, err := notify.NewWebhookPort(cfg.Notify.Webhook.URL, cfg.Notify.Webhook.Secret, nil)
		if err != nil {
			return nil, err
		}
		ports[notify.ChannelWebhook] = port
	}
	return notify.NewDispatcher(ports), nil
}

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
	// scheduler cycle. Its dispatch registry is filled below by the job
	// handlers of the I2/I3/I4 work packages: the source.run job types
	// (source.fetch and source.normalize, WP-2.08 / DEV-042, ARCH-002 §5),
	// the matching job types (matching.rebuild, matching.recompute, ARCH-003),
	// the priority.recompute handler (ARCH-004 §5, WP-4.05), the sla.evaluate
	// scheduler's escalation/reminder events and the notify handler of the
	// I4 notification kinds (ARCH-004 §6.3, WP-4.06) — which replaced the
	// I1b signal.created no-op sink on the same registry key.
	q := gen.New(pool)
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), logger)
	if err != nil {
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
	//
	// The epss_history feeder (WP-3.10/DEV-053, ARCH-003 §7) runs on the
	// matching read surface (the rule state, the component walk and the
	// reverse pair read) so the EPSS run appends the observed history of the
	// inventory-relevant CVEs on the pass transaction.
	epssHistory, err := application.NewEpssHistoryLoader(
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q), repo.NewEpssHistoryRepo(q))
	if err != nil {
		return fmt.Errorf("configure epss history loader: %w", err)
	}
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
		Inventory:       repo.NewInventoryRepo(q),
		EpssHistory:     epssHistory,
		Clock:           clock.RealClock{},
		// The I4 triage/SLA + priority use cases (ARCH-004) run on the
		// postgres I4 repositories; the sla.evaluate scheduler reads the
		// injected reminder cadence (config, not table state). The worker
		// wires the triage/priority ports so the sla.evaluate scheduler and
		// the priority.recompute handler can drive them.
		SignalTriage:       repo.NewSignalRepo(q),
		SlaClocks:          repo.NewSlaClockRepo(q),
		PriorityRules:      repo.NewPriorityRuleRepo(q),
		FactorSource:       repo.NewPriorityFactorRepo(q),
		SLAReminderCadence: cfg.Worker.SLAReminderCadence,
		// The I6 operations ports (ARCH-007 §1.2/§2, WP-6.06 / DEV-118): the
		// export CRUD + streaming read + spool the export.generate job runs on,
		// and the retention repo the retention.execute handler and the monthly
		// dry-run scheduler drive. ExportTTL/ExportMaxRows come from the export
		// config (export.ttl/export.max_rows); the retention period, batch size
		// and pseudonymisation period come from the retention config
		// (retention.closed_signal_years/batch_size/pseudonymise_years, §10).
		Exports:                    repo.NewExportRepo(q),
		ExportStore:                export.NewSpool(cfg.Export.Dir),
		SignalExport:               repo.NewSignalExportSource(q),
		ExportTTL:                  cfg.Export.TTL,
		ExportMaxRows:              cfg.Export.MaxRows,
		Retention:                  repo.NewRetentionRepo(q),
		RetentionClosedSignalYears: cfg.Retention.ClosedSignalYears,
		RetentionBatchSize:         cfg.Retention.BatchSize,
		RetentionPseudonymiseYears: cfg.Retention.PseudonymiseYears,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
	adapters := map[application.SourceType]application.SourcePort{
		application.SourceTypeNVD:  nvd.New(nil),
		application.SourceTypeKEV:  kev.New(nil),
		application.SourceTypeEPSS: epss.New(nil, clock.RealClock{}),
	}
	// The run-loop metrics registry (DEV-043, ch. 16.2): the source job
	// handlers record every completed fetch/normalize pass on it — the
	// in-process substrate of the /metrics exposition of the later
	// iteration I6 (source status renders the durable projection).
	sourceJobs, err := worker.NewSourceJobs(svc, repo.NewSourceRepo(q), adapters, metrics.New(), logger)
	if err != nil {
		return fmt.Errorf("configure source jobs: %w", err)
	}
	if err := sourceJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure source jobs: %w", err)
	}

	// The matching job handlers (ARCH-003 §5, DEV-064/DEV-065) run the
	// WP-3.08 bulk matching runs on the application service (the matching
	// core) over the postgres matching read adapters: the rule state
	// (effective rules + version counters), the component reads (keyset
	// page walk, by-id candidate rows, the product index) and the
	// vulnerability-side reads (the cpe_config statement decomposition
	// and the reverse pair read). Registering them on the relay makes the
	// matching.rebuild row every inventory commit enqueues (DEV-060)
	// consumable — without the registration the row would dead-letter
	// ("no handler registered") and the committed inventory would never
	// match. matching.recompute rows (the WP-3.09 NVD incremental path)
	// are served by the same registry keys.
	matchingRunner, err := application.NewMatchingRunner(svc,
		repo.NewRuleRepo(q),
		repo.NewComponentRepo(q),
		repo.NewVulnerabilityMatchRepo(q),
		clock.RealClock{}, logger)
	if err != nil {
		return fmt.Errorf("configure matching runner: %w", err)
	}
	// The ARCH-004 §5 fan-in: a matching.recompute run enqueues a per-signal
	// priority.recompute for the affected signals through the application
	// service (the run commits its matches first, then the enqueue).
	matchingRunner.SetPriorityRecomputeFanIn(svc.EnqueuePriorityRecomputeForVulnerabilities)
	matchingJobs, err := worker.NewMatchingJobs(matchingRunner, logger)
	if err != nil {
		return fmt.Errorf("configure matching jobs: %w", err)
	}
	if err := matchingJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure matching jobs: %w", err)
	}

	// The priority.recompute job handler (ARCH-004 §5, WP-4.05) drives the
	// targeted recompute use case: the factors are rebuilt fresh, the effective
	// ruleset is evaluated and the changed-only persist writes nothing when
	// the input is unchanged. Registering it makes the rows the §5 fan-in
	// enqueues (a ruleset publish, a matching.recompute run) consumable.
	priorityJobs, err := worker.NewPriorityRecomputeJobs(svc, logger)
	if err != nil {
		return fmt.Errorf("configure priority recompute jobs: %w", err)
	}
	if err := priorityJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure priority recompute jobs: %w", err)
	}

	// The notify handler (ARCH-004 §6.3, WP-4.06) delivers the four
	// notification outbox kinds — signal.created, signal.escalated,
	// signal.reopen_proposed and reminder — through the NotifyPort: the
	// in-app row itself plus, for an active notification, the configured
	// SMTP relay (Mailpit in the local environment, D-004) and the signed
	// webhook. It replaced the I1b signal.created no-op sink: the channel
	// policy is config-derived (notify.*, D-006), delivery is keyed on the
	// immutable outbox event id (exactly one notification per event and
	// channel, FR-023) and a delivered P1 create/escalate fulfils the
	// signal's notification SLA clock. There is no production mail/webhook
	// target in I4 — the SMTP/webhook channels are enabled only when the
	// operator configures a target.
	notifyPort, err := buildNotifyPort(cfg)
	if err != nil {
		return fmt.Errorf("configure notify port: %w", err)
	}
	notifyJobs, err := worker.NewNotifyJobs(worker.NotifyJobsDeps{
		Notifications: repo.NewNotificationRepo(q),
		SlaClocks:     repo.NewSlaClockRepo(q),
		Port:          notifyPort,
		Policy: worker.NotifyPolicy{
			P2Active:       cfg.Notify.P2Active,
			SMTPEnabled:    cfg.Notify.SMTP.Enabled,
			SMTPTo:         cfg.Notify.SMTP.To,
			WebhookEnabled: cfg.Notify.Webhook.Enabled,
			WebhookURL:     cfg.Notify.Webhook.URL,
		},
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
		Clock:  clock.RealClock{},
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("configure notify jobs: %w", err)
	}
	if err := notifyJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure notify jobs: %w", err)
	}

	// The sla.evaluate scheduler (ARCH-004 §4.4, WP-4.05) runs the breach
	// evaluation on its configured cadence through the injected clock. The
	// cycle invokes Tick every worker cycle; the scheduler itself gates the
	// cadence on the clock, so a production worker evaluates once per
	// worker.sla_evaluate_interval minute and a test drives it with a
	// FakeClock without real waiting.
	slaSchedule, err := worker.NewSlaSchedule(svc, clock.RealClock{}, cfg.Worker.SLAEvaluateInterval, logger)
	if err != nil {
		return fmt.Errorf("configure sla scheduler: %w", err)
	}

	// The I6 export/retention jobs (ARCH-007 §1.2/§2.2, WP-6.06 / DEV-118): the
	// export.generate and retention.execute relay handlers (registered on the
	// same dispatch registry as the other job types) plus their two schedulers
	// — the daily export sweep and the monthly retention dry-run proposal. The
	// schedulers gate their cadence on the injected clock, so a production
	// worker sweeps once per worker.export_sweep_interval and proposes a
	// retention dry-run once per retention.schedule, while a test drives
	// them with a FakeClock without real waiting. Registering the handlers makes
	// the rows the CreateExport/ApproveRetentionRun commands enqueue consumable
	// — without them those rows would dead-letter ("no handler registered").
	exportJobs, err := worker.NewExportJobs(svc, svc, clock.RealClock{}, cfg.Worker.ExportSweepInterval, logger)
	if err != nil {
		return fmt.Errorf("configure export jobs: %w", err)
	}
	if err := exportJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure export jobs: %w", err)
	}
	retentionJobs, err := worker.NewRetentionJobs(svc, svc, clock.RealClock{}, cfg.Retention.Schedule, logger)
	if err != nil {
		return fmt.Errorf("configure retention jobs: %w", err)
	}
	if err := retentionJobs.RegisterHandlers(relay); err != nil {
		return fmt.Errorf("configure retention jobs: %w", err)
	}

	health := worker.NewHealth()
	// One scheduler cycle runs the source scan first (ARCH-002 §5: enqueue
	// the source.fetch jobs of the due schedule slots — the dedupe keys of
	// ch. 14.1 make repeated cycles no-ops), then drains the outbox so the
	// jobs enqueued by this very cycle — and by earlier cycles and manual
	// source run triggers — are claimed and delivered. A failing scan (a
	// database read/write failure) fails the cycle; sources whose schedule
	// string is not supported are skipped and logged, never fatal.
	cycle := func(ctx context.Context) error {
		res, err := svc.EnqueueDueSourceFetches(ctx)
		if err != nil {
			return err
		}
		if len(res.Skipped) > 0 {
			logger.Warn("source scheduling skipped sources with an unparsable schedule",
				slog.Any("source_ids", res.Skipped))
		}
		if res.Enqueued > 0 || res.AlreadyQueued > 0 {
			logger.Debug("source scheduling cycle",
				slog.Int("enqueued", res.Enqueued),
				slog.Int("already_queued", res.AlreadyQueued))
		}
		// The SLA breach evaluation runs before the drain so the escalation/
		// reminder events it enqueues this very cycle are claimed and delivered
		// by the same drain. Its own cadence gate makes the call a no-op on the
		// cycles that are not due.
		if err := slaSchedule.Tick(ctx); err != nil {
			return err
		}
		// The I6 cadences run before the drain: the daily export sweep reclaims
		// the expired spool artifacts and the monthly retention scheduler
		// proposes a dry-run. Both gate on the injected clock, so most cycles
		// are no-ops.
		if err := exportJobs.Sweep(ctx); err != nil {
			return err
		}
		if err := retentionJobs.Tick(ctx); err != nil {
			return err
		}
		return relay.Drain(ctx)
	}
	sched, err := worker.NewScheduler(cfg.Worker.Interval, clock.RealClock{}, logger, health, cycle)
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
