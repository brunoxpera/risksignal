package worker

// The export.generate job handler and the daily export sweep (WP-6.06,
// ARCH-007 §1.2, ch. 14.1/14.2, DEV-118): the relay handler of the
// export.generate job type, registered on the outbox relay's type-keyed
// registry next to the matching, priority, source and notify handlers, plus
// the cadence-gated sweep that reclaims the expired spool artifacts.
//
// export.generate — the asynchronous materialisation of one export: the
// handler decodes the job payload the CreateExport command enqueued (dedupe
// key export_id, already settled by the outbox UQ) and drives the wired
// GenerateExport use case. The use case loads the export row, streams the
// frozen filter through the SignalExportSource read, materialises CSV/JSON
// through the neutralising writer, writes the artifact into the spool and
// stamps the row 'completed' — idempotent on the export id and crash-safe (a
// redelivery regenerates and re-stamps). An infrastructure failure (a read or
// write trouble) is reported as temporary — Retry leaves the row claimed and
// the expired lease redelivers it; a validation/not-found/conflict outcome is
// permanent and dead-letters the job with the error text recorded. A
// generation failure records status='failed' + last_error inside the use case,
// so the failure stays visible after the dead-letter.
//
// The sweep is a scheduler, not an outbox job: on its configured daily
// cadence it expires the completed exports past their TTL, deleting the spool
// artifacts and marking the rows 'expired' (ARCH-007 §1.2). It owns no SQL and
// no format logic — it is the cadence and the wiring of the SweepExports use
// case onto the worker loop.
//
// The handlers and the sweep carry no SQL: the work runs on the application
// service, injected at the composition root. Job payloads carry identities
// only — no secrets (ch. 3.3, TR-013).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// ExportGenerateRunner is the application surface the export.generate handler
// drives (ARCH-007 §1.2): the export materialisation use case. The
// application-side *Service implements it; tests substitute a scripted fake.
type ExportGenerateRunner interface {
	GenerateExport(ctx context.Context, in application.GenerateExportInput) (application.GenerateExportResult, error)
}

// ExportSweepRunner is the application surface the export sweep drives
// (ARCH-007 §1.2): the expiry sweep use case.
type ExportSweepRunner interface {
	SweepExports(ctx context.Context) (application.SweepExportsResult, error)
}

// ExportJobs is the dispatch state of the export.generate handler and the
// daily sweep. It is safe for use from one goroutine (the relay dispatches
// sequentially and the scheduler cycle is serial); handlers are registered at
// wiring time, before the scheduler loop starts.
type ExportJobs struct {
	runner ExportGenerateRunner
	sweep  ExportSweepRunner
	clk    clock.Clock
	logger *slog.Logger

	// sweepInterval is the daily sweep cadence; ran/lastRun gate it on the
	// injected clock (the first tick runs immediately).
	sweepInterval time.Duration
	ran           bool
	lastRun       time.Time
}

// NewExportJobs assembles the export.generate handler and the sweep. runner
// and sweep must not be nil (a nil runner/sweep is a wiring error reported
// here); sweepInterval must be positive; a nil clock falls back to the real
// clock and a nil logger to a silent logger.
func NewExportJobs(runner ExportGenerateRunner, sweep ExportSweepRunner, clk clock.Clock, sweepInterval time.Duration, logger *slog.Logger) (*ExportJobs, error) {
	if runner == nil {
		return nil, fmt.Errorf("worker: export jobs: runner must not be nil")
	}
	if sweep == nil {
		return nil, fmt.Errorf("worker: export jobs: sweep runner must not be nil")
	}
	if sweepInterval <= 0 {
		return nil, fmt.Errorf("worker: export jobs: sweep interval must be positive (got %s)", sweepInterval)
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &ExportJobs{runner: runner, sweep: sweep, clk: clk, sweepInterval: sweepInterval, logger: logger}, nil
}

// RegisterHandlers binds the export.generate handler to its outbox type on the
// relay's dispatch registry (ARCH-007 §1.2). A type that is already registered
// is a wiring error.
func (j *ExportJobs) RegisterHandlers(relay *Relay) error {
	if err := relay.Register(application.EventTypeExportGenerate, j.handle); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeExportGenerate, err)
	}
	return nil
}

// handle delivers one export.generate job: decode the payload the CreateExport
// command enqueued, materialise the export and map the outcome onto the relay
// semantics. A delivered export is acked; a run failure is classified by its
// error kind.
func (j *ExportJobs) handle(ctx context.Context, event ClaimedEvent) error {
	var payload application.ExportGeneratePayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("export.generate: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.Type != application.EventTypeExportGenerate {
		return fmt.Errorf("export.generate: job payload type %q does not match the outbox type", payload.Type) // permanent
	}
	if payload.EventID == "" || payload.ExportID == "" {
		return fmt.Errorf("export.generate: job payload carries no event_id/export_id") // permanent
	}

	res, err := j.runner.GenerateExport(ctx, application.GenerateExportInput{
		ExportID:      payload.ExportID,
		CorrelationID: payload.CorrelationID,
	})
	if err != nil {
		return classifyApplicationError(err)
	}
	j.logger.Info("export.generate job delivered",
		slog.String("event_id", event.ID),
		slog.String("job_event_id", payload.EventID),
		slog.String("export_id", payload.ExportID),
		slog.String("status", string(res.Status)),
		slog.Bool("skipped", res.Skipped),
		slog.Int("row_count", res.RowCount),
		slog.Int64("size_bytes", res.SizeBytes))
	return nil
}

// Sweep runs one cadence-gated export expiry sweep. The current instant is
// read through the injected clock; the tick is a no-op until one sweep
// interval has elapsed since the previous due tick (the first tick runs
// immediately). A due tick expires the completed exports past their TTL; the
// returned error is the use case's, so the worker loop records a failed run
// but keeps beating.
func (j *ExportJobs) Sweep(ctx context.Context) error {
	now := j.clk.Now()
	if j.ran && now.Sub(j.lastRun) < j.sweepInterval {
		return nil // cadence gate: not due on the injected clock yet
	}
	j.ran = true
	j.lastRun = now

	res, err := j.sweep.SweepExports(ctx)
	if err != nil {
		return err
	}
	if res.Expired > 0 {
		j.logger.Info("export sweep complete", slog.Int("expired", res.Expired))
	} else {
		j.logger.Debug("export sweep complete (no expired export)")
	}
	return nil
}
