package worker

// The retention.execute job handler and the monthly retention scheduler
// (WP-6.06, ARCH-007 §2.2, ch. 14.1/14.2, DEV-118): the relay handler of the
// retention.execute job type plus the cadence-gated proposal of the monthly
// retention dry-run.
//
// retention.execute — the execution of one approved retention run: the handler
// decodes the job payload the ApproveRetentionRun command enqueued (dedupe key
// policy_id + cutoff + batch, §14.1, already settled by the outbox UQ) and
// drives the wired ExecuteRetention use case. The use case claims the approved
// run (approved -> executing, the lifecycle gate), re-scans the candidates at
// the run's cutoff and processes the non-held ones in bounded batches (the
// configured retention.batch_size), pseudonymising first and then deleting in
// the §2.3 referentially-safe order, one retention.executed audit event per
// batch. The run is resumable (a re-run re-scans and naturally skips the
// already-deleted rows) and a failing batch stops only that batch
// (failed_count++, last_error). An infrastructure failure of the run is
// reported as temporary — Retry leaves the row claimed and the expired lease
// redelivers it; a validation/not-found/conflict outcome (an unknown run, a
// missing approval) is permanent and dead-letters the job with the error text
// recorded.
//
// The scheduler proposes the monthly dry-run (ARCH-007 §2.2 step 1): on its
// configured cadence it drives the RunRetentionDryRun use case, storing a
// counts-only dry_run row for the Product Owner to approve. The scheduler owns
// no SQL and no retention rule — it is the cadence and the wiring of the use
// case onto the worker loop; it never deletes anything (only an approved run
// executes).
//
// The handlers and the scheduler carry no SQL: the work runs on the
// application service, injected at the composition root. Payloads carry
// identities and the frozen cutoff only — no business content (ch. 3.3,
// TR-013).

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

// Worker system-actor ids of the retention jobs (trusted internal principals,
// ARCH-005 §5: a system actor is not user-authorised and passes the gate).
const (
	// retentionExecuteActorID is the audit actor of a retention.execute run.
	retentionExecuteActorID = "retention-executor"
	// retentionScheduleActorID is the audit actor of the monthly dry-run
	// proposal.
	retentionScheduleActorID = "retention-scheduler"
)

// RetentionExecuteRunner is the application surface the retention.execute
// handler drives (ARCH-007 §2.2): the run-execution use case. The
// application-side *Service implements it; tests substitute a scripted fake.
type RetentionExecuteRunner interface {
	ExecuteRetention(ctx context.Context, in application.ExecuteRetentionInput) (application.ExecuteRetentionResult, error)
}

// RetentionDryRunRunner is the application surface the monthly scheduler
// drives (ARCH-007 §2.2 step 1): the dry-run proposal use case.
type RetentionDryRunRunner interface {
	RunRetentionDryRun(ctx context.Context, in application.RunRetentionDryRunInput) (application.RetentionDryRunResult, error)
}

// RetentionJobs is the dispatch state of the retention.execute handler and the
// monthly dry-run scheduler. It is safe for use from one goroutine (the relay
// dispatches sequentially and the scheduler cycle is serial); handlers are
// registered at wiring time, before the scheduler loop starts.
type RetentionJobs struct {
	runner RetentionExecuteRunner
	dryRun RetentionDryRunRunner
	clk    clock.Clock
	logger *slog.Logger

	// scheduleInterval is the monthly dry-run cadence; ran/lastRun gate it on
	// the injected clock (the first tick runs immediately).
	scheduleInterval time.Duration
	ran              bool
	lastRun          time.Time
}

// NewRetentionJobs assembles the retention.execute handler and the monthly
// scheduler. runner and dryRun must not be nil (a nil dependency is a wiring
// error reported here); scheduleInterval must be positive; a nil clock falls
// back to the real clock and a nil logger to a silent logger.
func NewRetentionJobs(runner RetentionExecuteRunner, dryRun RetentionDryRunRunner, clk clock.Clock, scheduleInterval time.Duration, logger *slog.Logger) (*RetentionJobs, error) {
	if runner == nil {
		return nil, fmt.Errorf("worker: retention jobs: runner must not be nil")
	}
	if dryRun == nil {
		return nil, fmt.Errorf("worker: retention jobs: dry-run runner must not be nil")
	}
	if scheduleInterval <= 0 {
		return nil, fmt.Errorf("worker: retention jobs: schedule interval must be positive (got %s)", scheduleInterval)
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &RetentionJobs{runner: runner, dryRun: dryRun, clk: clk, scheduleInterval: scheduleInterval, logger: logger}, nil
}

// RegisterHandlers binds the retention.execute handler to its outbox type on
// the relay's dispatch registry (ARCH-007 §2.2). A type that is already
// registered is a wiring error.
func (j *RetentionJobs) RegisterHandlers(relay *Relay) error {
	if err := relay.Register(application.EventTypeRetentionExecute, j.handle); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeRetentionExecute, err)
	}
	return nil
}

// handle delivers one retention.execute job: decode the payload the approval
// enqueued, execute the approved run and map the outcome onto the relay
// semantics. A delivered run is acked; a run failure is classified by its
// error kind.
func (j *RetentionJobs) handle(ctx context.Context, event ClaimedEvent) error {
	var payload application.RetentionExecutePayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("retention.execute: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.Type != application.EventTypeRetentionExecute {
		return fmt.Errorf("retention.execute: job payload type %q does not match the outbox type", payload.Type) // permanent
	}
	if payload.EventID == "" || payload.RunID == "" {
		return fmt.Errorf("retention.execute: job payload carries no event_id/run_id") // permanent
	}

	res, err := j.runner.ExecuteRetention(ctx, application.ExecuteRetentionInput{
		RunID:         payload.RunID,
		Actor:         application.Actor{Type: application.ActorTypeSystem, ID: retentionExecuteActorID},
		CorrelationID: payload.CorrelationID,
	})
	if err != nil {
		return classifyApplicationError(err)
	}
	j.logger.Info("retention.execute job delivered",
		slog.String("event_id", event.ID),
		slog.String("job_event_id", payload.EventID),
		slog.String("run_id", payload.RunID),
		slog.String("status", string(res.Status)),
		slog.Int("pseudonymised", res.Pseudonymised),
		slog.Int("deleted", res.Deleted),
		slog.Int("failed_batches", res.FailedBatches))
	return nil
}

// Tick runs one cadence-gated retention dry-run proposal (ARCH-007 §2.2
// step 1). The current instant is read through the injected clock; the tick is
// a no-op until one schedule interval has elapsed since the previous due tick
// (the first tick runs immediately). A due tick stores a counts-only dry_run
// row for the Product Owner to approve — it changes no domain state and
// deletes nothing; the returned error is the use case's, so the worker loop
// records a failed run but keeps beating.
func (j *RetentionJobs) Tick(ctx context.Context) error {
	now := j.clk.Now()
	if j.ran && now.Sub(j.lastRun) < j.scheduleInterval {
		return nil // cadence gate: not due on the injected clock yet
	}
	j.ran = true
	j.lastRun = now

	res, err := j.dryRun.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{
		Actor: application.Actor{Type: application.ActorTypeSystem, ID: retentionScheduleActorID},
	})
	if err != nil {
		return err
	}
	if res.Counts.Candidates > 0 || res.Counts.Held > 0 {
		j.logger.Info("retention dry-run proposed",
			slog.String("run_id", res.RunID),
			slog.Int("candidates", res.Counts.Candidates),
			slog.Int("held", res.Counts.Held))
	} else {
		j.logger.Debug("retention dry-run proposed (no due candidate)",
			slog.String("run_id", res.RunID))
	}
	return nil
}
