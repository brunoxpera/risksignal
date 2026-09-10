package worker

// The priority.recompute job handler (WP-4.05, ARCH-004 §5, ch. 14.1): the
// relay handler of the priority.recompute job type, registered on the outbox
// relay's type-keyed registry next to the matching handlers (matching.go), the
// source.run handlers (source.go) and the I1b signal.created sink (sink.go).
//
// The job is enqueued by the ARCH-004 §5 fan-in — a ruleset publish
// (batched over the open signals) and a matching.recompute run (per affected
// signal) — and the handler drives the wired RecomputePriority use case for
// the signal of the payload: the factors are rebuilt fresh, the effective
// ruleset is evaluated, and the changed-only persist writes nothing when the
// factor-set, the rule version and the result are unchanged (a closed signal
// emits a reopen proposal instead of being mutated). The handler carries no
// SQL: the use case runs on the application service, injected at the
// composition root. The payload carries identities and hashes only (signal
// id, rule version, input hash) — no secrets (ch. 3.3, TR-013).
//
// Delivery semantics reuse the relay's lease mechanics unchanged (ch. 14.2):
// an infrastructure failure of the recompute is a temporary failure — Retry
// leaves the row claimed and the expired lease redelivers it, and the
// changed-only persist plus the job's dedupe key make the re-run a no-op at
// the data level (TR-012). A malformed payload, an envelope mismatch or a
// validation/not-found outcome is permanent and dead-letters the job with the
// error text recorded.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/brunoxpera/risksignal/internal/application"
)

// PriorityRecomputeRunner is the application surface the priority.recompute
// handler drives (ARCH-004 §5): the targeted recompute use case of DEV-077.
// The application-side *Service implements it; tests substitute a scripted
// fake.
type PriorityRecomputeRunner interface {
	RecomputePriority(ctx context.Context, in application.RecomputePriorityInput) (application.RecomputePriorityResult, error)
}

// PriorityRecomputeJobs is the dispatch state of the priority.recompute job
// handler: the runner (the application-side recompute) and the logger. It is
// safe for use from one goroutine (the relay dispatches sequentially);
// handlers are registered at wiring time, before the scheduler loop starts.
type PriorityRecomputeJobs struct {
	runner PriorityRecomputeRunner
	logger *slog.Logger
}

// NewPriorityRecomputeJobs assembles the priority.recompute handler. runner
// must not be nil (a nil runner is a wiring error reported here); a nil logger
// falls back to a silent logger.
func NewPriorityRecomputeJobs(runner PriorityRecomputeRunner, logger *slog.Logger) (*PriorityRecomputeJobs, error) {
	if runner == nil {
		return nil, fmt.Errorf("worker: priority recompute jobs: runner must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &PriorityRecomputeJobs{runner: runner, logger: logger}, nil
}

// RegisterHandlers binds the priority.recompute handler to its outbox type on
// the relay's dispatch registry (ARCH-004 §5). A type that is already
// registered is a wiring error.
func (j *PriorityRecomputeJobs) RegisterHandlers(relay *Relay) error {
	if err := relay.Register(application.EventTypePriorityRecompute, j.handle); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypePriorityRecompute, err)
	}
	return nil
}

// handle delivers one priority.recompute job: decode the payload the fan-in
// enqueued, drive the recompute for the signal and map the outcome onto the
// relay semantics (see the package comment). A delivered recompute is acked; a
// run failure is classified by its error kind.
func (j *PriorityRecomputeJobs) handle(ctx context.Context, event ClaimedEvent) error {
	var payload application.PriorityRecomputePayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("priority.recompute: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.Type != application.EventTypePriorityRecompute {
		return fmt.Errorf("priority.recompute: job payload type %q does not match the outbox type", payload.Type) // permanent
	}
	if payload.EventID == "" || payload.SignalID == "" || payload.RuleVersion == "" {
		return errors.New("priority.recompute: job payload carries no event_id/signal_id/rule_version") // permanent
	}

	res, err := j.runner.RecomputePriority(ctx, application.RecomputePriorityInput{
		SignalID:      payload.SignalID,
		Actor:         application.Actor{Type: application.ActorTypeSystem, ID: application.ActorPriorityRecompute},
		CorrelationID: payload.CorrelationID,
	})
	if err != nil {
		return classifyApplicationError(err)
	}
	j.logger.Info("priority.recompute job delivered",
		slog.String("event_id", event.ID),
		slog.String("job_event_id", payload.EventID),
		slog.String("signal_id", payload.SignalID),
		slog.String("rule_version", payload.RuleVersion),
		slog.String("payload_input_hash", payload.InputHash),
		slog.String("result_input_hash", res.InputHash),
		slog.String("priority", string(res.Priority)),
		slog.Bool("changed", res.Changed),
		slog.Bool("reopen_proposed", res.ReopenProposed))
	return nil
}

// classifyApplicationError maps an application-layer error onto the relay's
// delivery semantics: an infrastructure error (database trouble) is temporary
// and retried after the lease expires (ch. 14.2); a validation, not-found or
// conflict outcome is permanent and dead-letters the job with the error text
// recorded. A bare non-application error is classified infrastructure by
// ErrorKindOf — the safe default.
func classifyApplicationError(err error) error {
	kind, _ := application.ErrorKindOf(err)
	if kind == application.KindInfra {
		return Retry(err)
	}
	return err
}
