package worker

// The outbox relay (WP-1b.06, ARCH-001 §2): each scheduler cycle executes
// one drain over the transactional outbox. A drain claims the bounded batch
// of due rows with the lease-based UPDATE ... FOR UPDATE SKIP LOCKED claim
// of outbox.sql (WP-1b.03), dispatches every claimed row to the handler
// registered for its type, acks claimed -> done on success, leaves a
// temporarily failed row claimed (the expired lease makes it re-claimable —
// at-least-once delivery, TAT-05) and dead-letters a permanently failed row
// or one past the ch. 14.2 attempt cap, recording the failure in
// last_error. Consumers stay idempotent on the immutable outbox.id
// (ch. 14.3), and the ack is guarded by status='claimed' in the store, so a
// redelivered event cannot double-ack.
//
// The relay owns no SQL: ClaimBatch, Ack and DeadLetter are a port
// (OutboxStore) implemented by the postgres adapter
// (internal/adapters/postgres/repo). Handlers are registered by outbox.type
// in a registry; the I1b registry carries the single signal.created sink
// (sink.go) — a no-op standing in for the I4 notification adapter, which
// grows onto the same registry key (ch. 14.3 notification.deliver).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

// claimBatchSize bounds one drain to the ARCH-001 §2 guide of 50 rows. The
// claim query skips rows another worker instance holds (FOR UPDATE SKIP
// LOCKED), so several workers can drain concurrently without a broker; a
// bounded batch keeps one cycle short and its leases fresh.
const claimBatchSize = 50

// maxAttempts is the ch. 14.2 attempt cap the relay applies to
// handler-reported temporary failures while the per-job-type retry
// configuration of ch. 14.2 (exponential backoff with jitter per job type)
// arrives with I2/I4. After this many delivery attempts a row that still
// fails is dead-lettered instead of being redelivered forever.
const maxAttempts = 5

// ClaimedEvent is one outbox row the drain claimed and must deliver. The
// store hands it over exactly as the claim returned it: the immutable
// outbox.id (the delivery idempotency key, ch. 14.3), the type
// discriminator the registry dispatches on, the opaque jsonb payload and
// the attempt counter incremented by the claim.
type ClaimedEvent struct {
	ID       string
	Type     string
	Payload  []byte
	Attempts int
}

// OutboxStore is the relay's port to the outbox table (ARCH-001 §2).
// ClaimBatch claims the bounded batch of rows due for delivery — pending
// rows whose available_at has passed and claimed rows whose lease has
// expired (the crash-recovery path, TAT-05) — returning them with attempts
// already incremented and a fresh lease. Ack completes a delivery
// (claimed -> done, guarded by status='claimed', so it is idempotent: a row
// that is no longer claimed is already terminal). DeadLetter marks a
// permanently failed delivery (claimed -> dead_letter) and records the
// error, equally guarded. The store decides the SQL; the relay decides the
// delivery semantics.
type OutboxStore interface {
	ClaimBatch(ctx context.Context, limit int) ([]ClaimedEvent, error)
	Ack(ctx context.Context, id string) error
	DeadLetter(ctx context.Context, id, lastError string) error
}

// Handler delivers one claimed outbox event to its destination. In I1b that
// is the signal.created sink (sink.go); I4 registers the real notification
// adapter on the same registry. The return value classifies the delivery:
//
//	nil          — delivered; the relay acks the row (claimed -> done).
//	Retry(err)   — temporary failure; the relay leaves the row claimed and
//	               the expired lease makes the next claim redeliver it
//	               (attempts + 1), up to maxAttempts.
//	other error  — permanent failure; the relay dead-letters the row now and
//	               records the error text in last_error.
type Handler func(ctx context.Context, event ClaimedEvent) error

// retryError marks a handler error as a temporary delivery failure.
type retryError struct{ err error }

func (e *retryError) Error() string { return "retry: " + e.err.Error() }

func (e *retryError) Unwrap() error { return e.err }

// Retry wraps a handler error as a temporary delivery failure: the relay
// redelivers the event after the lease expires instead of dead-lettering
// it. A nil error stays nil.
func Retry(err error) error {
	if err == nil {
		return nil
	}
	return &retryError{err: err}
}

// isRetryable reports whether err was marked temporary with Retry (possibly
// wrapped deeper in the handler's error chain).
func isRetryable(err error) bool {
	var target *retryError
	return errors.As(err, &target)
}

// Relay drains the transactional outbox: it owns the dispatch registry
// (outbox.type -> Handler), the drain loop over the claimed batch and the
// terminal transitions per handler outcome (ARCH-001 §2). It is safe for
// use from one goroutine; handlers are registered at wiring time, before
// the scheduler loop starts.
type Relay struct {
	store    OutboxStore
	logger   *slog.Logger
	handlers map[string]Handler // dispatch registry, keyed by outbox.type

	// Observability (ARCH-007 §5, WP-6.08 / DEV-120), both optional: the
	// in-process metrics registry the dispatch completion points are recorded
	// on and the tracer opening the job-dispatch span. Wired through
	// SetObservability at the composition root; nil disables each.
	reg    *metrics.Registry
	tracer *tracing.Tracer
}

// NewRelay builds an outbox relay on store. A nil logger falls back to a
// silent logger; a nil store is a programming error reported here.
func NewRelay(store OutboxStore, logger *slog.Logger) (*Relay, error) {
	if store == nil {
		return nil, fmt.Errorf("worker: outbox relay: store must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Relay{
		store:    store,
		logger:   logger,
		handlers: make(map[string]Handler),
	}, nil
}

// SetObservability wires the optional metrics registry and tracer the relay
// records job dispatch on (ARCH-007 §5, WP-6.08 / DEV-120). Either may be nil
// to disable that half. It is called once at the composition root, before the
// scheduler loop starts.
func (r *Relay) SetObservability(reg *metrics.Registry, tracer *tracing.Tracer) {
	r.reg = reg
	r.tracer = tracer
}

// Register binds handler to eventType in the dispatch registry. Registering
// the same type twice, an empty type or a nil handler is a wiring error.
func (r *Relay) Register(eventType string, handler Handler) error {
	if eventType == "" {
		return fmt.Errorf("worker: outbox relay: event type must not be empty")
	}
	if handler == nil {
		return fmt.Errorf("worker: outbox relay: handler for type %q must not be nil", eventType)
	}
	if _, exists := r.handlers[eventType]; exists {
		return fmt.Errorf("worker: outbox relay: a handler for type %q is already registered", eventType)
	}
	r.handlers[eventType] = handler
	return nil
}

// drainOutcome is the terminal handling of one claimed event: delivered
// (acked), dead-lettered, or left claimed for a later redelivery.
type drainOutcome int

const (
	outcomeDelivered drainOutcome = iota
	outcomeRetryLater
	outcomeDeadLettered
)

// Drain executes one outbox relay drain (ARCH-001 §2): claim the bounded
// batch of due rows, dispatch each to its registered handler and apply the
// terminal transition per outcome. A store failure aborts the drain and is
// returned unwrapped enough for the caller (the scheduler run) to record:
// rows that were claimed but not yet handled keep their fresh lease and are
// redelivered by a later claim once it expires — at-least-once, never lost.
// A nil return means every claimed event of the batch reached its terminal
// state (delivered, dead-lettered or left for redelivery).
func (r *Relay) Drain(ctx context.Context) error {
	events, err := r.store.ClaimBatch(ctx, claimBatchSize)
	if err != nil {
		return fmt.Errorf("worker: outbox relay: claim batch: %w", err)
	}
	if len(events) == 0 {
		return nil
	}
	if r.reg != nil {
		// Best-effort queue depth: the claimed batch of this drain (a lower
		// bound on the due backlog).
		r.reg.Gauge(metrics.NameJobsQueueDepth, metrics.HelpJobsQueueDepth).Set(float64(len(events)))
	}

	delivered, deadLettered := 0, 0
	for _, event := range events {
		outcome, err := r.dispatch(ctx, event)
		if err != nil {
			return err
		}
		switch outcome {
		case outcomeDelivered:
			delivered++
		case outcomeDeadLettered:
			deadLettered++
		}
	}
	r.logger.Info("outbox relay drain complete",
		slog.Int("claimed", len(events)),
		slog.Int("delivered", delivered),
		slog.Int("dead_lettered", deadLettered))
	return nil
}

// dispatch delivers one claimed event: look up the handler for its type,
// run it and apply the terminal transition per outcome. An error is
// returned only for a store failure; handler outcomes are terminal states
// of the row, not errors of the drain.
func (r *Relay) dispatch(ctx context.Context, event ClaimedEvent) (drainOutcome, error) {
	// The job-dispatch span (ARCH-007 §5, WP-6.08): the correlation id carried
	// by the job payload (when present) joins the request's trace and log
	// scope, so a request -> job -> audit trail shares one correlation id.
	if cid := correlationIDFromPayload(event.Payload); cid != "" {
		if _, ok := logging.CorrelationIDFrom(ctx); !ok {
			ctx = logging.WithCorrelationID(ctx, cid)
		}
	}
	var span *tracing.Span
	if r.tracer != nil {
		ctx, span = r.tracer.Start(ctx, "job.dispatch")
		span.SetAttr("job.type", event.Type)
		span.SetAttr("job.event_id", event.ID)
	}
	defer span.End() // nil-safe when no tracer is wired
	if r.reg != nil {
		r.reg.Counter(metrics.NameJobsAttemptsTotal, metrics.HelpJobsAttemptsTotal).Inc()
	}

	handler, ok := r.handlers[event.Type]
	if !ok {
		// An unknown type must not crash the drain: treat it as a permanent
		// delivery failure and dead-letter the row with a clear error.
		return r.deadLetter(ctx, event, fmt.Errorf("no handler registered for outbox type %q", event.Type))
	}
	if err := handler(ctx, event); err != nil {
		if isRetryable(err) && event.Attempts < maxAttempts {
			// Temporary failure below the attempt cap: leave the row
			// claimed. The expired lease makes the next claim redeliver it
			// (attempts + 1) — the at-least-once path of ARCH-001 §2.
			r.logger.Warn("outbox delivery failed; will retry after lease expiry",
				slog.String("event_id", event.ID),
				slog.String("event_type", event.Type),
				slog.Int("attempts", event.Attempts),
				slog.Any("error", err))
			return outcomeRetryLater, nil
		}
		// Permanent failure, or a temporary one past the attempt cap
		// (ch. 14.2): terminal.
		return r.deadLetter(ctx, event, err)
	}

	if err := r.store.Ack(ctx, event.ID); err != nil {
		return 0, fmt.Errorf("worker: outbox relay: ack %s: %w", event.ID, err)
	}
	r.logger.Debug("outbox event delivered",
		slog.String("event_id", event.ID),
		slog.String("event_type", event.Type),
		slog.Int("attempts", event.Attempts))
	return outcomeDelivered, nil
}

// correlationIDFromPayload reads the correlation_id field of a job payload
// (the signal-command envelope carries it; source jobs carry identities only).
// An absent or malformed payload yields "" — best-effort, never fatal.
func correlationIDFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var envelope struct {
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	return envelope.CorrelationID
}

// deadLetter marks event permanently failed: claimed -> dead_letter with
// the handler error text recorded as last_error (guarded in the store, so a
// terminal row is never overwritten).
func (r *Relay) deadLetter(ctx context.Context, event ClaimedEvent, cause error) (drainOutcome, error) {
	if err := r.store.DeadLetter(ctx, event.ID, cause.Error()); err != nil {
		return 0, fmt.Errorf("worker: outbox relay: dead-letter %s: %w", event.ID, err)
	}
	if r.reg != nil {
		r.reg.Counter(metrics.NameJobsDeadLettersTotal, metrics.HelpJobsDeadLettersTotal).Inc()
	}
	r.logger.Warn("outbox delivery failed permanently; dead-lettered",
		slog.String("event_id", event.ID),
		slog.String("event_type", event.Type),
		slog.Int("attempts", event.Attempts),
		slog.Any("error", cause))
	return outcomeDeadLettered, nil
}
