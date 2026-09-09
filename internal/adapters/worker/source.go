package worker

// The source job handlers (WP-2.08, ARCH-002 §5, ch. 14.1): the relay
// handlers of the two job types the source.run loop is made of —
// source.fetch and source.normalize — registered on the outbox relay's
// type-keyed registry alongside the I1b signal.created sink (relay.go).
//
// source.fetch — one fetch half of one source run: the handler resolves
// the source row and its adapter, runs the wired FetchSource use case
// (open run -> SourcePort.Fetch -> store the raw record -> commit
// cursor_after -> enqueue the source.normalize job of the stored record,
// all transactional) and maps the outcome onto the relay's delivery
// semantics. A delivered fetch is acked; a no-change full set (ch. 8.3) is
// a successful no-op and equally acked.
//
// Rate limits (ch. 14.2, ARCH-002 §2.1/§5): a rate-limited response is
// recorded on the run as rate-limited — never as a source technical error —
// and the handler reports it as a temporary failure (Retry), so the relay
// leaves the job claimed and the expired lease makes the next claim
// redeliver it. The job is never dead-lettered *as a source fault*; only
// the relay's generic ch. 14.2 attempt cap (maxAttempts, relay.go) can
// eventually dead-letter a job whose upstream stays rate-limited across
// repeated redeliveries — per-job-type retry configuration (backoff with
// jitter per Retry-After) is the documented I2/I4 follow-up. An
// infrastructure failure (upstream unreachable, database trouble) is
// equally temporary and retried; a validation or not-found outcome (source
// row gone, malformed cursor, adapter mismatch) is permanent and
// dead-letters the job with the error text recorded.
//
// source.normalize — one normalise half of one stored raw record: the
// handler resolves the raw record's source adapter and runs the wired
// NormalizeSource use case (open the run, stream the stored payload
// through the adapter's Normalize into the persistence sink, isolate
// RecordErrors into quarantine, commit counters and terminal status).
// Per-record failures never fail the handler — the use case counts and
// isolates them, and the run succeeds — so the job is acked; only an
// infrastructure failure of the pass (a failing sink write, a failing
// terminal commit) is retried, and a missing record/source is permanent.
//
// The handlers carry no SQL: the use cases run on the application service,
// the source row read (the adapter registry lookup key) runs through a
// SourceRepo implementation injected at the composition root, and the
// type-keyed adapter registry maps a source's type onto its SourcePort
// implementation (ARCH-002 §1: "the composition root owns the type-keyed
// registry"). Job payloads carry identities only (source ids, raw record
// ids, timestamps) — no secrets (ch. 3.3, TR-013).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/xpera/risksignal/internal/application"
)

// SourceJobRunner is the application surface the source job handlers drive
// (ARCH-002 §5): the split fetch/normalise halves of the source run loop.
// *application.Service implements it; tests substitute a scripted fake.
type SourceJobRunner interface {
	FetchSource(ctx context.Context, in application.FetchSourceInput) (application.FetchSourceResult, error)
	NormalizeSource(ctx context.Context, in application.NormalizeSourceInput) (application.NormalizeSourceResult, error)
}

// SourceResolver resolves the sources row of a job to its adapter type —
// the read the handlers need to look the source's adapter up in the
// registry. The postgres SourceRepo implementation satisfies it.
type SourceResolver interface {
	GetByID(ctx context.Context, id string) (application.SourceDescriptor, error)
}

// SourceJobs is the dispatch state of the two source job handlers: the
// runner (application service), the source resolver and the type-keyed
// adapter registry the composition root owns. It is safe for use from one
// goroutine (the relay dispatches sequentially); handlers are registered at
// wiring time, before the scheduler loop starts.
type SourceJobs struct {
	svc      SourceJobRunner
	sources  SourceResolver
	adapters map[application.SourceType]application.SourcePort
	logger   *slog.Logger
}

// NewSourceJobs assembles the source job handlers. svc and sources must not
// be nil; a nil adapter registry is a programming error reported here (an
// empty registry is allowed — a worker without sources simply dead-letters
// their jobs with a clear error). A nil logger falls back to a silent
// logger.
func NewSourceJobs(svc SourceJobRunner, sources SourceResolver, adapters map[application.SourceType]application.SourcePort, logger *slog.Logger) (*SourceJobs, error) {
	if svc == nil {
		return nil, fmt.Errorf("worker: source jobs: runner must not be nil")
	}
	if sources == nil {
		return nil, fmt.Errorf("worker: source jobs: source resolver must not be nil")
	}
	if adapters == nil {
		return nil, fmt.Errorf("worker: source jobs: adapter registry must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &SourceJobs{
		svc:      svc,
		sources:  sources,
		adapters: adapters,
		logger:   logger,
	}, nil
}

// RegisterHandlers binds the source.fetch and source.normalize handlers to
// their outbox types on the relay's dispatch registry (ARCH-002 §5). A
// type that is already registered is a wiring error.
func (j *SourceJobs) RegisterHandlers(relay *Relay) error {
	if err := relay.Register(application.EventTypeSourceFetch, j.handleFetch); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeSourceFetch, err)
	}
	if err := relay.Register(application.EventTypeSourceNormalize, j.handleNormalize); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeSourceNormalize, err)
	}
	return nil
}

// handleFetch delivers one source.fetch job: resolve the source's adapter,
// run the fetch half and map the outcome onto the relay semantics (see the
// package comment).
func (j *SourceJobs) handleFetch(ctx context.Context, event ClaimedEvent) error {
	var payload application.SourceFetchJobPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("source.fetch: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.SourceID == "" {
		return errors.New("source.fetch: job payload carries no source_id") // permanent
	}
	adapter, err := j.adapterFor(ctx, payload.SourceID)
	if err != nil {
		return j.classify(err)
	}

	res, err := j.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: payload.SourceID, Adapter: adapter})
	if err != nil {
		return j.classify(err)
	}
	if res.Meta.RateLimited {
		// ch. 14.2/ARCH-002 §5: the run is recorded rate-limited (its error
		// text is the stable fetch.rate_limited code) and the job is left
		// claimed — Retry makes the relay redeliver it after the lease
		// expires instead of dead-lettering it as a source fault. The
		// relay's lease governs the redelivery timing; honouring the exact
		// Retry-After backoff is the per-job-type retry configuration of
		// I2/I4.
		j.logger.Warn("source.fetch rate-limited; will retry after lease expiry",
			slog.String("event_id", event.ID),
			slog.String("source_id", payload.SourceID),
			slog.String("run_id", res.RunID),
			slog.String("retry_after", res.Meta.RetryAfter.String()))
		return Retry(fmt.Errorf("source.fetch: rate-limited (run %s)", res.RunID))
	}
	if res.Meta.NoChange {
		// An unchanged full set is a successful no-op run (ch. 8.3): the
		// job is delivered.
		j.logger.Debug("source.fetch no-change run delivered",
			slog.String("event_id", event.ID),
			slog.String("source_id", payload.SourceID),
			slog.String("run_id", res.RunID))
		return nil
	}
	if res.RawRecordID == "" {
		// A fetch that neither errored, rate-limited nor reported no-change
		// must have stored a raw record — anything else is a use-case
		// contract violation and is permanent.
		return fmt.Errorf("source.fetch: run %s finished without a stored raw record and without a terminal no-op/rate-limit outcome", res.RunID)
	}
	return nil
}

// handleNormalize delivers one source.normalize job: resolve the source's
// adapter and run the normalise half (see the package comment).
func (j *SourceJobs) handleNormalize(ctx context.Context, event ClaimedEvent) error {
	var payload application.SourceNormalizeJobPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("source.normalize: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.RawRecordID == "" || payload.SourceID == "" {
		return errors.New("source.normalize: job payload carries no raw_record_id/source_id") // permanent
	}
	adapter, err := j.adapterFor(ctx, payload.SourceID)
	if err != nil {
		return j.classify(err)
	}

	if _, err := j.svc.NormalizeSource(ctx, application.NormalizeSourceInput{
		RawRecordID: payload.RawRecordID,
		Adapter:     adapter,
	}); err != nil {
		return j.classify(err)
	}
	return nil
}

// adapterFor resolves the adapter of a job's source row: the source row's
// type selects the registered SourcePort implementation (ARCH-002 §1). A
// missing source row or a source type without a registered adapter is a
// permanent failure of the job.
func (j *SourceJobs) adapterFor(ctx context.Context, sourceID string) (application.SourcePort, error) {
	desc, err := j.sources.GetByID(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	adapter, ok := j.adapters[desc.Type]
	if !ok {
		return nil, fmt.Errorf("no source adapter registered for type %q (source %s)", desc.Type, sourceID)
	}
	return adapter, nil
}

// classify maps an application-layer error of the use cases onto the
// relay's delivery semantics: an infrastructure error (upstream network,
// database trouble) is temporary and retried after the lease expires; a
// validation, not-found or conflict outcome is permanent and dead-letters
// the job with the error text recorded (ch. 5.2). A bare non-application
// error is classified infrastructure by ErrorKindOf — the safe default.
func (j *SourceJobs) classify(err error) error {
	kind, _ := application.ErrorKindOf(err)
	if kind == application.KindInfra {
		return Retry(err)
	}
	return err
}
