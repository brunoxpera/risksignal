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
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/metrics"
)

// Metric names of the source run-loop completion points (concept ch. 16.2,
// ARCH-002 §5, DEV-043): the worker records one sample per completed
// source.fetch/source.normalize pass on the in-process registry of
// internal/platform/metrics — the substrate of the later /metrics endpoint
// (I6). The values accumulate per process and are labelled per source
// (source_id + source_type); `source status` reports the same ch. 16.2
// names as current values measured from the database projection at read
// time. source_data_age_seconds is not recorded here — the worker would
// only ever observe the instant after a completed run; the durable data
// age is derived from the projection (a scrape-time computation of the I6
// endpoint / the status read).
const (
	metricSourceRunDurationSeconds = "source_run_duration_seconds" // duration of one completed pass
	metricSourceRecordsTotal       = "source_records_total"        // raw documents stored by fetch passes
	metricSourceErrorsTotal        = "source_errors_total"         // records isolated by normalize passes
	metricSourceRateLimited        = "source_rate_limited"         // latest fetch outcome was rate-limited
	metricEpssRowsTotal            = "epss_rows_total"             // rows loaded by epss normalize passes
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
// runner (application service), the source resolver, the type-keyed
// adapter registry the composition root owns and the optional metrics
// registry the handlers record their run-loop completion points on. It is
// safe for use from one goroutine (the relay dispatches sequentially);
// handlers are registered at wiring time, before the scheduler loop starts.
type SourceJobs struct {
	svc      SourceJobRunner
	sources  SourceResolver
	adapters map[application.SourceType]application.SourcePort
	metrics  *metrics.Registry // nil: run-loop metrics recording disabled
	logger   *slog.Logger
}

// NewSourceJobs assembles the source job handlers. svc and sources must not
// be nil; a nil adapter registry is a programming error reported here (an
// empty registry is allowed — a worker without sources simply dead-letters
// their jobs with a clear error). reg is the metrics registry the handlers
// record their completion points on; a nil reg disables the run-loop
// metrics recording (tests and registries that do not care). A nil logger
// falls back to a silent logger.
func NewSourceJobs(svc SourceJobRunner, sources SourceResolver, adapters map[application.SourceType]application.SourcePort, reg *metrics.Registry, logger *slog.Logger) (*SourceJobs, error) {
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
		metrics:  reg,
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

	// The run-loop completion point of one fetch half (ch. 16.2): the
	// pass duration is observed and the outcome recorded — a stored raw
	// document advances source_records_total, a rate-limited response sets
	// the source_rate_limited gauge (a non-rate-limited outcome clears it).
	started := time.Now()
	res, err := j.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: payload.SourceID, Adapter: adapter})
	labels := sourceMetricLabels(payload.SourceID, adapter.Type())
	if err != nil {
		j.observeFetchFailure(labels, started)
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
		j.observeFetchOutcome(labels, started, true, 0)
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
		j.observeFetchOutcome(labels, started, false, 0)
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
		j.observeFetchOutcome(labels, started, false, 0)
		return fmt.Errorf("source.fetch: run %s finished without a stored raw record and without a terminal no-op/rate-limit outcome", res.RunID)
	}
	j.observeFetchOutcome(labels, started, false, float64(res.Counters.Records))
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

	started := time.Now()
	res, err := j.svc.NormalizeSource(ctx, application.NormalizeSourceInput{
		RawRecordID: payload.RawRecordID,
		Adapter:     adapter,
	})
	labels := sourceMetricLabels(payload.SourceID, adapter.Type())
	if err != nil {
		j.observeNormalizeFailure(labels, started)
		return j.classify(err)
	}
	// The completion point of one normalise half (ch. 16.2): the pass
	// duration is observed and the committed counters recorded — the
	// isolated records advance source_errors_total, and an EPSS pass
	// advances epss_rows_total by the row count of the loaded daily set
	// (the pass's normalized counter, ARCH-002 §2.3).
	j.observeNormalizeOutcome(labels, started, res, adapter.Type() == application.SourceTypeEPSS)
	return nil
}

// sourceMetricLabels is the label set of one source's metric series: the
// source row id and its adapter type (identities only, no secrets).
func sourceMetricLabels(sourceID string, sourceType application.SourceType) metrics.Labels {
	return metrics.Labels{"source_id": sourceID, "source_type": string(sourceType)}
}

// observeFetchOutcome records the completion point of one fetch pass: the
// pass duration, the source_rate_limited gauge (set by the outcome — a
// rate-limited response sets it, every other outcome clears it) and the
// records the pass stored (source_records_total, 0 for no-op and
// rate-limited passes). All recording is skipped when the jobs run without
// a metrics registry.
func (j *SourceJobs) observeFetchOutcome(labels metrics.Labels, startedAt time.Time, rateLimited bool, storedRecords float64) {
	if j.metrics == nil {
		return
	}
	limited := 0.0
	if rateLimited {
		limited = 1
	}
	j.metrics.Seconds(metricSourceRunDurationSeconds, "duration of one completed source.fetch pass").With(labels).
		Observe(time.Since(startedAt).Seconds())
	j.metrics.Gauge(metricSourceRateLimited, "latest fetch outcome of the source was rate-limited").With(labels).
		Set(limited)
	if storedRecords > 0 {
		j.metrics.Counter(metricSourceRecordsTotal, "raw documents the source's fetch passes stored in this process").With(labels).
			Add(storedRecords)
	}
}

// observeFetchFailure records the duration of a fetch pass that failed
// (retried or dead-lettered): the duration is observed, the rate-limit
// gauge cleared (a failed pass is not a rate-limited outcome) and no
// records counter advanced.
func (j *SourceJobs) observeFetchFailure(labels metrics.Labels, startedAt time.Time) {
	if j.metrics == nil {
		return
	}
	j.metrics.Seconds(metricSourceRunDurationSeconds, "duration of one completed source.fetch pass").With(labels).
		Observe(time.Since(startedAt).Seconds())
	j.metrics.Gauge(metricSourceRateLimited, "latest fetch outcome of the source was rate-limited").With(labels).
		Set(0)
}

// observeNormalizeOutcome records the completion point of one normalise
// pass: the pass duration and the committed counters — the isolated
// records advance source_errors_total, and an EPSS pass (epss=true)
// advances epss_rows_total by the loaded row count (the pass's normalized
// counter).
func (j *SourceJobs) observeNormalizeOutcome(labels metrics.Labels, startedAt time.Time, res application.NormalizeSourceResult, epss bool) {
	if j.metrics == nil {
		return
	}
	j.metrics.Seconds(metricSourceRunDurationSeconds, "duration of one completed source.normalize pass").With(labels).
		Observe(time.Since(startedAt).Seconds())
	if res.Counters.Errors > 0 {
		j.metrics.Counter(metricSourceErrorsTotal, "records the source's normalize passes isolated in this process").With(labels).
			Add(float64(res.Counters.Errors))
	}
	if epss && res.Counters.Normalized > 0 {
		j.metrics.Counter(metricEpssRowsTotal, "rows the source's epss passes loaded in this process").With(labels).
			Add(float64(res.Counters.Normalized))
	}
}

// observeNormalizeFailure records the duration of a normalise pass that
// failed (retried or dead-lettered); no counters advance.
func (j *SourceJobs) observeNormalizeFailure(labels metrics.Labels, startedAt time.Time) {
	if j.metrics == nil {
		return
	}
	j.metrics.Seconds(metricSourceRunDurationSeconds, "duration of one completed source.normalize pass").With(labels).
		Observe(time.Since(startedAt).Seconds())
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
		// A source whose type has no registered adapter is a permanent
		// configuration gap (the composition root registers the adapters it
		// runs): classify it as a validation failure so the job dead-letters
		// with a clear error instead of retrying to the attempt cap.
		return nil, application.Validationf("source_jobs", "no source adapter registered for type %q (source %s)", desc.Type, sourceID)
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
