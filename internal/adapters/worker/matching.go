package worker

// The matching job handlers (WP-3.08, ARCH-003 §5, ch. 14.1/14.2,
// DEV-064): the relay handlers of the two matching job types —
// matching.rebuild and matching.recompute — registered on the outbox
// relay's type-keyed registry next to the I1b signal.created sink
// (sink.go) and the source.run handlers of WP-2.08 (source.go).
//
// matching.rebuild — one inventory-driven recomputation of the whole
// match set (initial import, rule change): the handler decodes the job
// payload the inventory commit enqueued (DEV-060; dedupe key
// matching.rebuild:<rule_version>:<inventory_snapshot>, already settled
// by the outbox UQ) and drives the wired RebuildMatching run — the
// components walked in bounded batches, every component's candidate CVEs
// resolved through the reverse candidate pre-filter (ADR-012: no
// CVE-driven fan-out) and committed through the idempotent match insert.
//
// matching.recompute — one pre-filtered CVE batch (guide 500 ids) of the
// incremental evidence path (new NVD evidence whose affected products
// have inventory relevance; the WP-3.09 enqueue side): the handler
// decodes the batch payload and drives the wired RecomputeMatching run,
// which resolves each CVE's candidate components through the WP-3.07
// candidate pre-filter and commits their matches.
//
// Rate of progress is bounded by construction (ARCH-003 §5): the runs
// commit in batches of matchingBatchSize via the DEV-063 core, so a
// drain stays short and a crash resumes at the next batch. Delivery
// semantics reuse the relay's lease mechanics unchanged (ch. 14.2,
// ARCH-001 §2): an infrastructure failure of a run (a read or write
// trouble) is reported as a temporary failure — Retry leaves the row
// claimed and the expired lease redelivers it (attempts + 1), so a
// crashed run is re-claimed and re-run; the idempotent match insert (UQ
// (vulnerability_id, component_id, rule_version)) plus the job's dedupe
// key make the re-run a no-op at the data level (TR-012). A malformed
// payload, an envelope mismatch or a validation/not-found outcome of the
// run is permanent and dead-letters the job with the error text
// recorded; the relay's generic attempt cap (maxAttempts) bounds the
// retries of a persistently failing run.
//
// The handlers carry no SQL: the runs execute on the application-side
// MatchingRunner (internal/application), injected at the composition
// root. Job payloads carry identities and hashes only (rule versions,
// snapshot hashes, vulnerability ids, timestamps) — no secrets
// (ch. 3.3, TR-013).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/xpera/risksignal/internal/application"
)

// MatchingJobRunner is the application surface the matching job handlers
// drive (ARCH-003 §5): the two bulk matching runs of WP-3.08. The
// application-side *MatchingRunner implements it; tests substitute a
// scripted fake.
type MatchingJobRunner interface {
	RebuildMatching(ctx context.Context, in application.RebuildMatchingInput) (application.RebuildMatchingResult, error)
	RecomputeMatching(ctx context.Context, in application.RecomputeMatchingInput) (application.RecomputeMatchingResult, error)
}

// MatchingJobs is the dispatch state of the two matching job handlers:
// the runner (the application-side matching runs) and the logger. It is
// safe for use from one goroutine (the relay dispatches sequentially);
// handlers are registered at wiring time, before the scheduler loop
// starts.
type MatchingJobs struct {
	runner MatchingJobRunner
	logger *slog.Logger
}

// NewMatchingJobs assembles the matching job handlers. runner must not be
// nil (a nil runner is a wiring error reported here); a nil logger falls
// back to a silent logger.
func NewMatchingJobs(runner MatchingJobRunner, logger *slog.Logger) (*MatchingJobs, error) {
	if runner == nil {
		return nil, fmt.Errorf("worker: matching jobs: runner must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &MatchingJobs{runner: runner, logger: logger}, nil
}

// RegisterHandlers binds the matching.rebuild and matching.recompute
// handlers to their outbox types on the relay's dispatch registry
// (ARCH-003 §5). A type that is already registered is a wiring error.
func (j *MatchingJobs) RegisterHandlers(relay *Relay) error {
	if err := relay.Register(application.EventTypeMatchingRebuild, j.handleRebuild); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeMatchingRebuild, err)
	}
	if err := relay.Register(application.EventTypeMatchingRecompute, j.handleRecompute); err != nil {
		return fmt.Errorf("worker: register %s handler: %w", application.EventTypeMatchingRecompute, err)
	}
	return nil
}

// handleRebuild delivers one matching.rebuild job: decode the payload the
// inventory commit enqueued, run the inventory-driven rebuild and map the
// outcome onto the relay semantics (see the package comment). A delivered
// rebuild is acked; a run failure is classified by its error kind.
func (j *MatchingJobs) handleRebuild(ctx context.Context, event ClaimedEvent) error {
	var payload application.MatchingRebuildPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("matching.rebuild: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.Type != application.EventTypeMatchingRebuild {
		return fmt.Errorf("matching.rebuild: job payload type %q does not match the outbox type", payload.Type) // permanent
	}
	if payload.EventID == "" || payload.RuleVersion == "" || payload.InventorySnapshot == "" {
		return errors.New("matching.rebuild: job payload carries no event_id/rule_version/inventory_snapshot") // permanent
	}

	res, err := j.runner.RebuildMatching(ctx, application.RebuildMatchingInput{
		RuleVersion:       payload.RuleVersion,
		InventorySnapshot: payload.InventorySnapshot,
	})
	if err != nil {
		return j.classify(err)
	}
	j.logger.Info("matching.rebuild job delivered",
		slog.String("event_id", event.ID),
		slog.String("job_event_id", payload.EventID),
		slog.String("import_id", payload.ImportID),
		slog.String("correlation_id", payload.CorrelationID),
		slog.String("rule_version", payload.RuleVersion),
		slog.String("inventory_snapshot", payload.InventorySnapshot),
		slog.Int("components", res.Components),
		slog.Int("candidates", res.Candidates),
		slog.Int("transactions", res.Transactions))
	return nil
}

// handleRecompute delivers one matching.recompute job: decode the
// pre-filtered CVE batch payload, run the batch and map the outcome onto
// the relay semantics. A delivered recompute is acked; a run failure is
// classified by its error kind.
func (j *MatchingJobs) handleRecompute(ctx context.Context, event ClaimedEvent) error {
	var payload application.MatchingRecomputePayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("matching.recompute: decode job payload: %w", err) // permanent: malformed payload
	}
	if payload.Type != application.EventTypeMatchingRecompute {
		return fmt.Errorf("matching.recompute: job payload type %q does not match the outbox type", payload.Type) // permanent
	}
	if payload.EventID == "" || payload.RuleVersion == "" {
		return errors.New("matching.recompute: job payload carries no event_id/rule_version") // permanent
	}

	res, err := j.runner.RecomputeMatching(ctx, application.RecomputeMatchingInput{
		VulnerabilityIDs: payload.VulnerabilityIDs,
		ComponentScope:   payload.ComponentScope,
		RuleVersion:      payload.RuleVersion,
	})
	if err != nil {
		return j.classify(err)
	}
	j.logger.Info("matching.recompute job delivered",
		slog.String("event_id", event.ID),
		slog.String("job_event_id", payload.EventID),
		slog.String("correlation_id", payload.CorrelationID),
		slog.String("rule_version", payload.RuleVersion),
		slog.Int("vulnerabilities", res.Vulnerabilities),
		slog.Int("candidates", res.Candidates),
		slog.Int("transactions", res.Transactions))
	return nil
}

// classify maps an application-layer error of the matching runs onto the
// relay's delivery semantics: an infrastructure error (database trouble)
// is temporary and retried after the lease expires (ch. 14.2); a
// validation, not-found or conflict outcome is permanent and dead-letters
// the job with the error text recorded. A bare non-application error is
// classified infrastructure by ErrorKindOf — the safe default.
func (j *MatchingJobs) classify(err error) error {
	kind, _ := application.ErrorKindOf(err)
	if kind == application.KindInfra {
		return Retry(err)
	}
	return err
}
