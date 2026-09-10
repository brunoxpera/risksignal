package application

// The NVD full-import driver (DEV-067, WP-3.09b, ARCH-003 §6): the
// checkpointed streaming of the whole history of an incremental,
// last-modified source (the NVD source in practice) into the run loop.
//
// The driver splits the history [lower, now] into bounded chunk windows
// and runs one ordinary source cycle per chunk through the existing run
// machinery (RunSource — the fetch + normalise pass of ARCH-002 §1, the
// same halves the worker composes into the source.fetch/source.normalize
// relay loop). Every chunk commits on its own transaction: the raw record
// and its normalised objects land, the run closes succeeded with the
// window's cursor_after, and the cursor promotion of DEV-067 writes that
// watermark back into sources.cursor — so each chunk is a checkpoint.
// A run that fails or is interrupted (an infrastructure failure, a rate
// limit, a crash) leaves the cursor at the last committed window end, and
// the next invocation — or the relay lease redelivering the interrupted
// step — resumes exactly there: the windows before the failure are never
// re-fetched, the window that failed is re-fetched whole (nothing partial
// ever commits, ARCH-002 §6), and the natural keys dedupe the re-run.
//
// The lower bound of the import is the source cursor when one exists (the
// resume case), else config.full_import_since when the operator pinned
// the import start, else the epoch — mirroring the open lower bound the
// NVD adapter derives for a cursor-less window (nvd.go windowFrom). The
// chunk length is config.full_import_chunk (a Go duration string or hours
// as a number; 720 h / 30 days by default — comfortably inside the NVD
// API's bounded date-range limit of one request). A rate-limited chunk
// stops the driver with the run recorded rate-limited (ch. 14.2 — the
// caller backs off with RetryAfter and re-invokes); it is never a source
// fault.
//
// The driver carries no SQL and no state of its own: the source row (its
// cursor) is the only checkpoint, read fresh before every chunk through
// the repositories the run machinery already owns.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/uuid"
)

// Full-import chunk vocabulary of the driver (ARCH-003 §6, DEV-067). The
// chunk length bounds one checkpointed window: the NVD API 2.0 rejects a
// date range wider than 120 days, so the default of 720 h (30 days) keeps
// every window of a real full import inside the API's limit while a
// years-long history still streams in few hundred committed steps.
const (
	// fullImportChunkConfigKey is config.full_import_chunk — the duration
	// of one checkpointed full-import window, a Go duration string
	// ("720h") or hours as a number (720.0). 0/absent selects the default.
	fullImportChunkConfigKey = "full_import_chunk"
	defaultFullImportChunk   = 720 * time.Hour

	// fullImportSinceConfigKey is config.full_import_since — the optional
	// lower bound of the full import (RFC 3339), the same source-config
	// member the NVD adapter reads for a cursor-less window (DEV-067).
	// The adapter owns the member for the fetch; the driver mirrors the
	// read to bound its first chunk. Absent: the epoch.
	fullImportSinceConfigKey = "full_import_since"
)

// FullImportSourceInput drives one full-import run of an incremental
// source (DEV-067, ARCH-003 §6): the resolved source row and its adapter,
// like every other run use case. The driver is idempotent and resumable —
// it opens from the source row's current cursor and stops when the cursor
// reaches the clock's now. CorrelationID is the optional id linking the
// matching.rebuild outbox row of the fan-in (empty generates one, like
// the inventory commit).
type FullImportSourceInput struct {
	SourceID      string
	Adapter       SourcePort
	CorrelationID string
}

// FullImportSourceResult reports one full-import run: Chunks is the number
// of committed window steps, CursorAfter the watermark the last committed
// step promoted into sources.cursor, MatchingJobsEnqueued the DEV-067
// job-count metric — the number of matching jobs the fan-in enqueued.
// Status failed with Meta.RateLimited marks a rate-limited interruption
// (the run of the interrupted chunk is recorded rate-limited, the cursor
// stays at the last committed chunk end — re-invoke after RetryAfter);
// every other failure is returned as an error.
type FullImportSourceResult struct {
	Status SourceRunStatus
	// Chunks is the number of committed checkpointed windows of this run.
	Chunks int
	// CursorAfter is the watermark the last committed chunk promoted into
	// sources.cursor (nil when no chunk committed).
	CursorAfter json.RawMessage
	Meta        FetchMeta
	// MatchingJobsEnqueued is the matching-job count of the full import:
	// exactly 1 when the single matching.rebuild fan-in appended its job,
	// 0 when a rebuild for the current (rule_version, inventory_snapshot)
	// pair was already in the outbox (the UQ dedupe — the rebuild is
	// enqueued exactly once per pair, ADR-012). By construction ≤ 1 — one
	// recomputation of the whole match set per full import, never one per
	// CVE — which is the observable ≪-relationship of the DEV-067 metric
	// against the imported CVE count.
	MatchingJobsEnqueued int
}

// FullImportSource streams the whole history of an incremental source in
// bounded checkpointed windows (see the package comment): it walks the
// chunk boundaries from the source cursor — or the open lower bound of a
// cursor-less source — up to the injected clock's now, running one
// committed source cycle per chunk through RunSource. A chunk that
// rate-limits stops the walk (nothing of it committed; the caller backs
// off via Meta.RetryAfter and re-invokes); an infrastructure failure is
// returned as an error with the same resume semantics.
func (s *Service) FullImportSource(ctx context.Context, in FullImportSourceInput) (FullImportSourceResult, error) {
	const op = "full_import_source"

	if in.Adapter == nil {
		return FullImportSourceResult{}, Validationf(op, "adapter must not be nil")
	}
	desc, err := s.sources.GetByID(ctx, in.SourceID)
	if err != nil {
		return FullImportSourceResult{}, err
	}
	if in.Adapter.Type() != desc.Type {
		return FullImportSourceResult{}, Validationf(op, "adapter type %q does not match source %s (type %q)", in.Adapter.Type(), in.SourceID, desc.Type)
	}
	if in.Adapter.Plan().CursorKind != CursorKindLastModified {
		return FullImportSourceResult{}, Validationf(op, "source %s (%s) is not a last-modified incremental source; a full import applies to the checkpointed window sources only", in.SourceID, desc.Type)
	}

	now := s.clock.Now()
	lower, err := fullImportLowerBound(desc, now)
	if err != nil {
		return FullImportSourceResult{}, Validationf(op, "malformed full-import window: %v", err)
	}
	chunk := fullImportChunkOf(desc.Config)

	result := FullImportSourceResult{Status: SourceRunStatusSucceeded}
	prev := lower
	for prev.Before(now) {
		// One checkpointed window: [prev, min(prev+chunk, now)]. The run
		// re-resolves the source row itself, so it opens from the cursor
		// the previous chunk promoted.
		stepTo := prev.Add(chunk)
		if stepTo.After(now) {
			stepTo = now
		}
		step, err := s.RunSource(ctx, RunSourceInput{SourceID: in.SourceID, Adapter: in.Adapter, WindowTo: stepTo})
		if err != nil {
			return result, err
		}
		if step.Meta.RateLimited {
			// ch. 14.2: recorded rate-limited on the chunk's run, never a
			// source fault — the driver stops and the caller backs off
			// with RetryAfter; the cursor sits at the last committed
			// chunk end.
			result.Status = SourceRunStatusFailed
			result.Meta = step.Meta
			return result, nil
		}
		if step.Status != SourceRunStatusSucceeded || len(step.CursorAfter) == 0 {
			// A last-modified fetch that neither errored nor rate-limited
			// always commits an advanced cursor; anything else is a
			// contract violation the driver must not paper over.
			return result, InfraError(op, fmt.Errorf("chunk window ending %s finished %s without an advanced cursor", stepTo.UTC().Format(time.RFC3339), step.Status))
		}
		next, err := lastModifiedCursorTime(step.CursorAfter)
		if err != nil {
			return result, InfraError(op, fmt.Errorf("chunk committed a malformed cursor: %w", err))
		}
		if !next.After(prev) {
			// The chunk's window [prev, stepTo] must advance the cursor
			// past prev — otherwise the walk would loop forever.
			return result, InfraError(op, errors.New("chunk committed a cursor that does not advance the walk"))
		}
		prev = next
		result.Chunks++
		result.CursorAfter = step.CursorAfter
	}

	if result.Status == SourceRunStatusSucceeded {
		// Single-rebuild fan-in (ARCH-003 §6, DEV-067): when the walk
		// reached the clock's now, the full import is complete and exactly
		// one matching.rebuild is enqueued — the DEV-060/065 contract
		// (payload MatchingRebuildPayload, dedupe key
		// matching.rebuild:<rule_version>:<inventory_snapshot>), appended
		// on its own transaction over the current inventory snapshot. The
		// outbox UQ makes the append exactly-once per pair, so a resume
		// that finalises an interrupted import re-appends nothing.
		enqueued, err := s.appendFullImportRebuild(ctx, in.CorrelationID)
		if err != nil {
			return result, err
		}
		result.MatchingJobsEnqueued = enqueued
	}
	return result, nil
}

// appendFullImportRebuild enqueues the single matching.rebuild of a
// completed full import (see FullImportSource): one transaction reads the
// current inventory snapshot and the ruleset version counters, pre-checks
// the ARCH-003 §5 dedupe key on the same transaction and appends the job —
// a rebuild for the pair that is already in the outbox makes the append a
// no-op, so the rebuild is enqueued exactly once per rule_version +
// inventory_snapshot (ADR-012 point 4). It returns 1 when the append
// inserted a row, 0 on the already-queued no-op.
func (s *Service) appendFullImportRebuild(ctx context.Context, correlationID string) (int, error) {
	const op = "full_import_source"

	importID := uuid.New()
	if correlationID == "" {
		correlationID = uuid.New()
	}
	enqueued := 0
	err := s.runTx(ctx, func(tx Tx) error {
		now := s.clock.Now()
		snap, err := s.inventory.InventorySnapshot(ctx, tx)
		if err != nil {
			return err
		}
		snapshotHash := inventorySnapshotHash(snap)
		aliasVersion, decisionVersion, err := s.inventory.RuleVersions(ctx, tx)
		if err != nil {
			return err
		}
		ruleVersion, err := domain.RulesetVersion(aliasVersion, decisionVersion)
		if err != nil {
			return InfraError(op, err)
		}
		dedupeKey := MatchingRebuildDedupeKey(ruleVersion, snapshotHash)
		// Exactly-once (ADR-012 point 4): a rebuild for the pair that is
		// already in the outbox — committed earlier or staged by this very
		// transaction — makes the append a pre-checked no-op, never a
		// duplicate INSERT (which would raise the unique violation and
		// abort the transaction).
		alreadyQueued, err := s.outbox.ExistsDedupeKey(ctx, tx, dedupeKey)
		if err != nil {
			return err
		}
		if alreadyQueued {
			return nil // the rebuild for this snapshot pair is already queued: exactly-once holds
		}
		payload, err := json.Marshal(MatchingRebuildPayload{
			EventID:           uuid.New(),
			Type:              EventTypeMatchingRebuild,
			ImportID:          importID,
			RuleVersion:       ruleVersion,
			InventorySnapshot: snapshotHash,
			OccurredAt:        now,
			CorrelationID:     correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeMatchingRebuild,
			Payload:     payload,
			DedupeKey:   dedupeKey,
			AvailableAt: now,
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		enqueued = 1
		return nil
	})
	return enqueued, err
}

// fullImportLowerBound derives the window start of the first chunk
// (DEV-067, ARCH-003 §6): the source cursor when one exists (the resume
// case), else config.full_import_since (RFC 3339) when the operator pinned
// the import start, else the epoch — the same open lower bound the NVD
// adapter derives for a cursor-less window. A cursor at or after now means
// the import is already complete (the walk has zero chunks).
func fullImportLowerBound(desc SourceDescriptor, now time.Time) (time.Time, error) {
	if len(desc.Cursor) > 0 {
		cur, err := lastModifiedCursorTime(desc.Cursor)
		if err != nil {
			return time.Time{}, err
		}
		return cur, nil
	}
	if since, ok := desc.Config[fullImportSinceConfigKey]; ok && since != nil {
		str, isString := since.(string)
		if !isString {
			return time.Time{}, fmt.Errorf("config full_import_since %v is not an RFC 3339 string", since)
		}
		if str == "" {
			return time.Time{}, errors.New("config full_import_since is empty")
		}
		lower, err := time.Parse(time.RFC3339, str)
		if err != nil {
			return time.Time{}, fmt.Errorf("config full_import_since %q is not an RFC 3339 instant: %w", str, err)
		}
		if !lower.Before(now) {
			return time.Time{}, fmt.Errorf("full-import lower bound %s is not before now %s", lower.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		return lower, nil
	}
	return time.Time{}, nil // the epoch: an open lower bound
}

// fullImportChunkOf reads the chunk length of one full import:
// config.full_import_chunk as a Go duration string ("720h") or hours as a
// JSON number (720.0 / 720); the default of 30 days when absent or
// unreadable (mirroring the adapter's lenient config-duration reading).
func fullImportChunkOf(config map[string]any) time.Duration {
	v, ok := config[fullImportChunkConfigKey]
	if !ok || v == nil {
		return defaultFullImportChunk
	}
	switch n := v.(type) {
	case float64:
		return time.Duration(n * float64(time.Hour))
	case int:
		return time.Duration(n) * time.Hour
	case string:
		if d, err := time.ParseDuration(n); err == nil {
			return d
		}
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return time.Duration(f * float64(time.Hour))
		}
	}
	return defaultFullImportChunk
}
