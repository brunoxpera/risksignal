package application

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Outbox and job vocabulary of the source run use cases (ARCH-002 §5,
// WP-2.08 wires the relay handlers on these keys).
const (
	// EventTypeSourceNormalize is the outbox type of the source.normalize
	// job a successful fetch enqueues. The enqueue is part of the fetch
	// run's terminal commit — the ARCH-002 §6 fault seam: a failing outbox
	// append rolls back the run completion, the stored raw record and the
	// cursor with it (the cursor advances only after commit).
	EventTypeSourceNormalize = "source.normalize"

	// sourceNormalizeDedupePrefix prefixes the job's dedupe key:
	// "source.normalize:<raw_record_id>" — one normalize job per raw record
	// for the record's whole lifetime (the outbox UQ dedupe_key makes a
	// repeated enqueue a no-op conflict, and WP-2.08 appends the adapter's
	// normalizer_version to the key when it lands, per ARCH-002 §1/§5).
	sourceNormalizeDedupePrefix = "source.normalize:"

	// rateLimitedErrorText is the stable error text of a rate-limited run:
	// the run closes failed (the cursor does not advance) but the failure is
	// recorded as rate-limited, never as a source technical error (ch. 14.2,
	// ARCH-002 §2.1) — the caller reads FetchMeta.RateLimited/RetryAfter.
	rateLimitedErrorText = "fetch.rate_limited"
)

// sourceNormalizePayload is the outbox payload of a source.normalize job
// (ARCH-002 §5): the raw record identity plus the fetch metadata the
// normalise pass receives. It carries no secret: the API key reference is
// resolved by the fetching adapter and never persisted (ch. 3.3, TR-013).
type sourceNormalizePayload struct {
	RawRecordID string    `json:"raw_record_id"`
	SourceID    string    `json:"source_id"`
	FetchedAt   time.Time `json:"fetched_at"`
}

// FetchSourceInput drives one fetch half (the worker's source.fetch job,
// ARCH-002 §5): the resolved source row and the adapter that implements the
// source's port. The adapter is injected — the composition root owns the
// type-keyed registry — and must match the source row's type (a wiring
// mistake is rejected before any run is opened).
type FetchSourceInput struct {
	SourceID string
	Adapter  SourcePort
}

// FetchSourceResult reports one fetch half. Status failed marks a fetch that
// did not store a raw record: an infrastructure failure (returned as the
// error), a rate-limited response (Meta.RateLimited — the run is recorded
// rate-limited, not as a source fault) or a no-change full set (a
// successful no-op run, Meta.NoChange). CursorAfter holds the cursor value
// committed with the successful run (nil otherwise); RawRecordID is "" when
// nothing was stored.
type FetchSourceResult struct {
	RunID       string
	RawRecordID string // "" for a no-change fetch
	Status      SourceRunStatus
	Counters    SourceRunCounters
	CursorAfter json.RawMessage
	Meta        FetchMeta
}

// FetchSource runs one fetch half (ARCH-002 §5 source.fetch): open a run
// from the source cursor, call the adapter's Fetch, store the unchanged raw
// record and commit the terminal state — status succeeded with the advanced
// cursor (ch. 8.1 steps 2–4) plus the enqueued source.normalize job, or
// failed without a cursor. Everything after the network call runs in one
// transaction, so a failing outbox append rolls the completion, the raw
// record and the cursor back together (ARCH-002 §6: the cursor advances
// only after the commit of a successful run, ch. 6.1).
//
// Error semantics (ch. 5.2): an unknown source or adapter/source mismatch
// is a validation error, a malformed stored cursor is a validation error,
// an infra/network failure is an infrastructure error — a rate-limited
// response is NOT an error: it surfaces as FetchMeta.RateLimited on the
// result with the run closed rate-limited (the caller backs off with
// RetryAfter, ARCH-002 §2.1).
func (s *Service) FetchSource(ctx context.Context, in FetchSourceInput) (FetchSourceResult, error) {
	const op = "fetch_source"

	if in.Adapter == nil {
		return FetchSourceResult{}, Validationf(op, "adapter must not be nil")
	}
	desc, err := s.sources.GetByID(ctx, in.SourceID)
	if err != nil {
		return FetchSourceResult{}, err
	}
	if in.Adapter.Type() != desc.Type {
		return FetchSourceResult{}, Validationf(op, "adapter type %q does not match source %s (type %q)", in.Adapter.Type(), in.SourceID, desc.Type)
	}

	now := s.clock.Now()
	window, err := fetchWindow(in.Adapter.Plan(), desc, now)
	if err != nil {
		return FetchSourceResult{}, Validationf(op, "malformed source cursor: %v", err)
	}

	// 1) open the run from the source cursor (ch. 7.1: cursor_before).
	runID, err := s.openRun(ctx, desc.ID, desc.Cursor, now)
	if err != nil {
		return FetchSourceResult{}, err
	}

	// 2) fetch — network I/O, outside any transaction.
	out, err := in.Adapter.Fetch(ctx, FetchInput{
		Source:    desc,
		Window:    window,
		APIKeyRef: apiKeyRefOf(desc.Config),
	})
	if err != nil {
		// Infrastructure failure: close the run failed — the cursor stays
		// where it was and the next run re-fetches the same window.
		return FetchSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, err, nil)
	}
	if out.Meta.RateLimited {
		// ch. 14.2: recorded as rate-limited, not a source fault; the
		// caller backs off via Meta.RetryAfter. The cursor does not advance.
		_ = s.completeRun(ctx, op, runID, SourceRunStatusFailed, SourceRunCounters{}, nil, rateLimitedErrorText)
		return FetchSourceResult{RunID: runID, Status: SourceRunStatusFailed, Meta: out.Meta}, nil
	}
	if out.Meta.NoChange {
		// An unchanged full set (ch. 8.3): a successful no-op run —
		// nothing new to store, counters all 0, no normalize job.
		_ = s.completeRun(ctx, op, runID, SourceRunStatusSucceeded, SourceRunCounters{}, nil, "")
		return FetchSourceResult{RunID: runID, Status: SourceRunStatusSucceeded, Meta: out.Meta}, nil
	}
	if out.ExternalID == "" || out.ContentHash == "" {
		// A fetch that neither failed nor reported no-change must carry a
		// storable slice — an adapter contract violation.
		cerr := InfraError(op, errNoStorableSlice(out))
		return FetchSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, cerr, nil)
	}

	// 3) terminal commit (one transaction, ARCH-002 §6): store the raw
	// record, close the run succeeded with the committed cursor and enqueue
	// the source.normalize job — a failure of any of the three rolls all of
	// them back and the cursor stays unadvanced.
	var rawID string
	counters := SourceRunCounters{Records: 1}
	if err := s.runTx(ctx, func(tx Tx) error {
		id, err := s.raws.Insert(ctx, tx, desc.ID, out.ExternalID, out.Payload, out.ContentHash, contentEncodingFor(out.Meta), out.FetchedAt)
		if err != nil {
			return err
		}
		rawID = id
		if err := s.runs.Complete(ctx, tx, runID, SourceRunStatusSucceeded, counters, out.Cursor, "", now); err != nil {
			return err
		}
		return s.appendNormalizeJob(ctx, tx, rawID, desc.ID, out, now)
	}); err != nil {
		// Nothing of the terminal commit landed — close the run failed (no
		// cursor) and surface the cause.
		return FetchSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, err, nil)
	}

	return FetchSourceResult{
		RunID:       runID,
		RawRecordID: rawID,
		Status:      SourceRunStatusSucceeded,
		Counters:    counters,
		CursorAfter: out.Cursor,
		Meta:        out.Meta,
	}, nil
}

// errNoStorableSlice is the adapter contract violation of a fetch that
// returned neither an error, a rate-limit nor a no-change signal, yet no
// slice to store.
func errNoStorableSlice(out FetchOutput) error {
	return fmt.Errorf("fetch returned no storable slice (external id %q, content hash %q)", out.ExternalID, out.ContentHash)
}

// openRun opens one run inside its own transaction and returns its id.
func (s *Service) openRun(ctx context.Context, sourceID string, cursorBefore json.RawMessage, now time.Time) (string, error) {
	var runID string
	err := s.runTx(ctx, func(tx Tx) error {
		id, err := s.runs.Open(ctx, tx, sourceID, cursorBefore, now)
		if err != nil {
			return err
		}
		runID = id
		return nil
	})
	return runID, err
}

// appendNormalizeJob enqueues the source.normalize job of one raw record on
// the caller's transaction (ARCH-002 §5). The outbox UQ on dedupe_key makes
// the enqueue idempotent: a job already queued for the record is a conflict
// and a no-op here, never an error.
func (s *Service) appendNormalizeJob(ctx context.Context, tx Tx, rawID, sourceID string, out FetchOutput, now time.Time) error {
	payload, err := json.Marshal(sourceNormalizePayload{
		RawRecordID: rawID,
		SourceID:    sourceID,
		FetchedAt:   out.FetchedAt,
	})
	if err != nil {
		return InfraError("fetch_source", err)
	}
	err = s.outbox.Append(ctx, tx, OutboxEvent{
		Type:        EventTypeSourceNormalize,
		Payload:     payload,
		DedupeKey:   sourceNormalizeDedupePrefix + rawID,
		AvailableAt: now,
		CreatedAt:   now,
	})
	if kind, ok := ErrorKindOf(err); ok && kind == KindConflict {
		return nil // the job is already queued for this raw record
	}
	return err
}

// fetchWindow derives the bounded TimeWindow of a fetch (ARCH-002 §1,
// §2.1): To is clock.Now() — the injectable clock, never the wall clock —
// and From is the persisted last-modified cursor minus the configured
// overlap (config.overlap, in hours) so window boundaries never gap.
// Full-set and cursor-less sources return the zero window the adapter
// ignores; an incremental source without a stored cursor yet (its first
// run) gets an open From — the WP-2.05 NVD adapter defines the first-run
// window. A malformed stored cursor is a validation error of the caller.
func fetchWindow(plan SourcePlan, desc SourceDescriptor, now time.Time) (TimeWindow, error) {
	if plan.CursorKind != CursorKindLastModified {
		return TimeWindow{}, nil
	}
	if len(desc.Cursor) == 0 {
		return TimeWindow{To: now}, nil
	}
	from, err := lastModifiedCursorTime(desc.Cursor)
	if err != nil {
		return TimeWindow{}, err
	}
	return TimeWindow{From: from.Add(-overlapOf(desc.Config)), To: now}, nil
}

// lastModifiedCursorTime reads the time of a last-modified cursor — the
// {"last_modified": "<RFC3339>"} shape of the NVD cursor (ARCH-002 §1).
func lastModifiedCursorTime(cursor json.RawMessage) (time.Time, error) {
	var c struct {
		LastModified string `json:"last_modified"`
	}
	if err := json.Unmarshal(cursor, &c); err != nil {
		return time.Time{}, err
	}
	if c.LastModified == "" {
		return time.Time{}, fmt.Errorf("cursor carries no last_modified member")
	}
	t, err := time.Parse(time.RFC3339, c.LastModified)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// overlapOf reads the source config's overlap setting (ARCH-002 §1,
// §2.1: the NVD config example carries overlap in hours); 0 when absent.
func overlapOf(config map[string]any) time.Duration {
	v, ok := config["overlap"]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return time.Duration(n * float64(time.Hour))
	case int:
		return time.Duration(n) * time.Hour
	}
	return 0
}

// apiKeyRefOf reads the secret reference of a source config
// (config.api_key_ref, ch. 3.3); "" when the source needs no key.
func apiKeyRefOf(config map[string]any) string {
	ref, _ := config["api_key_ref"].(string)
	return ref
}

// contentEncodingFor derives the self-describing encoding stamp of a stored
// payload (ARCH-002 §3: 'identity' | 'gzip' | 'json') from the fetch
// metadata's Content-Type; "" stores NULL (the stamping callers that know
// the encoding statically pass it through RawRecordRepo.Insert directly).
func contentEncodingFor(meta FetchMeta) string {
	switch ct := strings.ToLower(meta.ContentType); {
	case strings.Contains(ct, "gzip"):
		return "gzip"
	case strings.Contains(ct, "json"):
		return "json"
	}
	return ""
}
