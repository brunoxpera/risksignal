package application

import (
	"context"
	"encoding/json"
	"time"
)

// RunSourceInput drives one full source cycle (fetch then normalise,
// ARCH-002 §1/§5 as the inline orchestration; the worker composes the
// FetchSource and NormalizeSource jobs of the same split): the resolved
// source row and the adapter implementing its port.
//
// WindowTo optionally bounds the fetch window's To of this run (the
// full-import driver of DEV-067 caps every checkpointed window at the
// next chunk boundary). Zero — the ordinary scheduled runs — fetches to
// the injected clock's now.
type RunSourceInput struct {
	SourceID string
	Adapter  SourcePort
	WindowTo time.Time
}

// RunSourceResult reports one full cycle. Status succeeded means the run
// committed with its counters and — for an incremental source — the
// advanced cursor (CursorAfter); Meta surfaces the rate-limited / no-change
// outcomes of the fetch half. Errors of the normalise half never fail the
// run: isolated records are counted in Counters.Errors/Quarantined (ch. 8.1
// step 5). Status failed marks a fetch that stored nothing (infrastructure
// failure returned as the error, or a rate-limited response).
type RunSourceResult struct {
	RunID       string
	RawRecordID string // "" when the fetch stored nothing
	Status      SourceRunStatus
	Counters    SourceRunCounters
	CursorAfter json.RawMessage
	Meta        FetchMeta
}

// RunSource runs one full source cycle in a single run (ARCH-002 §1): open
// the run from the source cursor, fetch one slice through the adapter,
// store the unchanged raw record, stream the normalise pass into the
// persistence sink and commit the counters with the terminal status and the
// advanced cursor. All persistence of the cycle — raw record, normalised
// objects, quarantine isolations, run completion and cursor — happens in
// one transaction (ARCH-002 §6): a failing sink write aborts it and rolls
// the run back with nothing partially committed, and the cursor advances
// only after the commit of the successful run (ch. 6.1). A fetch that
// cannot store anything (rate-limited, unchanged full set, infrastructure
// failure) closes the run before any normalise runs.
func (s *Service) RunSource(ctx context.Context, in RunSourceInput) (RunSourceResult, error) {
	const op = "run_source"

	if in.Adapter == nil {
		return RunSourceResult{}, Validationf(op, "adapter must not be nil")
	}
	desc, err := s.sources.GetByID(ctx, in.SourceID)
	if err != nil {
		return RunSourceResult{}, err
	}
	if in.Adapter.Type() != desc.Type {
		return RunSourceResult{}, Validationf(op, "adapter type %q does not match source %s (type %q)", in.Adapter.Type(), in.SourceID, desc.Type)
	}

	now := s.clock.Now()
	windowTo := now
	if !in.WindowTo.IsZero() {
		// DEV-067 full-import step: the run fetches one bounded checkpoint
		// window [cursor, WindowTo] instead of the open run to now — the
		// next step resumes from the committed window end.
		windowTo = in.WindowTo
	}
	window, err := fetchWindow(in.Adapter.Plan(), desc, windowTo)
	if err != nil {
		return RunSourceResult{}, Validationf(op, "malformed source cursor: %v", err)
	}

	// 1) open the run from the source cursor.
	runID, err := s.openRun(ctx, desc.ID, desc.Cursor, now)
	if err != nil {
		return RunSourceResult{}, err
	}

	// 2) fetch — network I/O, outside any transaction.
	out, err := in.Adapter.Fetch(ctx, FetchInput{
		Source:    desc,
		Window:    window,
		APIKeyRef: apiKeyRefOf(desc.Config),
	})
	if err != nil {
		return RunSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, err, nil)
	}
	// A full-set fetch (KEV, EPSS) carries no time window and returns the
	// zero FetchedAt; stamp the run's clock instant (DEV-041) so the raw
	// record, the normalize job and the EPSS load carry the fetch time.
	out = stampFetchedAt(out, now)
	if out.Meta.RateLimited {
		// ch. 14.2: recorded rate-limited, not a source fault — the caller
		// backs off via Meta.RetryAfter. The cursor does not advance.
		_ = s.completeRun(ctx, op, runID, SourceRunStatusFailed, SourceRunCounters{}, nil, RateLimitedErrorText)
		return RunSourceResult{RunID: runID, Status: SourceRunStatusFailed, Meta: out.Meta}, nil
	}
	if out.Meta.NoChange {
		// An unchanged full set (ch. 8.3): successful no-op cycle.
		_ = s.completeRun(ctx, op, runID, SourceRunStatusSucceeded, SourceRunCounters{}, nil, "")
		return RunSourceResult{RunID: runID, Status: SourceRunStatusSucceeded, Meta: out.Meta}, nil
	}
	if out.ExternalID == "" || out.ContentHash == "" {
		cerr := InfraError(op, errNoStorableSlice(out))
		return RunSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, cerr, nil)
	}

	// 3) terminal commit (one transaction): store the raw record, stream
	// the normalise pass into the persistence sink and close the run
	// succeeded with the counters and the advanced cursor.
	counters := SourceRunCounters{Records: 1}
	var rawID string
	passErr := s.runTx(ctx, func(tx Tx) error {
		id, err := s.raws.Insert(ctx, tx, desc.ID, out.ExternalID, out.Payload, out.ContentHash, contentEncodingFor(out.Meta), out.FetchedAt)
		if err != nil {
			return err
		}
		rawID = id

		sink := newNormalizeSink(s, tx, desc.ID, runID, rawID, now)
		// The pass input carries the additive full-set specialisations at
		// the use-case boundary (DEV-041): the EPSS pass receives the
		// bulk writer over this transaction (TRUNCATE + COPY, loaded by
		// finish below), the KEV pass the previous catalog's CVE set
		// (removal historisation). Every other source reads neither.
		input, finish, err := s.sourcePassInput(ctx, tx, in.Adapter.Type(),
			desc.ID, rawID, out.ExternalID, out.FetchedAt,
			out.Payload, out.ContentHash, out.Meta, now)
		if err != nil {
			return err
		}
		res, err := in.Adapter.Normalize(ctx, input, sink)
		if err != nil {
			return err
		}
		// The EPSS bulk load runs on the pass transaction after the pass
		// succeeded — the daily-set swap commits atomically with the run
		// and its counters (ADR-013); a failing load aborts the pass and
		// rolls everything back, leaving the previous day's set intact.
		if err := finish(ctx); err != nil {
			return err
		}
		counters = normalizeCounters(counters, res)
		if err := s.runs.Complete(ctx, tx, runID, SourceRunStatusSucceeded, counters, out.Cursor, "", s.clock.Now()); err != nil {
			return err
		}
		// The next full-set fetch's NoChange detection reads the committed
		// raw record's hash from sources.config.last_content_hash (ch.
		// 8.3); the update commits with the run — the hash advances only
		// after a successful commit.
		if err := s.sources.SetLastContentHash(ctx, tx, desc.ID, out.ContentHash); err != nil {
			return err
		}
		// Cursor promotion (DEV-067, ARCH-003 §6): write the committed
		// cursor_after watermark back into sources.cursor on the same
		// transaction — the next run (and the next checkpointed full-import
		// window) reads the advanced cursor off the source row. Success
		// only by construction: this transaction is the terminal commit of
		// a successful run, so a failed run leaves the cursor untouched
		// (ch. 6.1). Full-set sources carry no cursor value and skip it.
		if len(out.Cursor) > 0 {
			if err := s.sources.SetCursor(ctx, tx, desc.ID, out.Cursor); err != nil {
				return err
			}
		}
		return nil
	})
	if passErr != nil {
		// The pass rolled back — no raw record, no normalised objects, no
		// cursor. Close the run failed and surface the cause.
		return RunSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, passErr, nil)
	}

	return RunSourceResult{
		RunID:       runID,
		RawRecordID: rawID,
		Status:      SourceRunStatusSucceeded,
		Counters:    counters,
		CursorAfter: out.Cursor,
		Meta:        out.Meta,
	}, nil
}
