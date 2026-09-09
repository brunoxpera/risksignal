package application

import (
	"context"
	"encoding/json"
)

// RunSourceInput drives one full source cycle (fetch then normalise,
// ARCH-002 §1/§5 as the inline orchestration; the worker composes the
// FetchSource and NormalizeSource jobs of the same split): the resolved
// source row and the adapter implementing its port.
type RunSourceInput struct {
	SourceID string
	Adapter  SourcePort
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
	window, err := fetchWindow(in.Adapter.Plan(), desc, now)
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
	if out.Meta.RateLimited {
		// ch. 14.2: recorded rate-limited, not a source fault — the caller
		// backs off via Meta.RetryAfter. The cursor does not advance.
		_ = s.completeRun(ctx, op, runID, SourceRunStatusFailed, SourceRunCounters{}, nil, rateLimitedErrorText)
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
		// Note (DEV-032 follow-up): as in NormalizeSource, the KEV
		// full-set path must populate NormalizeInput.PreviousKEVCVEs from
		// the source's previously stored catalog before removal
		// historisation (kev_removed evidence) can fire.
		res, err := in.Adapter.Normalize(ctx, NormalizeInput{
			RawRecordID: rawID,
			Payload:     out.Payload,
			ContentHash: out.ContentHash,
			Meta:        out.Meta,
		}, sink)
		if err != nil {
			return err
		}
		counters = normalizeCounters(counters, res)
		return s.runs.Complete(ctx, tx, runID, SourceRunStatusSucceeded, counters, out.Cursor, "", s.clock.Now())
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
