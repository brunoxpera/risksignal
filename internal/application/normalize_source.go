package application

import (
	"context"
)

// NormalizeSourceInput drives one normalise half (the worker's
// source.normalize job, ARCH-002 §5): the raw record to re-process and the
// adapter implementing the source's port. Meta is the fetch metadata of the
// raw record (the fetch headers are not persisted; the worker job payload
// carries them) — leave it zero for the paths that have none (a direct
// reprocess) and the use case reconstructs the content type from the stored
// record's self-describing encoding.
type NormalizeSourceInput struct {
	RawRecordID string
	Adapter     SourcePort
	Meta        FetchMeta
}

// NormalizeSourceResult reports one normalise half.
type NormalizeSourceResult struct {
	RunID    string
	Status   SourceRunStatus
	Counters SourceRunCounters
}

// NormalizeSource runs one normalise half (ARCH-002 §5 source.normalize):
// open its own run, stream the stored raw record through the adapter's
// Normalize into the persistence sink — every RecordError is isolated into
// quarantine in the same transaction, and per-record failures never abort
// the run (ch. 8.1 step 5: an isolated error is counted, not fatal; the run
// succeeds with errors > 0) — then commit the counters with the terminal
// status. A normalise-only run carries no cursor.
//
// The sink and the run's terminal commit share one transaction (ARCH-002
// §6): a failing sink write aborts the pass and rolls the run back with
// nothing partially committed; the use case then closes the run failed.
func (s *Service) NormalizeSource(ctx context.Context, in NormalizeSourceInput) (NormalizeSourceResult, error) {
	const op = "normalize_source"

	if in.Adapter == nil {
		return NormalizeSourceResult{}, Validationf(op, "adapter must not be nil")
	}
	if in.RawRecordID == "" {
		return NormalizeSourceResult{}, Validationf(op, "raw record id must not be empty")
	}
	rawRec, err := s.raws.GetByID(ctx, in.RawRecordID)
	if err != nil {
		return NormalizeSourceResult{}, err
	}
	desc, err := s.sources.GetByID(ctx, rawRec.SourceID)
	if err != nil {
		return NormalizeSourceResult{}, err
	}
	if in.Adapter.Type() != desc.Type {
		return NormalizeSourceResult{}, Validationf(op, "adapter type %q does not match source %s (type %q)", in.Adapter.Type(), desc.ID, desc.Type)
	}

	now := s.clock.Now()
	runID, err := s.openRun(ctx, desc.ID, nil, now)
	if err != nil {
		return NormalizeSourceResult{}, err
	}

	meta := in.Meta
	if meta == (FetchMeta{}) {
		meta = metaForRawRecord(rawRec)
	}
	counters := SourceRunCounters{Records: 1}
	passErr := s.runTx(ctx, func(tx Tx) error {
		sink := newNormalizeSink(s, tx, desc.ID, runID, rawRec.ID, now)
		// The pass input carries the additive full-set specialisations at
		// the use-case boundary (DEV-041): the EPSS pass receives the
		// bulk writer over this transaction (TRUNCATE + COPY, loaded by
		// finish below), the KEV pass the previous catalog's CVE set
		// (removal historisation). Every other source reads neither.
		input, finish, err := s.sourcePassInput(ctx, tx, in.Adapter.Type(),
			desc.ID, rawRec.ID, rawRec.ExternalID, rawRec.FetchedAt,
			rawRec.Payload, rawRec.ContentHash, meta, now)
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
		return s.runs.Complete(ctx, tx, runID, SourceRunStatusSucceeded, counters, nil, "", s.clock.Now())
	})
	if passErr != nil {
		return NormalizeSourceResult{}, s.failRun(ctx, op, runID, SourceRunCounters{}, passErr, nil)
	}
	return NormalizeSourceResult{RunID: runID, Status: SourceRunStatusSucceeded, Counters: counters}, nil
}

// metaForRawRecord reconstructs the fetch metadata a stored raw record does
// not persist: the content type is derived from the record's self-describing
// content encoding (ARCH-002 §3). Status stays 0.
func metaForRawRecord(raw RawRecord) FetchMeta {
	switch raw.ContentEncoding {
	case "gzip":
		return FetchMeta{ContentType: "application/gzip"}
	case "json":
		return FetchMeta{ContentType: "application/json"}
	}
	return FetchMeta{}
}

// normalizeCounters folds one NormalizeResult into the run counters: the
// pass's Records are the normalised domain records persisted, its Errors
// the records isolated — each of which also became a quarantine row, so
// quarantined mirrors errors (matched/signals stay 0 in I2, ARCH-002 §1).
func normalizeCounters(counters SourceRunCounters, res NormalizeResult) SourceRunCounters {
	counters.Normalized = res.Records
	counters.Errors = res.Errors
	counters.Quarantined = res.Errors
	return counters
}
