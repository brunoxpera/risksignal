package application_test

// Unit tests of the DEV-041 source-run wiring (ARCH-002 §1/§2.3, ADR-013):
// the EPSS full-set pass receives its BulkRowWriter at the use-case
// boundary and the daily set is TRUNCATE + COPY-loaded on the pass
// transaction — committed atomically with the run, rolled back with it on a
// failing pass or a failing flush. The KEV previous-set and the content
// hash / FetchedAt wiring are covered in their own test files of this
// package.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/application"
)

// epssSource seeds an EPSS-style full-set source and returns its adapter
// fake, pre-wired to fetch the 2026-09-09 daily file (the fixture day of
// this package's tests).
func epssSource(h *harness, t *testing.T) *runSource {
	t.Helper()
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:   "src-epss",
		Type: application.SourceTypeEPSS,
	})
	return &runSource{
		typ: application.SourceTypeEPSS,
		plan: application.SourcePlan{
			Schedule:   "@daily",
			Kind:       application.SourceKindFullSet,
			CursorKind: application.CursorKindNone,
		},
		fetchOut: application.FetchOutput{
			ExternalID:  "epss_scores-2026-09-09.csv.gz",
			Payload:     []byte("gzip bytes are opaque to this fake"),
			ContentHash: "epss-hash-1",
			Meta:        application.FetchMeta{Status: 200, ContentType: "application/gzip"},
		},
	}
}

// epssNumericValue renders a staged pgtype.Numeric back to float64 for the
// row assertions (fixture values are exact decimals).
func epssNumericValue(t *testing.T, n pgtype.Numeric) float64 {
	t.Helper()
	f, err := n.Float64Value()
	if err != nil || !f.Valid {
		t.Fatalf("numeric to float64 = %v, %v; want a valid decimal", f, err)
	}
	return f.Float64
}

// TestRunSourceEpssBulkLoadsDailySetInRunTransaction is the required EPSS
// wiring behaviour: the EPSS adapter receives NormalizeInput.EpssBulk, the
// rows it streams are TRUNCATE + COPY-loaded on the pass transaction
// (stamped with the file date and the run's clock instant) and the run
// commits with the copied-row count in its counters.
func TestRunSourceEpssBulkLoadsDailySetInRunTransaction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := epssSource(h, t)
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if in.EpssBulk == nil {
			t.Fatal("EPSS pass received no NormalizeInput.EpssBulk — the source-run wiring must hand it the bulk writer")
		}
		for _, row := range []application.EpssRow{
			{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"},
			{CveID: "CVE-2026-0002", Score: "0.00510", Percentile: "0.4021"},
			{CveID: "CVE-2026-0003", Score: "7e-05", Percentile: "0.1937"},
		} {
			if err := in.EpssBulk.WriteEpssRow(ctx, row); err != nil {
				return application.NormalizeResult{}, err
			}
		}
		return application.NormalizeResult{Records: 3}, nil
	}

	res, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-epss", Adapter: src})
	if err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded", res.Status)
	}
	if res.Counters.Records != 1 || res.Counters.Normalized != 3 || res.Counters.Errors != 0 {
		t.Fatalf("counters = %+v, want records 1 normalized 3 (the copied row count)", res.Counters)
	}

	// The load ran inside the pass transaction, before its completion —
	// TRUNCATE, then the COPY, then the run completion in one transaction.
	tx := h.runner.last()
	log := strings.Join(tx.log, ",")
	if !strings.Contains(log, "raw,epss.truncate,epss.copy,run.complete") {
		t.Fatalf("pass transaction write order = %q, want raw insert then epss.truncate/epss.copy then run.complete", tx.log)
	}

	// The staged rows committed with the run: the set holds exactly the
	// streamed rows, stamped with model_version = the file date and
	// loaded_at = the injected clock instant.
	if len(h.db.epssRows) != 3 {
		t.Fatalf("committed epss_current rows = %d, want 3", len(h.db.epssRows))
	}
	for i, want := range []struct {
		cveID string
		score float64
	}{
		{"CVE-2026-0001", 0.97368},
		{"CVE-2026-0002", 0.00510},
		{"CVE-2026-0003", 0.00007}, // the scientific-notation literal round-trips
	} {
		row := h.db.epssRows[i]
		if row.cveID != want.cveID {
			t.Fatalf("row %d cve_id = %q, want %q", i, row.cveID, want.cveID)
		}
		if got := epssNumericValue(t, row.score); got != want.score {
			t.Fatalf("row %d score = %v, want %v", i, got, want.score)
		}
		if row.modelVersion != "2026-09-09" {
			t.Fatalf("row %d model_version = %q, want the file date 2026-09-09", i, row.modelVersion)
		}
		if !row.loadedAt.Equal(fixedNow) {
			t.Fatalf("row %d loaded_at = %v, want the clock instant %v", i, row.loadedAt, fixedNow)
		}
	}
	if h.db.epssRows[0].percentile.Valid != true {
		t.Fatal("row percentile is not valid, want the parsed decimal")
	}
}

// TestNormalizeSourceEpssBulkLoadsDailySet proves the same wiring on the
// normalise half running alone over a stored raw record (the worker's
// source.normalize job, ARCH-002 §5): the reprocess path hands the EPSS
// adapter its bulk writer and the load commits with the run.
func TestNormalizeSourceEpssBulkLoadsDailySet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.rawRecords = append(h.db.rawRecords, storedRawRecord{
		id: "raw-epss-1", sourceID: "src-epss", externalID: "epss_scores-2026-09-09.csv.gz",
		contentHash: "epss-hash-1", contentEncoding: "gzip",
		payload: []byte("stored gzip file bytes"), fetchedAt: fixedNow,
	})
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID: "src-epss", Type: application.SourceTypeEPSS,
	})
	src := &runSource{
		typ:  application.SourceTypeEPSS,
		plan: application.SourcePlan{Kind: application.SourceKindFullSet, CursorKind: application.CursorKindNone},
	}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if in.EpssBulk == nil {
			t.Fatal("EPSS reprocess pass received no NormalizeInput.EpssBulk")
		}
		if err := in.EpssBulk.WriteEpssRow(ctx, application.EpssRow{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"}); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 1}, nil
	}

	res, err := h.svc.NormalizeSource(ctx, application.NormalizeSourceInput{RawRecordID: "raw-epss-1", Adapter: src})
	if err != nil {
		t.Fatalf("NormalizeSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Counters.Normalized != 1 {
		t.Fatalf("result = %+v, want a succeeded run with normalized 1", res)
	}
	if len(h.db.epssRows) != 1 || h.db.epssRows[0].cveID != "CVE-2026-0001" || h.db.epssRows[0].modelVersion != "2026-09-09" {
		t.Fatalf("committed epss rows = %+v, want CVE-2026-0001 with model 2026-09-09", h.db.epssRows)
	}
}

// TestRunSourceEpssFailingNormalizeLeavesSetUntouched is the abort path of
// the flush wiring: a failing pass must never reach the load — no TRUNCATE,
// no COPY — and the run closes failed with the previous set (none here)
// intact.
func TestRunSourceEpssFailingNormalizeLeavesSetUntouched(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := epssSource(h, t)
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		// One row streams before the pass fails mid-stream.
		if err := in.EpssBulk.WriteEpssRow(ctx, application.EpssRow{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"}); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{}, errors.New("epss: normalize: broken gzip stream")
	}

	_, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-epss", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error", err)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" {
		t.Fatalf("run status = %q, want failed", run.status)
	}
	tx := h.runner.last()
	if strings.Contains(strings.Join(tx.log, ","), "epss.truncate") || strings.Contains(strings.Join(tx.log, ","), "epss.copy") {
		t.Fatalf("pass transaction log = %q, want no TRUNCATE/COPY on a failing pass", tx.log)
	}
	if len(h.db.epssRows) != 0 {
		t.Fatalf("committed epss rows = %d, want 0 — nothing loaded on a failing pass", len(h.db.epssRows))
	}
}

// TestRunSourceEpssFailingFlushRollsBackRun is the ARCH-002 §6 fault seam
// of the bulk path: a failing COPY aborts the pass — the run closes failed
// and nothing of the load is observable (the previous day's set stays
// intact in production; here the staged rows roll back with the run).
func TestRunSourceEpssFailingFlushRollsBackRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.runner.copyErr = errors.New("epss: copy rows into epss_current: duplicate key")
	src := epssSource(h, t)
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := in.EpssBulk.WriteEpssRow(ctx, application.EpssRow{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"}); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 1}, nil
	}

	_, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-epss", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error from the failing COPY", err)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" {
		t.Fatalf("run status = %q, want failed", run.status)
	}
	if len(h.db.epssRows) != 0 {
		t.Fatalf("committed epss rows = %d, want 0 — the failed flush rolled the load back", len(h.db.epssRows))
	}
}

// TestRunSourceNonEpssPassCarriesNoBulkWriter is the nil-safe contract of
// the additive input: a KEV/NVD/synthetic pass never receives an EpssBulk
// writer and the finish step is a no-op — the run completes untouched.
func TestRunSourceNonEpssPassCarriesNoBulkWriter(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID: "src-kev", Type: application.SourceTypeKEV,
	})
	src := &runSource{
		typ:  application.SourceTypeKEV,
		plan: application.SourcePlan{Kind: application.SourceKindFullSet, CursorKind: application.CursorKindNone},
		fetchOut: application.FetchOutput{
			ExternalID:  "kev-2026-09-09",
			Payload:     []byte(`{"catalogVersion":"2026.09.09"}`),
			ContentHash: "kev-hash-1",
			Meta:        application.FetchMeta{Status: 200, ContentType: "application/json"},
		},
	}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if in.EpssBulk != nil {
			t.Fatal("a non-EPSS pass must not receive an EpssBulk writer (nil-safe additive input)")
		}
		return application.NormalizeResult{}, nil
	}

	res, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-kev", Adapter: src})
	if err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded", res.Status)
	}
	if len(h.db.epssRows) != 0 {
		t.Fatalf("committed epss rows = %d, want 0", len(h.db.epssRows))
	}
	if h.db.sourceRuns[0].counters.Records != 1 {
		t.Fatalf("run counters = %+v, want the raw record counted", h.db.sourceRuns[0].counters)
	}
}
