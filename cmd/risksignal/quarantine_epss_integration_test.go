package main

// Integration tests of the WP-2.03a quarantine + epss_current sqlc queries
// (DEV-037) at the composition root, on a real short-lived PostgreSQL.
//
// Quarantine (ARCH-002 §3/§4, ch. 8.6): a quarantined row is inserted in
// status 'new' with the run attribution and the fixed test clock, read back
// through the generated read path and walked through the whole state machine
// — new -> acknowledged -> ready_for_retry -> resolved — with the failed-
// reprocess attempt increment in between. Every transition is guarded on the
// source status (ARCH-002 §4), so a transition that does not apply matches
// zero rows: the assertions prove the guards by re-applying each transition
// and expecting pgx.ErrNoRows (a double ack, a mark on a resolved row, a
// resolve of a resolved row).
//
// epss_current (ADR-013, ARCH-002 §2.3): the daily set is loaded by the
// TRUNCATE + COPY swap inside one transaction — TruncateEpssCurrent then the
// generated CopyFrom insert — and the row count is measured with
// CountEpssRows. Loading a second, smaller day replaces the set atomically:
// the count matches the new fixture and no row of the previous day survives.
// GetEpssByCveID serves the cve_id lookup read, including the not-found case.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
)

// epssNumeric scans a decimal string into the pgtype.Numeric the generated
// epss_current queries use for the numeric score/percentile columns.
func epssNumeric(t *testing.T, s string) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(s); err != nil {
		t.Fatalf("scan numeric %q: %v", s, err)
	}
	return n
}

// epssFloat renders a scanned pgtype.Numeric back to float64 for the value
// assertions (the fixture values are exact decimals, so a 1e-9 tolerance is
// far wider than the round trip needs).
func epssFloat(t *testing.T, n pgtype.Numeric) float64 {
	t.Helper()
	f, err := n.Float64Value()
	if err != nil {
		t.Fatalf("numeric to float64: %v", err)
	}
	if !f.Valid {
		t.Fatal("numeric to float64: value is not valid")
	}
	return f.Float64
}

func TestQuarantineInsertReadAndStateMachineTransitions(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	isolated := mustTS(t, "2026-09-09T09:00:05Z")
	ackTS := mustTS(t, "2026-09-09T09:15:00Z")
	resolvedTS := mustTS(t, "2026-09-09T10:00:00Z")

	// --- seed path ---------------------------------------------------------
	// The quarantine row is attributed (source_id, source_run_id,
	// raw_record_id, ARCH-002 §3), so the fixture seeds one source, one run
	// and one raw record behind the foreign keys.
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type: "synthetic", Name: "quarantine-source", Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	run, err := q.CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID: sourceID, StartedAt: isolated,
	})
	if err != nil {
		t.Fatalf("CreateSourceRun: %v", err)
	}
	rawID, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "synthetic-quarantine-doc",
		ContentHash: testHash('q'), Payload: []byte(`{"records": [{"ok": 1}, {"bad": true}]}`),
		FetchedAt: isolated,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord: %v", err)
	}

	// --- isolate (insert, status 'new', attempts 0) ------------------------
	qrow, err := q.InsertQuarantine(ctx, gen.InsertQuarantineParams{
		SourceID:    sourceID,
		SourceRunID: run.ID,
		RawRecordID: rawID,
		Position:    "records/1",
		Reason:      "parse.invalid_cve_id: CVE id is empty",
		PayloadHash: testHash('x'),
		CreatedAt:   isolated,
		UpdatedAt:   isolated,
	})
	if err != nil {
		t.Fatalf("InsertQuarantine: %v", err)
	}
	if qrow.Status != "new" || qrow.Attempts != 0 {
		t.Fatalf("InsertQuarantine = %+v, want status new and attempts 0", qrow)
	}
	if qrow.SourceID != sourceID || !qrow.SourceRunID.Valid || qrow.SourceRunID != run.ID ||
		!qrow.RawRecordID.Valid || qrow.RawRecordID != rawID {
		t.Fatalf("InsertQuarantine attribution = source %v run %v raw %v, want the seeded ids", qrow.SourceID, qrow.SourceRunID, qrow.RawRecordID)
	}
	if qrow.Position != "records/1" || qrow.Reason != "parse.invalid_cve_id: CVE id is empty" || qrow.PayloadHash != testHash('x') {
		t.Fatalf("InsertQuarantine position/reason/hash = %q/%q/%q, want the isolated slice", qrow.Position, qrow.Reason, qrow.PayloadHash)
	}

	// --- reads --------------------------------------------------------------
	byID, err := q.GetQuarantineByID(ctx, qrow.ID)
	if err != nil || byID.ID != qrow.ID || byID.Status != "new" {
		t.Fatalf("GetQuarantineByID = %+v, %v; want the inserted row in status new", byID, err)
	}
	list, err := q.ListQuarantine(ctx, gen.ListQuarantineParams{MaxRows: 10})
	if err != nil || len(list) != 1 || list[0].ID != qrow.ID {
		t.Fatalf("ListQuarantine(open) = %+v, %v; want exactly the inserted row", list, err)
	}
	filtered, err := q.ListQuarantine(ctx, gen.ListQuarantineParams{
		Status: pgtype.Text{String: "new", Valid: true}, MaxRows: 10,
	})
	if err != nil || len(filtered) != 1 || filtered[0].ID != qrow.ID {
		t.Fatalf("ListQuarantine(status=new) = %+v, %v; want exactly the inserted row", filtered, err)
	}
	filtered, err = q.ListQuarantine(ctx, gen.ListQuarantineParams{
		Status: pgtype.Text{String: "resolved", Valid: true}, MaxRows: 10,
	})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("ListQuarantine(status=resolved) = %+v, %v; want no rows", filtered, err)
	}
	filtered, err = q.ListQuarantine(ctx, gen.ListQuarantineParams{
		SourceID: sourceID, MaxRows: 10,
	})
	if err != nil || len(filtered) != 1 || filtered[0].ID != qrow.ID {
		t.Fatalf("ListQuarantine(source) = %+v, %v; want exactly the inserted row", filtered, err)
	}
	filtered, err = q.ListQuarantine(ctx, gen.ListQuarantineParams{
		SourceID: sourceID, Status: pgtype.Text{String: "new", Valid: true}, MaxRows: 10,
	})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("ListQuarantine(source + status=new) = %+v, %v; want exactly the inserted row", filtered, err)
	}

	// --- new -> acknowledged (guarded on status = 'new') ---------------------
	ack, err := q.AcknowledgeQuarantine(ctx, gen.AcknowledgeQuarantineParams{
		ID: qrow.ID, AcknowledgedAt: ackTS,
		AcknowledgedBy:   pgtype.Text{String: "ops@example.com", Valid: true},
		AcknowledgedNote: pgtype.Text{String: "reviewed: parser fix upcoming", Valid: true},
		UpdatedAt:        ackTS,
	})
	if err != nil {
		t.Fatalf("AcknowledgeQuarantine: %v", err)
	}
	if ack.Status != "acknowledged" || ack.AcknowledgedBy.String != "ops@example.com" ||
		ack.AcknowledgedNote.String != "reviewed: parser fix upcoming" {
		t.Fatalf("AcknowledgeQuarantine = %+v, want acknowledged with operator + note", ack)
	}
	if _, err := q.AcknowledgeQuarantine(ctx, gen.AcknowledgeQuarantineParams{
		ID: qrow.ID, AcknowledgedAt: ackTS,
		AcknowledgedBy: pgtype.Text{String: "ops@example.com", Valid: true},
		UpdatedAt:      ackTS,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second AcknowledgeQuarantine error = %v, want pgx.ErrNoRows (guard: only 'new' is acknowledged)", err)
	}

	// --- acknowledged -> ready_for_retry -------------------------------------
	retry, err := q.MarkQuarantineReadyForRetry(ctx, gen.MarkQuarantineReadyForRetryParams{
		ID: qrow.ID, UpdatedAt: ackTS,
	})
	if err != nil {
		t.Fatalf("MarkQuarantineReadyForRetry: %v", err)
	}
	if retry.Status != "ready_for_retry" {
		t.Fatalf("MarkQuarantineReadyForRetry status = %q, want ready_for_retry", retry.Status)
	}

	// --- failed reprocess: attempts + 1, stays retryable ----------------------
	again, err := q.IncrementQuarantineAttempts(ctx, gen.IncrementQuarantineAttemptsParams{
		ID: qrow.ID, UpdatedAt: ackTS,
	})
	if err != nil {
		t.Fatalf("IncrementQuarantineAttempts: %v", err)
	}
	if again.Attempts != 1 || again.Status != "ready_for_retry" {
		t.Fatalf("IncrementQuarantineAttempts = attempts %d status %q, want attempts 1 and the row still retryable", again.Attempts, again.Status)
	}

	// --- ready_for_retry -> resolved (terminal) --------------------------------
	res, err := q.MarkQuarantineResolved(ctx, gen.MarkQuarantineResolvedParams{
		ID:           qrow.ID,
		ResolvedAt:   resolvedTS,
		ResolvedNote: pgtype.Text{String: "reprocessed with normalizer-v2: valid now", Valid: true},
		UpdatedAt:    resolvedTS,
	})
	if err != nil {
		t.Fatalf("MarkQuarantineResolved: %v", err)
	}
	if res.Status != "resolved" || !res.ResolvedAt.Valid || res.ResolvedNote.String != "reprocessed with normalizer-v2: valid now" {
		t.Fatalf("MarkQuarantineResolved = %+v, want resolved with resolved_at + note", res)
	}
	if res.ResolvedVulnerabilityID.Valid || res.ResolvedEvidenceID.Valid {
		t.Fatalf("MarkQuarantineResolved links = %v/%v, want NULL (record normalised to neither)", res.ResolvedVulnerabilityID, res.ResolvedEvidenceID)
	}
	if _, err := q.MarkQuarantineResolved(ctx, gen.MarkQuarantineResolvedParams{
		ID: qrow.ID, ResolvedAt: resolvedTS, UpdatedAt: resolvedTS,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second MarkQuarantineResolved error = %v, want pgx.ErrNoRows (resolved is terminal)", err)
	}
	if _, err := q.MarkQuarantineReadyForRetry(ctx, gen.MarkQuarantineReadyForRetryParams{
		ID: qrow.ID, UpdatedAt: resolvedTS,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("MarkQuarantineReadyForRetry on a resolved row error = %v, want pgx.ErrNoRows", err)
	}
	if _, err := q.IncrementQuarantineAttempts(ctx, gen.IncrementQuarantineAttemptsParams{
		ID: qrow.ID, UpdatedAt: resolvedTS,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("IncrementQuarantineAttempts on a resolved row error = %v, want pgx.ErrNoRows", err)
	}

	// The terminal row still reads back resolved through the generated read.
	done, err := q.GetQuarantineByID(ctx, qrow.ID)
	if err != nil || done.Status != "resolved" || done.Attempts != 1 {
		t.Fatalf("GetQuarantineByID after resolve = %+v, %v; want the resolved row with attempts 1", done, err)
	}
}

func TestEpssCurrentTruncateCopySwapCountAndLookup(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	// The fresh database holds an empty current set: the count is 0 and the
	// lookup read answers the not-found case with pgx.ErrNoRows.
	count, err := q.CountEpssRows(ctx)
	if err != nil || count != 0 {
		t.Fatalf("CountEpssRows on empty set = %d, %v; want 0", count, err)
	}
	if _, err := q.GetEpssByCveID(ctx, "CVE-2024-0001"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetEpssByCveID on empty set error = %v, want pgx.ErrNoRows", err)
	}

	// dayOneFixture is the small epss_current fixture of the 2026-09-09
	// daily set (realistic EPSS score/percentile values, fixed test clock).
	dayOneLoadedAt := mustTS(t, "2026-09-09T09:00:05Z")
	dayOneFixture := []gen.InsertEpssRowsParams{
		{CveID: "CVE-2024-0001", Score: epssNumeric(t, "0.97368"), Percentile: epssNumeric(t, "0.9991"), ModelVersion: "2026-09-09", LoadedAt: dayOneLoadedAt},
		{CveID: "CVE-2024-0002", Score: epssNumeric(t, "0.00510"), Percentile: epssNumeric(t, "0.4021"), ModelVersion: "2026-09-09", LoadedAt: dayOneLoadedAt},
		{CveID: "CVE-2024-0003", Score: epssNumeric(t, "0.00057"), Percentile: epssNumeric(t, "0.1937"), ModelVersion: "2026-09-09", LoadedAt: dayOneLoadedAt},
	}

	// The load is TRUNCATE + COPY inside one transaction: the swap of the
	// current set is atomic (ADR-013) — a reader never sees a partial day.
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qt := q.WithTx(tx)
		if err := qt.TruncateEpssCurrent(ctx); err != nil {
			return err
		}
		n, err := qt.InsertEpssRows(ctx, dayOneFixture)
		if err != nil {
			return err
		}
		if n != int64(len(dayOneFixture)) {
			t.Fatalf("InsertEpssRows copied %d rows, want %d", n, len(dayOneFixture))
		}
		return nil
	}); err != nil {
		t.Fatalf("day-one TRUNCATE+COPY load: %v", err)
	}

	// Measured row count of the loaded set (the I2 exit criterion read).
	count, err = q.CountEpssRows(ctx)
	if err != nil || count != int64(len(dayOneFixture)) {
		t.Fatalf("CountEpssRows after day one = %d, %v; want %d", count, err, len(dayOneFixture))
	}

	row, err := q.GetEpssByCveID(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2024-0001): %v", err)
	}
	if row.ModelVersion != "2026-09-09" || row.LoadedAt.Time != dayOneLoadedAt.Time {
		t.Fatalf("day-one row meta = %q/%v, want model 2026-09-09 loaded at %v", row.ModelVersion, row.LoadedAt.Time, dayOneLoadedAt.Time)
	}
	if got := epssFloat(t, row.Score); math.Abs(got-0.97368) > 1e-9 {
		t.Fatalf("day-one score = %v, want 0.97368", got)
	}
	if got := epssFloat(t, row.Percentile); math.Abs(got-0.9991) > 1e-9 {
		t.Fatalf("day-one percentile = %v, want 0.9991", got)
	}

	// dayTwoFixture is the next day's set: a different, smaller file. The
	// second TRUNCATE+COPY load must replace the set atomically — the count
	// matches the new fixture and no row of 2026-09-09 survives.
	dayTwoLoadedAt := mustTS(t, "2026-09-10T09:00:05Z")
	dayTwoFixture := []gen.InsertEpssRowsParams{
		{CveID: "CVE-2024-0001", Score: epssNumeric(t, "0.98200"), Percentile: epssNumeric(t, "0.9995"), ModelVersion: "2026-09-10", LoadedAt: dayTwoLoadedAt},
		{CveID: "CVE-2025-0001", Score: epssNumeric(t, "0.31000"), Percentile: epssNumeric(t, "0.8800"), ModelVersion: "2026-09-10", LoadedAt: dayTwoLoadedAt},
	}
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qt := q.WithTx(tx)
		if err := qt.TruncateEpssCurrent(ctx); err != nil {
			return err
		}
		n, err := qt.InsertEpssRows(ctx, dayTwoFixture)
		if err != nil {
			return err
		}
		if n != int64(len(dayTwoFixture)) {
			t.Fatalf("InsertEpssRows copied %d rows, want %d", n, len(dayTwoFixture))
		}
		return nil
	}); err != nil {
		t.Fatalf("day-two TRUNCATE+COPY load: %v", err)
	}

	count, err = q.CountEpssRows(ctx)
	if err != nil || count != int64(len(dayTwoFixture)) {
		t.Fatalf("CountEpssRows after day two = %d, %v; want %d (set replaced, no residue)", count, err, len(dayTwoFixture))
	}
	row, err = q.GetEpssByCveID(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2024-0001) after day two: %v", err)
	}
	if row.ModelVersion != "2026-09-10" {
		t.Fatalf("day-two CVE-2024-0001 model = %q, want 2026-09-10", row.ModelVersion)
	}
	if got := epssFloat(t, row.Score); math.Abs(got-0.982) > 1e-9 {
		t.Fatalf("day-two CVE-2024-0001 score = %v, want 0.982", got)
	}
	if _, err := q.GetEpssByCveID(ctx, "CVE-2024-0002"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetEpssByCveID(day-one-only CVE) error = %v, want pgx.ErrNoRows (previous day truncated)", err)
	}
	if _, err := q.GetEpssByCveID(ctx, "CVE-2024-0003"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetEpssByCveID(day-one-only CVE) error = %v, want pgx.ErrNoRows (previous day truncated)", err)
	}
}
