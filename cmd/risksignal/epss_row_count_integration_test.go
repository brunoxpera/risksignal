package main

// Integration test proving I2 exit criterion 3 — the EPSS daily set is
// loaded and its row count measured (ARCH-002 §6.3, ADR-013, ch. 8.4) —
// against a real, short-lived PostgreSQL. The gzipped daily-file fixtures
// under testdata/ (epss_scores-2026-09-09.csv.gz, 3 rows; the next day's
// file, 2 rows) are fetched through RunSource with the real EPSS adapter
// pointing at an in-process httptest server:
//
//  1. the daily set lands in epss_current through the TRUNCATE + COPY swap
//     of the run transaction, and the measured COUNT(*) equals the number
//     of data rows of the fixture file (the load's own row stream, counted
//     from the fixture — never a hard-coded constant), with score and
//     percentile in the EPSS [0,1] range and the model_version/loaded_at
//     stamps set;
//  2. the same day's unchanged file re-import is a content-hash no-op
//     (ch. 8.3): counters all 0, the set untouched;
//  3. the next day's file replaces the set atomically: the count matches
//     the new fixture and no row of the previous day survives.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/sources/epss"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// epssDataRows counts the data rows of one daily-file fixture (the lines
// after the #model_version comment and the cve,epss,percentile header) —
// the row count the load must measure.
func epssDataRows(t *testing.T, gz []byte) int {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("open fixture gzip: %v", err)
	}
	defer func() { _ = gr.Close() }()
	rows := 0
	sc := bufio.NewScanner(gr)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "cve,epss,percentile" {
			continue
		}
		rows++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	return rows
}

// TestEpssDailySetLoadedRowCountMeasuredNoOpAndAtomicReplacement drives
// exit criterion 3 through RunSource against the versioned daily-file
// fixtures.
func TestEpssDailySetLoadedRowCountMeasuredNoOpAndAtomicReplacement(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	day1 := readFixture(t, "epss_scores-2026-09-09.csv.gz")
	day2 := readFixture(t, "epss_scores-2026-09-10.csv.gz")
	wantDay1Rows, wantDay2Rows := epssDataRows(t, day1), epssDataRows(t, day2)
	if wantDay1Rows != 3 || wantDay2Rows != 2 {
		t.Fatalf("fixture row counts = day1 %d / day2 %d, want 3 / 2 (fixture drift)", wantDay1Rows, wantDay2Rows)
	}

	files := map[string][]byte{
		"epss_scores-2026-09-09.csv.gz": day1,
		"epss_scores-2026-09-10.csv.gz": day2,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		if _, err := w.Write(body); err != nil {
			panic(err)
		}
	}))
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "epss",
		Name:     "epss-rowcount-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@daily", Valid: true},
		Enabled:  true,
		Config:   []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)
	adapter := epss.New(srv.Client().Transport, clk)

	// --- run 1: the 2026-09-09 daily set is loaded with the run ----------
	res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (day one): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("day-one status = %s, want succeeded", res.Status)
	}
	assertSourceRunCounters(t, res.Counters, 1, wantDay1Rows, 0)

	// The measured row count of the loaded set equals the fixture's data
	// rows (the exit-criterion read, ADR-013).
	count, err := q.CountEpssRows(ctx)
	if err != nil || int(count) != wantDay1Rows {
		t.Fatalf("epss_current count = %d, %v; want the fixture's %d data rows", count, err, wantDay1Rows)
	}
	// Every row carries the daily file's date as model_version and the
	// run's clock instant as loaded_at; score/percentile hold the EPSS
	// [0,1] probability range.
	var models, outOfRange int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE model_version = '2026-09-09'),
		        count(*) FILTER (WHERE score < 0 OR score > 1 OR percentile < 0 OR percentile > 1)
		 FROM epss_current`).Scan(&models, &outOfRange); err != nil {
		t.Fatalf("measure epss_current rows: %v", err)
	}
	if models != wantDay1Rows || outOfRange != 0 {
		t.Fatalf("epss_current rows with model 2026-09-09 = %d, out-of-range rows = %d, want %d / 0", models, outOfRange, wantDay1Rows)
	}
	row, err := q.GetEpssByCveID(ctx, "CVE-2026-0001")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2026-0001): %v", err)
	}
	if row.ModelVersion != "2026-09-09" || !row.LoadedAt.Time.Equal(sourceRunClockStart) {
		t.Fatalf("day-one row meta = %q / %v, want model 2026-09-09 loaded at the run's clock %v", row.ModelVersion, row.LoadedAt.Time, sourceRunClockStart)
	}
	if got := epssFloat(t, row.Score); math.Abs(got-0.97368) > 1e-9 {
		t.Fatalf("day-one score = %v, want the fixture's 0.97368", got)
	}

	// --- run 2: the same day's unchanged file is a no-op ------------------
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (same-day re-import): %v", err)
	}
	if !res.Meta.NoChange || res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("same-day re-import = status %s meta %+v, want the successful no-op (Meta.NoChange)", res.Status, res.Meta)
	}
	if res.Counters.Records != 0 || res.Counters.Normalized != 0 {
		t.Fatalf("no-op counters = %+v, want all 0", res.Counters)
	}
	if count, err := q.CountEpssRows(ctx); err != nil || int(count) != wantDay1Rows {
		t.Fatalf("epss_current count after no-op = %d, %v; want %d — the set is untouched", count, err, wantDay1Rows)
	}
	if n := countRawRecords(t, pool, srcID); n != 1 {
		t.Fatalf("raw records after no-op = %d, want 1 — nothing stored", n)
	}

	// --- run 3: the next day's file replaces the set atomically -----------
	clk.Advance(24 * time.Hour)
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (day two): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("day-two status = %s, want succeeded", res.Status)
	}
	assertSourceRunCounters(t, res.Counters, 1, wantDay2Rows, 0)
	count, err = q.CountEpssRows(ctx)
	if err != nil || int(count) != wantDay2Rows {
		t.Fatalf("epss_current count after day two = %d, %v; want %d — the set was replaced, no residue", count, err, wantDay2Rows)
	}
	row, err = q.GetEpssByCveID(ctx, "CVE-2026-0009")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2026-0009): %v", err)
	}
	if row.ModelVersion != "2026-09-10" {
		t.Fatalf("day-two row model = %q, want 2026-09-10", row.ModelVersion)
	}
	if _, err := q.GetEpssByCveID(ctx, "CVE-2026-0002"); err == nil {
		t.Fatal("day-one-only CVE still present after day two — the atomic swap must leave no residue")
	}
	if n := countRawRecords(t, pool, srcID); n != 2 {
		t.Fatalf("raw records after day two = %d, want 2", n)
	}
}
