package main

// Integration tests proving I2 exit criterion 1 — a twofold reference
// import produces no duplicates (ARCH-002 §6.1, iterations.md) — against a
// real, short-lived PostgreSQL: the NVD window fixture and the KEV catalog
// fixture under testdata/ (versioned, network-free; see testdata/README.md
// for the fetch dates) are each imported twice through RunSource with the
// real adapters, their endpoints pointed at in-process httptest servers.
//
// NVD leg (incremental window): the source's cursor is pinned at the clock
// instant with a 24 h overlap, so the second run re-fetches the identical
// window [from, to] the first run committed (the cursor advanced to the
// same clock instant — the injected clock does not move). The re-fetch
// dedupes on the raw-record natural key (UQ (source_id, external_id,
// content_hash) returns the stored row) and the re-normalisation of that
// record is deduped by the remaining natural keys: UQ (cve_id) for the
// vulnerability upsert and UQ (raw_record_id, type, value_hash) for the
// immutable evidence statements. The assertion is the literal exit-criteria
// read: identical vulnerabilities/evidences/raw_records row counts after
// run 2 as after run 1, one additional succeeded run row whose committed
// counters equal run 1's (stable run counters), and zero risk_signals.
//
// KEV leg (full set): the identical catalog re-import is recognised by its
// content hash (FetchMeta.NoChange, ch. 8.3) — a successful no-op run that
// stores nothing and re-historises nothing: the same census after run 2 as
// after run 1 with counters all 0.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/sources/kev"
	"github.com/xpera/risksignal/internal/adapters/sources/nvd"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// twofoldNvdConfig fixes the overlap to 24 h (ARCH-002 §2.1 config key)
// and the test seeds the source cursor at the clock instant, so both runs
// open the identical window [now−24h, now] and commit the cursor at now —
// the injected clock does not move, and the second run re-opens
// [now−24h, now] (the promoted cursor minus the 24 h overlap). The
// identical window makes the twofold re-import of the same reference
// deterministic: same external id, same content hash, and therefore the
// same raw record. (DEV-067 widened the cursor-less first window of NVD
// to the full-import lower bound, so a twofold window proof must pin the
// cursor instead of relying on the first-run look-back.)
const twofoldNvdConfig = `{"overlap": 24.0}`

// readFixture loads one versioned reference fixture of this test set
// (testdata/, documented fetch dates in testdata/README.md).
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	// #nosec G304 — name is a compile-time constant of this file; the read
	// is pinned to the package's testdata/ directory, never caller input.
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture testdata/%s: %v", name, err)
	}
	return b
}

// serveBytes serves one fixed fixture body with a JSON content type — the
// network-free stand-in of a full-set source endpoint (KEV catalog).
func serveBytes(body []byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		if _, err := w.Write(body); err != nil {
			panic(err) // serving an in-memory fixture cannot fail
		}
	}))
	return srv
}

// emptyNvdPage is the terminating empty page of an NVD window walk (the
// walk must terminate on an empty page, never on totalResults — ARCH-002
// §2.1).
const emptyNvdPage = `{"resultsPerPage":2000,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`

// writeNvdWindowPage writes one NVD API 2.0 window response: the fixture
// page for the first page of a walk (startIndex 0) and the terminating
// empty page for every further page, so a multi-page request sequence
// cannot loop.
func writeNvdWindowPage(w http.ResponseWriter, body []byte, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
	if r.URL.Query().Get("startIndex") != "0" {
		fmt.Fprint(w, emptyNvdPage)
		return
	}
	if _, err := w.Write(body); err != nil {
		panic(err) // serving an in-memory fixture cannot fail
	}
}

// serveNvdWindow serves one NVD window fixture (the network-free stand-in
// of the NVD API for the window of the tests): the fixture page on the
// first request of a walk, the terminating empty page afterwards.
func serveNvdWindow(body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeNvdWindowPage(w, body, r)
	}))
}

// TestTwofoldNvdImportProducesNoDuplicateRows is the NVD leg of exit
// criterion 1: the same window fixture is imported twice; after run 2 the
// vulnerabilities/evidences/raw_records censuses are identical to after run
// 1 (the natural-key idempotency of UQ (cve_id), UQ (raw_record_id, type,
// value_hash) and UQ (source_id, external_id, content_hash)), the run
// counters are stable across the two runs, and no risk signal exists.
func TestTwofoldNvdImportProducesNoDuplicateRows(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	// The versioned 2026-09-09 window fixture (two reduced CVE records,
	// testdata/README.md) is served for the window of both runs.
	window := readFixture(t, "nvd-window-2026-09-09.json")
	srv := serveNvdWindow(window)
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "nvd",
		Name:     "nvd-twofold-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@hourly", Valid: true},
		Enabled:  true,
		// Pinned cursor (see twofoldNvdConfig): the twofold proof needs
		// two runs over the identical window, not the open-ended
		// full-import window of a cursor-less source.
		Cursor: []byte(`{"last_modified":"2026-09-09T09:30:00Z"}`),
		Config: []byte(twofoldNvdConfig),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)
	adapter := nvd.New(srv.Client().Transport)

	// --- run 1: the reference window is imported once ---------------------
	res1, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (run 1): %v", err)
	}
	if res1.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run-1 status = %s, want succeeded", res1.Status)
	}
	// The fixture normalises to 2 vulnerabilities and 4 evidence
	// statements (nvd_statement + cvss per record — the second record
	// carries only a V2 metric, still one cvss evidence): 6 normalised
	// domain records over the one stored raw record.
	assertSourceRunCounters(t, res1.Counters, 1, 6, 0)
	if res1.CursorAfter == nil {
		t.Fatal("run-1 committed no cursor, want the advanced last-modified cursor")
	}

	censusAfter1 := map[string]int{
		"vulnerabilities": 2, "evidences": 4, "raw_records": 1, "risk_signals": 0,
	}
	assertTableCounts(t, pool, censusAfter1)
	// The committed cursor lives on the succeeded run row (cursor_after is
	// written only by the success path, ch. 6.1 — the sources row itself is
	// never advanced; the monitor reads the freshness basis from the run
	// rows). Run 1 committed the last-modified cursor at the run's clock
	// instant.
	if got := runCursorLastModified(t, pool, res1.RunID); got != "2026-09-09T09:30:00Z" {
		t.Fatalf("run-1 cursor_after last_modified = %q, want the run's clock instant 2026-09-09T09:30:00Z", got)
	}

	// --- run 2: the identical window is imported again --------------------
	// The cursor committed by run 1 minus the 24 h overlap re-opens the
	// exact same window; the fixture server answers it with the same
	// bytes, so the raw record dedupes (UQ) and the re-normalisation of
	// the same raw record is deduped by the cve_id and evidence natural
	// keys. Nothing may grow — this is the no-duplicates proof.
	res2, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (run 2): %v", err)
	}
	if res2.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run-2 status = %s, want succeeded", res2.Status)
	}
	assertSourceRunCounters(t, res2.Counters, 1, 6, 0)
	if string(res2.CursorAfter) != string(res1.CursorAfter) {
		t.Fatalf("run-2 cursor = %s, want the same advanced cursor %s", res2.CursorAfter, res1.CursorAfter)
	}
	assertTableCounts(t, pool, censusAfter1) // identical census after run 2 as after run 1

	// The natural keys hold row-level: one row per cve_id and one
	// immutable statement per (raw_record_id, type, value_hash) — no row
	// a second pass could have added.
	assertSingleRowPerNaturalKey(t, pool, "vulnerabilities", "cve_id")
	assertSingleRowPerNaturalKey(t, pool, "evidences", "raw_record_id, type, value_hash")

	// Stable run counters: exactly two run rows, both succeeded, the
	// second one carrying the same committed counters as the first
	// (records 1 / normalized 6 / no errors) — run 2 re-imported the
	// reference set and added nothing.
	runs := sourceRunCensus(t, pool, srcID)
	if len(runs) != 2 {
		t.Fatalf("run rows after twofold import = %d, want exactly 2: %+v", len(runs), runs)
	}
	wantCounters, err := json.Marshal(res1.Counters)
	if err != nil {
		t.Fatalf("marshal run-1 counters: %v", err)
	}
	for i, row := range runs {
		if row.status != "succeeded" {
			t.Fatalf("run row %d status = %s, want succeeded", i, row.status)
		}
		if !jsonEqual(t, row.counters, wantCounters) {
			t.Fatalf("run row %d counters = %s, want the stable run-1 counters %s", i, row.counters, wantCounters)
		}
	}
}

// TestTwofoldKevImportProducesNoDuplicateRows is the KEV leg of exit
// criterion 1: the identical catalog revision is imported twice; the second
// import is recognised by its content hash (ch. 8.3 NoChange no-op) — the
// content censuses after run 2 equal those after run 1, no second raw
// record is stored and no removal is historised.
func TestTwofoldKevImportProducesNoDuplicateRows(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	catalog := readFixture(t, "kev-catalog-2026-09-09.json")
	srv := serveBytes(catalog)
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "kev",
		Name:     "kev-twofold-int",
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
	adapter := kev.New(srv.Client().Transport)

	// --- run 1: the 2026-09-09 catalog revision is imported once ----------
	res1, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (run 1): %v", err)
	}
	if res1.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run-1 status = %s, want succeeded", res1.Status)
	}
	// Three catalog entries -> three skeleton vulnerabilities and three
	// kev evidence statements: 6 normalised domain records over the one
	// stored raw record.
	assertSourceRunCounters(t, res1.Counters, 1, 6, 0)
	censusAfter1 := map[string]int{
		"vulnerabilities": 3, "evidences": 3, "raw_records": 1, "risk_signals": 0,
	}
	assertTableCounts(t, pool, censusAfter1)
	if n := countEvidenceRows(t, pool, "kev_removed"); n != 0 {
		t.Fatalf("kev_removed rows after run 1 = %d, want 0 (first import)", n)
	}
	// The committed fetch maintained the source's last content hash — the
	// NoChange input of the second import.
	if got := sourceConfigHash(t, pool, srcID); got != sha256Hex(catalog) {
		t.Fatalf("config last_content_hash = %q, want the SHA-256 of the catalog fixture", got)
	}

	// --- run 2: the identical catalog revision is imported again ----------
	// The content-hash match reports the unchanged catalog: a successful
	// no-op run (Meta.NoChange, counters all 0) that stores nothing and
	// re-historises nothing — the census is unchanged.
	res2, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (run 2): %v", err)
	}
	if !res2.Meta.NoChange || res2.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run-2 = status %s meta %+v, want the successful no-op (Meta.NoChange)", res2.Status, res2.Meta)
	}
	if res2.Counters.Records != 0 || res2.Counters.Normalized != 0 || res2.Counters.Errors != 0 {
		t.Fatalf("no-op counters = %+v, want all 0", res2.Counters)
	}
	assertTableCounts(t, pool, censusAfter1) // identical census after run 2 as after run 1
	assertSingleRowPerNaturalKey(t, pool, "vulnerabilities", "cve_id")
	assertSingleRowPerNaturalKey(t, pool, "evidences", "raw_record_id, type, value_hash")

	// Both imports are recorded as run rows (the second one the no-op);
	// the content rows and the raw record never double.
	runs := sourceRunCensus(t, pool, srcID)
	if len(runs) != 2 {
		t.Fatalf("run rows after twofold import = %d, want exactly 2: %+v", len(runs), runs)
	}
	for i, row := range runs {
		if row.status != "succeeded" {
			t.Fatalf("run row %d status = %s, want succeeded", i, row.status)
		}
	}
	if n := countRawRecords(t, pool, srcID); n != 1 {
		t.Fatalf("raw records after twofold import = %d, want 1 — the second import stored nothing", n)
	}
}

// assertSourceRunCounters pins the counters of one reference import run:
// the expected records/normalized/errors, with quarantined mirroring
// errors (every isolated error became a quarantine row).
func assertSourceRunCounters(t *testing.T, c application.SourceRunCounters, records, normalized, errors int) {
	t.Helper()
	if c.Records != records || c.Normalized != normalized || c.Errors != errors || c.Quarantined != errors {
		t.Fatalf("run counters = %+v, want records %d normalized %d errors %d", c, records, normalized, errors)
	}
}

// runState is one committed source_runs row of the census reads.
type runState struct {
	status   string
	counters []byte
}

// sourceRunCensus returns the ordered committed run rows of one source
// (status + counters jsonb).
func sourceRunCensus(t *testing.T, pool *pgxpool.Pool, sourceID string) []runState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		"SELECT status, counters FROM source_runs WHERE source_id = $1 ORDER BY started_at", mustUUID(t, sourceID))
	if err != nil {
		t.Fatalf("list run rows: %v", err)
	}
	defer rows.Close()
	var out []runState
	for rows.Next() {
		var s runState
		if err := rows.Scan(&s.status, &s.counters); err != nil {
			t.Fatalf("scan run row: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate run rows: %v", err)
	}
	return out
}

// runCursorLastModified reads the committed cursor_after jsonb of one run
// row and returns its last_modified member ("" when the run committed no
// cursor).
func runCursorLastModified(t *testing.T, pool *pgxpool.Pool, runID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var cursor pgtype.Text
	if err := pool.QueryRow(ctx,
		"SELECT cursor_after::text FROM source_runs WHERE id = $1", mustUUID(t, runID)).Scan(&cursor); err != nil {
		t.Fatalf("read run cursor_after: %v", err)
	}
	if !cursor.Valid {
		return ""
	}
	var parsed struct {
		LastModified string `json:"last_modified"`
	}
	if err := json.Unmarshal([]byte(cursor.String), &parsed); err != nil {
		t.Fatalf("decode run cursor_after %q: %v", cursor.String, err)
	}
	return parsed.LastModified
}

// assertSingleRowPerNaturalKey asserts that the row census of one table

// assertSingleRowPerNaturalKey asserts that the row census of one table
// equals its distinct natural-key census — no table row that a duplicate
// import could have added (the row-level idempotency read of exit
// criterion 1). The table and key expressions are compile-time constants
// of this file, never caller input.
func assertSingleRowPerNaturalKey(t *testing.T, pool *pgxpool.Pool, table, keys string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var total, distinct int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&total); err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(DISTINCT ("+keys+")) FROM "+table).Scan(&distinct); err != nil {
		t.Fatalf("count distinct (%s) in %s: %v", keys, table, err)
	}
	if total != distinct {
		t.Fatalf("%s rows = %d but distinct (%s) = %d — duplicates present", table, total, keys, distinct)
	}
}

// jsonEqual compares two JSON documents semantically.
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("decode %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	aj, _ := json.Marshal(av)
	bj, _ := json.Marshal(bv)
	return string(aj) == string(bj)
}
