package main

// The DEV-067 acceptance test (WP-3.09b, ARCH-003 §6) against a real,
// short-lived PostgreSQL: the NVD full import — the real NVD adapter
// walking a multi-page, network-free in-process httptest server — streams
// the cursor-less source's whole history in one checkpointed window,
// promotes sources.cursor to the clock's now and enqueues exactly ONE
// matching.rebuild (the DEV-060/065 contract), with the DEV-067 job-count
// metric ≤ the threshold of 1 and ≪ the imported CVE count. A second
// invocation over the completed source fetches nothing and dedupes its
// fan-in onto the existing job: the rebuild stays exactly-once (ADR-012
// point 4).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newMigratedTestPool), so `go test ./...`
// stays green on machines without the environment.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/sources/nvd"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// fullImportPage renders one API 2.0 response page of the multi-page full
// import fixture: two reduced CVE records per data page (the {"cve": …}
// entry shape the normaliser decodes), the terminating empty page past the
// served set. startIndex advances by the adapter's resultsPerPage (2000).
func fullImportPage(startIndex int) string {
	base := startIndex / 2000
	vulns := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		vulns = append(vulns, fmt.Sprintf(`{"cve":{"id":"CVE-2026-%04d"}}`, base*1000+i+1))
	}
	return fmt.Sprintf(`{"resultsPerPage":2000,"startIndex":%d,"totalResults":4,"vulnerabilities":[%s]}`,
		startIndex, strings.Join(vulns, ","))
}

// serveMultiPageNvd serves the fixed two-data-page dataset of the full
// import walk and counts the requests.
func serveMultiPageNvd() (*httptest.Server, func() int) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		switch start {
		case 0, 2000:
			fmt.Fprint(w, fullImportPage(start)) // two data pages…
		default:
			fmt.Fprint(w, `{"resultsPerPage":2000,"startIndex":`+strconv.Itoa(start)+`,"totalResults":4,"vulnerabilities":[]}`) // …then the empty page stops the walk
		}
	}))
	return srv, func() int { return hits }
}

// TestFullImportNvdPromotesCursorAndEnqueuesOneRebuild is the DEV-067
// acceptance criterion: multi-page NVD full import → sources.cursor
// promoted; exactly one matching.rebuild enqueued; matching-job count ≤
// threshold and ≪ the imported CVE count.
func TestFullImportNvdPromotesCursorAndEnqueuesOneRebuild(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	srv, pageRequests := serveMultiPageNvd()
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "nvd",
		Name:     "nvd-full-import-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@hourly", Valid: true},
		Enabled:  true,
		Config: []byte(`{"full_import_since": "2026-09-09T00:00:00Z",
		                 "full_import_chunk": "720h"}`),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)
	adapter := nvd.New(srv.Client().Transport)

	// --- the full import: one window [since, now], three pages -----------
	res, err := svc.FullImportSource(ctx, application.FullImportSourceInput{
		SourceID: srcID,
		Adapter:  adapter,
	})
	if err != nil {
		t.Fatalf("FullImportSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Chunks != 1 {
		t.Fatalf("full import = status %s chunks %d, want succeeded with 1 committed window", res.Status, res.Chunks)
	}
	if got := pageRequests(); got != 3 {
		t.Fatalf("page requests = %d, want 3 (two data pages + the terminating empty page)", got)
	}

	// Cursor promotion: sources.cursor holds the window's watermark — the
	// injected clock's now (compared semantically: jsonb renders its text
	// canonically, with whitespace the compact literal does not carry).
	var storedCursor []byte
	if err := pool.QueryRow(ctx,
		"SELECT cursor FROM sources WHERE id = $1", sourceID).Scan(&storedCursor); err != nil {
		t.Fatalf("read sources.cursor: %v", err)
	}
	var cursor struct {
		LastModified string `json:"last_modified"`
	}
	if err := json.Unmarshal(storedCursor, &cursor); err != nil {
		t.Fatalf("decode sources.cursor %s: %v", storedCursor, err)
	}
	if cursor.LastModified != "2026-09-09T09:30:00Z" {
		t.Fatalf("sources.cursor last_modified = %q, want the promoted final watermark 2026-09-09T09:30:00Z", cursor.LastModified)
	}

	// The four distinct fixture CVEs normalised once; no record failed.
	assertTableCounts(t, pool, map[string]int{
		"vulnerabilities": 4, "raw_records": 1, "quarantine": 0,
	})

	// Single-rebuild fan-in: exactly one matching.rebuild outbox row with
	// the DEV-060/065 payload contract and the §5 dedupe key.
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE type = $1", application.EventTypeMatchingRebuild).Scan(&n); err != nil {
		t.Fatalf("count matching.rebuild rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("matching.rebuild rows = %d, want exactly 1", n)
	}
	var payloadBytes []byte
	var dedupeKey string
	if err := pool.QueryRow(ctx,
		"SELECT payload, dedupe_key FROM outbox WHERE type = $1 LIMIT 1",
		application.EventTypeMatchingRebuild).Scan(&payloadBytes, &dedupeKey); err != nil {
		t.Fatalf("read matching.rebuild row: %v", err)
	}
	var payload application.MatchingRebuildPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode rebuild payload: %v", err)
	}
	if payload.Type != application.EventTypeMatchingRebuild || payload.EventID == "" || payload.ImportID == "" {
		t.Fatalf("payload envelope = %+v, want type/event_id/import_id set", payload)
	}
	if payload.RuleVersion != "a0000000000d0000000000" {
		t.Fatalf("payload rule_version = %q, want a0000000000d0000000000 (no rules configured)", payload.RuleVersion)
	}
	if len(payload.InventorySnapshot) != 64 {
		t.Fatalf("payload inventory_snapshot = %q, want a 64-hex sha-256", payload.InventorySnapshot)
	}
	if wantKey := "matching.rebuild:" + payload.RuleVersion + ":" + payload.InventorySnapshot; dedupeKey != wantKey {
		t.Fatalf("dedupe key = %q, want %q", dedupeKey, wantKey)
	}

	// Job-count metric (DEV-067): exactly 1 matching job — ≤ the
	// threshold of 1 by construction and ≪ the four imported CVEs.
	const threshold = 1
	if res.MatchingJobsEnqueued != 1 || res.MatchingJobsEnqueued > threshold {
		t.Fatalf("matching jobs enqueued = %d, want exactly 1 (≤ threshold %d)", res.MatchingJobsEnqueued, threshold)
	}
	if res.MatchingJobsEnqueued >= 4 {
		t.Fatalf("matching jobs %d ≪ CVE count 4 must hold", res.MatchingJobsEnqueued)
	}

	// --- a second invocation fetches nothing and the fan-in dedupes ------
	res2, err := svc.FullImportSource(ctx, application.FullImportSourceInput{
		SourceID: srcID,
		Adapter:  adapter,
	})
	if err != nil {
		t.Fatalf("FullImportSource (run 2): %v", err)
	}
	if res2.Status != application.SourceRunStatusSucceeded || res2.Chunks != 0 {
		t.Fatalf("second full import = status %s chunks %d, want succeeded with 0 windows (cursor already at now)", res2.Status, res2.Chunks)
	}
	if res2.MatchingJobsEnqueued != 0 {
		t.Fatalf("second run matching jobs = %d, want 0 (fan-in deduped onto the existing job)", res2.MatchingJobsEnqueued)
	}
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE type = $1", application.EventTypeMatchingRebuild).Scan(&n); err != nil {
		t.Fatalf("count matching.rebuild rows (run 2): %v", err)
	}
	if n != 1 {
		t.Fatalf("matching.rebuild rows after run 2 = %d, want still exactly 1", n)
	}
	if got := pageRequests(); got != 3 {
		t.Fatalf("page requests after run 2 = %d, want still 3 — the second invocation fetches nothing", got)
	}
}
