package application_test

// Network-free tests of the NVD full-import driver (DEV-067, WP-3.09b,
// ARCH-003 §6): FullImportSource streams the whole history of a
// cursor-less NVD source in bounded checkpointed windows through the
// existing RunSource machinery (fetch + normalise per window, committed
// run by run), with the real NVD adapter walking a multi-page in-process
// httptest server. Each window is one committed step — the raw record and
// its normalised objects land and the cursor promotion writes the window's
// watermark back into sources.cursor, so the driver is resumable: a
// rate-limited interruption stops the walk with the cursor at the last
// committed chunk end, and the re-invocation resumes there instead of
// re-fetching the committed windows.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/adapters/sources/nvd"
	"github.com/xpera/risksignal/internal/application"
)

// fullImportCveEntry renders one minimal NVD record entry (the {"cve": …}
// shape the normalise pass decodes).
func fullImportCveEntry(id string) string {
	return fmt.Sprintf(`{"cve":{"id":%q}}`, id)
}

// fullImportNvdPage renders one API 2.0 response page of a multi-page
// full-import fixture: every data page carries nVulns records, the walk
// terminates on the empty page (startIndex 4000) exactly like the real
// API's pagination beyond the served set.
func fullImportNvdPage(startIndex, nVulns int) string {
	vulns := make([]string, 0, nVulns)
	for i := 0; i < nVulns; i++ {
		vulns = append(vulns, fullImportCveEntry(fmt.Sprintf("CVE-2026-%04d", startIndex/2000*1000+i+1)))
	}
	return fmt.Sprintf(`{"resultsPerPage":2000,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`,
		startIndex, startIndex+nVulns, strings.Join(vulns, ","))
}

// serveFullImportNvd serves the fixed three-page dataset of the full
// import tests and counts the requests of the whole walk.
func serveFullImportNvd() (*httptest.Server, *atomic.Int64) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		switch start {
		case 0:
			fmt.Fprint(w, fullImportNvdPage(0, 2)) // two full data pages…
		case 2000:
			fmt.Fprint(w, fullImportNvdPage(2000, 2))
		default:
			fmt.Fprint(w, fullImportNvdPage(start, 0)) // …then the empty page stops the walk
		}
	}))
	return srv, &hits
}

// fullImportSource seeds the cursor-less NVD source row of the full-import
// tests: the import starts at config.full_import_since and walks
// config.full_import_chunk-sized windows up to the injected clock.
func fullImportSource(h *harness, endpoint, since string, chunk any) {
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:       "src-nvd-full",
		Type:     application.SourceTypeNVD,
		Endpoint: endpoint,
		Config: map[string]any{
			"full_import_since": since,
			"full_import_chunk": chunk,
		},
	})
}

// TestFullImportSourceStreamsCheckpointedWindows is the checkpointed
// streaming proof (ARCH-003 §6): the cursor-less source's history
// [2026-09-01, now] is walked in two 168 h windows; every window commits
// its own run and promotes its cursor watermark into sources.cursor, the
// multi-page NVD walk runs per window (six page requests in total), the
// normalised CVEs dedupe across the re-fetched overlap and the final
// watermark equals the clock's now.
func TestFullImportSourceStreamsCheckpointedWindows(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	srv, hits := serveFullImportNvd()
	defer srv.Close()
	fullImportSource(h, srv.URL, "2026-09-01T00:00:00Z", "168h")
	adapter := nvd.New(srv.Client().Transport)

	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: adapter})
	if err != nil {
		t.Fatalf("FullImportSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded", res.Status)
	}
	// Two committed chunk windows: [09-01, 09-08] and [09-08, 09-09 09:30]
	// (the clock's now), each fetching three pages of the fixture.
	if res.Chunks != 2 {
		t.Fatalf("chunks = %d, want 2 committed windows", res.Chunks)
	}
	if got := hits.Load(); got != 6 {
		t.Fatalf("page requests = %d, want 6 (three pages per window × two windows)", got)
	}

	// Cursor promotion per committed step: the source row cursor holds the
	// final window's watermark — the clock's now.
	desc, err := h.sources.GetByID(ctx, "src-nvd-full")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	want := json.RawMessage(`{"last_modified":"2026-09-09T09:30:00Z"}`)
	if string(desc.Cursor) != string(want) {
		t.Fatalf("sources.cursor = %s, want the promoted final watermark %s", desc.Cursor, want)
	}

	// Every window committed its own succeeded run with one raw record.
	if len(h.db.sourceRuns) != 2 {
		t.Fatalf("runs = %d, want 2 (one per checkpointed window)", len(h.db.sourceRuns))
	}
	for i, run := range h.db.sourceRuns {
		if run.status != "succeeded" || run.counters.Records != 1 {
			t.Fatalf("run %d = status %q records %d, want succeeded with 1 raw record", i, run.status, run.counters.Records)
		}
		if len(run.cursorAfter) == 0 {
			t.Fatalf("run %d committed no cursor_after", i)
		}
	}
	if len(h.db.rawRecords) != 2 {
		t.Fatalf("raw records = %d, want 2 (one stored slice per window)", len(h.db.rawRecords))
	}
	// The four distinct fixture CVEs normalise once each — the windows
	// re-fetch the overlap and the natural key (cve_id) dedupes.
	if len(h.db.vulns) != 4 {
		t.Fatalf("vulnerabilities = %d, want the 4 distinct fixture CVEs", len(h.db.vulns))
	}
}

// TestFullImportSourceResumesAfterRateLimit is the resume proof of the
// checkpointed walk: a rate-limited window stops the driver with the run
// recorded rate-limited (ch. 14.2) and the cursor at the last committed
// chunk end; the re-invocation resumes at the interrupted window instead
// of re-fetching the committed one.
func TestFullImportSourceResumesAfterRateLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		switch start {
		case 0:
			fmt.Fprint(w, fullImportNvdPage(0, 2))
		case 2000:
			fmt.Fprint(w, fullImportNvdPage(2000, 2))
		default:
			fmt.Fprint(w, fullImportNvdPage(start, 0))
		}
	}))
	defer srv.Close()
	fullImportSource(h, srv.URL, "2026-09-01T00:00:00Z", "168h")
	adapter := nvd.New(srv.Client().Transport)

	// --- the first window is rate-limited (recorded rate-limited) --------
	healthy.Store(false)
	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: adapter})
	if err != nil {
		t.Fatalf("FullImportSource (rate limited): %v", err)
	}
	if res.Status != application.SourceRunStatusFailed || !res.Meta.RateLimited {
		t.Fatalf("result = status %s meta %+v, want failed with Meta.RateLimited", res.Status, res.Meta)
	}
	if res.Meta.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want the header's 30s backoff", res.Meta.RetryAfter)
	}
	if res.Chunks != 0 {
		t.Fatalf("chunks = %d, want 0 — the rate-limited window committed nothing", res.Chunks)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" || run.errText != application.RateLimitedErrorText {
		t.Fatalf("rate-limited run = status %q error %q, want failed recorded rate-limited", run.status, run.errText)
	}
	desc, _ := h.sources.GetByID(ctx, "src-nvd-full")
	if len(desc.Cursor) != 0 {
		t.Fatalf("sources.cursor = %s, want none — a rate-limited run never promotes", desc.Cursor)
	}

	// --- the recovered re-invocation imports both windows -----------------
	healthy.Store(true)
	res, err = h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: adapter})
	if err != nil {
		t.Fatalf("FullImportSource after recovery: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Chunks != 2 {
		t.Fatalf("recovered import = status %s chunks %d, want succeeded with 2 committed windows", res.Status, res.Chunks)
	}
	desc, _ = h.sources.GetByID(ctx, "src-nvd-full")
	want := json.RawMessage(`{"last_modified":"2026-09-09T09:30:00Z"}`)
	if string(desc.Cursor) != string(want) {
		t.Fatalf("sources.cursor = %s, want the promoted final watermark %s", desc.Cursor, want)
	}
	if len(h.db.sourceRuns) != 3 {
		t.Fatalf("runs = %d, want 3 (one rate-limited + two committed windows)", len(h.db.sourceRuns))
	}
}
