package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// epssCSV is the daily-file fixture (shape of the real FIRST file:
// a "#model_version…" comment line, a "cve,epss,percentile" header and the
// plain data rows). It is shared by the fetch tests and the normalise tests
// of this package.
const epssCSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
CVE-2026-0002,0.00510,0.4021
CVE-2026-0003,0.00057,0.1937
`

// gzipBytes compresses text into the daily file's gzip form — the payload
// shape the fetch returns and the normaliser decompresses.
func gzipBytes(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// hashOf is the SHA-256 hex digest of b — the expected ContentHash.
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fetchInput builds the FetchInput of a full-set fetch: the descriptor
// (endpoint + config, no cursor — EPSS advances none) and no window.
func fetchInput(endpoint string, config map[string]any) application.FetchInput {
	return application.FetchInput{
		Source: application.SourceDescriptor{
			ID:       "src-epss-1",
			Type:     application.SourceTypeEPSS,
			Endpoint: endpoint,
			Config:   config,
		},
	}
}

// newAdapter returns an EPSS adapter whose client talks to srv through the
// server's own transport (network-free) and whose clock reads the fixed
// instant at.
func newAdapter(srv *httptest.Server, at time.Time) *Adapter {
	return New(srv.Client().Transport, clock.NewFakeClock(at))
}

// doFetch runs one Fetch and fails the test on an unexpected error.
func doFetch(t *testing.T, a *Adapter, in application.FetchInput) application.FetchOutput {
	t.Helper()
	out, err := a.Fetch(context.Background(), in)
	if err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}
	return out
}

// TestTypeAndPlan pins the static adapter contract (ARCH-002 §1/§2.3): a
// daily full-set source without a cursor.
func TestTypeAndPlan(t *testing.T) {
	a := New(nil, nil)
	if got := a.Type(); got != application.SourceTypeEPSS {
		t.Errorf("Type() = %q, want epss", got)
	}
	p := a.Plan()
	if p.Kind != application.SourceKindFullSet || p.CursorKind != application.CursorKindNone {
		t.Errorf("Plan() = %+v, want full_set with no cursor", p)
	}
	if p.Schedule != "@daily" {
		t.Errorf("Plan().Schedule = %q, want @daily", p.Schedule)
	}
}

// TestFetchLoadsDailyFile drives one full fetch of the clock's day: the
// server is asked for <endpoint>/epss_scores-2026-09-09.csv.gz and the
// verbatim compressed bytes come back unchanged with their SHA-256 — over
// the compressed file, the raw record (ADR-013) — the file name as the
// external id, no cursor and the response's technical metadata, plus the
// documented zero FetchedAt of a window-less full-set fetch (the wiring
// stamps it).
func TestFetchLoadsDailyFile(t *testing.T) {
	file := gzipBytes(t, epssCSV)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("ETag", `"epss-2026-09-09"`)
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		if _, err := w.Write(file); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}))
	defer srv.Close()

	day := time.Date(2026, 9, 9, 10, 30, 0, 0, time.UTC)
	out := doFetch(t, newAdapter(srv, day), fetchInput(srv.URL, nil))

	if want := "/epss_scores-2026-09-09.csv.gz"; gotPath != want {
		t.Errorf("requested path = %q, want %q (the daily file of the clock's UTC date)", gotPath, want)
	}
	if out.ExternalID != "epss_scores-2026-09-09.csv.gz" {
		t.Errorf("ExternalID = %q, want the daily file name epss_scores-2026-09-09.csv.gz", out.ExternalID)
	}
	if !bytes.Equal(out.Payload, file) {
		t.Error("payload = the decompressed content, want the verbatim compressed file bytes (ADR-013)")
	}
	if want := hashOf(file); out.ContentHash != want {
		t.Errorf("ContentHash = %s, want %s (SHA-256 of the compressed file)", out.ContentHash, want)
	}
	if hashOf([]byte(epssCSV)) == out.ContentHash {
		t.Error("ContentHash matches the decompressed text — the hash must cover the compressed bytes")
	}
	if out.Cursor != nil {
		t.Errorf("Cursor = %s, want nil (full-set source)", out.Cursor)
	}
	if out.Meta.NoChange || out.Meta.RateLimited {
		t.Errorf("Meta = %+v, want a plain successful fetch", out.Meta)
	}
	if out.Meta.Status != http.StatusOK || out.Meta.ContentType != "application/gzip" || out.Meta.Size != int64(len(file)) {
		t.Errorf("Meta status/type/size = %d/%q/%d, want 200/application/gzip/%d", out.Meta.Status, out.Meta.ContentType, out.Meta.Size, len(file))
	}
	if out.Meta.ETag != `"epss-2026-09-09"` {
		t.Errorf("Meta.ETag = %q, want the response's ETag", out.Meta.ETag)
	}
	if !out.Meta.LastModified.Equal(time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("Meta.LastModified = %v, want 2026-09-09T04:00:00Z", out.Meta.LastModified)
	}
	if !out.FetchedAt.IsZero() {
		t.Errorf("FetchedAt = %v, want zero (a full-set fetch carries no window; the wiring stamps it)", out.FetchedAt)
	}
}

// TestFetchDayFromInjectedClockUTC pins the daily date source (ARCH-002
// §2.3, ch. 7.2): the file of the *UTC* date of the injected clock is
// fetched — a clock reading 2026-09-09 01:30 in a +02:00 zone is still
// 2026-09-08 in UTC, and the UTC day is what names the file.
func TestFetchDayFromInjectedClockUTC(t *testing.T) {
	file := gzipBytes(t, epssCSV)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if _, err := w.Write(file); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}))
	defer srv.Close()

	// 2026-09-09 01:30 +02:00 == 2026-09-08 23:30 UTC.
	cest := time.FixedZone("CEST", 2*60*60)
	day := time.Date(2026, 9, 9, 1, 30, 0, 0, cest)
	out := doFetch(t, newAdapter(srv, day), fetchInput(srv.URL, nil))

	if want := "/epss_scores-2026-09-08.csv.gz"; gotPath != want {
		t.Errorf("requested path = %q, want %q (the clock's UTC date)", gotPath, want)
	}
	if out.ExternalID != "epss_scores-2026-09-08.csv.gz" {
		t.Errorf("ExternalID = %q, want epss_scores-2026-09-08.csv.gz", out.ExternalID)
	}
}

// TestFetchUnchangedFileIsNoOp is the content-hash no-op of the same day's
// unchanged file (ch. 8.3, ARCH-002 §2.3): the adapter holds no state and
// reads no database — it compares the fetched file's hash against the last
// committed raw record's hash, which the fetch use case supplies through
// sources.config.last_content_hash. A match reports FetchMeta.NoChange (the
// use case then closes a successful no-op run with counters all 0 and
// skips the reload); the payload and its hash come back either way.
func TestFetchUnchangedFileIsNoOp(t *testing.T) {
	file := gzipBytes(t, epssCSV)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(file); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}))
	defer srv.Close()

	day := time.Date(2026, 9, 9, 10, 30, 0, 0, time.UTC)

	// First import: no stored hash to compare against — full output.
	first := doFetch(t, newAdapter(srv, day), fetchInput(srv.URL, nil))
	if first.Meta.NoChange {
		t.Fatal("first import reported NoChange, want a full fetch")
	}

	// Re-import of the same file: the config carries the previous content
	// hash — a no-op that skips the reload.
	again := doFetch(t, newAdapter(srv, day), fetchInput(srv.URL, map[string]any{"last_content_hash": first.ContentHash}))
	if !again.Meta.NoChange {
		t.Fatalf("unchanged re-import Meta = %+v, want NoChange", again.Meta)
	}
	if again.ContentHash != first.ContentHash || !bytes.Equal(again.Payload, first.Payload) {
		t.Errorf("re-import payload/hash differ: %s vs %s", again.ContentHash, first.ContentHash)
	}
	if again.ExternalID != first.ExternalID || again.Cursor != nil {
		t.Errorf("re-import ExternalID/Cursor = %q/%v, want %q/nil", again.ExternalID, again.Cursor, first.ExternalID)
	}

	// A different day's file (new content hash — and in the wild a new
	// external id too) against the same stored hash is a full fetch again.
	changed := gzipBytes(t, strings.ReplaceAll(epssCSV, "2026-09-09", "2026-09-10"))
	srvChanged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(changed); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}))
	defer srvChanged.Close()
	next := doFetch(t, newAdapter(srvChanged, day), fetchInput(srvChanged.URL, map[string]any{"last_content_hash": first.ContentHash}))
	if next.Meta.NoChange {
		t.Fatal("changed file reported NoChange, want a full fetch")
	}
	if next.ContentHash == first.ContentHash {
		t.Errorf("changed file hash = %s, want a new hash", next.ContentHash)
	}
}

// TestFetchRateLimitedReportsNotAnError pins ch. 14.2: a 429 with
// Retry-After is a rate limit reported through FetchMeta — never an error
// and never a source fault.
func TestFetchRateLimitedReportsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	out, err := New(srv.Client().Transport, nil).Fetch(context.Background(), fetchInput(srv.URL, nil))
	if err != nil {
		t.Fatalf("Fetch of a 429: unexpected error: %v", err)
	}
	if !out.Meta.RateLimited || out.Meta.RetryAfter != 120*time.Second {
		t.Errorf("Meta = %+v, want RateLimited with RetryAfter 120s", out.Meta)
	}
}

// TestFetchStatusErrorIsAnError: any other non-200 status is an
// infrastructure error of the fetch.
func TestFetchStatusErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := New(srv.Client().Transport, nil).Fetch(context.Background(), fetchInput(srv.URL, nil))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("Fetch of a 500 error = %v, want an unexpected-status error", err)
	}
}

// TestFetchRejectsBadEndpoint: the endpoint must be an http(s) URL — the
// scheme check runs before any request (network-free).
func TestFetchRejectsBadEndpoint(t *testing.T) {
	_, err := New(nil, nil).Fetch(context.Background(), fetchInput("ftp://epss.example/files", nil))
	if err == nil || !strings.Contains(err.Error(), "no http(s) scheme") {
		t.Fatalf("Fetch of a non-http endpoint error = %v, want a scheme error", err)
	}
}
