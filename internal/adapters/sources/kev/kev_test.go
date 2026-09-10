package kev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// Catalog fixtures (shape of the official KEV feed,
// known_exploited_vulnerabilities.json): a metadata envelope plus a
// vulnerabilities[] array. The entries below are shared by the fetch tests
// and the normalise tests of this package.
const (
	entryA = `{
	  "cveID": "CVE-2026-0001",
	  "vendorProject": "Acme Corporation",
	  "product": "Widget Parser",
	  "vulnerabilityName": "Acme Widget Parser Stack Overflow",
	  "dateAdded": "2026-08-01",
	  "shortDescription": "Stack overflow in the Acme Widget Parser allows remote code execution.",
	  "requiredAction": "Apply vendor-supplied mitigations or discontinue use.",
	  "dueDate": "2026-10-01",
	  "knownRansomwareCampaignUse": true,
	  "notes": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
	}`
	entryB = `{
	  "cveID": "CVE-2026-0002",
	  "vendorProject": "Acme Corporation",
	  "product": "Widget Parser",
	  "vulnerabilityName": "Acme Widget Parser Use-After-Free",
	  "dateAdded": "2026-08-15",
	  "shortDescription": "Use-after-free in the Acme Widget Parser leads to code execution.",
	  "requiredAction": "Apply vendor-supplied mitigations.",
	  "dueDate": "",
	  "knownRansomwareCampaignUse": false
	}`
	entryC = `{
	  "cveID": "CVE-2026-0003",
	  "vendorProject": "Beta Systems",
	  "product": "Gateway",
	  "vulnerabilityName": "Beta Gateway Command Injection",
	  "dateAdded": "2026-09-01",
	  "shortDescription": "Command injection in the Beta Gateway allows remote takeover.",
	  "requiredAction": "Apply the vendor update.",
	  "dueDate": "2026-11-01",
	  "knownRansomwareCampaignUse": false
	}`
)

// catalogDoc renders one catalog document envelope around the given
// entries. The dateReleased/catalogVersion metadata is what the fetch's
// external id is derived from; some tests set a release date that
// deliberately differs from the version to pin the probe order.
func catalogDoc(dateReleased, version string, entries ...string) string {
	return `{"title":"CISA Catalog of Known Exploited Vulnerabilities",` +
		`"catalogVersion":"` + version + `",` +
		`"dateReleased":"` + dateReleased + `",` +
		`"count":` + fmt.Sprintf("%d", len(entries)) + `,` +
		`"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
}

// fetchInput builds the FetchInput of a full-set fetch: the descriptor
// (endpoint + config, no cursor — KEV advances none) and no window.
func fetchInput(endpoint string, config map[string]any) application.FetchInput {
	return application.FetchInput{
		Source: application.SourceDescriptor{
			ID:       "src-kev-1",
			Type:     application.SourceTypeKEV,
			Endpoint: endpoint,
			Config:   config,
		},
	}
}

// newAdapter returns a KEV adapter whose client talks to srv through the
// server's own transport (network-free).
func newAdapter(srv *httptest.Server) *Adapter {
	return New(srv.Client().Transport)
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

// hashOf is the SHA-256 hex digest of b — the expected ContentHash.
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestTypeAndPlan pins the static adapter contract (ARCH-002 §1/§2.2): a
// daily full-set source without a cursor.
func TestTypeAndPlan(t *testing.T) {
	a := New(nil)
	if got := a.Type(); got != application.SourceTypeKEV {
		t.Errorf("Type() = %q, want kev", got)
	}
	p := a.Plan()
	if p.Kind != application.SourceKindFullSet || p.CursorKind != application.CursorKindNone {
		t.Errorf("Plan() = %+v, want full_set with no cursor", p)
	}
	if p.Schedule != "@daily" {
		t.Errorf("Plan().Schedule = %q, want @daily", p.Schedule)
	}
}

// TestFetchLoadsCatalog drives one full fetch: the verbatim document bytes
// come back unchanged with their SHA-256, the catalog-version external id,
// no cursor and the response's technical metadata — plus the documented
// zero FetchedAt of a window-less full-set fetch (the wiring stamps it).
func TestFetchLoadsCatalog(t *testing.T) {
	doc := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA, entryB, entryC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"kev-2026.09.09"`)
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		fmt.Fprint(w, doc)
	}))
	defer srv.Close()

	out := doFetch(t, newAdapter(srv), fetchInput(srv.URL, nil))

	if out.ExternalID != "kev-2026-09-09" {
		t.Errorf("ExternalID = %q, want kev-2026-09-09 (the catalog version/date)", out.ExternalID)
	}
	if string(out.Payload) != doc {
		t.Errorf("payload = %s, want the verbatim document bytes", out.Payload)
	}
	if want := hashOf([]byte(doc)); out.ContentHash != want {
		t.Errorf("ContentHash = %s, want %s (SHA-256 of the whole document)", out.ContentHash, want)
	}
	if out.Cursor != nil {
		t.Errorf("Cursor = %s, want nil (full-set source)", out.Cursor)
	}
	if out.Meta.NoChange || out.Meta.RateLimited {
		t.Errorf("Meta = %+v, want a plain successful fetch", out.Meta)
	}
	if out.Meta.Status != http.StatusOK || out.Meta.ContentType != "application/json" || out.Meta.Size != int64(len(doc)) {
		t.Errorf("Meta status/type/size = %d/%q/%d, want 200/application/json/%d", out.Meta.Status, out.Meta.ContentType, out.Meta.Size, len(doc))
	}
	if out.Meta.ETag != `"kev-2026.09.09"` {
		t.Errorf("Meta.ETag = %q, want the response's ETag", out.Meta.ETag)
	}
	if !out.Meta.LastModified.Equal(time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("Meta.LastModified = %v, want 2026-09-09T04:00:00Z", out.Meta.LastModified)
	}
	if !out.FetchedAt.IsZero() {
		t.Errorf("FetchedAt = %v, want zero (a full-set fetch carries no window; the wiring stamps it)", out.FetchedAt)
	}
}

// TestFetchExternalIDPriority pins the metadata probe order (ARCH-002
// §2.2): dateReleased wins over a conflicting catalogVersion, and the
// dotted catalog-version spelling alone still resolves to the same date
// key.
func TestFetchExternalIDPriority(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "dateReleased wins over catalogVersion",
			doc:  `{"catalogVersion":"2020.01.01","dateReleased":"2026-09-09T04:00:00.000Z","count":0,"vulnerabilities":[]}`,
			want: "kev-2026-09-09",
		},
		{
			name: "dotted catalogVersion only",
			doc:  `{"catalogVersion":"2026.09.09","count":0,"vulnerabilities":[]}`,
			want: "kev-2026-09-09",
		},
		{
			name: "dashed catalogVersion only",
			doc:  `{"catalogVersion":"2026-09-10","count":0,"vulnerabilities":[]}`,
			want: "kev-2026-09-10",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.doc)
			}))
			defer srv.Close()
			out := doFetch(t, newAdapter(srv), fetchInput(srv.URL, nil))
			if out.ExternalID != tc.want {
				t.Errorf("ExternalID = %q, want %q", out.ExternalID, tc.want)
			}
		})
	}
}

// TestFetchUnchangedCatalogIsNoOp is the content-hash no-op of an
// unchanged catalog (ch. 8.3): the adapter holds no state and reads no
// database — it compares the fetched document's hash against the last
// committed raw record's hash, which the fetch use case supplies through
// sources.config.last_content_hash. A match reports FetchMeta.NoChange
// (the use case then closes a successful no-op run with counters all 0);
// the payload and its hash come back either way.
func TestFetchUnchangedCatalogIsNoOp(t *testing.T) {
	doc := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA, entryB, entryC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, doc)
	}))
	defer srv.Close()

	// First import: no stored hash to compare against — full output.
	first := doFetch(t, newAdapter(srv), fetchInput(srv.URL, nil))
	if first.Meta.NoChange {
		t.Fatal("first import reported NoChange, want a full fetch")
	}

	// Re-import of the same document: the config carries the previous
	// content hash — a no-op.
	again := doFetch(t, newAdapter(srv), fetchInput(srv.URL, map[string]any{"last_content_hash": first.ContentHash}))
	if !again.Meta.NoChange {
		t.Fatalf("unchanged re-import Meta = %+v, want NoChange", again.Meta)
	}
	if again.ContentHash != first.ContentHash || string(again.Payload) != string(first.Payload) {
		t.Errorf("re-import payload/hash differ: %s vs %s", again.ContentHash, first.ContentHash)
	}
	if again.ExternalID != first.ExternalID || again.Cursor != nil {
		t.Errorf("re-import ExternalID/Cursor = %q/%v, want %q/nil", again.ExternalID, again.Cursor, first.ExternalID)
	}

	// A changed catalog against the same stored hash is a full fetch again
	// (new revision, new version/date and new hash).
	changed := catalogDoc("2026-09-10T04:00:00.000Z", "2026.09.10", entryA, entryB)
	srvChanged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, changed)
	}))
	defer srvChanged.Close()
	next := doFetch(t, newAdapter(srvChanged), fetchInput(srvChanged.URL, map[string]any{"last_content_hash": first.ContentHash}))
	if next.Meta.NoChange {
		t.Fatal("changed catalog reported NoChange, want a full fetch")
	}
	if next.ExternalID != "kev-2026-09-10" || next.ContentHash == first.ContentHash {
		t.Errorf("changed catalog ExternalID/hash = %q/%s, want kev-2026-09-10 with a new hash", next.ExternalID, next.ContentHash)
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

	out, err := New(srv.Client().Transport).Fetch(context.Background(), fetchInput(srv.URL, nil))
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

	_, err := New(srv.Client().Transport).Fetch(context.Background(), fetchInput(srv.URL, nil))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("Fetch of a 500 error = %v, want an unexpected-status error", err)
	}
}

// TestFetchRejectsUnidentifiableCatalog: a document whose envelope carries
// no parseable version/date cannot be named and is not storable.
func TestFetchRejectsUnidentifiableCatalog(t *testing.T) {
	doc := `{"title":"CISA Catalog of Known Exploited Vulnerabilities","count":0,"vulnerabilities":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, doc)
	}))
	defer srv.Close()

	_, err := New(srv.Client().Transport).Fetch(context.Background(), fetchInput(srv.URL, nil))
	if err == nil || !strings.Contains(err.Error(), "version/date metadata") {
		t.Fatalf("Fetch of a metadata-less catalog error = %v, want a version/date error", err)
	}
}

// TestFetchRejectsBadEndpoint: the endpoint must be an http(s) URL — the
// scheme check runs before any request (network-free).
func TestFetchRejectsBadEndpoint(t *testing.T) {
	_, err := New(nil).Fetch(context.Background(), fetchInput("ftp://cisa.gov/kev.json", nil))
	if err == nil || !strings.Contains(err.Error(), "no http(s) scheme") {
		t.Fatalf("Fetch of a non-http endpoint error = %v, want a scheme error", err)
	}
}
