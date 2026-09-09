package nvd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
)

// Fixed window of the fetch tests: the injected clock's now (Window.To)
// and the stored cursor it is measured from.
var (
	windowTo    = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)
	cursor07UTC = json.RawMessage(`{"last_modified":"2026-09-09T07:00:00Z"}`)
	rfc3339To   = windowTo.UTC().Format(time.RFC3339)
)

// fetchInput builds a FetchInput with the given descriptor bits and the
// fixed window To; Window.From is deliberately left zero — the adapter
// derives the start from the cursor/config itself (ARCH-002 §2.1).
func fetchInput(endpoint string, config map[string]any, cursor json.RawMessage, apiKeyRef string) application.FetchInput {
	return application.FetchInput{
		Source: application.SourceDescriptor{
			ID:       "src-nvd-1",
			Type:     application.SourceTypeNVD,
			Endpoint: endpoint,
			Config:   config,
			Cursor:   cursor,
		},
		Window:    application.TimeWindow{To: windowTo},
		APIKeyRef: apiKeyRef,
	}
}

// pageJSON renders one minimal API 2.0 response page. totalResults echoes
// the whole-window total (as the real API does); the tests deliberately
// never let the walk trust it.
func pageJSON(startIndex, totalResults, nVulns int) string {
	vulns := make([]string, 0, nVulns)
	for i := 0; i < nVulns; i++ {
		vulns = append(vulns, fmt.Sprintf(`{"id":"CVE-2026-%04d"}`, startIndex+i+1))
	}
	return fmt.Sprintf(`{"resultsPerPage":2000,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`,
		startIndex, totalResults, strings.Join(vulns, ","))
}

// newAdapter returns an NVD adapter whose client talks to srv through the
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

// TestTypeAndPlan pins the static adapter contract (ARCH-002 §1).
func TestTypeAndPlan(t *testing.T) {
	a := New(nil)
	if got := a.Type(); got != application.SourceTypeNVD {
		t.Errorf("Type() = %q, want nvd", got)
	}
	p := a.Plan()
	if p.Kind != application.SourceKindIncremental || p.CursorKind != application.CursorKindLastModified {
		t.Errorf("Plan() = %+v, want incremental last_modified", p)
	}
}

// TestFetchWalksPagesUntilEmptyPage drives the full pagination walk: the
// server advertises only 4 CVEs in total (one page at 2000/page), yet
// serves two full pages and a terminating empty one. A walk that trusted
// totalResults would stop after one request; the adapter must issue three
// (startIndex 0, 2000, 4000) and stop on the empty page.
func TestFetchWalksPagesUntilEmptyPage(t *testing.T) {
	var starts []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != apiPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, apiPath)
		}
		if got := r.URL.Query().Get("resultsPerPage"); got != "2000" {
			t.Errorf("resultsPerPage = %q, want 2000", got)
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		starts = append(starts, start)
		switch start {
		case 0:
			fmt.Fprint(w, pageJSON(0, 4, 2)) // two full pages…
		case 2000:
			fmt.Fprint(w, pageJSON(2000, 4, 2))
		default:
			fmt.Fprint(w, pageJSON(start, 4, 0)) // …then the empty page stops the walk
		}
	}))
	defer srv.Close()

	out := doFetch(t, newAdapter(srv), fetchInput(srv.URL, nil, cursor07UTC, ""))

	if len(starts) != 3 || starts[0] != 0 || starts[1] != 2000 || starts[2] != 4000 {
		t.Fatalf("walk issued startIndex pages %v, want [0 2000 4000] (terminate on empty page, never totalResults)", starts)
	}

	wantPayload := strings.Join([]string{pageJSON(0, 4, 2), pageJSON(2000, 4, 2)}, "\n")
	if string(out.Payload) != wantPayload {
		t.Errorf("payload = %s, want the two verbatim pages joined", out.Payload)
	}
	sum := sha256.Sum256([]byte(wantPayload))
	if out.ContentHash != hex.EncodeToString(sum[:]) {
		t.Errorf("ContentHash = %s, want SHA-256 of the joined payload", out.ContentHash)
	}
	if want := "nvd:2026-09-09T05:00:00Z:" + rfc3339To; out.ExternalID != want {
		t.Errorf("ExternalID = %q, want %q", out.ExternalID, want)
	}
	if !out.FetchedAt.Equal(windowTo) {
		t.Errorf("FetchedAt = %v, want the injected clock's now %v", out.FetchedAt, windowTo)
	}
	if got, want := string(out.Cursor), `{"last_modified":"`+rfc3339To+`"}`; got != want {
		t.Errorf("Cursor = %s, want %s", got, want)
	}
}

// TestFetchEmptyWindowStoresSlice proves that a window without modified
// CVEs still returns a storable slice (its single empty page), so the use
// case can commit the run and advance the cursor.
func TestFetchEmptyWindowStoresSlice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pageJSON(0, 0, 0))
	}))
	defer srv.Close()

	out := doFetch(t, newAdapter(srv), fetchInput(srv.URL, map[string]any{"overlap": 2.0}, cursor07UTC, ""))
	if out.ExternalID == "" || out.ContentHash == "" || len(out.Payload) == 0 {
		t.Fatalf("empty window must still return a storable slice, got %+v", out)
	}
}

// TestFetchRateLimited covers the ch. 14.2 contract: 429/503 is a
// rate-limit signal on the metadata — never an error — and the walk stops.
func TestFetchRateLimited(t *testing.T) {
	t.Run("429 with Retry-After", func(t *testing.T) {
		var hits int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()

		out, err := newAdapter(srv).Fetch(context.Background(), fetchInput(srv.URL, nil, cursor07UTC, ""))
		if err != nil {
			t.Fatalf("Fetch: a rate limit must not be an error, got %v", err)
		}
		if !out.Meta.RateLimited {
			t.Errorf("Meta.RateLimited = false, want true")
		}
		if out.Meta.RetryAfter != 30*time.Second {
			t.Errorf("Meta.RetryAfter = %v, want 30s", out.Meta.RetryAfter)
		}
		if out.Meta.Status != http.StatusTooManyRequests {
			t.Errorf("Meta.Status = %d, want 429", out.Meta.Status)
		}
		if out.ExternalID != "" || out.Cursor != nil || len(out.Payload) != 0 {
			t.Errorf("a rate-limited fetch must return no slice, got %+v", out)
		}
		if hits != 1 {
			t.Errorf("walk issued %d requests, want 1 (stop on rate limit)", hits)
		}
	})

	t.Run("503 without Retry-After", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		out, err := newAdapter(srv).Fetch(context.Background(), fetchInput(srv.URL, nil, cursor07UTC, ""))
		if err != nil {
			t.Fatalf("Fetch: a rate limit must not be an error, got %v", err)
		}
		if !out.Meta.RateLimited || out.Meta.RetryAfter != 0 {
			t.Errorf("Meta = %+v, want RateLimited with no RetryAfter", out.Meta)
		}
	})
}

// TestFetchWindow derives the window from the stored cursor minus the
// configured overlap, and bounds the first run by the look-back window —
// all from the injected clock (never the wall clock).
func TestFetchWindow(t *testing.T) {
	cases := []struct {
		name      string
		config    map[string]any
		cursor    json.RawMessage
		wantStart string
	}{
		{
			name:      "cursor minus configured overlap",
			config:    map[string]any{"overlap": 2.0},
			cursor:    cursor07UTC,
			wantStart: "2026-09-09T05:00:00Z",
		},
		{
			name:      "overlap defaults to two hours",
			cursor:    cursor07UTC,
			wantStart: "2026-09-09T05:00:00Z",
		},
		{
			name:      "first run bounded by default window",
			wantStart: "2026-09-08T09:30:00Z",
		},
		{
			name:      "first run bounded by configured window",
			config:    map[string]any{"window": "2h"},
			wantStart: "2026-09-09T07:30:00Z",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotStart, gotEnd string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotStart = r.URL.Query().Get("lastModStartDate")
				gotEnd = r.URL.Query().Get("lastModEndDate")
				fmt.Fprint(w, pageJSON(0, 0, 0))
			}))
			defer srv.Close()

			out := doFetch(t, newAdapter(srv), fetchInput(srv.URL, tc.config, tc.cursor, ""))

			if gotStart != tc.wantStart {
				t.Errorf("lastModStartDate = %q, want %q", gotStart, tc.wantStart)
			}
			if gotEnd != rfc3339To {
				t.Errorf("lastModEndDate = %q, want %q (the injected clock)", gotEnd, rfc3339To)
			}
			if want := `{"last_modified":"` + rfc3339To + `"}`; string(out.Cursor) != want {
				t.Errorf("Cursor = %s, want %s (window end)", out.Cursor, want)
			}
			if !out.Meta.RateLimited && out.Meta.Status != http.StatusOK {
				t.Errorf("Meta = %+v, want a successful page", out.Meta)
			}
		})
	}
}

// TestFetchAPIKeyInjection covers the secret-reference contract (ARCH-002
// §1, TR-013): the reference resolves at fetch time and travels as the
// apiKey query parameter; without a reference the request is
// unauthenticated. The resolved value never leaves the request.
func TestFetchAPIKeyInjection(t *testing.T) {
	const secret = "s3cr3t-nvd-key"

	cases := []struct {
		name      string
		apiKeyRef string
		setEnv    bool
		wantKey   string // "" asserts the parameter stays absent
	}{
		{name: "env reference resolved", apiKeyRef: "env:RISKSIGNAL_TEST_NVD_API_KEY", setEnv: true, wantKey: secret},
		{name: "no reference, unauthenticated"},
		{name: "unset environment variable falls back to unauthenticated", apiKeyRef: "env:RISKSIGNAL_UNSET_NVD_API_KEY", wantKey: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv("RISKSIGNAL_TEST_NVD_API_KEY", secret)
			} else {
				t.Setenv("RISKSIGNAL_UNSET_NVD_API_KEY", "")
			}

			var gotKey string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotKey = r.URL.Query().Get("apiKey")
				fmt.Fprint(w, pageJSON(0, 0, 0))
			}))
			defer srv.Close()

			doFetch(t, newAdapter(srv), fetchInput(srv.URL, nil, cursor07UTC, tc.apiKeyRef))

			if gotKey != tc.wantKey {
				t.Errorf("apiKey parameter = %q, want %q", gotKey, tc.wantKey)
			}
		})
	}
}
