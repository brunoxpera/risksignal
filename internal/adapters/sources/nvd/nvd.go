package nvd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// API path of the NVD Vulnerability API 2.0 (ARCH-002 §2.1). The sources
// row's endpoint holds the base URL — either the full API URL
// (https://services.nvd.nist.gov/rest/json/cves/2.0, ARCH-002 §1) or a bare
// host used in tests; apiPath is appended when the endpoint does not carry
// it yet.
const apiPath = "/rest/json/cves/2.0"

// resultsPerPage is the fixed page size of the window walk (the API guide
// value 2000). The loop never trusts totalResults; it terminates on an
// empty page.
const resultsPerPage = 2000

// Config defaults (ARCH-002 §2.1): overlap guards window boundaries
// against gaps; a cursor-less first fetch opens at the full-import lower
// bound — config.full_import_since when the operator pinned it, the epoch
// otherwise (ARCH-003 §6, DEV-067).
const (
	defaultOverlapHours = 2.0
	overlapConfigKey    = "overlap"
	// fullImportSinceConfigKey is the optional lower bound of the full
	// import: config.full_import_since, an RFC 3339 instant. A first fetch
	// without a stored cursor opens its window there; without it the
	// window opens at the epoch — the whole history of the source.
	fullImportSinceConfigKey = "full_import_since"
	// #nosec G101 — api_key_ref is the config member *name* that holds a
	// secret reference ("env:VAR", ch. 3.3), never a credential literal.
	apiKeyRefConfigKey = "api_key_ref"
	envRefPrefix       = "env:"
	userAgent          = "risksignal-nvd-adapter/0.1 (xpera riskSignal)"
)

// normalizerVersion is the compile-time normaliser version of the NVD
// adapter (ARCH-002 §1, ch. 14.1): it stamps the source.normalize dedupe
// key of every NVD raw record. Bumping it forces a fresh normalise pass of
// previously fetched windows without dedupe.
const normalizerVersion = "nvd-normalizer-v1"

// Adapter implements application.SourcePort for the NVD source type
// (ARCH-002 §1): Type() "nvd", incremental last-modified plan, the bounded
// window fetch of §2.1 and the normalise half (normalize.go).
type Adapter struct {
	// hc is the HTTP client of the walk. The transport is injectable at
	// construction (ARCH-002 §6: tests point the client at an in-process
	// server); a nil transport falls back to the standard client defaults.
	hc *http.Client
}

// New returns the NVD adapter. rt is the injectable RoundTripper of the
// fetch client; nil selects the standard transport. The adapter is
// endpoint-less on purpose — the base URL arrives per fetch through the
// resolved source descriptor (FetchInput.Source.Endpoint) — so one adapter
// instance serves every configured NVD source row.
func New(rt http.RoundTripper) *Adapter {
	return &Adapter{hc: &http.Client{Transport: rt}}
}

// Type identifies the adapter (ARCH-002 §1).
func (*Adapter) Type() application.SourceType { return application.SourceTypeNVD }

// NormalizerVersion identifies the adapter's normalise pass (ARCH-002 §1).
func (*Adapter) NormalizerVersion() string { return normalizerVersion }

// Plan is the static, operator-visible contract of the source (ARCH-002
// §1/§5): an incremental source advancing the last-modified cursor on an
// hourly schedule.
func (*Adapter) Plan() application.SourcePlan {
	return application.SourcePlan{
		Schedule:   "@hourly",
		Kind:       application.SourceKindIncremental,
		CursorKind: application.CursorKindLastModified,
	}
}

// Fetch walks the bounded window [from, to] of one fetch slice over the NVD
// API and returns the window as one storable raw record (see the package
// comment). A rate-limited response (429/503) stops the walk and is
// reported through FetchMeta.RateLimited — never as an error.
func (a *Adapter) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	to := in.Window.To
	if to.IsZero() {
		return application.FetchOutput{}, errors.New("nvd: fetch input carries no bounded window (Window.To is zero)")
	}
	from, err := windowFrom(in, to)
	if err != nil {
		return application.FetchOutput{}, err
	}

	apiKeyRef := in.APIKeyRef
	if apiKeyRef == "" {
		// The fetch use case resolves config.api_key_ref into APIKeyRef;
		// a direct caller may leave the reference in the config only.
		apiKeyRef, _ = in.Source.Config[apiKeyRefConfigKey].(string)
	}
	apiKey, err := resolveAPIKey(apiKeyRef)
	if err != nil {
		return application.FetchOutput{}, err
	}

	// Walk every page of the window (ARCH-002 §2.1): startIndex advances by
	// resultsPerPage; the loop terminates on an empty page. totalResults is
	// decoded but never trusted as the bound.
	startIndex := 0
	var pages [][]byte
	for {
		body, meta, err := a.getPage(ctx, in.Source.Endpoint, from, to, startIndex, apiKey)
		if err != nil {
			return application.FetchOutput{}, err
		}
		if meta.RateLimited {
			// A rate limit stops the walk immediately — even mid-
			// pagination. The window is dropped whole: nothing partial is
			// returned, the cursor does not advance and the next run
			// re-fetches the window after the backoff.
			return application.FetchOutput{Meta: meta}, nil
		}

		var p page
		if err := json.Unmarshal(body, &p); err != nil {
			return application.FetchOutput{}, fmt.Errorf("nvd: page %d: decode page body: %w", startIndex/resultsPerPage, err)
		}
		if len(p.Vulnerabilities) == 0 {
			if len(pages) == 0 {
				// A window without modified CVEs still yields one record:
				// its single empty page is the document of "no changes",
				// so the run stores a slice and the cursor can advance.
				pages = append(pages, body)
			}
			break // empty page: the window is fully walked
		}
		pages = append(pages, body)
		startIndex += resultsPerPage
	}

	payload := joinPages(pages)
	hash := sha256.Sum256(payload)
	fromS, toS := from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)
	cursor, err := lastModifiedCursor(toS)
	if err != nil {
		return application.FetchOutput{}, err
	}

	return application.FetchOutput{
		ExternalID:  fmt.Sprintf("nvd:%s:%s", fromS, toS),
		Payload:     payload,
		ContentHash: hex.EncodeToString(hash[:]),
		FetchedAt:   to,
		Cursor:      cursor,
		Meta:        application.FetchMeta{Status: http.StatusOK, ContentType: "application/json", Size: int64(len(payload))},
	}, nil
}

// page is the decoded envelope of one API 2.0 response page. Only the
// vulnerabilities slice matters for the walk; resultsPerPage, startIndex and
// totalResults are carried for observability and for the never-trusted
// totalResults contract (ARCH-002 §2.1).
type page struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

// getPage performs one windowed API request and returns the unchanged body
// bytes plus the response's technical metadata. 429/503 responses are
// mapped to a rate-limited FetchMeta — no error; any other non-200 status
// is an error.
func (a *Adapter) getPage(ctx context.Context, endpoint string, from, to time.Time, startIndex int, apiKey string) ([]byte, application.FetchMeta, error) {
	u, err := apiURL(endpoint, from, to, startIndex, apiKey)
	if err != nil {
		return nil, application.FetchMeta{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, application.FetchMeta{}, fmt.Errorf("nvd: build page %d request: %w", startIndex/resultsPerPage, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, application.FetchMeta{}, fmt.Errorf("nvd: page %d (startIndex %d): %w", startIndex/resultsPerPage, startIndex, err)
	}
	defer func() { _ = resp.Body.Close() }()

	meta := application.FetchMeta{
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		LastModified: parseHTTPTime(resp.Header.Get("Last-Modified")),
		ETag:         resp.Header.Get("ETag"),
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		// ch. 14.2: a rate limit is not a source fault — the caller backs
		// off via RetryAfter and retries the window.
		meta.RateLimited = true
		meta.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, meta, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, meta, fmt.Errorf("nvd: page %d (startIndex %d): unexpected status %d", startIndex/resultsPerPage, startIndex, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, meta, fmt.Errorf("nvd: page %d (startIndex %d): read body: %w", startIndex/resultsPerPage, startIndex, err)
	}
	meta.Size = int64(len(body))
	return body, meta, nil
}

// apiURL builds the request URL of one page: the resolved endpoint (the
// API path is appended only when the endpoint does not carry it) plus the
// windowed query parameters.
func apiURL(endpoint string, from, to time.Time, startIndex int, apiKey string) (string, error) {
	base := endpoint
	if !strings.HasSuffix(endpoint, apiPath) {
		base = strings.TrimRight(endpoint, "/") + apiPath
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("nvd: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("nvd: endpoint %q carries no http(s) scheme", endpoint)
	}

	q := u.Query()
	q.Set("lastModStartDate", from.UTC().Format(time.RFC3339))
	q.Set("lastModEndDate", to.UTC().Format(time.RFC3339))
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	if apiKey != "" {
		q.Set("apiKey", apiKey)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// windowFrom derives the window start of one fetch (ARCH-002 §2.1): the
// stored last-modified cursor minus the configured overlap (2 h default),
// or — on the first run without a stored cursor (the NVD full import,
// ARCH-003 §6/DEV-067) — the open lower bound: config.full_import_since
// (RFC 3339) when the operator pinned the import start, the epoch
// otherwise. The fetch then walks every page of the source's whole history
// and stops on the empty page past the last modified CVE.
func windowFrom(in application.FetchInput, to time.Time) (time.Time, error) {
	if len(in.Source.Cursor) > 0 {
		var c struct {
			LastModified string `json:"last_modified"`
		}
		if err := json.Unmarshal(in.Source.Cursor, &c); err != nil {
			return time.Time{}, fmt.Errorf("nvd: read cursor %s: %w", in.Source.Cursor, err)
		}
		if c.LastModified == "" {
			return time.Time{}, fmt.Errorf("nvd: cursor %s carries no last_modified", in.Source.Cursor)
		}
		cursorTime, err := time.Parse(time.RFC3339, c.LastModified)
		if err != nil {
			return time.Time{}, fmt.Errorf("nvd: cursor last_modified %q: %w", c.LastModified, err)
		}
		from := cursorTime.Add(-durationHours(in.Source.Config, overlapConfigKey, defaultOverlapHours))
		if !from.Before(to) {
			return time.Time{}, fmt.Errorf("nvd: window [%s, %s] is not positive (cursor at or after now)", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
		}
		return from, nil
	}

	// Cursor-less first run: open at the full-import lower bound. The
	// epoch is the unbound default (a real deployment pins
	// full_import_since — its history does not reach back to year 1); the
	// window is always positive because the epoch precedes every bounded
	// To. A malformed full_import_since is an operator-data mistake and
	// fails the fetch like a malformed cursor.
	if since, ok := in.Source.Config[fullImportSinceConfigKey]; ok && since != nil {
		s, isString := since.(string)
		if !isString {
			return time.Time{}, fmt.Errorf("nvd: config full_import_since %v is not an RFC 3339 string", since)
		}
		if s == "" {
			return time.Time{}, fmt.Errorf("nvd: config full_import_since is empty")
		}
		lower, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("nvd: config full_import_since %q is not an RFC 3339 instant: %w", s, err)
		}
		if !lower.Before(to) {
			return time.Time{}, fmt.Errorf("nvd: full-import lower bound %s is not before now %s", lower.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
		}
		return lower, nil
	}
	return time.Time{}, nil // the epoch: an open lower bound
}

// durationHours reads a config duration that may be expressed in hours (a
// JSON number) or as a Go duration string ("2h"); def is the fallback.
func durationHours(config map[string]any, key string, def float64) time.Duration {
	v, ok := config[key]
	if !ok || v == nil {
		return time.Duration(def * float64(time.Hour))
	}
	switch n := v.(type) {
	case float64:
		return time.Duration(n * float64(time.Hour))
	case int:
		return time.Duration(n) * time.Hour
	case string:
		if d, err := time.ParseDuration(n); err == nil {
			return d
		}
	}
	return time.Duration(def * float64(time.Hour))
}

// resolveAPIKey resolves the secret reference of the source config
// (ARCH-002 §1, ch. 3.3): "env:NAME" reads NAME from the process
// environment. The resolved value is returned only to the caller of one
// fetch — it never enters FetchOutput, logs, metrics or audit snapshots
// (TR-013). An empty reference or an unset variable falls back to the
// unauthenticated request rate; an unknown reference scheme is a
// configuration error.
func resolveAPIKey(ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if !strings.HasPrefix(ref, envRefPrefix) {
		return "", fmt.Errorf("nvd: unsupported api_key_ref scheme %q (want %s<VAR>)", ref, envRefPrefix)
	}
	return os.Getenv(strings.TrimPrefix(ref, envRefPrefix)), nil
}

// lastModifiedCursor builds the {"last_modified": "<RFC3339>"} cursor value
// of the window (ARCH-002 §1). The fetch use case commits it with the
// successful run only.
func lastModifiedCursor(lastModified string) (json.RawMessage, error) {
	c, err := json.Marshal(struct {
		LastModified string `json:"last_modified"`
	}{LastModified: lastModified})
	if err != nil {
		return nil, fmt.Errorf("nvd: marshal cursor: %w", err)
	}
	return c, nil
}

// joinPages concatenates the verbatim page bodies of one window into the
// single storable payload of the slice ('\n'-joined — JSON documents are
// self-delimiting, so a normalise pass can stream them back apart with a
// json.Decoder; every page's bytes stay unchanged).
func joinPages(pages [][]byte) []byte {
	return bytes.Join(pages, []byte("\n"))
}

// parseRetryAfter reads a Retry-After header as whole seconds or an HTTP
// date; 0 when absent or unparsable.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// parseHTTPTime parses an HTTP header timestamp; the zero time when absent.
func parseHTTPTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := http.ParseTime(v); err == nil {
		return t
	}
	return time.Time{}
}
