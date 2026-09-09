package epss

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// Config defaults and constants of the EPSS adapter (ARCH-002 §1/§2.3).
const (
	// lastContentHashConfigKey names the sources.config key through which
	// the fetch use case hands the content hash of the source's last
	// committed raw record back into Fetch (the adapter never reads the
	// database) — the same key the KEV adapter uses. Absent or empty —
	// today, until the wiring lands — every fetch returns a full output
	// (NoChange false).
	lastContentHashConfigKey = "last_content_hash"

	userAgent   = "risksignal-epss-adapter/0.1 (xpera riskSignal)"
	dateLayout  = "2006-01-02"
	fileNameFmt = "epss_scores-%s.csv.gz"
)

// Adapter implements application.SourcePort for the EPSS source type
// (ARCH-002 §1): Type() "epss", full-set plan without a cursor, the daily
// file fetch of §2.3 and the normalise half (normalize.go).
type Adapter struct {
	// hc is the HTTP client of the fetch. The transport is injectable at
	// construction (ARCH-002 §6: tests point the client at an in-process
	// server); a nil transport falls back to the standard client defaults.
	hc *http.Client

	// clock is the injectable time source of the daily file date (ch. 7.2):
	// the fetched day derives from clock.Now().UTC() — never the wall clock
	// — so a fetch is reproducible in tests.
	clock clock.Clock
}

// New returns the EPSS adapter. rt is the injectable RoundTripper of the
// fetch client; nil selects the standard transport. clk is the injectable
// clock the daily file date derives from; nil selects the real clock. The
// adapter is endpoint-less on purpose — the base URL arrives per fetch
// through the resolved source descriptor (FetchInput.Source.Endpoint) — so
// one adapter instance serves every configured EPSS source row.
func New(rt http.RoundTripper, clk clock.Clock) *Adapter {
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &Adapter{hc: &http.Client{Transport: rt}, clock: clk}
}

// Type identifies the adapter (ARCH-002 §1).
func (*Adapter) Type() application.SourceType { return application.SourceTypeEPSS }

// Plan is the static, operator-visible contract of the source (ARCH-002
// §1/§2.3): a full-set source replacing the whole daily set on a daily
// schedule, advancing no cursor.
func (*Adapter) Plan() application.SourcePlan {
	return application.SourcePlan{
		Schedule:   "@daily",
		Kind:       application.SourceKindFullSet,
		CursorKind: application.CursorKindNone,
	}
}

// Fetch downloads the daily EPSS file of the injected clock's UTC date
// (ARCH-002 §2.3, ADR-013): GET <endpoint>/epss_scores-YYYY-MM-DD.csv.gz.
// The raw record is the file itself, not its rows: the verbatim compressed
// bytes are returned unchanged with their SHA-256 content hash, the file
// name as the external id ("epss_scores-2026-09-09.csv.gz") and no cursor —
// a full-set source advances none. When the fetched hash equals the last
// committed raw record's hash — supplied via sources.config.
// last_content_hash, see the package doc — the output reports
// FetchMeta.NoChange, the successful no-op signal of the same day's
// unchanged file (ch. 8.3); the use case then closes the run with counters
// all 0 and stores nothing. A rate-limited response (429/503) is reported
// through FetchMeta.RateLimited — never as an error (ch. 14.2).
//
// FetchedAt stays the input window's To — the injected clock's now of an
// incremental fetch. A full-set fetch carries no window (the use case
// passes the zero window), so the adapter leaves the zero time; the fetch
// wiring stamps FetchedAt with the run's clock instant when it lands
// (DEV-032 follow-up, same as the KEV adapter).
func (a *Adapter) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	day := a.clock.Now().UTC()
	u, err := dailyFileURL(in.Source.Endpoint, day)
	if err != nil {
		return application.FetchOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("epss: build daily file request: %w", err)
	}
	req.Header.Set("Accept", "application/gzip")
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.hc.Do(req)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("epss: fetch daily file %s: %w", u, err)
	}
	defer resp.Body.Close()

	meta := application.FetchMeta{
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		LastModified: parseHTTPTime(resp.Header.Get("Last-Modified")),
		ETag:         resp.Header.Get("ETag"),
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		// ch. 14.2: a rate limit is not a source fault — the caller backs
		// off via RetryAfter and retries the fetch.
		meta.RateLimited = true
		meta.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		return application.FetchOutput{Meta: meta}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return application.FetchOutput{}, fmt.Errorf("epss: fetch daily file %s: unexpected status %d", u, resp.StatusCode)
	}

	// The payload is the compressed file — the unchanged raw record
	// (ADR-013); the daily file stays a few MB compressed, and the
	// streaming decompression happens on the normalise side, never here.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("epss: read daily file body: %w", err)
	}
	meta.Size = int64(len(body))

	sum := sha256.Sum256(body)
	contentHash := hex.EncodeToString(sum[:])

	out := application.FetchOutput{
		ExternalID:  epssFileName(day),
		Payload:     body,
		ContentHash: contentHash,
		FetchedAt:   in.Window.To,
		Cursor:      nil, // full-set source: nothing to advance
		Meta:        meta,
	}

	// Content-hash no-op (ch. 8.3, ARCH-002 §2.3): the fetch use case
	// maintains the last committed raw record's hash in
	// sources.config.last_content_hash (wiring follow-up, as for KEV); a
	// match reports the same day's unchanged file.
	if prev, _ := in.Source.Config[lastContentHashConfigKey].(string); prev != "" && prev == contentHash {
		out.Meta.NoChange = true
	}
	return out, nil
}

// epssFileName renders the daily file name of one UTC date
// ("epss_scores-2026-09-09.csv.gz", ARCH-002 §2.3).
func epssFileName(day time.Time) string {
	return fmt.Sprintf(fileNameFmt, day.Format(dateLayout))
}

// dailyFileURL validates the resolved endpoint — it must carry an http(s)
// scheme; it is the base URL of the daily file host (ARCH-002 §1:
// https://epss.empiricalsecurity.com) — and appends the daily file name of
// the given date.
func dailyFileURL(endpoint string, day time.Time) (string, error) {
	if endpoint == "" {
		return "", errors.New("epss: source descriptor carries no endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("epss: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("epss: endpoint %q carries no http(s) scheme", endpoint)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + epssFileName(day)
	return u.String(), nil
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
