package kev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xpera/risksignal/internal/application"
)

// Config defaults and constants of the KEV adapter (ARCH-002 §1/§2.2).
const (
	// lastContentHashConfigKey names the sources.config key through which
	// the fetch use case hands the content hash of the source's last
	// committed raw record back into Fetch (the adapter never reads the
	// database). The fetch use cases maintain the key after every committed
	// fetch (DEV-041); absent or empty — a source without a committed
	// fetch yet — every fetch returns a full output (NoChange false).
	lastContentHashConfigKey = "last_content_hash"
	userAgent                = "risksignal-kev-adapter/0.1 (xpera riskSignal)"
)

// externalIDPrefix prefixes the raw-record external id:
// "kev-2026-09-09" (ARCH-002 §2.2: the catalog version/date).
const externalIDPrefix = "kev-"

// normalizerVersion is the compile-time normaliser version of the KEV
// adapter (ARCH-002 §1, ch. 14.1): it stamps the source.normalize dedupe
// key of every KEV raw record. Bumping it forces a fresh normalise pass of
// a stored catalog without dedupe.
const normalizerVersion = "kev-normalizer-v1"

// Adapter implements application.SourcePort for the KEV source type
// (ARCH-002 §1): Type() "kev", full-set plan without a cursor, the
// versioned catalog fetch of §2.2 and the normalise half (normalize.go).
type Adapter struct {
	// hc is the HTTP client of the fetch. The transport is injectable at
	// construction (ARCH-002 §6: tests point the client at an in-process
	// server); a nil transport falls back to the standard client defaults.
	hc *http.Client
}

// New returns the KEV adapter. rt is the injectable RoundTripper of the
// fetch client; nil selects the standard transport. The adapter is
// endpoint-less on purpose — the catalog URL arrives per fetch through the
// resolved source descriptor (FetchInput.Source.Endpoint) — so one adapter
// instance serves every configured KEV source row.
func New(rt http.RoundTripper) *Adapter {
	return &Adapter{hc: &http.Client{Transport: rt}}
}

// Type identifies the adapter (ARCH-002 §1).
func (*Adapter) Type() application.SourceType { return application.SourceTypeKEV }

// NormalizerVersion identifies the adapter's normalise pass (ARCH-002 §1).
func (*Adapter) NormalizerVersion() string { return normalizerVersion }

// Plan is the static, operator-visible contract of the source (ARCH-002
// §1/§2.2): a full-set source replacing the whole catalog on a daily
// schedule, advancing no cursor.
func (*Adapter) Plan() application.SourcePlan {
	return application.SourcePlan{
		Schedule:   "@daily",
		Kind:       application.SourceKindFullSet,
		CursorKind: application.CursorKindNone,
	}
}

// Fetch downloads the KEV catalog document (the source descriptor's
// endpoint) and returns it as one storable full-set slice (ARCH-002
// §2.2): the verbatim document bytes, its SHA-256 content hash, the
// catalog-version external id ("kev-YYYY-MM-DD") and no cursor. When the
// fetched hash equals the last committed raw record's hash — supplied via
// sources.config.last_content_hash, see the package doc — the output
// reports FetchMeta.NoChange, the successful no-op signal of an unchanged
// catalog (ch. 8.3); the use case then closes the run with counters all 0
// and stores nothing. A rate-limited response (429/503) is reported
// through FetchMeta.RateLimited — never as an error.
//
// FetchedAt stays the input window's To — the injected clock's now of an
// incremental fetch. A full-set fetch carries no window (the use case
// passes the zero window), so the adapter leaves the zero time; the run
// wiring stamps FetchedAt with the run's clock instant (DEV-041), so the
// zero time only surfaces when the output is inspected outside a run.
func (a *Adapter) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	u, err := fetchURL(in.Source.Endpoint)
	if err != nil {
		return application.FetchOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("kev: build catalog request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := a.hc.Do(req)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("kev: fetch catalog %s: %w", u, err)
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
		return application.FetchOutput{}, fmt.Errorf("kev: fetch catalog %s: unexpected status %d", u, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return application.FetchOutput{}, fmt.Errorf("kev: read catalog body: %w", err)
	}
	meta.Size = int64(len(body))

	hash := sha256.Sum256(body)
	contentHash := hex.EncodeToString(hash[:])

	// The external id is the catalog version/date of the document itself
	// (ARCH-002 §2.2) — stable for one revision, whatever the endpoint
	// serves. A document without parseable version metadata cannot be
	// identified and is not storable.
	externalID, err := catalogExternalID(body)
	if err != nil {
		return application.FetchOutput{}, err
	}

	out := application.FetchOutput{
		ExternalID:  externalID,
		Payload:     body,
		ContentHash: contentHash,
		FetchedAt:   in.Window.To,
		Cursor:      nil, // full-set source: nothing to advance
		Meta:        meta,
	}

	// Content-hash no-op (ch. 8.3): the fetch use case maintains the last
	// committed raw record's hash in sources.config.last_content_hash
	// (DEV-041); a match reports the unchanged catalog.
	if prev, _ := in.Source.Config[lastContentHashConfigKey].(string); prev != "" && prev == contentHash {
		out.Meta.NoChange = true
	}
	return out, nil
}

// catalogDocument is the metadata envelope of the KEV catalog the external
// id is derived from. Vulnerabilities stay raw messages — the normalise
// half parses each entry individually so one malformed entry is isolatable
// (RecordError payload hash) without losing the others.
type catalogDocument struct {
	Title           string            `json:"title"`
	CatalogVersion  string            `json:"catalogVersion"`
	DateReleased    string            `json:"dateReleased"`
	Count           int               `json:"count"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

// catalogMeta carries only the version/date carriers of the document
// envelope (see catalogExternalID for the probe order).
type catalogMeta struct {
	DateReleased             string `json:"dateReleased"`
	CveExploitabilityUpdated string `json:"cveExploitabilityUpdated"`
	CatalogVersion           string `json:"catalogVersion"`
}

// catalogExternalID derives the raw-record external id of one catalog
// document: "kev-" plus the catalog date normalised to YYYY-MM-DD. The
// carriers are probed in order — dateReleased, cveExploitabilityUpdated,
// catalogVersion — and the first parseable one wins; catalog versions
// arrive as RFC3339 instants, "YYYY-MM-DD" or the dotted "YYYY.MM.DD"
// form, all of which normalise to the same stable date key. A document
// whose envelope carries no parseable version/date is not identifiable and
// errors.
func catalogExternalID(body []byte) (string, error) {
	var m catalogMeta
	if err := json.Unmarshal(body, &m); err != nil {
		// The envelope must at least decode as JSON for the metadata probe
		// to run; a body that cannot is not a catalog document.
		return "", fmt.Errorf("kev: decode catalog envelope for version metadata: %w", err)
	}
	for _, v := range []string{m.DateReleased, m.CveExploitabilityUpdated, m.CatalogVersion} {
		if d, ok := parseCatalogDate(v); ok {
			return externalIDPrefix + d, nil
		}
	}
	return "", errors.New("kev: catalog carries no version/date metadata (probed dateReleased, cveExploitabilityUpdated, catalogVersion)")
}

// parseCatalogDate normalises one catalog date carrier to its canonical
// YYYY-MM-DD form. The accepted shapes are the RFC3339 instants of the
// feed metadata ("2026-09-09T04:00:00.000Z"), the date-only
// "YYYY-MM-DD" of the catalog rows and the dotted "YYYY.MM.DD" catalog
// version spelling. ok is false for anything else — the caller decides
// whether that is a malformed record or an unidentifiable document.
func parseCatalogDate(v string) (string, bool) {
	for _, layout := range []string{"2006-01-02", "2006.01.02", time.RFC3339Nano} {
		if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
			return t.UTC().Format("2006-01-02"), true
		}
	}
	return "", false
}

// fetchURL validates the resolved catalog endpoint — it must carry an
// http(s) scheme; the endpoint is the document URL itself, no path is
// appended (ARCH-002 §1 lists the full feed URL).
func fetchURL(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("kev: source descriptor carries no endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("kev: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("kev: endpoint %q carries no http(s) scheme", endpoint)
	}
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

// compile-time check that the adapter satisfies the shared port.
var _ application.SourcePort = (*Adapter)(nil)
