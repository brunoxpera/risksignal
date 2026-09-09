package application

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xpera/risksignal/internal/domain"
)

// SourceType identifies a source adapter (ARCH-002 §1); the sources table
// keeps one row per (type, name). Adapters expose their type through
// SourcePort.Type and the worker registry keys handlers by it.
type SourceType string

// Known SourceType values (ARCH-002 §1). The I2 adapters are NVD, KEV and
// EPSS; the I1b synthetic source implements the same port retroactively.
const (
	SourceTypeNVD       SourceType = "nvd"
	SourceTypeKEV       SourceType = "kev"
	SourceTypeEPSS      SourceType = "epss"
	SourceTypeSynthetic SourceType = "synthetic"
)

// SourceKind distinguishes cursor-driven incremental sources from
// replace-all full-set sources (ADR-013, implementation concept ch. 8.1
// step 4).
type SourceKind string

// Known SourceKind values (ARCH-002 §1).
const (
	// SourceKindIncremental advances a persisted cursor over bounded time
	// windows (NVD: the last-modified window).
	SourceKindIncremental SourceKind = "incremental"
	// SourceKindFullSet replaces the whole set on every run (KEV catalog,
	// EPSS daily set).
	SourceKindFullSet SourceKind = "full_set"
)

// CursorKind names the cursor a source advances; full-set sources advance
// none.
type CursorKind string

// Known CursorKind values (ARCH-002 §1).
const (
	// CursorKindLastModified is the NVD last-modified cursor.
	CursorKindLastModified CursorKind = "last_modified"
	// CursorKindNone marks a source without a cursor (KEV, EPSS).
	CursorKindNone CursorKind = "none"
)

// SourcePlan is the static, operator-visible contract of a source
// (ARCH-002 §1): its schedule, its kind and the cursor it advances. The
// scheduler and the source monitor read the plan; sources.schedule stays
// NULL for the I1b synthetic source until the I2 HTTP sources activate it.
type SourcePlan struct {
	Schedule   string // cron/interval, persisted on sources.schedule
	Kind       SourceKind
	CursorKind CursorKind
}

// SourceDescriptor is the resolved sources row an adapter reads (ARCH-002
// §1): identity, the base endpoint (config-driven and therefore injectable
// in tests) and the per-type configuration. Config carries no secret
// literal — only references such as api_key_ref (see FetchInput.APIKeyRef).
type SourceDescriptor struct {
	ID       string // sources.id
	Type     SourceType
	Endpoint string          // sources.endpoint (base URL)
	Config   map[string]any  // sources.config (window, overlap, page size, …)
	Cursor   json.RawMessage // sources.cursor (nil for full-set)
}

// TimeWindow bounds one incremental fetch (ARCH-002 §1, §2.1): From is the
// persisted cursor value minus the configured overlap, To is clock.Now() —
// the injectable clock, never the wall clock. Full-set sources ignore the
// window.
type TimeWindow struct {
	From time.Time
	To   time.Time
}

// FetchInput drives one Fetch slice (ARCH-002 §1): the resolved source
// descriptor, the bounded time window and the API-key secret reference.
//
// APIKeyRef is a *reference* to the key — "env:RISKSIGNAL_NVD_API_KEY" or a
// secret-store key, read from sources.config.api_key_ref — never the key
// literal: the resolved value must not enter the port types, logs, metrics
// or audit snapshots (implementation concept ch. 3.3, ch. 12.3, TR-013).
// The adapter resolves the reference at fetch time and falls back to the
// lower unauthenticated request rate when no key is configured.
type FetchInput struct {
	Source    SourceDescriptor
	Window    TimeWindow
	APIKeyRef string // secret reference; empty when the source needs no key
}

// FetchMeta is the technical metadata of one fetch (ARCH-002 §1): the HTTP
// status and headers where the source is HTTP, plus the two signals the run
// bookkeeping reads (rate limit and unchanged full set). It never carries
// payload bytes — the unchanged document travels in FetchOutput.Payload and
// is hashed into FetchOutput.ContentHash.
type FetchMeta struct {
	Status       int           // HTTP status code of the response
	ContentType  string        // response Content-Type
	Size         int64         // payload size in bytes
	LastModified time.Time     // HTTP Last-Modified; the zero time when absent
	ETag         string        // HTTP ETag; "" when absent
	RetryAfter   time.Duration // suggested backoff of a 429/503; 0 when absent
	RateLimited  bool          // 429/503: recorded as rate-limited, not a source fault (ch. 14.2)
	NoChange     bool          // unchanged full set: a successful no-op run (ch. 8.3)
}

// FetchOutput is one fetched slice (ARCH-002 §1, ch. 8.1 steps 2–4): the
// unchanged payload plus its technical metadata and the cursor to persist
// after a successful commit. Cursor is nil for full-set sources, where a
// content-hash match against the stored raw record is the no-op success
// signal.
type FetchOutput struct {
	ExternalID  string          // raw_records.external_id: window/page key, file name, …
	Payload     []byte          // the unchanged source bytes
	ContentHash string          // SHA-256 hex over Payload
	FetchedAt   time.Time       // from the injected clock
	Cursor      json.RawMessage // value to persist after commit; nil for full-set
	Meta        FetchMeta
}

// NormalizeInput carries the raw record identity of one normalise pass
// (ARCH-002 §1): the stored record's id, its unchanged payload and content
// hash, plus the fetch metadata recorded with it. The EPSS full-set path is
// a documented specialisation of the shared port (the application hands its
// adapter a bulk row writer for the COPY load; ARCH-002 §1, ADR-013) — it
// does not change this input shape.
type NormalizeInput struct {
	RawRecordID string
	Payload     []byte
	ContentHash string
	Meta        FetchMeta

	// PreviousKEVCVEs carries the CVE ids of the source's previously
	// stored full set (the KEV catalog of the last committed run,
	// ARCH-002 §2.2): the KEV normaliser emits a kev_removed evidence for
	// every id that is absent from the new set, historising removals
	// instead of silently dropping them (ch. 8.3). The normalise use case
	// (NormalizeSource/RunSource wiring) must populate the field for KEV
	// full-set passes by reading the CVE ids of the source's previous raw
	// record; nil/empty — the first import — emits no removals. The other
	// sources ignore it.
	PreviousKEVCVEs []string
}

// RecordError isolates one failed record of a payload (ARCH-002 §1,
// implementation concept ch. 8.6 "new"): its position inside the payload, a
// stable reason and the SHA-256 of the offending record/slice so it stays
// re-addressable on reprocess. PayloadHash is a hash — never the offending
// payload itself — and the application inserts the quarantine row from it
// in the same transaction as the run counters.
type RecordError struct {
	Position    string // byte offset | line number | JSON pointer
	Reason      string // stable error_code + human message (ch. 5.2)
	PayloadHash string // SHA-256 hex of the offending record/slice
}

// NormalizeSink is the seam where a normaliser hands its output to the
// application for persistence (ARCH-002 §1): normalised domain objects
// stream in and per-record failures stream out through RecordError, which
// isolates them into quarantine — a failure never aborts the run (ch. 8.1
// step 5). The application implements the sink on the normalise
// transaction; only infrastructure failures abort it.
type NormalizeSink interface {
	// Vulnerability receives a normalised vulnerability (the NVD full
	// record, the KEV skeleton) for the natural-key upsert (UQ cve_id).
	Vulnerability(ctx context.Context, v domain.Vulnerability) error
	// Evidence receives one immutable, typed source statement for insert
	// (UQ (raw_record_id, type, value_hash)).
	Evidence(ctx context.Context, e domain.Evidence) error
	// RecordError receives one isolated record for the quarantine insert
	// (ch. 8.6 "new": position, reason, payload hash).
	RecordError(ctx context.Context, e RecordError) error
}

// NormalizeResult reports one Normalize pass (ARCH-002 §1). Records counts
// the domain records the normaliser emitted to the sink (vulnerabilities +
// evidences); the EPSS full-set path reports the number of rows copied into
// epss_current instead. Errors counts the records isolated through
// sink.RecordError — the run counter of the E1 error class.
type NormalizeResult struct {
	Records int // emitted domain records (or copied rows for the EPSS full set)
	Errors  int // records isolated via RecordError
}

// SourcePort is the shared contract every source adapter implements
// (ARCH-002 §1, implementation concept ch. 8.1): plan, fetch with technical
// metadata, normalise streaming into the sink, and a reproducible cursor.
// The NVD/KEV/EPSS adapters (internal/adapters/sources/{nvd,kev,epss}) and —
// retroactively — the I1b synthetic source implement it.
//
// The port is persistence-agnostic: it carries no repository, transaction
// or database types. The persistence half of a normalise pass arrives as
// the NormalizeSink the application hands in; fetch/normalise are split
// along the ch. 14.1 job boundary into two halves that the worker runs
// separately.
type SourcePort interface {
	// Type identifies the adapter.
	Type() SourceType

	// Plan is the static, operator-visible contract of the source.
	Plan() SourcePlan

	// Fetch retrieves one slice and returns its unchanged payload plus
	// technical metadata and the cursor to persist after a successful
	// commit (ch. 8.1 steps 2–4). For full-set sources the cursor is nil
	// and a content-hash match is the no-op success signal (ch. 8.3).
	Fetch(ctx context.Context, in FetchInput) (FetchOutput, error)

	// Normalize stream-parses one fetched payload into normalised domain
	// records, emitting them through sink. Per-record parse/normalise
	// failures are emitted through sink.RecordError for quarantine
	// isolation and never abort the run (ch. 8.1 step 5).
	Normalize(ctx context.Context, in NormalizeInput, sink NormalizeSink) (NormalizeResult, error)
}
