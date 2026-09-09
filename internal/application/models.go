package application

import (
	"encoding/json"
	"time"

	"github.com/xpera/risksignal/internal/domain"
)

// Signal is the readable signal view (ARCH-001 §4 Signal schema): the signal
// joined with its match, vulnerability, component and asset. Persistence
// adapters map their joined rows into this type; the HTTP layer serialises
// it as snake_case JSON.
type Signal struct {
	ID         string // uuid
	MatchID    string
	CveID      string
	Priority   domain.Priority
	Status     domain.SignalStatus
	Confidence domain.Confidence
	Method     domain.MatchMethod
	Asset      SignalAsset
	Product    SignalProduct
	Summary    string
	CreatedAt  time.Time // RFC 3339 UTC, from the injected clock
	Version    int       // optimistic-lock token
	DueAt      *time.Time
}

// SignalAsset is the joined asset of a signal (ARCH-001 §4 asset).
type SignalAsset struct {
	ID          string
	Name        string
	Type        domain.AssetType
	Criticality domain.Criticality
	Exposure    domain.Exposure
}

// SignalProduct is the joined component product of a signal (ARCH-001 §4
// product: vendor/product/version).
type SignalProduct struct {
	Vendor  string
	Product string
	Version string
}

// SignalFilter narrows the working-list read (ARCH-001 §4 listSignals).
// Nil fields keep the filter open.
type SignalFilter struct {
	Priority *domain.Priority
	Status   *domain.SignalStatus
}

// AuditEvent is one append-only audit row (ARCH-001 §1 audit_events,
// WP-1b.03). It carries no secrets: before/after are minimised state
// snapshots (concept ch. 13.5) and the actor is a system principal in I1b.
type AuditEvent struct {
	AggregateType    string // e.g. "risk_signal"
	AggregateID      string // uuid of the changed aggregate
	ActorType        string // "system" in I1b ("user" from I5a)
	ActorID          string // e.g. "synthetic-source" | "demo-seed"
	ActorDisplayName string
	Action           string // e.g. "signal.created"
	OccurredAt       time.Time
	Before           json.RawMessage // nil for creates
	After            json.RawMessage
	CorrelationID    string // links this row to the outbox row of the same command
}

// OutboxEvent is one transactional outbox row to append (ARCH-001 §1 and §2,
// WP-1b.03). Payload carries the typed event envelope (see
// signalCreatedPayload in create_signal.go); DedupeKey is the command-level
// idempotency key, unique for the row's whole lifetime (ADR-012
// consequence).
type OutboxEvent struct {
	Type        string // e.g. "signal.created"
	Payload     json.RawMessage
	DedupeKey   string
	AvailableAt time.Time // earliest claim time; I1b events are due immediately
	CreatedAt   time.Time
}

// Component is one seeded inventory component as read by the I1b matcher
// (ARCH-001 §3 step 4). The full inventory model (CPE, purl, digest) is I3.
type Component struct {
	ID      string // uuid
	AssetID string
	Vendor  string
	Product string
	Version string
}

// ScheduledSource is one enabled, schedulable sources row as the scheduler
// scan reads it (ARCH-002 §5): the row identity plus its schedule — the
// sources a worker cycle checks for a due slot. The scan is the only read
// of the schedule column; every other path resolves the full descriptor.
type ScheduledSource struct {
	ID       string
	Type     SourceType
	Schedule string
}

// SourceRunCounters are the counters of a source run (ARCH-001 §1
// source_runs.counters; extended by ARCH-002 §1 to
// {records, normalized, errors, quarantined, matched, signals}), committed
// with the terminal status. The I2 keys exist from the first I2 run on so
// the source monitor renders a uniform shape; matched/signals stay 0 in I2
// (no inventory matching yet, ARCH-002 §1).
//
// records counts the raw documents/record slices the run processed (1 for a
// fetch or a full-cycle run, the per-pass count for a normalise pass);
// normalized counts the domain records a normalise pass persisted;
// errors counts the isolated records of a pass (each one also becomes a
// quarantine row, so quarantined mirrors errors); an I2 normalise run with
// errors still succeeds (ch. 8.1 step 5 — an isolated error is counted, not
// fatal).
type SourceRunCounters struct {
	Records     int `json:"records"`     // documents/slices processed by the run
	Normalized  int `json:"normalized"`  // domain records persisted by the normalise pass
	Errors      int `json:"errors"`      // records isolated by the normalise pass
	Quarantined int `json:"quarantined"` // quarantine rows written by the pass
	Matched     int `json:"matched"`     // confirmed vulnerability-component matches (0 in I2)
	Signals     int `json:"signals"`     // signals created by the run (0 in I2)
}

// SignalRecord is the field set the risk_signals insert persists (ARCH-001
// §1). The id, status ('new') and version (1) are assigned by the database
// and the column defaults; priority and rule_version are derived by the
// ch. 9.3 rules at the application layer before the write.
type SignalRecord struct {
	MatchID     string
	Priority    domain.Priority
	RuleVersion string
	Factors     domain.PriorityFactors
}

// VulnerabilityRecord is the field set the vulnerabilities upsert persists
// (ARCH-001 §1; extended by ARCH-002 §3 with the I2 NVD fields); the id is
// assigned by the database and returned by the natural-key upsert (UQ
// cve_id). The descriptive fields are optional — the I1b synthetic and KEV
// skeleton writes carry identity + summary only — and a statement only
// writes what it carries (a refresh with absent fields sets them NULL again,
// as the sqlc upsert semantics pin).
type VulnerabilityRecord struct {
	CVEID   string
	Summary string

	// I2 (ARCH-002 §2.1/§3): the full NVD descriptive fields. CVSS is the
	// metrics summary, References the advisory links, CPECfg the raw NVD
	// configurations block (opaque here, normalised into the product index
	// in I3).
	Description string
	CVSS        *domain.CVSSMetrics
	References  []domain.Reference
	CPECfg      any
}

// RawRecord is the stored raw document of a source (ARCH-002 §1, §3): the
// unchanged source bytes plus their self-describing content encoding, the
// read the normalise/reprocess paths start from. ContentEncoding is
// 'identity' | 'gzip' | 'json' as stamped at insert time; "" when the
// storing caller did not set it.
type RawRecord struct {
	ID              string
	SourceID        string
	ExternalID      string
	ContentHash     string
	Payload         []byte
	ContentEncoding string
	FetchedAt       time.Time
}

// EvidenceRecord is one immutable evidence row to insert (ARCH-001 §1
// evidences); value is the canonical JSON payload and ValueHash its SHA-256,
// both produced by the application layer.
type EvidenceRecord struct {
	VulnerabilityID string
	RawRecordID     string
	Type            domain.EvidenceType
	Value           []byte
	ValueHash       string
}

// MatchRecord is the field set the matches insert persists (ARCH-001 §1,
// ADR-015). Confidence and score are derived from the authoritative method
// through the versioned mapping (domain.MatchMethod.Derive) before the
// write; the id is assigned by the database and returned (the natural key
// (vulnerability_id, component_id, rule_version) makes re-runs idempotent).
//
// The I3 decision-rule state mirrors domain.Match (ARCH-003 §3, ADR-015):
// Reasons is the auditable TR-007 rationale list (jsonb, '[]' for purely
// computed rows), DecisionRuleID the decision rule that produced the match
// (an exclusion or an override — nil for purely computed matches), and
// AutoMethod/AutoConfidence/AutoScore the raw computed triple preserved
// when a decision rule overrode the match (nil when no rule overrode). A
// purely computed record carries nil Reasons/DecisionRuleID/auto_*; the
// repository persists that as '[]' + NULLs.
type MatchRecord struct {
	VulnerabilityID string
	ComponentID     string
	Method          domain.MatchMethod
	Confidence      domain.Confidence
	Score           int
	RuleVersion     string

	Reasons        []string // TR-007 rationale list; nil/empty persists as jsonb '[]'
	DecisionRuleID *string  // decision rule that produced the match; nil = purely computed

	// AutoMethod/AutoConfidence/AutoScore preserve the raw computed triple
	// when a decision rule overrode it; nil when no rule overrode.
	AutoMethod     *domain.MatchMethod
	AutoConfidence *domain.Confidence
	AutoScore      *int
}
