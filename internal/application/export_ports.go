package application

// This file owns the I6 export surface of the application layer (ARCH-007
// §1.1/§1.2, WP-6.04 / DEV-115): the frozen filter vocabulary, the export
// job read model and the three ports the export use cases (and the
// export.generate worker job of WP-6.06) program against — the export CRUD
// repository, the spool artifact store and the streaming SignalExportSource
// read. The concrete adapters are wired at the composition root; the
// application layer never imports the generated package or a filesystem
// package directly (.go-arch-lint.yml).
//
// Exports are asynchronous materialised jobs, not on-demand queries: the
// CreateExport use case freezes the §10.4 filter context plus the creation
// instant and enqueues a job; the worker materialises the artifact into the
// spool and stamps the generation columns; a download streams the stored
// artifact while it is unexpired. The filter vocabulary is bounded by
// construction — a fixed set of optional fields, never a free-form query
// (the strict input limits of §12.3).

import (
	"context"
	"io"
	"time"

	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// ExportStatus is the lifecycle of an export job (ARCH-007 §1.2). An export
// is created 'pending', the export.generate job stamps it 'completed' (or
// 'failed' + last_error) and the daily sweep flips a stale completed row to
// 'expired' after it deletes the artifact.
type ExportStatus string

// Allowed ExportStatus values (ARCH-007 §1.2).
const (
	// ExportStatusPending is the creation state — no artifact yet.
	ExportStatusPending ExportStatus = "pending"
	// ExportStatusCompleted carries the spool reference and the generation
	// stamps.
	ExportStatusCompleted ExportStatus = "completed"
	// ExportStatusFailed records a failed generation (+ last_error).
	ExportStatusFailed ExportStatus = "failed"
	// ExportStatusExpired marks a completed export whose artifact the sweep
	// deleted after its TTL elapsed.
	ExportStatusExpired ExportStatus = "expired"
)

// Valid reports whether s is an allowed ExportStatus value.
func (s ExportStatus) Valid() bool {
	switch s {
	case ExportStatusPending, ExportStatusCompleted, ExportStatusFailed, ExportStatusExpired:
		return true
	}
	return false
}

// ExportSLAState is the sla_state vocabulary of the frozen export filter
// (ARCH-007 §1.2): the SLA-clock state of a signal evaluated against the
// generation clock — breached (an open clock past its effective deadline),
// open (an open clock not yet breached), met (has clocks, none open) or none
// (no clocks). The export query evaluates it; the filter only carries it.
type ExportSLAState string

// Allowed ExportSLAState values (ARCH-007 §1.2).
const (
	// ExportSLAStateBreached selects signals with an open, breached clock.
	ExportSLAStateBreached ExportSLAState = "breached"
	// ExportSLAStateOpen selects signals with an open, unbreached clock.
	ExportSLAStateOpen ExportSLAState = "open"
	// ExportSLAStateMet selects signals whose clocks are all fulfilled.
	ExportSLAStateMet ExportSLAState = "met"
	// ExportSLAStateNone selects signals without any SLA clock.
	ExportSLAStateNone ExportSLAState = "none"
)

// Valid reports whether s is an allowed ExportSLAState value.
func (s ExportSLAState) Valid() bool {
	switch s {
	case ExportSLAStateBreached, ExportSLAStateOpen, ExportSLAStateMet, ExportSLAStateNone:
		return true
	}
	return false
}

// ExportFilter is the frozen signal filter context of an export (ARCH-007
// §1.2, the concept ch. 10.4 signal filter vocabulary): priority, status,
// asset_id, asset_type, product, cve, owner_id, source_id, created_from/to,
// sla_state, free_text. Every field is optional — the zero value is the
// unfiltered working list. It is stored verbatim as the exports.filter jsonb
// and never changes after creation, so the field set is a stable wire shape
// (the json tags are the stored keys and the API's property names).
//
// OwnerID is both a user filter and the object-scope injection point: the
// CreateExport use case overwrites it with the creator's principal id for an
// `assigned`/`own` exports.create grant, so a scoped export can never range
// beyond its creator's assigned signals (ARCH-005 §5).
type ExportFilter struct {
	Priority    *domain.Priority     `json:"priority,omitempty"`
	Status      *domain.SignalStatus `json:"status,omitempty"`
	AssetID     string               `json:"asset_id,omitempty"`
	AssetType   *domain.AssetType    `json:"asset_type,omitempty"`
	Product     string               `json:"product,omitempty"`
	Cve         string               `json:"cve,omitempty"`
	OwnerID     *string              `json:"owner_id,omitempty"`
	SourceID    string               `json:"source_id,omitempty"`
	CreatedFrom *time.Time           `json:"created_from,omitempty"`
	CreatedTo   *time.Time           `json:"created_to,omitempty"`
	SLAState    *ExportSLAState      `json:"sla_state,omitempty"`
	FreeText    string               `json:"free_text,omitempty"`
}

// Validate checks the frozen filter against the §10.4 vocabulary: the
// signal enums reuse the working-list validation (validateSignalFilterEnums,
// ListSignals), the asset type and sla_state vocabularies are checked here,
// and a created window must be a non-empty half-open range ([from, to)). It
// runs before the transaction is opened, so an invalid filter writes nothing.
func (f ExportFilter) Validate(op string) error {
	if err := validateSignalFilterEnums(op, f.Priority, f.Status); err != nil {
		return err
	}
	if f.AssetType != nil && !f.AssetType.Valid() {
		return Validationf(op, "invalid asset_type filter %q", *f.AssetType)
	}
	if f.SLAState != nil && !f.SLAState.Valid() {
		return Validationf(op, "invalid sla_state filter %q", *f.SLAState)
	}
	if f.CreatedFrom != nil && f.CreatedTo != nil && !f.CreatedFrom.Before(*f.CreatedTo) {
		return Validationf(op, "created_from %s must be before created_to %s",
			f.CreatedFrom.UTC().Format(time.RFC3339), f.CreatedTo.UTC().Format(time.RFC3339))
	}
	return nil
}

// Export is the stored export job (ARCH-007 §1.2): the frozen filter and
// format plus the generation stamps. StoragePath/RowCount/SchemaVersion/
// RuleVersion/Checksum are empty and ExpiresAt is the zero time while the row
// is pending/failed; the export.generate job fills them when it completes.
type Export struct {
	ID            string
	Status        ExportStatus
	Filter        ExportFilter
	Format        export.Format
	StoragePath   string
	RowCount      int
	SizeBytes     int64
	Checksum      string
	SchemaVersion string
	RuleVersion   string
	CreatedBy     string
	CreatedAt     time.Time
	ExpiresAt     time.Time // zero = not yet stamped (pending/failed)
	LastError     string
}

// ExportRecord is the insert payload of one export row (ARCH-007 §1.2): the
// frozen filter, the requested format and the creating principal. The id,
// the 'pending' status and the generation columns' NULLs are assigned by the
// database; CreatedAt comes from the injected clock.
type ExportRecord struct {
	Filter    ExportFilter
	Format    export.Format
	CreatedBy string
	CreatedAt time.Time
}

// ExportCompletion is the generation outcome the export.generate job stamps
// onto an export row when it completes (ARCH-007 §1.2): the spool reference,
// the materialised counts/size, the artifact SHA-256, the schema/rule
// versions stamped at generation time and the expiry (created_at +
// export.ttl). It carries no business content — identities, counts and hashes
// only.
type ExportCompletion struct {
	// ID is the export row the completion belongs to.
	ID string
	// StoragePath is the spool-relative artifact reference.
	StoragePath string
	// RowCount is the number of materialised signal rows.
	RowCount int
	// SizeBytes is the artifact byte size.
	SizeBytes int64
	// Checksum is the lowercase hex SHA-256 of the artifact bytes.
	Checksum string
	// SchemaVersion is the export document schema version (export.SchemaVersion).
	SchemaVersion string
	// RuleVersion is MAX(priority_rules.version) at generation time.
	RuleVersion string
	// ExpiresAt is the artifact expiry (created_at + export.ttl).
	ExpiresAt time.Time
}

// ExportRepo persists and reads export jobs (ARCH-007 §1.2). Insert and the
// generation stamps (MarkCompleted/MarkFailed/MarkExpired) run on the
// caller's transaction — the export row and its export.generate outbox job
// commit or roll back together (one command, one transaction, ch. 5.1) —
// while GetByID and ListExpired are pool-scoped reads of the
// status/download/sweep paths and the load step of the export.generate job.
// The concrete adapter maps the generated exports row onto Export and
// unmarshals the stored filter jsonb, so the application layer never imports
// the generated package.
type ExportRepo interface {
	// Insert stores one 'pending' export row on the caller's transaction and
	// returns the stored row with its database-assigned id.
	Insert(ctx context.Context, tx Tx, rec ExportRecord) (Export, error)

	// GetByID reads one export by its id. A missing id is a not-found Error.
	GetByID(ctx context.Context, id string) (Export, error)

	// MarkCompleted stamps the generation outcome and flips the export to
	// 'completed' on the caller's transaction (ARCH-007 §1.2). The
	// `status IN ('pending','failed')` guard keeps a retried generation
	// idempotent (a crash/failure is regenerated and re-stamps the row) while
	// an already-completed/expired row matches no row — a conflict Error. The
	// cleared last_error makes the row indistinguishable from a first-run
	// completion.
	MarkCompleted(ctx context.Context, tx Tx, done ExportCompletion) (Export, error)

	// MarkFailed records a failed generation (status 'failed' + last_error)
	// on the caller's transaction, visible like any dead-letter/source-runs
	// error (ARCH-007 §1.2). The guard lets a retried failing generation
	// re-stamp the error but never overwrites a completed/expired row — a
	// conflict Error.
	MarkFailed(ctx context.Context, tx Tx, id, lastError string) (Export, error)

	// ListExpired returns the completed exports whose TTL elapsed
	// (expires_at <= now), ordered by expiry then id — the input of the daily
	// export sweep (ARCH-007 §1.2). No expired export yields an empty slice,
	// never an error.
	ListExpired(ctx context.Context, now time.Time) ([]Export, error)

	// MarkExpired flips a completed export to 'expired' on the caller's
	// transaction after the sweep deleted its artifact. The `status =
	// 'completed'` guard makes the mark idempotent (a second sweep of the same
	// row matches no row — a conflict Error) and never re-expires a
	// pending/failed row.
	MarkExpired(ctx context.Context, tx Tx, id string) (Export, error)
}

// ExportArtifactStore reads and writes the server-local export spool
// artifacts (ARCH-007 §1.2). The export.generate job writes the materialised
// artifact and records the returned reference; a download opens it to
// stream. The concrete implementation is *export.Spool (export.dir-relative,
// atomic write + SHA-256); tests substitute an in-memory fake.
type ExportArtifactStore interface {
	// Write stores the artifact bytes under key and returns the stored
	// reference (path, size, SHA-256).
	Write(ctx context.Context, key string, r io.Reader) (export.Artifact, error)

	// Open returns a reader over the stored artifact at the spool-relative
	// path (the exports.storage_path reference).
	Open(ctx context.Context, path string) (io.ReadCloser, error)

	// Remove deletes the stored artifact at the spool-relative path — the
	// daily sweep's artifact deletion of an expired export (ARCH-007 §1.2).
	// A missing artifact is not an error (the sweep still marks the row
	// expired): the caller cannot distinguish an already-swept export from a
	// never-materialised one, and both cases end in the same terminal state.
	Remove(ctx context.Context, path string) error
}

// SignalExportSource is the streaming read behind an export (ARCH-007 §1.2):
// the full-scan variant of ListSignals — no pagination — the export.generate
// job (WP-6.06) will stream through. It reuses the working-list filter
// vocabulary and the object scope (the filter carries OwnerID; an
// `assigned`/`own` creator's export was already frozen to its owner at
// creation) and returns every matching signal ordered by the §10.4 standard
// sort (priority ascending P1→P4, then the next open SLA deadline, then the
// creation instant, then id). It is a pure read: it materialises nothing and
// is not a second write path. now is the injected clock instant the sla_state
// filter and the deadline ordering are evaluated against.
type SignalExportSource interface {
	// Scan returns every signal matching filter, ordered by the §10.4
	// standard sort. The result is intentionally unbounded — export.max_rows
	// bounds the export in the materialisation use case, never here.
	Scan(ctx context.Context, filter ExportFilter, now time.Time) ([]export.Row, error)
}
