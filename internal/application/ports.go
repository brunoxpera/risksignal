package application

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// Tx is the handle of one database transaction. It is an alias of pgx.Tx —
// the pgx/v5 transaction interface, the locked persistence of the project
// (ADR-009) — so that the repository ports can run their writes on the very
// transaction postgres.WithTx opens (ARCH-001 §2): one domain command, one
// transaction, state change + audit + outbox committed or rolled back
// together. Repositories receive Tx on every write method; read-only
// repositories ignore it. Test fakes implement Tx by embedding it and
// staging writes per transaction.
type Tx = pgx.Tx

// TxRunner executes fn inside one transaction: it commits when fn returns
// nil and rolls back — returning fn's error unwrapped — when fn fails. The
// production implementation is postgres.WithTx(ctx, pool, fn), wired at the
// composition root (cmd/*); tests inject a fake runner that stages writes
// and simulates commit/rollback. The seam this creates is exactly the
// ARCH-001 §5 fault point: a failing OutboxRepo.Append inside the runner's
// transaction rolls the signal and the audit write back with it.
type TxRunner func(ctx context.Context, fn func(tx Tx) error) error

// Clock is the injectable time source of the application. It aliases the
// platform clock port (internal/platform/clock): every timestamp the use
// cases stamp (created_at, occurred_at, fetched_at, started_at …) comes from
// this port — there is no wall-clock access in the run path (ch. 7.2,
// ARCH-001 §3 reproducibility guarantee).
type Clock = clock.Clock

// SignalRepo persists and reads risk signals (ARCH-001 §1 risk_signals).
// The write runs on the caller's transaction; the reads are plain
// working-list queries returning the joined §4 view.
type SignalRepo interface {
	// Create inserts one signal row on tx and returns the stored signal
	// with the database-assigned id, status and version. createdAt is the
	// clock timestamp stamped by the caller.
	Create(ctx context.Context, tx Tx, rec SignalRecord, createdAt time.Time) (domain.RiskSignal, error)

	// GetByID returns the joined readable view of one signal. A missing
	// signal is a not-found Error.
	GetByID(ctx context.Context, id string) (Signal, error)

	// List returns the working list ordered by priority (P1→P4), then
	// created_at, then id (ARCH-001 §4 / ch. 10.4). limit and offset are
	// the page window; the implementation fetches one more row than limit
	// so the caller can detect a further page: the result therefore holds
	// at most limit+1 signals.
	List(ctx context.Context, filter SignalFilter, limit, offset int) ([]Signal, error)

	// ExistsByMatchID reports whether a signal already exists for the
	// match — the ARCH-001 §3 step 5 check that keeps re-runs from
	// creating duplicates (UQ match_id backs it at the schema level).
	ExistsByMatchID(ctx context.Context, matchID string) (bool, error)
}

// AuditRepo appends audit rows (ARCH-001 §1 audit_events, WP-1b.03). The
// table is append-only: this is the only write path, and it runs on the
// caller's transaction so the event commits atomically with its state
// change (ch. 5.1).
type AuditRepo interface {
	Append(ctx context.Context, tx Tx, ev AuditEvent) error
}

// OutboxRepo appends outbox rows (ARCH-001 §1 and §2, WP-1b.03). The append
// runs on the caller's transaction — the row is the third write of the
// CreateSignal command and the injectable fault point of the ARCH-001 §5
// rollback proof. The UQ (dedupe_key) makes the append idempotent at the
// schema level.
type OutboxRepo interface {
	Append(ctx context.Context, tx Tx, ev OutboxEvent) error
}

// VulnerabilityRepo persists normalised vulnerabilities and their immutable
// source statements (ARCH-001 §1 vulnerabilities + evidences, §3 step 3).
// Both write paths are idempotent by natural key (UQ cve_id; UQ
// (raw_record_id, type, value_hash)).
type VulnerabilityRepo interface {
	// Upsert inserts or refreshes the vulnerability by its natural key
	// cve_id and returns its database-assigned id (existing or new).
	Upsert(ctx context.Context, tx Tx, rec VulnerabilityRecord, publishedAt, modifiedAt time.Time) (string, error)

	// AddEvidence inserts one immutable evidence row; repeated ingestion
	// of the same statement is a no-op (ON CONFLICT DO NOTHING).
	AddEvidence(ctx context.Context, tx Tx, ev EvidenceRecord, observedAt time.Time) error
}

// MatchRepo persists method-led matches (ARCH-001 §1 matches, §3 step 4).
// The insert is idempotent on the natural key (vulnerability_id,
// component_id, rule_version) and returns the match id — newly inserted or
// already existing.
type MatchRepo interface {
	Insert(ctx context.Context, tx Tx, rec MatchRecord, createdAt time.Time) (string, error)
}

// SourceRunRepo owns the source-run lifecycle and its raw document
// (ARCH-001 §1 source_runs + raw_records, §3 steps 1, 2 and 6): opening a
// run, storing the unchanged document (idempotent by UQ (source_id,
// external_id, content_hash)) and committing the terminal state with the
// counters.
type SourceRunRepo interface {
	// InsertRawRecord stores the unchanged source document and returns the
	// row id — newly inserted or already existing.
	InsertRawRecord(ctx context.Context, tx Tx, sourceID, externalID string, payload []byte, contentHash string, fetchedAt time.Time) (string, error)

	// Open starts a run in status 'running' and returns its id.
	Open(ctx context.Context, tx Tx, sourceID string, startedAt time.Time) (string, error)

	// Complete closes a run with its terminal state: status succeeded or
	// failed, finishedAt, the committed counters and the error text of a
	// failed run (concept ch. 8.1 step 5: the E1 error is counted and
	// recorded, it does not abort the other cases).
	Complete(ctx context.Context, tx Tx, runID string, status SourceRunStatus, counters SourceRunCounters, errText string, finishedAt time.Time) error
}

// ComponentRepo is the I1b matcher's read path over the seeded inventory
// (ARCH-001 §1 components, §3 step 4). The minimal matcher resolves the
// affected version range over the returned set in application code.
type ComponentRepo interface {
	ListByVendorProduct(ctx context.Context, vendor, product string) ([]Component, error)
}
