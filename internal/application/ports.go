package application

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
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
	// Append appends one pending outbox row on the caller's transaction.
	// A row whose dedupe key already exists — committed earlier or staged
	// by this very transaction — surfaces as a conflict Error (the schema
	// raises the unique violation; the enqueuers that treat a duplicate as
	// a no-op pre-check through ExistsDedupeKey on the same transaction,
	// because a failed statement would abort the transaction).
	Append(ctx context.Context, tx Tx, ev OutboxEvent) error

	// ExistsDedupeKey reports whether an outbox row with the dedupe key
	// already exists — queued, claimed or terminal (the UQ spans the
	// row's whole lifetime, ADR-012 point 4). The check runs on the
	// caller's transaction and sees its own uncommitted appends: the
	// exactly-once enqueuers (the scheduler scan, the DEV-067 full-import
	// fan-in) pre-check on the same transaction they would append on, so
	// a duplicate re-enqueue is a no-op instead of a statement that fails
	// and aborts the transaction.
	ExistsDedupeKey(ctx context.Context, tx Tx, dedupeKey string) (bool, error)
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
	// of the same statement is a no-op (ON CONFLICT DO NOTHING). It
	// returns the evidence id — newly inserted, or the already existing
	// one of an identical earlier statement — so the reprocess path can
	// link it into quarantine.resolved_evidence_id (ARCH-003 §7, I2
	// forward-note; DEV-053 wires the link).
	AddEvidence(ctx context.Context, tx Tx, ev EvidenceRecord, observedAt time.Time) (string, error)
}

// MatchRepo persists method-led matches (ARCH-001 §1 matches, §3 step 4).
// The insert is idempotent on the natural key (vulnerability_id,
// component_id, rule_version) and returns the match id — newly inserted or
// already existing.
type MatchRepo interface {
	Insert(ctx context.Context, tx Tx, rec MatchRecord, createdAt time.Time) (string, error)
}

// SourceRepo resolves the sources row of a run, a raw record or a
// quarantined record into the adapter descriptor (ARCH-002 §1): the
// descriptor read every run use case starts from and the scheduler reads
// to enqueue a fetch.
type SourceRepo interface {
	// GetByID resolves the sources row by its id (sources.id — the
	// attribution key of source_runs, raw_records and quarantine rows). A
	// missing row is a not-found Error.
	GetByID(ctx context.Context, id string) (SourceDescriptor, error)

	// ListEnabledScheduled returns the sources the scheduler scan checks
	// (ARCH-002 §5): every enabled source whose schedule is set (NULL
	// schedules — e.g. the operator-triggered synthetic source — never
	// appear). The scan then derives each row's due schedule slot; the
	// schedule strings are the adapters' declared plans ("@hourly",
	// "@daily").
	ListEnabledScheduled(ctx context.Context) ([]ScheduledSource, error)

	// SetLastContentHash records the content hash of the source's last
	// committed raw record into sources.config.last_content_hash (DEV-041,
	// ch. 8.3/ARCH-002 §2.2/§2.3): the fetch use cases (FetchSource,
	// RunSource) run the update in the same transaction as the raw-record
	// insert and the run completion, so the hash advances only with a
	// committed run (ch. 6.1) and the next full-set fetch's NoChange
	// detection sees it. The update merges the member into the existing
	// config — every other member (window, overlap, the api_key_ref secret
	// reference) stays intact.
	SetLastContentHash(ctx context.Context, tx Tx, sourceID, contentHash string) error

	// SetCursor promotes the cursor_after watermark of one successful run
	// back into sources.cursor (DEV-067, ARCH-003 §6): the fetch use cases
	// (FetchSource, RunSource) run the update in the same transaction as
	// the raw-record insert and the run completion — success only; a
	// failing or rate-limited run never reaches it, so the cursor advances
	// only with a committed successful run (ch. 6.1) and the next fetch
	// re-runs the failed window. cursor is the adapter-produced cursor
	// value (the last-modified watermark of an incremental source); the
	// full-set sources never call it — their fetches carry no cursor.
	SetCursor(ctx context.Context, tx Tx, sourceID string, cursor json.RawMessage) error
}

// RawRecordRepo persists the unchanged raw source documents (ARCH-002 §1,
// §3 raw_records) and reads them back for a normalise pass. The insert is
// idempotent on the natural key (source_id, external_id, content_hash); the
// read returns the stored bytes of the reprocess path (ARCH-002 §4).
type RawRecordRepo interface {
	// Insert stores the unchanged source document and returns the row id —
	// newly inserted, or the already existing one of an identical earlier
	// ingest. contentEncoding describes the payload bytes ('identity' |
	// 'gzip' | 'json'; "" stores NULL).
	Insert(ctx context.Context, tx Tx, sourceID, externalID string, payload []byte, contentHash, contentEncoding string, fetchedAt time.Time) (string, error)

	// GetByID returns the stored document with its payload bytes. A
	// missing record is a not-found Error.
	GetByID(ctx context.Context, id string) (RawRecord, error)

	// PreviousKEVCVEs returns the CVE ids of the source's previously
	// stored KEV full set (DEV-041, ARCH-002 §2.2): the kev evidences
	// attached to the source's latest stored raw record other than
	// excludeRawRecordID — the raw record the current pass normalises,
	// whose evidence rows belong to the new catalog, never to the
	// previous one. The normalise use cases (NormalizeSource/RunSource
	// wiring) populate NormalizeInput.PreviousKEVCVEs from the result so
	// the KEV adapter historises removals against the previous catalog
	// (ch. 8.3); the result is nil for a source without a prior raw
	// record — the first import, which emits no removals. The other
	// sources never call it.
	PreviousKEVCVEs(ctx context.Context, sourceID, excludeRawRecordID string) ([]string, error)
}

// SourceRunRepo owns the source-run lifecycle (ARCH-001 §1 source_runs,
// §3 steps 1 and 6; cursor bookkeeping ARCH-002 §1): opening a run from
// the source cursor and committing the terminal state with the counters
// and the advanced cursor. The raw document of a run is stored through
// RawRecordRepo.
type SourceRunRepo interface {
	// Open starts a run in status 'running' and returns its id.
	// cursorBefore records the source cursor value the run opens from (the
	// value the fetch half read off sources.cursor; nil for full-set
	// sources and the I1b synthetic source).
	Open(ctx context.Context, tx Tx, sourceID string, cursorBefore json.RawMessage, startedAt time.Time) (string, error)

	// Complete closes a run with its terminal state: status succeeded or
	// failed, finishedAt, the committed counters and the error text of a
	// failed run. cursorAfter is committed with a successful run only —
	// the persistence layer guards it on the succeeded status, so a failed
	// run can never advance the cursor (ch. 6.1: the cursor advances only
	// after the commit of a successful run; ARCH-002 §1/§6) — pass nil for
	// full-set sources and failures.
	Complete(ctx context.Context, tx Tx, runID string, status SourceRunStatus, counters SourceRunCounters, cursorAfter json.RawMessage, errText string, finishedAt time.Time) error
}

// QuarantineRepo persists the ch. 8.6 isolation state machine (ARCH-002
// §3/§4 quarantine): the isolation insert, the reads (list + by-id) and
// the guarded state transitions. Every transition is guarded on the source
// status in SQL and returns the updated row; a transition that does not
// apply to the current state — the state changed concurrently between the
// caller's read and the write — is a conflict Error (one command, one
// transaction: the audit event of a transition that did not happen must
// not be written, ch. 13.2).
type QuarantineRepo interface {
	// Insert isolates one failed record slice in status 'new' and returns
	// its id. sourceID, position, reason and payloadHash are required;
	// sourceRunID and rawRecordID may be "" (NULL — the isolation is not
	// yet attributed to a run/raw record).
	Insert(ctx context.Context, tx Tx, sourceID, sourceRunID, rawRecordID, position, reason, payloadHash string, now time.Time) (string, error)

	// GetByID returns one quarantined row. A missing row is a not-found
	// Error.
	GetByID(ctx context.Context, id string) (domain.Quarantine, error)

	// List returns the working list ordered by created_at then id
	// (oldest isolation first). status and sourceID filter optionally; nil
	// / "" keep the filter open. limit is the page size (>= 1).
	List(ctx context.Context, status *domain.QuarantineStatus, sourceID string, limit int) ([]domain.Quarantine, error)

	// Acknowledge records the operator review (new -> acknowledged) and
	// returns the updated row.
	Acknowledge(ctx context.Context, tx Tx, id, acknowledgedBy, note string, now time.Time) (domain.Quarantine, error)

	// MarkReadyForRetry moves a reviewed row to the retryable state (new /
	// acknowledged -> ready_for_retry) and returns the updated row.
	MarkReadyForRetry(ctx context.Context, tx Tx, id string, now time.Time) (domain.Quarantine, error)

	// MarkResolved is the terminal transition of a successful reprocess
	// (ready_for_retry or new -> resolved) and returns the updated row.
	// The resolution links the new domain object via
	// resolvedVulnerabilityID/resolvedEvidenceID ("" for none) and
	// documents the outcome in note (which may carry a justified discard).
	MarkResolved(ctx context.Context, tx Tx, id, resolvedVulnerabilityID, resolvedEvidenceID, note string, now time.Time) (domain.Quarantine, error)

	// IncrementAttempts records a failed reprocess (new / ready_for_retry
	// -> attempts + 1, the row stays retryable) and returns the updated
	// row.
	IncrementAttempts(ctx context.Context, tx Tx, id string, now time.Time) (domain.Quarantine, error)
}

// ComponentRepo is the I1b matcher's read path over the seeded inventory
// (ARCH-001 §1 components, §3 step 4). The minimal matcher resolves the
// affected version range over the returned set in application code.
type ComponentRepo interface {
	ListByVendorProduct(ctx context.Context, vendor, product string) ([]Component, error)
}

// AliasRuleRepo resolves the effective alias rules the match-time alias
// closure reads through (ARCH-003 §2 item 2, WP-3.04/DEV-047): the
// enabled alias rules of the current ruleset version, which the matcher
// feeds to normalise.AliasClosure / normalise.ValidateAliasRules — one
// closure per (scope, value), both the CVE side and the component side
// closed before the semi-join (ADR-012). The adapter implementation lands
// with the matching engine (WP-3.06); the port is declared here so the
// matching use case programs against the read, never against the
// alias_rules table. Disabled rules and stale ruleset versions are inert
// and must not be returned.
type AliasRuleRepo interface {
	// Effective returns the enabled alias rules of the current ruleset
	// version (both scopes). A ruleset with no rules yet yields an empty
	// slice, never an error.
	Effective(ctx context.Context) ([]domain.AliasRule, error)
}

// ComponentNormLister is the candidate pre-filter's read over the
// inventory product index (ADR-012, ARCH-003 §4, IX
// components_product_idx ON (vendor_norm, product_norm)): the components
// of one normalised vendor/product pair as the alias-closure semi-join
// resolves them (WP-3.07/DEV-062). The pre-filter calls it once per
// closed (vendor, product) pair; the I3 matcher (WP-3.08) and the
// epss_history loader share the same read — both call
// CandidateComponentIDs, never this port directly. The adapter is the
// ListComponentsByVendorProductNorm query of components.sql wired with
// the I3 matching reads (WP-3.08); the port is declared here so the
// pre-filter programs against the read, never against the components
// table.
type ComponentNormLister interface {
	// ListByVendorProductNorm returns the components whose normalised
	// vendor/product keys equal the pair, in natural_key order
	// (deactivated rows included — the matching engine decides what a
	// deactivated component may still match).
	ListByVendorProductNorm(ctx context.Context, vendorNorm, productNorm string) ([]Component, error)
}

// ---------------------------------------------------------------------------
// I4 ports — signals, priority & SLA (ARCH-004, WP-4.04a / DEV-075)

// SignalTriageRepo is the guarded-command port over risk_signals of the I4
// triage commands (ARCH-004 §2.1/§2.3 and §3): the plain by-id row read the
// command layer takes before a guarded write, the status transition, the
// manual priority override and its revert, and the owner assignment. Every
// mutating method runs on the caller's transaction and is guarded on the
// optimistic-lock version the client read: a stale version matches zero rows
// and surfaces as a conflict Error (HTTP 409, ch. 7.3), never a silent
// overwrite, and the updated row is mapped back to the domain aggregate. It
// is declared separately from SignalRepo so the unchanged I1b read/creation
// surface is untouched; the DEV-073 concrete adapter *repo.SignalRepo
// (signaltriage.go) implements both.
//
// It is a port only for now: the I5b composition root wires it alongside the
// other ports (no composition root constructs a Service with it before the
// triage HTTP/CLI surface lands).
type SignalTriageRepo interface {
	// GetRiskSignal returns the plain stored signal row (no joins) — the
	// read a command takes before its guarded write. A missing row is a
	// not-found Error.
	GetRiskSignal(ctx context.Context, id string) (domain.RiskSignal, error)

	// Transition applies the ch. 6.3 status change under the optimistic
	// lock: it writes the new status and the closed_at stamp (the entry
	// instant of a closed state; nil clears it on a non-closed target or
	// on a reopen) and bumps version. A stale expectedVersion is a
	// conflict Error. The domain state machine (domain.Transition) rules
	// which edges are legal before the write is attempted.
	Transition(ctx context.Context, tx Tx, id string, to domain.SignalStatus, closedAt *time.Time, expectedVersion int) (domain.RiskSignal, error)

	// OverridePriority is the manual re-prioritisation (ADR-015 mirror,
	// ARCH-004 §3): it sets the effective priority, preserves the computed
	// value in auto_priority and stamps the mandatory reason/actor/time.
	// The four override columns are all-set together. A stale
	// expectedVersion is a conflict Error.
	OverridePriority(ctx context.Context, tx Tx, id string, priority, autoPriority domain.Priority, reason, actorID string, at time.Time, expectedVersion int) (domain.RiskSignal, error)

	// RevertPriority restores priority = auto_priority and clears the four
	// override columns in one guarded write. A stale expectedVersion is a
	// conflict Error.
	RevertPriority(ctx context.Context, tx Tx, id string, expectedVersion int) (domain.RiskSignal, error)

	// AssignOwner assigns the (opaque until I5a) owner principal under the
	// optimistic lock; "" clears the owner. A stale expectedVersion is a
	// conflict Error.
	AssignOwner(ctx context.Context, tx Tx, id, owner string, expectedVersion int) (domain.RiskSignal, error)

	// RecomputePriority persists the outcome of a targeted priority
	// recompute (ARCH-004 §5, ch. 9.5) on the caller's transaction: the
	// freshly rebuilt factor set, the rule version the recompute ran under
	// and the recomputed computed priority. The override-survival mirror of
	// §3 (ADR-015) is enforced in the write: for a purely computed signal
	// (auto_priority IS NULL) the effective priority is updated; for an
	// overridden signal the computed value updates auto_priority only and
	// the effective priority — the human decision — is left untouched. It
	// is deliberately not version-guarded: the command's changed-only
	// comparison keeps an identical recompute from reaching it at all, and
	// the background recompute computes from the row it read (a concurrent
	// guarded write bumps version afterwards, never silently). The updated
	// row is returned.
	RecomputePriority(ctx context.Context, tx Tx, id string, priority domain.Priority, ruleVersion string, factors domain.PriorityFactors) (domain.RiskSignal, error)
}

// PriorityRuleRepo is the versioned priority_rules snapshot port (ARCH-004
// §1): the effective-version read the create path stamps a signal with, the
// copy-on-write snapshot publish, and the effective-snapshot read the
// evaluator runs against. The ruleset is a versioned data snapshot — the
// effective version is MAX(version), a publish writes the whole P1..P4 rows
// at MAX(version)+1, and a signal references exactly one snapshot through
// its rule_version. The DEV-073 adapter *repo.PriorityRuleRepo
// (priorityrule.go) implements it; its effective-snapshot read is called
// Effective there (the ListEffectivePriorityRules query), so the port
// mirrors that name.
type PriorityRuleRepo interface {
	// EffectiveVersion returns the current effective ruleset version
	// (MAX(version)). An empty table reads 0 — the "no ruleset published
	// yet" sentinel (the create path then keeps the I1b stamp).
	EffectiveVersion(ctx context.Context) (int, error)

	// Publish writes one full ruleset snapshot — the four rules P1..P4 of
	// the passed slice, in order — at next = MAX(version)+1, all sharing
	// one effectiveFrom/reason/actorID, and returns the new effective
	// version. reason and actorID are mandatory; the snapshot must carry
	// exactly the four rules.
	Publish(ctx context.Context, tx Tx, rules []domain.PriorityRule, effectiveFrom time.Time, reason, actorID string, createdAt time.Time) (int, error)

	// Effective returns the whole effective snapshot — the rules at
	// MAX(version) — ordered P1→P4. Disabled rules are returned too (a
	// disabled rule is inert; the evaluator skips it). An empty ruleset
	// yields an empty slice, never an error.
	Effective(ctx context.Context) ([]domain.PriorityRule, error)
}

// PriorityFactorRepo is the minimal read port of the priority factor rebuild
// (ARCH-004 §5, ch. 9.5): the fresh PriorityFactors of one signal, sourced
// from the linked match's method/confidence (ADR-015), the vulnerability's
// latest KEV/CVSS/EPSS evidence and the owning asset's criticality/exposure.
// It is read-only and transaction-free — the recompute use case reads it
// before it decides whether anything changed (changed-only persist), so an
// unchanged recompute opens no transaction at all. The DEV-077 adapter
// *repo.PriorityFactorRepo (priorityfactor.go) implements it; the read port
// exists because no other port exposes the signal's joined factor context.
type PriorityFactorRepo interface {
	// Rebuild returns the freshly sourced factors of one signal and the CVE
	// id of its vulnerability. The confidence is re-derived from the
	// authoritative match method (ADR-015), never trusted from a stored
	// copy. A missing signal is a not-found Error.
	Rebuild(ctx context.Context, signalID string) (PriorityFactorRebuild, error)
}

// CommentRepo is the append-only signal-timeline port (ARCH-004 §2.2): the
// insert and the ordered per-signal read. There is no update or delete path
// — a comment is never edited or deleted; the command layer writes the
// signal.commented audit event in the same transaction as the insert. The
// DEV-073 adapter *repo.CommentRepo (comment.go) implements it.
type CommentRepo interface {
	// Add appends one comment to a signal on the caller's transaction and
	// returns it. createdAt is the injected clock instant; the id is the
	// database default.
	Add(ctx context.Context, tx Tx, signalID, actorID, body string, createdAt time.Time) (domain.Comment, error)

	// ListBySignal returns the signal's comments ordered by created_at then
	// id. A signal without comments yields an empty slice, never an error.
	ListBySignal(ctx context.Context, signalID string) ([]domain.Comment, error)
}

// SlaClockRepo is the SLA-clock persistence port (ARCH-004 §4): the
// natural-key (signal_id, target) upsert, the fulfil/pause/resume guarded
// writes, the reopen reset and the due-deadline breach scan. The command
// layer and the worker supply the injected clock instants; the port only
// persists and maps the stored rows back to the domain value object. The
// DEV-073 adapter *repo.SlaClockRepo (slaclock.go) implements it; its
// breach scan is called Due there (the ScanDueSlaClocks query), so the port
// mirrors that name.
type SlaClockRepo interface {
	// Upsert writes one clock's full state by its natural key: a fresh
	// insert, or the full-state replacement of an existing clock (the
	// create path and the reopen reset in one statement). The stored row is
	// returned.
	Upsert(ctx context.Context, tx Tx, clock domain.SlaClock) (domain.SlaClock, error)

	// Fulfil marks the target met at the instant, returning the stored
	// clock and whether the fulfil changed it. Idempotent: an
	// already-fulfilled clock reports changed = false (a fulfilled clock is
	// never re-opened).
	Fulfil(ctx context.Context, tx Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, bool, error)

	// Pause starts a pause at the instant (paused_at is set). A fulfilled
	// or already-paused clock (or a missing one) is a conflict Error.
	Pause(ctx context.Context, tx Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error)

	// Resume ends the active pause at the instant: the elapsed pause
	// accumulates into paused_seconds and paused_at is cleared. A clock
	// that is not paused (or missing) is a conflict Error.
	Resume(ctx context.Context, tx Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error)

	// Reset restarts one clock on a reopen: started_at = now, deadline_at =
	// now + duration, fulfilled_at cleared and the pause counters zeroed. A
	// clock that does not exist is a not-found Error.
	Reset(ctx context.Context, tx Tx, signalID string, target domain.SLATarget, startedAt, deadlineAt time.Time) (domain.SlaClock, error)

	// Due returns the open clocks whose effective deadline has passed —
	// the sla.evaluate breach scan. The effective deadline accounts for
	// accumulated and running pauses. No due clock yields an empty slice,
	// never an error.
	Due(ctx context.Context) ([]domain.SlaClock, error)
}

// NotificationRepo is the notification delivery-state port (ARCH-004 §6.2):
// the idempotent insert keyed on (outbox_event_id, channel), the
// delivery-state update and the per-signal read. The relay handler and the
// NotifyPort adapters that drive it land with WP-4.06; this port owns the
// persistence shape the application layer programs against. It returns the
// application-level Notification (models.go), not the generated row type:
// the application layer never imports the adapters' gen package
// (.go-arch-lint.yml). The DEV-073 adapter *repo.NotificationRepo
// (notification.go) currently returns gen.Notification; aligning it onto
// this port is WP-4.06's read-model work.
type NotificationRepo interface {
	// Insert stores one notification row on the caller's transaction and
	// reports whether it was newly inserted. The UQ (outbox_event_id,
	// channel) makes the insert idempotent: a redelivery stores nothing and
	// reports inserted = false — exactly one notification per (event,
	// channel) (FR-023). status is the initial delivery state ('pending' on
	// the create path), createdAt the injected clock.
	Insert(ctx context.Context, tx Tx, signalID, channel, kind, recipient, status, outboxEventID string, createdAt time.Time) (Notification, bool, error)

	// UpdateDelivery records the delivery receipt of one notification by
	// its id: the new status, the attempt count, the last error text (""
	// clears it) and the delivered instant (nil clears it). A missing
	// notification is a not-found Error.
	UpdateDelivery(ctx context.Context, tx Tx, id, status string, attempts int, lastError string, deliveredAt *time.Time) (Notification, error)

	// ListBySignal returns a signal's notifications ordered by created_at
	// then id. A signal without notifications yields an empty slice, never
	// an error.
	ListBySignal(ctx context.Context, signalID string) ([]Notification, error)
}
