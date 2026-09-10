package application_test

// In-memory fakes for the application-layer unit tests (DEV-018 acceptance:
// "Unit tests with in-memory fakes; fault-injection unit test shows no
// partial commit").
//
// The fakes mirror the production wiring one level down: the fake
// transaction runner plays the role of postgres.WithTx, and the fake
// repositories stage their writes on the fake transaction they receive —
// commit publishes the staged rows into the shared fake database, rollback
// discards them. A test therefore observes exactly what a caller of the real
// stack observes: rows exist only after the transaction committed, and the
// per-transaction write order is recorded for assertions. The ARCH-001 §5
// fault seam is armed by setting the failpoint on the fake outbox
// repository: Append records the write and then returns the injected error,
// exactly as a decorated production OutboxRepo.Append would.
//
// Read-path fakes (GetByID/List over the joined §4 view) are seeded directly
// with application.Signal values: the view aggregates match/vulnerability/
// component/asset rows from other tables, which the write-path fakes do not
// model. No test mixes both paths on the same rows, so the split stays
// faithful to what each test exercises.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// fixedNow is the single point in time every fake clock reads, so tests can
// assert exact timestamps and the reproducibility of re-runs.
var fixedNow = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// shared fake database

type storedSignal struct {
	sig       domain.RiskSignal
	createdAt time.Time
	// closedAt is the closed_at stamp of the row (nil while the signal is
	// open) — the retention-countdown instant the transition write sets on
	// entering a closed state and clears on a reopen.
	closedAt *time.Time
}

type storedVuln struct {
	id, cveID, summary string
}

type storedEvidence struct {
	id            string
	vulnID, rawID string
	typ           domain.EvidenceType
	value         []byte
	hash          string
	observedAt    time.Time
}

type storedMatch struct {
	id        string
	rec       application.MatchRecord
	createdAt time.Time
}

type storedRawRecord struct {
	id, sourceID, externalID, contentHash, contentEncoding string
	payload                                                []byte
	fetchedAt                                              time.Time
}

type storedSourceRun struct {
	id, sourceID string
	status       string
	counters     application.SourceRunCounters
	errText      string
	cursorBefore json.RawMessage
	cursorAfter  json.RawMessage
	startedAt    time.Time
	finishedAt   time.Time
}

// storedEpssRow is one epss_current row the fake EPSS bulk load stages: the
// tuple values the application's bulk writer sends through the fake
// CopyFrom (cve id + the COPY-ready decimals, model_version and loaded_at
// stamped by the writer — ARCH-002 §3).
type storedEpssRow struct {
	cveID        string
	score        pgtype.Numeric
	percentile   pgtype.Numeric
	modelVersion string
	loadedAt     time.Time
}

type storedRunCompletion struct {
	runID       string
	status      application.SourceRunStatus
	counters    application.SourceRunCounters
	cursorAfter json.RawMessage
	errText     string
	finishedAt  time.Time
}

// sourceHashMutation is one staged sources.config.last_content_hash update
// of a fetch run's terminal commit (DEV-041, ch. 8.3).
type sourceHashMutation struct {
	sourceID    string
	contentHash string
}

// sourceCursorMutation is one staged sources.cursor promotion of a fetch
// run's terminal commit (DEV-067, ARCH-003 §6).
type sourceCursorMutation struct {
	sourceID string
	cursor   json.RawMessage
}

// fakeDB is the committed state of the fake persistence: rows are visible
// here only after the transaction that staged them committed.
type fakeDB struct {
	signalRows   []storedSignal
	auditEvents  []application.AuditEvent
	outboxEvents []application.OutboxEvent
	vulns        []storedVuln
	evidenceRows []storedEvidence
	matchRows    []storedMatch
	rawRecords   []storedRawRecord
	sourceRuns   []storedSourceRun
	sources      []application.SourceDescriptor
	// scheduled are the enabled scheduled source rows of the scheduler scan
	// (ARCH-002 §5): the fake SourceRepo.ListEnabledScheduled reads them;
	// tests seed them independently of the descriptor store (the descriptor
	// shape carries no schedule/enabled columns).
	scheduled  []application.ScheduledSource
	quarantine []domain.Quarantine
	epssRows   []storedEpssRow
	// components is the seeded inventory (demo seed data), written by the
	// test before a run and only ever read by the matcher fake.
	components []application.Component
	// signalViews is the joined §4 read store, seeded by read-path tests.
	signalViews []application.Signal
	// comments is the committed append-only comment timeline (ARCH-004
	// §2.2); slaClocks the committed SLA clocks (ARCH-004 §4.1).
	comments  []domain.Comment
	slaClocks []domain.SlaClock
	// assets is the committed inventory of the commit write path
	// (DEV-060): staged wholesale per transaction (copy-on-write overlay),
	// replaced on commit, discarded on rollback. nextAssetID is the id
	// generator of the overlay (ids stay unique across rolled-back
	// transactions — irrelevant to the assertions, ids are only compared
	// for identity). aliasVersion/decisionVersion are the ruleset version
	// counters of RuleVersions (0 until a test raises them).
	assets          []fakeStoredAsset
	nextAssetID     int
	aliasVersion    int
	decisionVersion int
	// imports is the committed staged-import store (WP-5b.03); nextImportID
	// is its id generator (monotonic over the test, rolled-back transactions
	// included — ids are only compared for identity).
	imports      []application.InventoryImportRecord
	nextImportID int
	// priorityRulesets is the committed copy-on-write priority_rules store
	// (WP-4.04b / DEV-077): version -> the full P1..P4 snapshot at it. The
	// fake PriorityRuleRepo reads it (effective = MAX version) and stages
	// publishes into it on commit.
	priorityRulesets map[int][]domain.PriorityRule
	// sourceStatus is the committed source-monitor store of the DEV-110 read
	// (the fake SourceMonitorRepo returns it verbatim).
	sourceStatus []application.SourceStatusRecord
	// exports is the committed export-job store of the DEV-115 read/write
	// paths (the fake ExportRepo stages inserts into it and reads it back).
	exports []application.Export
	// retention is the committed retention state of the DEV-116 use cases: the
	// retention-run store (the report rows), the legal holds and the candidate
	// seed; notifications and priorityFactors model the dependent rows the
	// retention deletion touches (they are not modelled by any earlier fake).
	retentionRuns       []application.RetentionRun
	legalHolds          []application.LegalHold
	retentionCandidates []application.RetentionCandidate
	notifications       []application.Notification
	priorityFactors     []retentionPriorityFactor
}

func (d *fakeDB) hasSignalForMatch(matchID string) bool {
	for _, r := range d.signalRows {
		if r.sig.MatchID == matchID {
			return true
		}
	}
	return false
}

// signalRowByID resolves one committed signal row by its id (the read the
// I4 triage commands take before a guarded write).
func (d *fakeDB) signalRowByID(id string) (storedSignal, bool) {
	for _, r := range d.signalRows {
		if r.sig.ID == id {
			return r, true
		}
	}
	return storedSignal{}, false
}

// applySignalMutation replaces the committed signal row of the mutation's id
// with the mutated aggregate and its closed_at stamp — the commit effect of
// the guarded I4 signal writes (the row's created_at is preserved).
func (d *fakeDB) applySignalMutation(m storedSignal) {
	for i := range d.signalRows {
		if d.signalRows[i].sig.ID == m.sig.ID {
			d.signalRows[i].sig = m.sig
			d.signalRows[i].closedAt = m.closedAt
			return
		}
	}
}

// slaClockByKey resolves one committed clock by its natural key.
func (d *fakeDB) slaClockByKey(signalID string, target domain.SLATarget) (domain.SlaClock, bool) {
	for _, c := range d.slaClocks {
		if c.SignalID == signalID && c.Target == target {
			return c, true
		}
	}
	return domain.SlaClock{}, false
}

// applySlaClock upserts the committed clock by its natural key.
func (d *fakeDB) applySlaClock(c domain.SlaClock) {
	for i := range d.slaClocks {
		if d.slaClocks[i].SignalID == c.SignalID && d.slaClocks[i].Target == c.Target {
			d.slaClocks[i] = c
			return
		}
	}
	d.slaClocks = append(d.slaClocks, c)
}

func (d *fakeDB) vulnByCVE(cveID string) (string, bool) {
	for _, v := range d.vulns {
		if v.cveID == cveID {
			return v.id, true
		}
	}
	return "", false
}

func (d *fakeDB) evidenceID(rawID string, typ domain.EvidenceType, hash string) (string, bool) {
	for _, e := range d.evidenceRows {
		if e.rawID == rawID && e.typ == typ && e.hash == hash {
			return e.id, true
		}
	}
	return "", false
}

func (d *fakeDB) matchExists(vulnID, compID, ruleVersion string) (string, bool) {
	for _, m := range d.matchRows {
		if m.rec.VulnerabilityID == vulnID && m.rec.ComponentID == compID && m.rec.RuleVersion == ruleVersion {
			return m.id, true
		}
	}
	return "", false
}

func (d *fakeDB) rawRecordExists(sourceID, externalID, hash string) (string, bool) {
	for _, r := range d.rawRecords {
		if r.sourceID == sourceID && r.externalID == externalID && r.contentHash == hash {
			return r.id, true
		}
	}
	return "", false
}

func (d *fakeDB) outboxEventExists(dedupeKey string) bool {
	for _, ev := range d.outboxEvents {
		if ev.DedupeKey == dedupeKey {
			return true
		}
	}
	return false
}

func (d *fakeDB) rawRecordByID(id string) (storedRawRecord, bool) {
	for _, r := range d.rawRecords {
		if r.id == id {
			return r, true
		}
	}
	return storedRawRecord{}, false
}

func (d *fakeDB) sourceByID(id string) (application.SourceDescriptor, bool) {
	for _, s := range d.sources {
		if s.ID == id {
			return s, true
		}
	}
	return application.SourceDescriptor{}, false
}

func (d *fakeDB) quarantineByID(id string) (domain.Quarantine, bool) {
	for _, q := range d.quarantine {
		if q.ID == id {
			return q, true
		}
	}
	return domain.Quarantine{}, false
}

func (d *fakeDB) applyQuarantine(q domain.Quarantine) {
	for i := range d.quarantine {
		if d.quarantine[i].ID == q.ID {
			d.quarantine[i] = q
			return
		}
	}
	d.quarantine = append(d.quarantine, q)
}

func (d *fakeDB) applyCompletion(c storedRunCompletion) error {
	for i := range d.sourceRuns {
		if d.sourceRuns[i].id == c.runID {
			d.sourceRuns[i].status = string(c.status)
			d.sourceRuns[i].counters = c.counters
			d.sourceRuns[i].errText = c.errText
			d.sourceRuns[i].finishedAt = c.finishedAt
			// The cursor advances only after the commit of a successful
			// run (ch. 6.1): the fake mirrors the generated CASE guard of
			// CompleteSourceRun, which writes cursor_after on 'succeeded'
			// and forces NULL on every other terminal status.
			if c.status == application.SourceRunStatusSucceeded {
				d.sourceRuns[i].cursorAfter = c.cursorAfter
			} else {
				d.sourceRuns[i].cursorAfter = nil
			}
			return nil
		}
	}
	return errors.New("fake: source run not found for completion")
}

// ---------------------------------------------------------------------------
// fake transaction + runner

// fakeTx is one transaction: it records the write order and stages rows;
// commit publishes them into the shared database, rollback discards them.
// pgx.Tx is embedded so the fake satisfies the application.Tx alias; its
// methods are never invoked by the fakes (they stage on the struct, they do
// not run SQL) except the two the application's EPSS bulk writer issues
// directly on the transaction — Exec (the TRUNCATE) and CopyFrom (the
// COPY) — which this fake stages into epssRows (DEV-041).
type fakeTx struct {
	pgx.Tx
	db     *fakeDB
	log    []string
	staged fakeStaged

	copyErr error // armed failpoint of the EPSS COPY (flush path)

	committed  bool
	rolledBack bool
}

type fakeStaged struct {
	signals     []storedSignal
	audit       []application.AuditEvent
	outbox      []application.OutboxEvent
	vulns       []storedVuln
	evidences   []storedEvidence
	matches     []storedMatch
	rawRecords  []storedRawRecord
	runs        []storedSourceRun
	completions []storedRunCompletion
	quarantine  []domain.Quarantine
	qMutations  []domain.Quarantine
	epssRows    []storedEpssRow
	sourceHash  []sourceHashMutation
	// sourceCursor is the staged sources.cursor promotions of fetch terminal
	// commits (DEV-067): applied to the committed source descriptor at
	// commit, discarded on rollback — the cursor advances only with a
	// committed successful run.
	sourceCursor []sourceCursorMutation
	// assets is the copy-on-write overlay of the inventory commit path:
	// nil until the inventory writer first stages on the transaction, then
	// a deep clone of the committed assets the writer mutates (upserts by
	// natural key) and commit publishes wholesale. A transaction that
	// never touches inventory leaves it nil and commit leaves the
	// committed assets alone.
	assets []fakeStoredAsset
	// signalMutations are the guarded I4 signal writes (transition,
	// override, revert, owner assignment) staged on the transaction; commit
	// applies them to the committed signal rows (replace by id).
	signalMutations []storedSignal
	// comments and slaClocks are the staged I4 timeline/clock writes,
	// published on commit.
	comments  []domain.Comment
	slaClocks []domain.SlaClock
	// priorityRulesets are the staged priority-rules snapshot publishes
	// (WP-4.04b), applied to the committed store on commit.
	priorityRulesets []storedRuleset
	// importInserts and importMarks are the staged staged-import writes
	// (WP-5b.03), applied to the committed import store on commit.
	importInserts []application.InventoryImportRecord
	importMarks   []storedImportMark
	// exports is the staged export-row inserts of the DEV-115 CreateExport
	// command, published on commit (discarded on rollback).
	exports []application.Export
	// retention is the staged DEV-116 retention state: the run-row inserts and
	// lifecycle updates, the legal-hold inserts/releases, the in-place
	// redactions and the referentially-safe deletions. Commit applies them to
	// the committed retention state, rollback discards them.
	retentionRunInserts []application.RetentionRun
	retentionRunUpdates []application.RetentionRun
	holdInserts         []application.LegalHold
	holdReleases        []retentionHoldRelease
	redactions          []retentionRedaction
	deletions           []retentionDeletion
}

// storedImportMark is one staged staged-import commit-mark (WP-5b.03).
type storedImportMark struct {
	id     string
	counts application.InventoryImportCounts
	now    time.Time
}

// storedRuleset is one staged priority-rules snapshot publish.
type storedRuleset struct {
	version int
	rules   []domain.PriorityRule
}

func (t *fakeTx) record(op string) { t.log = append(t.log, op) }

func (t *fakeTx) commit() {
	if t.staged.assets != nil {
		t.db.assets = t.staged.assets
	}
	t.db.signalRows = append(t.db.signalRows, t.staged.signals...)
	t.db.auditEvents = append(t.db.auditEvents, t.staged.audit...)
	t.db.outboxEvents = append(t.db.outboxEvents, t.staged.outbox...)
	t.db.vulns = append(t.db.vulns, t.staged.vulns...)
	t.db.evidenceRows = append(t.db.evidenceRows, t.staged.evidences...)
	t.db.matchRows = append(t.db.matchRows, t.staged.matches...)
	t.db.rawRecords = append(t.db.rawRecords, t.staged.rawRecords...)
	t.db.sourceRuns = append(t.db.sourceRuns, t.staged.runs...)
	t.db.epssRows = append(t.db.epssRows, t.staged.epssRows...)
	for _, m := range t.staged.sourceHash {
		for i := range t.db.sources {
			if t.db.sources[i].ID != m.sourceID {
				continue
			}
			if t.db.sources[i].Config == nil {
				t.db.sources[i].Config = make(map[string]any)
			}
			t.db.sources[i].Config["last_content_hash"] = m.contentHash
		}
	}
	for _, m := range t.staged.sourceCursor {
		for i := range t.db.sources {
			if t.db.sources[i].ID == m.sourceID {
				t.db.sources[i].Cursor = m.cursor
			}
		}
	}
	for _, q := range t.staged.quarantine {
		t.db.applyQuarantine(q)
	}
	for _, q := range t.staged.qMutations {
		t.db.applyQuarantine(q)
	}
	for _, c := range t.staged.completions {
		if err := t.db.applyCompletion(c); err != nil {
			panic(err) // a completion of a missing run is a test bug
		}
	}
	for _, m := range t.staged.signalMutations {
		t.db.applySignalMutation(m)
	}
	t.db.comments = append(t.db.comments, t.staged.comments...)
	for _, c := range t.staged.slaClocks {
		t.db.applySlaClock(c)
	}
	if len(t.staged.priorityRulesets) > 0 && t.db.priorityRulesets == nil {
		t.db.priorityRulesets = make(map[int][]domain.PriorityRule)
	}
	for _, s := range t.staged.priorityRulesets {
		t.db.priorityRulesets[s.version] = s.rules
	}
	t.db.imports = append(t.db.imports, t.staged.importInserts...)
	t.db.exports = append(t.db.exports, t.staged.exports...)
	t.db.retentionRuns = append(t.db.retentionRuns, t.staged.retentionRunInserts...)
	for _, r := range t.staged.retentionRunUpdates {
		t.db.applyRetentionRun(r)
	}
	t.db.legalHolds = append(t.db.legalHolds, t.staged.holdInserts...)
	for _, rel := range t.staged.holdReleases {
		t.db.applyHoldRelease(rel)
	}
	for _, red := range t.staged.redactions {
		t.db.applyRetentionRedaction(red)
	}
	for _, del := range t.staged.deletions {
		t.db.applyRetentionDeletion(del)
	}
	for _, m := range t.staged.importMarks {
		for i := range t.db.imports {
			if t.db.imports[i].ID != m.id {
				continue
			}
			t.db.imports[i].Status = application.InventoryImportCommitted
			t.db.imports[i].CommittedAt = m.now
			t.db.imports[i].AssetsCreated = m.counts.AssetsCreated
			t.db.imports[i].AssetsUpdated = m.counts.AssetsUpdated
			t.db.imports[i].ComponentsCreated = m.counts.ComponentsCreated
			t.db.imports[i].ComponentsUpdated = m.counts.ComponentsUpdated
		}
	}
	t.committed = true
}

func (t *fakeTx) rollback() {
	t.rolledBack = true
	t.staged = fakeStaged{}
}

// Exec implements the one statement class the application issues directly
// on a transaction: the EPSS bulk writer's TRUNCATE epss_current (DEV-041
// — every other write travels through the repository fakes and their
// staging). An unexpected statement is a test bug.
func (t *fakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "TRUNCATE") && strings.Contains(sql, "epss_current") {
		t.record("epss.truncate")
		return pgconn.NewCommandTag("TRUNCATE TABLE"), nil
	}
	return pgconn.CommandTag{}, fmt.Errorf("fake: unexpected Exec statement %q", sql)
}

// CopyFrom implements the application's EPSS bulk COPY on the fake
// transaction: the row source is drained into the staged epss_current rows
// (the bulk writer sends cve ids as strings, the COPY-ready numerics, the
// model_version and the loaded_at instant — the exact tuple of the real
// COPY). The armed copyErr failpoint makes the COPY fail like a real
// infrastructure failure of the flush path.
func (t *fakeTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	if t.copyErr != nil {
		return 0, t.copyErr
	}
	t.record("epss.copy")
	var n int64
	for rowSrc.Next() {
		values, err := rowSrc.Values()
		if err != nil {
			return n, err
		}
		t.staged.epssRows = append(t.staged.epssRows, storedEpssRow{
			cveID:        values[0].(string),
			score:        values[1].(pgtype.Numeric),
			percentile:   values[2].(pgtype.Numeric),
			modelVersion: values[3].(string),
			loadedAt:     values[4].(time.Time),
		})
		n++
	}
	return n, rowSrc.Err()
}

// fakeTxRunner plays postgres.WithTx: commit on nil, rollback and the
// original error (unwrapped) otherwise. Every transaction it opens stays
// observable for assertions (write order, commit/rollback state).
type fakeTxRunner struct {
	db      *fakeDB
	txs     []*fakeTx
	copyErr error // armed on every opened transaction (EPSS flush fault seam)
}

func (r *fakeTxRunner) Run(ctx context.Context, fn func(tx application.Tx) error) error {
	ftx := &fakeTx{db: r.db, copyErr: r.copyErr}
	r.txs = append(r.txs, ftx)
	if err := fn(ftx); err != nil {
		ftx.rollback()
		return err
	}
	ftx.commit()
	return nil
}

func (r *fakeTxRunner) last() *fakeTx {
	if len(r.txs) == 0 {
		return nil
	}
	return r.txs[len(r.txs)-1]
}

func fakeTxOf(tx application.Tx) (*fakeTx, error) {
	ftx, ok := tx.(*fakeTx)
	if !ok {
		return nil, application.InfraError("fake", errors.New("unexpected transaction type"))
	}
	return ftx, nil
}

// ---------------------------------------------------------------------------
// fake repositories

type fakeSignalRepo struct{ db *fakeDB }

func (f *fakeSignalRepo) Create(ctx context.Context, tx application.Tx, rec application.SignalRecord, createdAt time.Time) (domain.RiskSignal, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal")
	if f.db.hasSignalForMatch(rec.MatchID) {
		return domain.RiskSignal{}, application.ConflictError("create_signal", fmt.Errorf("signal already exists for match %s", rec.MatchID))
	}
	sig := domain.RiskSignal{
		ID:          uuid.New(),
		MatchID:     rec.MatchID,
		Priority:    rec.Priority,
		Status:      domain.SignalStatusNew,
		Version:     1,
		RuleVersion: rec.RuleVersion,
		Factors:     rec.Factors,
	}
	ftx.staged.signals = append(ftx.staged.signals, storedSignal{sig: sig, createdAt: createdAt})
	return sig, nil
}

func (f *fakeSignalRepo) GetByID(ctx context.Context, id string) (application.Signal, error) {
	for _, s := range f.db.signalViews {
		if s.ID == id {
			return s, nil
		}
	}
	return application.Signal{}, application.NotFoundError("get_signal", fmt.Errorf("signal %s not found", id))
}

// priorityRank mirrors the SQL ORDER BY of ListSignals (P1→P4 text order).
func priorityRank(p domain.Priority) int {
	switch p {
	case domain.PriorityP1:
		return 0
	case domain.PriorityP2:
		return 1
	case domain.PriorityP3:
		return 2
	case domain.PriorityP4:
		return 3
	}
	return 99
}

func (f *fakeSignalRepo) List(ctx context.Context, filter application.SignalFilter, limit, offset int) ([]application.Signal, error) {
	var rows []application.Signal
	for _, s := range f.db.signalViews {
		if filter.Priority != nil && s.Priority != *filter.Priority {
			continue
		}
		if filter.Status != nil && s.Status != *filter.Status {
			continue
		}
		if filter.OwnerID != nil && s.Owner != *filter.OwnerID {
			continue
		}
		rows = append(rows, s)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		pi, pj := priorityRank(rows[i].Priority), priorityRank(rows[j].Priority)
		if pi != pj {
			return pi < pj
		}
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.Before(rows[j].CreatedAt)
		}
		return rows[i].ID < rows[j].ID
	})
	if offset >= len(rows) {
		return []application.Signal{}, nil
	}
	rows = rows[offset:]
	if len(rows) > limit+1 {
		rows = rows[:limit+1]
	}
	return rows, nil
}

func (f *fakeSignalRepo) ExistsByMatchID(ctx context.Context, matchID string) (bool, error) {
	return f.db.hasSignalForMatch(matchID), nil
}

// fakeUserRepo is the in-memory application.UserRepo of the I5a authorizer
// tests (WP-5a.06): users.id → UserIdentity plus users.id → roles. An id
// absent from the user map is a not-found error (resolvePrincipal denies it).
type fakeUserRepo struct {
	byID  map[string]application.UserIdentity
	roles map[string][]domain.Role
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		byID:  map[string]application.UserIdentity{},
		roles: map[string][]domain.Role{},
	}
}

// add registers one user with the given roles (an empty role list is a
// role-less user — deny-by-default on everything). The issuer-qualified
// subject defaults to the id so a test can resolve the principal by either.
func (f *fakeUserRepo) add(id, displayName string, roles ...domain.Role) {
	f.byID[id] = application.UserIdentity{ID: id, SubjectID: id, DisplayName: displayName}
	f.roles[id] = roles
}

// addWithSubject registers one user with an explicit issuer-qualified
// subject_id (the login key the reveal endpoint / CLI resolve on).
func (f *fakeUserRepo) addWithSubject(id, subjectID, displayName string, roles ...domain.Role) {
	f.byID[id] = application.UserIdentity{ID: id, SubjectID: subjectID, DisplayName: displayName}
	f.roles[id] = roles
}

// deactivate marks a registered user deactivated at instant (the authorizer
// denies it while it still resolves in the audit trail).
func (f *fakeUserRepo) deactivate(id string, at time.Time) {
	u := f.byID[id]
	u.DeactivatedAt = at
	f.byID[id] = u
}

func (f *fakeUserRepo) GetUserByID(ctx context.Context, id string) (application.UserIdentity, error) {
	u, ok := f.byID[id]
	if !ok {
		return application.UserIdentity{}, application.NotFoundError("user.get_by_id", fmt.Errorf("user %s not found", id))
	}
	return u, nil
}

func (f *fakeUserRepo) RolesByUserID(ctx context.Context, userID string) ([]domain.Role, error) {
	return f.roles[userID], nil
}

// GetUserBySubject implements application.UserRepo: the subject_id → user
// resolution (ARCH-005 §2). An unknown subject is a not-found error.
func (f *fakeUserRepo) GetUserBySubject(ctx context.Context, subjectID string) (application.UserIdentity, error) {
	for _, u := range f.byID {
		if u.SubjectID == subjectID {
			return u, nil
		}
	}
	return application.UserIdentity{}, application.NotFoundError("user.get_by_subject", fmt.Errorf("user with subject %s not found", subjectID))
}

var _ application.UserRepo = (*fakeUserRepo)(nil)

type fakeAuditRepo struct {
	db *fakeDB
	// failpoint, when set, makes Append fail after recording the write.
	failpoint error
}

func (f *fakeAuditRepo) Append(ctx context.Context, tx application.Tx, ev application.AuditEvent) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("audit")
	if f.failpoint != nil {
		return f.failpoint
	}
	if ev.ID == "" {
		// Mirror the gen_random_uuid() column default: the stored row carries
		// a database-assigned id, so the read path (GetByID) can resolve it.
		ev.ID = uuid.New()
	}
	ftx.staged.audit = append(ftx.staged.audit, ev)
	return nil
}

// GetEventByID implements application.AuditRepo: the load step of the
// governed audit.reveal_identity act. It reads the committed audit store
// (the real read runs pool-scoped, outside any transaction); a missing id is
// a not-found error.
func (f *fakeAuditRepo) GetEventByID(ctx context.Context, id string) (application.AuditEvent, error) {
	for _, ev := range f.db.auditEvents {
		if ev.ID == id {
			return ev, nil
		}
	}
	return application.AuditEvent{}, application.NotFoundError("audit.get_by_id", fmt.Errorf("audit event %s not found", id))
}

// ListByAggregate implements application.AuditRepo: the signal-detail audit
// timeline read (DEV-110). It filters the committed audit store by aggregate
// type + id and orders by occurred_at then id — the real read's contract. An
// aggregate with no event yields an empty slice, never an error.
func (f *fakeAuditRepo) ListByAggregate(_ context.Context, aggregateType, aggregateID string) ([]application.AuditEvent, error) {
	out := make([]application.AuditEvent, 0, len(f.db.auditEvents))
	for _, ev := range f.db.auditEvents {
		if ev.AggregateType == aggregateType && ev.AggregateID == aggregateID {
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

var _ application.AuditRepo = (*fakeAuditRepo)(nil)

type fakeOutboxRepo struct {
	db *fakeDB
	// failpoint is the ARCH-001 §5 seam: when set, Append records the write
	// and then fails — simulating an outbox write error after the signal
	// and audit writes of the same transaction succeeded.
	failpoint error
}

func (f *fakeOutboxRepo) Append(ctx context.Context, tx application.Tx, ev application.OutboxEvent) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("outbox")
	// The UQ (dedupe_key) spans the row's whole lifetime (ADR-012): a row
	// with the same dedupe key — committed earlier or staged by this very
	// transaction — makes the append a unique violation, exactly as the
	// schema raises it. The enqueue use cases of the source jobs rely on
	// this idempotency backstop (the scheduler re-enqueues every cycle;
	// the outbox dedupes).
	if f.db.outboxEventExists(ev.DedupeKey) || f.stagedOutboxEventExists(ftx, ev.DedupeKey) {
		return application.ConflictError("outbox.append", fmt.Errorf("outbox row with dedupe key %q already exists", ev.DedupeKey))
	}
	if f.failpoint != nil {
		return f.failpoint
	}
	ftx.staged.outbox = append(ftx.staged.outbox, ev)
	return nil
}

// ExistsDedupeKey implements application.OutboxRepo on the fake store: the
// pre-check of the exactly-once enqueuers — the key exists when the
// committed store or the transaction's own staged rows already carry it
// (mirroring the same-transaction visibility of the real EXISTS).
func (f *fakeOutboxRepo) ExistsDedupeKey(ctx context.Context, tx application.Tx, dedupeKey string) (bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return false, err
	}
	return f.db.outboxEventExists(dedupeKey) || f.stagedOutboxEventExists(ftx, dedupeKey), nil
}

// stagedOutboxEventExists reports whether the transaction already staged an
// outbox row with the dedupe key (the transaction's own uncommitted writes
// are visible to itself, mirroring the unique index of the real schema).
func (f *fakeOutboxRepo) stagedOutboxEventExists(ftx *fakeTx, dedupeKey string) bool {
	for _, ev := range ftx.staged.outbox {
		if ev.DedupeKey == dedupeKey {
			return true
		}
	}
	return false
}

type fakeVulnerabilityRepo struct {
	db *fakeDB
	// failEvidence is the ARCH-002 §6 sink fault point: when set,
	// AddEvidence records the write and then fails mid-pass, so the
	// normalise transaction rolls back with nothing partially committed.
	failEvidence error
}

func (f *fakeVulnerabilityRepo) Upsert(ctx context.Context, tx application.Tx, rec application.VulnerabilityRecord, publishedAt, modifiedAt time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("vuln")
	if id, ok := f.db.vulnByCVE(rec.CVEID); ok {
		return id, nil
	}
	id := uuid.New()
	ftx.staged.vulns = append(ftx.staged.vulns, storedVuln{id: id, cveID: rec.CVEID, summary: rec.Summary})
	return id, nil
}

// AddEvidence mirrors application.VulnerabilityRepo: stage one immutable
// evidence row (or resolve the already staged/committed one of the same
// natural key (raw_record_id, type, value_hash)) and return its id — the
// new-or-existing evidence id of the real RETURNING statement (ARCH-003
// §7). The transaction's own uncommitted writes are visible to itself
// (like stagedOutboxEventExists): two identical statements inside one
// transaction resolve to the same staged row, mirroring the unique index
// of the real schema.
func (f *fakeVulnerabilityRepo) AddEvidence(ctx context.Context, tx application.Tx, ev application.EvidenceRecord, observedAt time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("evidence")
	if f.failEvidence != nil {
		return "", f.failEvidence
	}
	for _, staged := range ftx.staged.evidences {
		if staged.rawID == ev.RawRecordID && staged.typ == ev.Type && staged.hash == ev.ValueHash {
			return staged.id, nil
		}
	}
	if id, ok := f.db.evidenceID(ev.RawRecordID, ev.Type, ev.ValueHash); ok {
		return id, nil // ON CONFLICT DO NOTHING
	}
	id := uuid.New()
	ftx.staged.evidences = append(ftx.staged.evidences, storedEvidence{
		id: id, vulnID: ev.VulnerabilityID, rawID: ev.RawRecordID, typ: ev.Type,
		value: ev.Value, hash: ev.ValueHash, observedAt: observedAt,
	})
	return id, nil
}

type fakeMatchRepo struct{ db *fakeDB }

func (f *fakeMatchRepo) Insert(ctx context.Context, tx application.Tx, rec application.MatchRecord, createdAt time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("match")
	if id, ok := f.db.matchExists(rec.VulnerabilityID, rec.ComponentID, rec.RuleVersion); ok {
		return id, nil
	}
	id := uuid.New()
	ftx.staged.matches = append(ftx.staged.matches, storedMatch{id: id, rec: rec, createdAt: createdAt})
	return id, nil
}

type fakeSourceRunRepo struct{ db *fakeDB }

func (f *fakeSourceRunRepo) Open(ctx context.Context, tx application.Tx, sourceID string, cursorBefore json.RawMessage, startedAt time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("run.open")
	id := uuid.New()
	ftx.staged.runs = append(ftx.staged.runs, storedSourceRun{
		id: id, sourceID: sourceID, status: "running", cursorBefore: cursorBefore, startedAt: startedAt,
	})
	return id, nil
}

func (f *fakeSourceRunRepo) Complete(ctx context.Context, tx application.Tx, runID string, status application.SourceRunStatus, counters application.SourceRunCounters, cursorAfter json.RawMessage, errText string, finishedAt time.Time) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("run.complete")
	ftx.staged.completions = append(ftx.staged.completions, storedRunCompletion{
		runID: runID, status: status, counters: counters, cursorAfter: cursorAfter, errText: errText, finishedAt: finishedAt,
	})
	return nil
}

type fakeRawRecordRepo struct{ db *fakeDB }

func (f *fakeRawRecordRepo) Insert(ctx context.Context, tx application.Tx, sourceID, externalID string, payload []byte, contentHash, contentEncoding string, fetchedAt time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("raw")
	if id, ok := f.db.rawRecordExists(sourceID, externalID, contentHash); ok {
		return id, nil // ON CONFLICT DO NOTHING: identical earlier ingest
	}
	id := uuid.New()
	ftx.staged.rawRecords = append(ftx.staged.rawRecords, storedRawRecord{
		id: id, sourceID: sourceID, externalID: externalID, contentHash: contentHash,
		payload: payload, contentEncoding: contentEncoding, fetchedAt: fetchedAt,
	})
	return id, nil
}

func (f *fakeRawRecordRepo) GetByID(ctx context.Context, id string) (application.RawRecord, error) {
	row, ok := f.db.rawRecordByID(id)
	if !ok {
		return application.RawRecord{}, application.NotFoundError("raw_record.get_by_id", fmt.Errorf("raw record %s not found", id))
	}
	return application.RawRecord{
		ID: row.id, SourceID: row.sourceID, ExternalID: row.externalID,
		ContentHash: row.contentHash, Payload: row.payload, ContentEncoding: row.contentEncoding,
		FetchedAt: row.fetchedAt,
	}, nil
}

// PreviousKEVCVEs implements application.RawRecordRepo on the fake store,
// mirroring the generated ListPreviousKEVCVEs statement: the kev evidence
// cve ids of the source's latest stored raw record other than the pass's
// own, ordered by fetched_at then id (descending), deduplicated and
// sorted. A source without a prior raw record yields nil.
func (f *fakeRawRecordRepo) PreviousKEVCVEs(ctx context.Context, sourceID, excludeRawRecordID string) ([]string, error) {
	var latest *storedRawRecord
	for i := range f.db.rawRecords {
		r := &f.db.rawRecords[i]
		if r.sourceID != sourceID || r.id == excludeRawRecordID {
			continue
		}
		if latest == nil || r.fetchedAt.After(latest.fetchedAt) ||
			(r.fetchedAt.Equal(latest.fetchedAt) && r.id > latest.id) {
			latest = r
		}
	}
	if latest == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	var cves []string
	for _, e := range f.db.evidenceRows {
		if e.rawID != latest.id || e.typ != domain.EvidenceTypeKEV {
			continue
		}
		var v struct {
			CveID string `json:"cve_id"`
		}
		if err := json.Unmarshal(e.value, &v); err != nil || v.CveID == "" {
			continue
		}
		if !seen[v.CveID] {
			seen[v.CveID] = true
			cves = append(cves, v.CveID)
		}
	}
	sort.Strings(cves)
	return cves, nil
}

type fakeSourceRepo struct{ db *fakeDB }

func (f *fakeSourceRepo) GetByID(ctx context.Context, id string) (application.SourceDescriptor, error) {
	desc, ok := f.db.sourceByID(id)
	if !ok {
		return application.SourceDescriptor{}, application.NotFoundError("source.get_by_id", fmt.Errorf("source %s not found", id))
	}
	return desc, nil
}

// SetLastContentHash implements application.SourceRepo on the fake store:
// the update is staged on the transaction and merged into the committed
// source descriptor's config at commit (mirroring the jsonb merge of the
// generated statement — other config members stay intact).
func (f *fakeSourceRepo) SetLastContentHash(ctx context.Context, tx application.Tx, sourceID, contentHash string) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("source.hash")
	ftx.staged.sourceHash = append(ftx.staged.sourceHash, sourceHashMutation{sourceID: sourceID, contentHash: contentHash})
	return nil
}

// SetCursor implements application.SourceRepo on the fake store: the
// promotion is staged on the transaction and applied to the committed
// source descriptor's cursor at commit (mirroring the generated UPDATE of
// SetSourceCursor — the cursor advances only with the run's terminal
// commit).
func (f *fakeSourceRepo) SetCursor(ctx context.Context, tx application.Tx, sourceID string, cursor json.RawMessage) error {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return err
	}
	ftx.record("source.cursor")
	ftx.staged.sourceCursor = append(ftx.staged.sourceCursor, sourceCursorMutation{sourceID: sourceID, cursor: cursor})
	return nil
}

// ListEnabledScheduled implements application.SourceRepo on the fake store:
// the scheduler scan reads the seeded enabled scheduled rows (ARCH-002 §5).
func (f *fakeSourceRepo) ListEnabledScheduled(ctx context.Context) ([]application.ScheduledSource, error) {
	return append([]application.ScheduledSource(nil), f.db.scheduled...), nil
}

type fakeQuarantineRepo struct {
	db *fakeDB
	// failInsert is a sink fault point on the RecordError isolation write.
	failInsert error
}

func (f *fakeQuarantineRepo) Insert(ctx context.Context, tx application.Tx, sourceID, sourceRunID, rawRecordID, position, reason, payloadHash string, now time.Time) (string, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return "", err
	}
	ftx.record("quarantine.insert")
	if f.failInsert != nil {
		return "", f.failInsert
	}
	q, err := domain.NewQuarantine(uuid.New(), sourceID, sourceRunID, rawRecordID, position, reason, payloadHash)
	if err != nil {
		return "", application.ValidationError("quarantine.insert", err)
	}
	ftx.staged.quarantine = append(ftx.staged.quarantine, q)
	return q.ID, nil
}

func (f *fakeQuarantineRepo) GetByID(ctx context.Context, id string) (domain.Quarantine, error) {
	q, ok := f.db.quarantineByID(id)
	if !ok {
		return domain.Quarantine{}, application.NotFoundError("quarantine.get_by_id", fmt.Errorf("quarantine %s not found", id))
	}
	return q, nil
}

func (f *fakeQuarantineRepo) List(ctx context.Context, status *domain.QuarantineStatus, sourceID string, limit int) ([]domain.Quarantine, error) {
	if limit < 1 {
		return nil, application.Validationf("quarantine.list", "limit %d must be >= 1", limit)
	}
	var rows []domain.Quarantine
	for _, q := range f.db.quarantine {
		if status != nil && q.Status != *status {
			continue
		}
		if sourceID != "" && q.SourceID != sourceID {
			continue
		}
		rows = append(rows, q)
	}
	// committed rows are appended in created order; creation time is
	// monotonic in the fakes, so insertion order is the SQL ordering.
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (f *fakeQuarantineRepo) mutate(ctx context.Context, tx application.Tx, id string, want []domain.QuarantineStatus, fn func(domain.Quarantine) domain.Quarantine) (domain.Quarantine, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.Quarantine{}, err
	}
	// Intra-transaction visibility: an earlier mutation of this row in the
	// same transaction is the base state the next guarded transition sees —
	// exactly as the real guarded UPDATE sees its own uncommitted writes.
	base, ok := f.db.quarantineByID(id)
	if !ok {
		// Mirrors the guarded UPDATE ... RETURNING of the generated
		// statements: a row that is not there matches zero rows.
		return domain.Quarantine{}, application.ConflictError("quarantine.transition", fmt.Errorf("no row for id %s", id))
	}
	for _, m := range ftx.staged.qMutations {
		if m.ID == id {
			base = m
		}
	}
	allowed := false
	for _, s := range want {
		if base.Status == s {
			allowed = true
			break
		}
	}
	if !allowed {
		return domain.Quarantine{}, application.ConflictError("quarantine.transition", fmt.Errorf("quarantine %s is %s; transition wants one of %v", id, base.Status, want))
	}
	next := fn(base)
	ftx.staged.qMutations = append(ftx.staged.qMutations, next)
	return next, nil
}

func (f *fakeQuarantineRepo) Acknowledge(ctx context.Context, tx application.Tx, id, acknowledgedBy, note string, now time.Time) (domain.Quarantine, error) {
	return f.mutate(ctx, tx, id, []domain.QuarantineStatus{domain.QuarantineStatusNew}, func(q domain.Quarantine) domain.Quarantine {
		next, err := q.Acknowledge(acknowledgedBy, note)
		if err != nil {
			panic(err) // guarded above; a mismatch is a fake bug
		}
		return next
	})
}

func (f *fakeQuarantineRepo) MarkReadyForRetry(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	return f.mutate(ctx, tx, id, []domain.QuarantineStatus{domain.QuarantineStatusNew, domain.QuarantineStatusAcknowledged}, func(q domain.Quarantine) domain.Quarantine {
		next, err := q.MarkReadyForRetry()
		if err != nil {
			panic(err)
		}
		return next
	})
}

func (f *fakeQuarantineRepo) MarkResolved(ctx context.Context, tx application.Tx, id, resolvedVulnerabilityID, resolvedEvidenceID, note string, now time.Time) (domain.Quarantine, error) {
	return f.mutate(ctx, tx, id, []domain.QuarantineStatus{domain.QuarantineStatusReadyForRetry, domain.QuarantineStatusNew}, func(q domain.Quarantine) domain.Quarantine {
		next, err := q.ReprocessSucceeded(resolvedVulnerabilityID, resolvedEvidenceID, note)
		if err != nil {
			panic(err)
		}
		return next
	})
}

func (f *fakeQuarantineRepo) IncrementAttempts(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	return f.mutate(ctx, tx, id, []domain.QuarantineStatus{domain.QuarantineStatusNew, domain.QuarantineStatusReadyForRetry}, func(q domain.Quarantine) domain.Quarantine {
		next, err := q.ReprocessFailed()
		if err != nil {
			panic(err)
		}
		return next
	})
}

type fakeComponentRepo struct{ db *fakeDB }

func (f *fakeComponentRepo) ListByVendorProduct(ctx context.Context, vendor, product string) ([]application.Component, error) {
	var out []application.Component
	for _, c := range f.db.components {
		if c.Vendor == vendor && c.Product == product {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// ---------------------------------------------------------------------------
// I4 triage/SLA fakes (ARCH-004 §2/§3/§4)

// fakeSignalTriageRepo is the in-memory application.SignalTriageRepo. Writes
// are guarded on the optimistic-lock version exactly as the DEV-073 adapter:
// a stale expectedVersion (or a missing row) is a conflict Error and nothing
// is staged. Staged mutations are visible to a later method of the same
// transaction (intra-transaction visibility) and are applied to the committed
// rows on commit.
type fakeSignalTriageRepo struct{ db *fakeDB }

// resolve returns the base signal of a guarded write: the transaction's own
// staged mutation when one exists, otherwise the committed row.
func (f *fakeSignalTriageRepo) resolve(ftx *fakeTx, id string) (domain.RiskSignal, bool) {
	for i := len(ftx.staged.signalMutations) - 1; i >= 0; i-- {
		if ftx.staged.signalMutations[i].sig.ID == id {
			return ftx.staged.signalMutations[i].sig, true
		}
	}
	row, ok := f.db.signalRowByID(id)
	if !ok {
		return domain.RiskSignal{}, false
	}
	return row.sig, true
}

func (f *fakeSignalTriageRepo) GetRiskSignal(ctx context.Context, id string) (domain.RiskSignal, error) {
	row, ok := f.db.signalRowByID(id)
	if !ok {
		return domain.RiskSignal{}, application.NotFoundError("signals.get_risk_signal", fmt.Errorf("signal %s not found", id))
	}
	return row.sig, nil
}

// guarded returns the committed/staged base of a guarded write after the
// optimistic-lock check, mirroring guardedSignalError: a missing row or a
// stale version is a conflict.
func (f *fakeSignalTriageRepo) guarded(ftx *fakeTx, op, id string, expectedVersion int) (domain.RiskSignal, error) {
	base, ok := f.resolve(ftx, id)
	if !ok || base.Version != expectedVersion {
		return domain.RiskSignal{}, application.ConflictError(op, fmt.Errorf("signal %s: stale version (optimistic lock failed)", id))
	}
	return base, nil
}

func (f *fakeSignalTriageRepo) Transition(ctx context.Context, tx application.Tx, id string, to domain.SignalStatus, closedAt *time.Time, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.transition"
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal.transition")
	base, err := f.guarded(ftx, op, id, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	next := base
	next.Status = to
	next.Version = base.Version + 1
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next, closedAt: closedAt})
	return next, nil
}

func (f *fakeSignalTriageRepo) OverridePriority(ctx context.Context, tx application.Tx, id string, priority, autoPriority domain.Priority, reason, actorID string, at time.Time, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.override_priority"
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal.override")
	base, err := f.guarded(ftx, op, id, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	auto := autoPriority
	next := base
	next.Priority = priority
	next.AutoPriority = &auto
	next.OverrideReason = reason
	next.OverrideActorID = actorID
	next.OverrideAt = at
	next.Version = base.Version + 1
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next})
	return next, nil
}

func (f *fakeSignalTriageRepo) RevertPriority(ctx context.Context, tx application.Tx, id string, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.revert_priority"
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal.revert")
	base, err := f.guarded(ftx, op, id, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	if base.AutoPriority == nil {
		return domain.RiskSignal{}, application.ConflictError(op, fmt.Errorf("signal %s has no override to revert", id))
	}
	next := base
	next.Priority = *base.AutoPriority
	next.AutoPriority = nil
	next.OverrideReason = ""
	next.OverrideActorID = ""
	next.OverrideAt = time.Time{}
	next.Version = base.Version + 1
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next})
	return next, nil
}

func (f *fakeSignalTriageRepo) AssignOwner(ctx context.Context, tx application.Tx, id, owner string, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.assign_owner"
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal.owner")
	base, err := f.guarded(ftx, op, id, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	next := base
	next.Owner = owner
	next.Version = base.Version + 1
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next})
	return next, nil
}

// RecomputePriority mirrors the DEV-077 adapter: it applies the
// override-survival mirror of ARCH-004 §5 in memory and stages the updated
// row. It is not version-guarded (the command's changed-only comparison
// keeps an identical recompute from reaching it); a missing row is not-found.
func (f *fakeSignalTriageRepo) RecomputePriority(ctx context.Context, tx application.Tx, id string, priority domain.Priority, ruleVersion string, factors domain.PriorityFactors) (domain.RiskSignal, error) {
	const op = "signals.recompute_priority"
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	ftx.record("signal.recompute")
	base, ok := f.resolve(ftx, id)
	if !ok {
		return domain.RiskSignal{}, application.NotFoundError(op, fmt.Errorf("signal %s not found", id))
	}
	var closedAt *time.Time
	if row, ok := f.db.signalRowByID(id); ok {
		closedAt = row.closedAt
	}
	next := base
	if base.AutoPriority == nil {
		next.Priority = priority
	} else {
		auto := priority
		next.AutoPriority = &auto
	}
	next.RuleVersion = ruleVersion
	next.Factors = factors
	next.Version = base.Version + 1
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next, closedAt: closedAt})
	return next, nil
}

// MarkEscalated mirrors the DEV-073 adapter's set-once write (ARCH-004 §4.4):
// the first call on a non-escalated signal stamps EscalatedAt and reports
// true; a later call (already escalated, or a missing row) reports false and
// stages nothing.
func (f *fakeSignalTriageRepo) MarkEscalated(ctx context.Context, tx application.Tx, id string, at time.Time) (bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return false, err
	}
	ftx.record("signal.escalate")
	base, ok := f.resolve(ftx, id)
	if !ok || !base.EscalatedAt.IsZero() {
		return false, nil
	}
	next := base
	next.EscalatedAt = at
	next.Version = base.Version + 1
	var closedAt *time.Time
	if row, ok := f.db.signalRowByID(id); ok {
		closedAt = row.closedAt
	}
	ftx.staged.signalMutations = append(ftx.staged.signalMutations, storedSignal{sig: next, closedAt: closedAt})
	return true, nil
}

// OpenRecomputeTargets returns the committed open (non-closed) signals' ids
// and stored factor-sets, ascending by id — the ruleset-publish fan-in read.
func (f *fakeSignalTriageRepo) OpenRecomputeTargets(ctx context.Context) ([]application.PriorityRecomputeTarget, error) {
	var out []application.PriorityRecomputeTarget
	for _, row := range f.db.signalRows {
		if row.sig.Status.IsClosed() {
			continue
		}
		out = append(out, application.PriorityRecomputeTarget{SignalID: row.sig.ID, Factors: row.sig.Factors})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SignalID < out[j].SignalID })
	return out, nil
}

// RecomputeTargetsByVulnerabilityIDs returns the ids and stored factor-sets of
// the committed signals whose match references one of the given vulnerability
// row ids, ascending by id — the matching.recompute fan-in read.
func (f *fakeSignalTriageRepo) RecomputeTargetsByVulnerabilityIDs(ctx context.Context, vulnerabilityIDs []string) ([]application.PriorityRecomputeTarget, error) {
	vulnSet := make(map[string]struct{}, len(vulnerabilityIDs))
	for _, id := range vulnerabilityIDs {
		vulnSet[id] = struct{}{}
	}
	matchSet := make(map[string]struct{})
	for _, m := range f.db.matchRows {
		if _, ok := vulnSet[m.rec.VulnerabilityID]; ok {
			matchSet[m.id] = struct{}{}
		}
	}
	var out []application.PriorityRecomputeTarget
	for _, row := range f.db.signalRows {
		if _, ok := matchSet[row.sig.MatchID]; !ok {
			continue
		}
		out = append(out, application.PriorityRecomputeTarget{SignalID: row.sig.ID, Factors: row.sig.Factors})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SignalID < out[j].SignalID })
	return out, nil
}

// fakeCommentRepo is the in-memory application.CommentRepo: append-only, the
// committed timeline read back in insertion order.
type fakeCommentRepo struct{ db *fakeDB }

func (f *fakeCommentRepo) Add(ctx context.Context, tx application.Tx, signalID, actorID, body string, createdAt time.Time) (domain.Comment, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.Comment{}, err
	}
	ftx.record("comment")
	c, err := domain.NewComment(uuid.New(), signalID, actorID, body)
	if err != nil {
		return domain.Comment{}, application.ValidationError("comments.add", err)
	}
	ftx.staged.comments = append(ftx.staged.comments, c)
	return c, nil
}

func (f *fakeCommentRepo) ListBySignal(ctx context.Context, signalID string) ([]domain.Comment, error) {
	var out []domain.Comment
	for _, c := range f.db.comments {
		if c.SignalID == signalID {
			out = append(out, c)
		}
	}
	return out, nil
}

// fakeSlaClockRepo is the in-memory application.SlaClockRepo. Its guarded
// writes apply the domain preconditions (domain.SlaClock.Pause/Resume/…)
// exactly as the DEV-073 SQL guards do and stage the updated clock.
type fakeSlaClockRepo struct {
	db  *fakeDB
	clk clock.Clock // the injected clock the Due breach scan reads (nil → fixedNow)
}

func (f *fakeSlaClockRepo) resolve(ftx *fakeTx, signalID string, target domain.SLATarget) (domain.SlaClock, bool) {
	for i := len(ftx.staged.slaClocks) - 1; i >= 0; i-- {
		if ftx.staged.slaClocks[i].SignalID == signalID && ftx.staged.slaClocks[i].Target == target {
			return ftx.staged.slaClocks[i], true
		}
	}
	return f.db.slaClockByKey(signalID, target)
}

func (f *fakeSlaClockRepo) Upsert(ctx context.Context, tx application.Tx, clock domain.SlaClock) (domain.SlaClock, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.SlaClock{}, err
	}
	ftx.record("sla.upsert")
	if clock.ID == "" {
		clock.ID = uuid.New()
	}
	// The write stages on the transaction and publishes on commit, like every
	// other fake write: a rolled-back create discards the clock with it.
	ftx.staged.slaClocks = append(ftx.staged.slaClocks, clock)
	return clock, nil
}

// Get resolves one clock by its natural key (staged first, then committed),
// mirroring the adapter's natural-key read. A missing clock is (zero, false,
// nil).
func (f *fakeSlaClockRepo) Get(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget) (domain.SlaClock, bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.SlaClock{}, false, err
	}
	ftx.record("sla.get")
	clock, ok := f.resolve(ftx, signalID, target)
	return clock, ok, nil
}

// Tighten mirrors the adapter's guarded statement: only an open clock whose
// stored deadline is later than deadlineAt is updated (never lengthened); a
// missing, fulfilled or already-earlier clock reports changed = false.
func (f *fakeSlaClockRepo) Tighten(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, deadlineAt time.Time) (domain.SlaClock, bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.SlaClock{}, false, err
	}
	ftx.record("sla.tighten")
	base, ok := f.resolve(ftx, signalID, target)
	if !ok || base.Fulfilled() || !deadlineAt.Before(base.DeadlineAt) {
		return domain.SlaClock{}, false, nil
	}
	next := base
	next.DeadlineAt = deadlineAt
	ftx.staged.slaClocks = append(ftx.staged.slaClocks, next)
	return next, true, nil
}

func (f *fakeSlaClockRepo) Fulfil(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.SlaClock{}, false, err
	}
	ftx.record("sla.fulfil")
	base, ok := f.resolve(ftx, signalID, target)
	if !ok || base.Fulfilled() {
		return domain.SlaClock{}, false, nil // missing / already fulfilled: no change
	}
	next, err := base.Fulfil(at)
	if err != nil {
		return domain.SlaClock{}, false, application.ConflictError("sla_clocks.fulfil", err)
	}
	ftx.staged.slaClocks = append(ftx.staged.slaClocks, next)
	return next, true, nil
}

func (f *fakeSlaClockRepo) Pause(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error) {
	return f.guardedClock(tx, "sla_clocks.pause", signalID, target, func(c domain.SlaClock) (domain.SlaClock, error) { return c.Pause(at) })
}

func (f *fakeSlaClockRepo) Resume(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error) {
	return f.guardedClock(tx, "sla_clocks.resume", signalID, target, func(c domain.SlaClock) (domain.SlaClock, error) { return c.Resume(at) })
}

func (f *fakeSlaClockRepo) Reset(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, startedAt, deadlineAt time.Time) (domain.SlaClock, error) {
	return f.guardedClock(tx, "sla_clocks.reset", signalID, target, func(c domain.SlaClock) (domain.SlaClock, error) {
		return c.Reset(startedAt, deadlineAt.Sub(startedAt))
	})
}

// guardedClock applies the domain precondition of a guarded clock write and
// stages the result; a missing clock or a failed precondition is a conflict,
// mirroring guardedClockError of the adapter.
func (f *fakeSlaClockRepo) guardedClock(tx application.Tx, op, signalID string, target domain.SLATarget, fn func(domain.SlaClock) (domain.SlaClock, error)) (domain.SlaClock, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return domain.SlaClock{}, err
	}
	ftx.record("sla.guarded")
	base, ok := f.resolve(ftx, signalID, target)
	if !ok {
		return domain.SlaClock{}, application.ConflictError(op, fmt.Errorf("sla clock %s/%s missing", signalID, target))
	}
	next, err := fn(base)
	if err != nil {
		return domain.SlaClock{}, application.ConflictError(op, err)
	}
	ftx.staged.slaClocks = append(ftx.staged.slaClocks, next)
	return next, nil
}

func (f *fakeSlaClockRepo) Due(ctx context.Context) ([]domain.SlaClock, error) {
	now := fixedNow
	if f.clk != nil {
		now = f.clk.Now()
	}
	var out []domain.SlaClock
	for _, c := range f.db.slaClocks {
		if c.Overdue(now) {
			out = append(out, c)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// harness

// harness wires every fake into a ready-to-use application service.
type harness struct {
	db     *fakeDB
	runner *fakeTxRunner

	signals    *fakeSignalRepo
	audit      *fakeAuditRepo
	outbox     *fakeOutboxRepo
	vulns      *fakeVulnerabilityRepo
	matches    *fakeMatchRepo
	runs       *fakeSourceRunRepo
	raws       *fakeRawRecordRepo
	sources    *fakeSourceRepo
	quarantine *fakeQuarantineRepo
	comps      *fakeComponentRepo
	inventory  *fakeInventoryWriter
	clock      *clock.FakeClock

	signalTriage *fakeSignalTriageRepo
	comments     *fakeCommentRepo
	slaClocks    *fakeSlaClockRepo

	priorityRules *fakePriorityRuleRepo
	factorSource  *fakePriorityFactorRepo

	users *fakeUserRepo

	// I5b fakes (WP-5b.03): the asset read repo, the current-state inventory
	// reader (the preview diffs against it) and the staged-import store. The
	// user/role administration port is served by h.users itself (one shared
	// in-memory user store).
	assets          *fakeAssetRepo
	inventoryReader *fakeInventoryReader
	imports         *fakeInventoryImportRepo
	sourceMonitor   *fakeSourceMonitorRepo

	exports     *fakeExportRepo
	exportStore *fakeExportStore

	retention *fakeRetentionRepo

	svc *application.Service
}

// harnessOption customises the service dependencies a harness wires (e.g. a
// scaled SLA reminder cadence for the accelerated SLA test).
type harnessOption func(*application.ServiceDeps)

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	h := &harness{
		db:    &fakeDB{},
		clock: clock.NewFakeClock(fixedNow),
	}
	h.runner = &fakeTxRunner{db: h.db}
	h.signals = &fakeSignalRepo{db: h.db}
	h.audit = &fakeAuditRepo{db: h.db}
	h.outbox = &fakeOutboxRepo{db: h.db}
	h.vulns = &fakeVulnerabilityRepo{db: h.db}
	h.matches = &fakeMatchRepo{db: h.db}
	h.runs = &fakeSourceRunRepo{db: h.db}
	h.raws = &fakeRawRecordRepo{db: h.db}
	h.sources = &fakeSourceRepo{db: h.db}
	h.quarantine = &fakeQuarantineRepo{db: h.db}
	h.comps = &fakeComponentRepo{db: h.db}
	h.inventory = &fakeInventoryWriter{db: h.db}
	h.signalTriage = &fakeSignalTriageRepo{db: h.db}
	h.comments = &fakeCommentRepo{db: h.db}
	h.slaClocks = &fakeSlaClockRepo{db: h.db, clk: h.clock}
	h.priorityRules = &fakePriorityRuleRepo{db: h.db}
	h.factorSource = &fakePriorityFactorRepo{rebuilds: map[string]application.PriorityFactorRebuild{}}
	h.users = newFakeUserRepo()
	h.assets = &fakeAssetRepo{db: h.db}
	h.inventoryReader = &fakeInventoryReader{db: h.db}
	h.imports = &fakeInventoryImportRepo{db: h.db}
	h.sourceMonitor = &fakeSourceMonitorRepo{db: h.db}
	h.exports = &fakeExportRepo{db: h.db}
	h.exportStore = &fakeExportStore{artifacts: map[string][]byte{}}
	h.retention = &fakeRetentionRepo{db: h.db}
	deps := application.ServiceDeps{
		Signals:          h.signals,
		Audit:            h.audit,
		Outbox:           h.outbox,
		Vulnerabilities:  h.vulns,
		Matches:          h.matches,
		SourceRuns:       h.runs,
		RawRecords:       h.raws,
		Sources:          h.sources,
		Quarantine:       h.quarantine,
		Components:       h.comps,
		Inventory:        h.inventory,
		SignalTriage:     h.signalTriage,
		Comments:         h.comments,
		SlaClocks:        h.slaClocks,
		PriorityRules:    h.priorityRules,
		FactorSource:     h.factorSource,
		Users:            h.users,
		Assets:           h.assets,
		InventoryReader:  h.inventoryReader,
		InventoryImports: h.imports,
		UserAdmin:        h.users,
		SourceMonitor:    h.sourceMonitor,
		Exports:          h.exports,
		ExportStore:      h.exportStore,
		Retention:        h.retention,
		Clock:            h.clock,
		RunTx:            h.runner.Run,
	}
	for _, opt := range opts {
		opt(&deps)
	}
	h.svc = application.NewService(deps)
	return h
}

// systemActor is the I1b audit actor of the command-level tests.
func systemActor(id string) application.Actor {
	return application.Actor{Type: application.ActorTypeSystem, ID: id}
}
