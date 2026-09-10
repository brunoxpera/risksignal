package worker

// In-memory persistence fakes for the WP-2.08 source.run loop tests
// (ARCH-002 §5): a minimal application-persistence stack — the repositories
// the FetchSource/NormalizeSource use cases write through — plus the relay
// outbox store over the same fake database, so the full loop (scheduler
// scan -> relay drain -> source.fetch handler -> FetchSource -> stored raw
// record + enqueued source.normalize job -> relay drain ->
// source.normalize handler -> NormalizeSource -> domain records) can run
// against a real httptest-backed source adapter without a database.
//
// The fakes mirror the production semantics the tests assert on: raw
// records dedupe on the natural key (source_id, external_id, content_hash),
// evidence inserts on (raw_record_id, type, value_hash), outbox appends on
// the UQ dedupe_key (the idempotency backstop of the scheduler and manual
// trigger), the cursor advances only with a succeeded run completion, and
// the relay store claims the bounded due batch with a 60s lease (pending
// rows whose available_at has passed, claimed rows whose lease expired) and
// acks/dead-letters guarded on the claimed status — the at-least-once
// semantics of ARCH-001 §2. Writes are immediate (no staging/rollback): the
// rollback proofs of ARCH-002 §6 live in the application-layer tests with
// their own transactional fakes; these tests assert the run-loop outcomes,
// not transaction atomicity.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
	"github.com/xpera/risksignal/internal/platform/uuid"
)

// jobRaw is one stored raw record of the fake database.
type jobRaw struct {
	id, sourceID, externalID, contentHash, contentEncoding string
	payload                                                []byte
	fetchedAt                                              time.Time
}

// jobVuln is one normalised vulnerability of the fake database.
type jobVuln struct {
	id, cveID, summary string
}

// jobEvidence is one immutable evidence row of the fake database; id is
// the row id the real InsertEvidence returns (new-or-existing, ARCH-003 §7).
type jobEvidence struct {
	id            string
	vulnID, rawID string
	typ           domain.EvidenceType
	value         []byte
	hash          string
}

// jobRun is one source run of the fake database.
type jobRun struct {
	id, sourceID string
	status       string
	counters     application.SourceRunCounters
	errText      string
	cursorBefore json.RawMessage
	cursorAfter  json.RawMessage
	startedAt    time.Time
	finishedAt   time.Time
}

// jobDB is the committed state of the fake persistence.
type jobDB struct {
	sources    []application.SourceDescriptor
	scheduled  []application.ScheduledSource
	raws       []jobRaw
	vulns      []jobVuln
	evidences  []jobEvidence
	runs       []jobRun
	outbox     []application.OutboxEvent
	quarantine []domain.Quarantine
}

func (d *jobDB) sourceByID(id string) (*application.SourceDescriptor, bool) {
	for i := range d.sources {
		if d.sources[i].ID == id {
			return &d.sources[i], true
		}
	}
	return nil, false
}

func (d *jobDB) rawByID(id string) (*jobRaw, bool) {
	for i := range d.raws {
		if d.raws[i].id == id {
			return &d.raws[i], true
		}
	}
	return nil, false
}

func (d *jobDB) rawByNaturalKey(sourceID, externalID, hash string) (*jobRaw, bool) {
	for i := range d.raws {
		r := &d.raws[i]
		if r.sourceID == sourceID && r.externalID == externalID && r.contentHash == hash {
			return r, true
		}
	}
	return nil, false
}

func (d *jobDB) vulnByCVE(cveID string) (*jobVuln, bool) {
	for i := range d.vulns {
		if d.vulns[i].cveID == cveID {
			return &d.vulns[i], true
		}
	}
	return nil, false
}

// evidenceID resolves the stored evidence row of one natural key
// (raw_record_id, type, value_hash) — the id the real InsertEvidence
// returns for an already existing statement (ARCH-003 §7).
func (d *jobDB) evidenceID(rawID string, typ domain.EvidenceType, hash string) (string, bool) {
	for _, e := range d.evidences {
		if e.rawID == rawID && e.typ == typ && e.hash == hash {
			return e.id, true
		}
	}
	return "", false
}

func (d *jobDB) outboxByDedupe(key string) bool {
	for _, ev := range d.outbox {
		if ev.DedupeKey == key {
			return true
		}
	}
	return false
}

func (d *jobDB) runByID(id string) (*jobRun, bool) {
	for i := range d.runs {
		if d.runs[i].id == id {
			return &d.runs[i], true
		}
	}
	return nil, false
}

// jobTx is the transaction handle of the fake stack: application.Tx is
// satisfied by embedding pgx.Tx (never invoked — the fakes write directly);
// the EPSS bulk writer that issues Exec/CopyFrom on the transaction is not
// part of these tests (the KEV loop exercises the shared port halves).
type jobTx struct {
	pgx.Tx
	db *jobDB
}

// jobRunner plays application.TxRunner: execute fn and commit (the fakes
// stage immediately). Wired as the method value (*jobRunner).Run.
type jobRunner struct{ db *jobDB }

func (r *jobRunner) Run(ctx context.Context, fn func(tx application.Tx) error) error {
	return fn(&jobTx{db: r.db})
}

// ---------------------------------------------------------------------------
// repository fakes

type jobSourceRepo struct{ db *jobDB }

func (f *jobSourceRepo) GetByID(ctx context.Context, id string) (application.SourceDescriptor, error) {
	desc, ok := f.db.sourceByID(id)
	if !ok {
		return application.SourceDescriptor{}, application.NotFoundError("source.get_by_id", fmt.Errorf("source %s not found", id))
	}
	return *desc, nil
}

func (f *jobSourceRepo) SetLastContentHash(ctx context.Context, tx application.Tx, sourceID, contentHash string) error {
	desc, ok := f.db.sourceByID(sourceID)
	if !ok {
		return application.NotFoundError("source.set_last_content_hash", fmt.Errorf("source %s not found", sourceID))
	}
	if desc.Config == nil {
		desc.Config = make(map[string]any)
	}
	desc.Config["last_content_hash"] = contentHash
	return nil
}

func (f *jobSourceRepo) SetCursor(ctx context.Context, tx application.Tx, sourceID string, cursor json.RawMessage) error {
	desc, ok := f.db.sourceByID(sourceID)
	if !ok {
		return application.NotFoundError("source.set_cursor", fmt.Errorf("source %s not found", sourceID))
	}
	desc.Cursor = cursor
	return nil
}

func (f *jobSourceRepo) ListEnabledScheduled(ctx context.Context) ([]application.ScheduledSource, error) {
	return append([]application.ScheduledSource(nil), f.db.scheduled...), nil
}

var _ application.SourceRepo = (*jobSourceRepo)(nil)

type jobRawRecordRepo struct{ db *jobDB }

func (f *jobRawRecordRepo) Insert(ctx context.Context, tx application.Tx, sourceID, externalID string, payload []byte, contentHash, contentEncoding string, fetchedAt time.Time) (string, error) {
	if r, ok := f.db.rawByNaturalKey(sourceID, externalID, contentHash); ok {
		return r.id, nil // ON CONFLICT DO NOTHING: identical earlier ingest
	}
	id := uuid.New()
	f.db.raws = append(f.db.raws, jobRaw{
		id: id, sourceID: sourceID, externalID: externalID, contentHash: contentHash,
		payload: payload, contentEncoding: contentEncoding, fetchedAt: fetchedAt,
	})
	return id, nil
}

func (f *jobRawRecordRepo) GetByID(ctx context.Context, id string) (application.RawRecord, error) {
	r, ok := f.db.rawByID(id)
	if !ok {
		return application.RawRecord{}, application.NotFoundError("raw_record.get_by_id", fmt.Errorf("raw record %s not found", id))
	}
	return application.RawRecord{
		ID: r.id, SourceID: r.sourceID, ExternalID: r.externalID,
		ContentHash: r.contentHash, Payload: r.payload, ContentEncoding: r.contentEncoding,
		FetchedAt: r.fetchedAt,
	}, nil
}

// PreviousKEVCVEs mirrors the generated read: the kev evidence cve ids of
// the source's latest stored raw record other than the pass's own, sorted.
func (f *jobRawRecordRepo) PreviousKEVCVEs(ctx context.Context, sourceID, excludeRawRecordID string) ([]string, error) {
	var latest *jobRaw
	for i := range f.db.raws {
		r := &f.db.raws[i]
		if r.sourceID != sourceID || r.id == excludeRawRecordID {
			continue
		}
		if latest == nil || r.fetchedAt.After(latest.fetchedAt) || (r.fetchedAt.Equal(latest.fetchedAt) && r.id > latest.id) {
			latest = r
		}
	}
	if latest == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	var cves []string
	for _, e := range f.db.evidences {
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

var _ application.RawRecordRepo = (*jobRawRecordRepo)(nil)

type jobRunRepo struct{ db *jobDB }

func (f *jobRunRepo) Open(ctx context.Context, tx application.Tx, sourceID string, cursorBefore json.RawMessage, startedAt time.Time) (string, error) {
	id := uuid.New()
	f.db.runs = append(f.db.runs, jobRun{
		id: id, sourceID: sourceID, status: "running", cursorBefore: cursorBefore, startedAt: startedAt,
	})
	return id, nil
}

func (f *jobRunRepo) Complete(ctx context.Context, tx application.Tx, runID string, status application.SourceRunStatus, counters application.SourceRunCounters, cursorAfter json.RawMessage, errText string, finishedAt time.Time) error {
	run, ok := f.db.runByID(runID)
	if !ok {
		return application.NotFoundError("source_run.complete", fmt.Errorf("run %s not found", runID))
	}
	run.status = string(status)
	run.counters = counters
	run.errText = errText
	run.finishedAt = finishedAt
	// The cursor advances only with a succeeded run (the generated CASE
	// guard forces NULL on every other terminal status, ch. 6.1).
	if status == application.SourceRunStatusSucceeded {
		run.cursorAfter = cursorAfter
	} else {
		run.cursorAfter = nil
	}
	return nil
}

var _ application.SourceRunRepo = (*jobRunRepo)(nil)

type jobOutboxRepo struct{ db *jobDB }

func (f *jobOutboxRepo) Append(ctx context.Context, tx application.Tx, ev application.OutboxEvent) error {
	if f.db.outboxByDedupe(ev.DedupeKey) {
		return application.ConflictError("outbox.append", fmt.Errorf("outbox row with dedupe key %q already exists", ev.DedupeKey))
	}
	f.db.outbox = append(f.db.outbox, ev)
	return nil
}

func (f *jobOutboxRepo) ExistsDedupeKey(ctx context.Context, tx application.Tx, dedupeKey string) (bool, error) {
	return f.db.outboxByDedupe(dedupeKey), nil
}

var _ application.OutboxRepo = (*jobOutboxRepo)(nil)

type jobVulnRepo struct{ db *jobDB }

func (f *jobVulnRepo) Upsert(ctx context.Context, tx application.Tx, rec application.VulnerabilityRecord, publishedAt, modifiedAt time.Time) (string, error) {
	if v, ok := f.db.vulnByCVE(rec.CVEID); ok {
		return v.id, nil
	}
	id := uuid.New()
	f.db.vulns = append(f.db.vulns, jobVuln{id: id, cveID: rec.CVEID, summary: rec.Summary})
	return id, nil
}

func (f *jobVulnRepo) AddEvidence(ctx context.Context, tx application.Tx, ev application.EvidenceRecord, observedAt time.Time) (string, error) {
	if id, ok := f.db.evidenceID(ev.RawRecordID, ev.Type, ev.ValueHash); ok {
		return id, nil // ON CONFLICT DO NOTHING
	}
	id := uuid.New()
	f.db.evidences = append(f.db.evidences, jobEvidence{
		id: id, vulnID: ev.VulnerabilityID, rawID: ev.RawRecordID, typ: ev.Type, value: ev.Value, hash: ev.ValueHash,
	})
	return id, nil
}

var _ application.VulnerabilityRepo = (*jobVulnRepo)(nil)

type jobQuarantineRepo struct{ db *jobDB }

func (f *jobQuarantineRepo) Insert(ctx context.Context, tx application.Tx, sourceID, sourceRunID, rawRecordID, position, reason, payloadHash string, now time.Time) (string, error) {
	q, err := domain.NewQuarantine(uuid.New(), sourceID, sourceRunID, rawRecordID, position, reason, payloadHash)
	if err != nil {
		return "", application.ValidationError("quarantine.insert", err)
	}
	f.db.quarantine = append(f.db.quarantine, q)
	return q.ID, nil
}

func (f *jobQuarantineRepo) GetByID(ctx context.Context, id string) (domain.Quarantine, error) {
	return domain.Quarantine{}, application.NotFoundError("quarantine.get_by_id", errors.New("not modelled"))
}
func (f *jobQuarantineRepo) List(ctx context.Context, status *domain.QuarantineStatus, sourceID string, limit int) ([]domain.Quarantine, error) {
	return nil, nil
}
func (f *jobQuarantineRepo) Acknowledge(ctx context.Context, tx application.Tx, id, acknowledgedBy, note string, now time.Time) (domain.Quarantine, error) {
	return domain.Quarantine{}, application.NotFoundError("quarantine.ack", errors.New("not modelled"))
}
func (f *jobQuarantineRepo) MarkReadyForRetry(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	return domain.Quarantine{}, application.NotFoundError("quarantine.transition", errors.New("not modelled"))
}
func (f *jobQuarantineRepo) MarkResolved(ctx context.Context, tx application.Tx, id, resolvedVulnerabilityID, resolvedEvidenceID, note string, now time.Time) (domain.Quarantine, error) {
	return domain.Quarantine{}, application.NotFoundError("quarantine.transition", errors.New("not modelled"))
}
func (f *jobQuarantineRepo) IncrementAttempts(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	return domain.Quarantine{}, application.NotFoundError("quarantine.transition", errors.New("not modelled"))
}

var _ application.QuarantineRepo = (*jobQuarantineRepo)(nil)

// jobStubRepo is the one-method stub for the ports the run loop never
// touches (signals, audit, matches, components) — the service requires them
// non-nil at wiring, and any call is a test bug surfaced loudly.
type jobStubRepo struct{ name string }

func (s *jobStubRepo) method() error {
	return fmt.Errorf("jobStubRepo.%s: unexpected call (not part of the run loop)", s.name)
}

// jobStubInventoryWriter is the InventoryWriter stub of the run-loop
// tests: the run loop never touches the inventory commit path — the stub
// satisfies the mandatory service dependency and fails loudly if a test
// ever drives it.
type jobStubInventoryWriter struct{}

func (jobStubInventoryWriter) CurrentAssetOnTx(context.Context, application.Tx, string, string) (application.CurrentInventoryAsset, bool, error) {
	return application.CurrentInventoryAsset{}, false, fmt.Errorf("jobStubInventoryWriter: unexpected call (inventory commit is not part of the run loop)")
}

func (jobStubInventoryWriter) UpsertAsset(context.Context, application.Tx, application.InventoryAsset, time.Time) (string, error) {
	return "", fmt.Errorf("jobStubInventoryWriter: unexpected call (inventory commit is not part of the run loop)")
}

func (jobStubInventoryWriter) UpsertComponent(context.Context, application.Tx, string, application.InventoryComponent, time.Time) error {
	return fmt.Errorf("jobStubInventoryWriter: unexpected call (inventory commit is not part of the run loop)")
}

func (jobStubInventoryWriter) InventorySnapshot(context.Context, application.Tx) (application.InventorySnapshot, error) {
	return application.InventorySnapshot{}, fmt.Errorf("jobStubInventoryWriter: unexpected call (inventory commit is not part of the run loop)")
}

func (jobStubInventoryWriter) RuleVersions(context.Context, application.Tx) (int, int, error) {
	return 0, 0, fmt.Errorf("jobStubInventoryWriter: unexpected call (inventory commit is not part of the run loop)")
}

func (s *jobStubRepo) Create(ctx context.Context, tx application.Tx, rec application.SignalRecord, createdAt time.Time) (domain.RiskSignal, error) {
	return domain.RiskSignal{}, s.method()
}
func (s *jobStubRepo) GetByID(ctx context.Context, id string) (application.Signal, error) {
	return application.Signal{}, s.method()
}
func (s *jobStubRepo) List(ctx context.Context, filter application.SignalFilter, limit, offset int) ([]application.Signal, error) {
	return nil, s.method()
}
func (s *jobStubRepo) ExistsByMatchID(ctx context.Context, matchID string) (bool, error) {
	return false, s.method()
}
func (s *jobStubRepo) Append(ctx context.Context, tx application.Tx, ev application.AuditEvent) error {
	return s.method()
}
func (s *jobStubRepo) Insert(ctx context.Context, tx application.Tx, rec application.MatchRecord, createdAt time.Time) (string, error) {
	return "", s.method()
}
func (s *jobStubRepo) ListByVendorProduct(ctx context.Context, vendor, product string) ([]application.Component, error) {
	return nil, s.method()
}

// newJobService wires the application service of the run-loop tests on the
// fake database with the given clock.
func newJobService(db *jobDB, clk clock.Clock) *application.Service {
	return application.NewService(application.ServiceDeps{
		Signals:         &jobStubRepo{name: "signals"},
		Audit:           &jobStubRepo{name: "audit"},
		Outbox:          &jobOutboxRepo{db: db},
		Vulnerabilities: &jobVulnRepo{db: db},
		Matches:         &jobStubRepo{name: "matches"},
		SourceRuns:      &jobRunRepo{db: db},
		RawRecords:      &jobRawRecordRepo{db: db},
		Sources:         &jobSourceRepo{db: db},
		Quarantine:      &jobQuarantineRepo{db: db},
		Components:      &jobStubRepo{name: "components"},
		Inventory:       &jobStubInventoryWriter{},
		Clock:           clk,
		RunTx:           (&jobRunner{db: db}).Run,
	})
}

// ---------------------------------------------------------------------------
// relay outbox store over the fake database

// outbox lease duration mirrors the 60s lease of the generated claim.
const outboxLease = 60 * time.Second

// loopRowState is the relay-side state of one outbox row (identified by its
// dedupe key — unique per row by schema).
type loopRowState struct {
	status     string // pending | claimed | done | dead_letter
	attempts   int
	leaseUntil time.Time
	lastError  string
}

// loopStore is the relay's OutboxStore over the committed outbox rows of
// the fake database (ARCH-001 §2 semantics): ClaimBatch claims the bounded
// batch of due rows — pending rows whose available_at has passed plus
// claimed rows whose lease expired — with a fresh 60s lease and an
// incremented attempt count; Ack and DeadLetter are guarded on the claimed
// status. New rows appended during a drain (the source.normalize job of a
// committed fetch) are reconciled on the next claim.
type loopStore struct {
	db  *jobDB
	clk clock.Clock

	mu   sync.Mutex
	rows map[string]*loopRowState
}

func newLoopStore(db *jobDB, clk clock.Clock) *loopStore {
	return &loopStore{db: db, clk: clk, rows: make(map[string]*loopRowState)}
}

// sync reconciles the committed outbox rows into the state map.
func (s *loopStore) sync() {
	for _, ev := range s.db.outbox {
		if _, ok := s.rows[ev.DedupeKey]; !ok {
			s.rows[ev.DedupeKey] = &loopRowState{status: "pending"}
		}
	}
}

// stateOf returns the relay-side state of one row ("" when unknown).
func (s *loopStore) stateOf(dedupeKey string) loopRowState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.rows[dedupeKey]
	if !ok {
		return loopRowState{}
	}
	return *st
}

func (s *loopStore) ClaimBatch(ctx context.Context, limit int) ([]ClaimedEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sync()
	now := s.clk.Now()
	var claimed []ClaimedEvent
	for _, ev := range s.db.outbox {
		if len(claimed) >= limit {
			break
		}
		st := s.rows[ev.DedupeKey]
		due := (st.status == "pending" && !ev.AvailableAt.After(now)) ||
			(st.status == "claimed" && st.leaseUntil.Before(now))
		if !due {
			continue
		}
		st.status = "claimed"
		st.attempts++
		st.leaseUntil = now.Add(outboxLease)
		claimed = append(claimed, ClaimedEvent{
			ID:       ev.DedupeKey,
			Type:     ev.Type,
			Payload:  ev.Payload,
			Attempts: st.attempts,
		})
	}
	return claimed, nil
}

func (s *loopStore) Ack(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.rows[id]; ok && st.status == "claimed" {
		st.status = "done"
	}
	return nil
}

func (s *loopStore) DeadLetter(ctx context.Context, id, lastError string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.rows[id]; ok && st.status == "claimed" {
		st.status = "dead_letter"
		st.lastError = lastError
	}
	return nil
}

var _ OutboxStore = (*loopStore)(nil)
