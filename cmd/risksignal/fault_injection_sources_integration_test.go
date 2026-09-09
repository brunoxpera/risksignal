package main

// Fault-injection integration tests of the I2 source run paths (ARCH-002
// §6, TR-004) against a real, short-lived PostgreSQL. The fault seam is
// the ARCH-002 §6 boundary itself, injected from the test package only:
//
//  1. a sink failure mid-pass — the normaliser→sink boundary is wrapped
//     with a deterministic failpoint after one forwarded write — aborts
//     the run transaction: nothing of the pass is partially committed
//     (no raw record, no vulnerability, no evidence) and the run closes
//     failed without a cursor (cursor_after is written only by the
//     success path, ch. 6.1); the source stays retryable and the next
//     run succeeds and commits the cursor;
//  2. a failing outbox append inside the fetch's terminal commit (the
//     source.normalize job enqueue) rolls the raw-record insert, the run
//     completion and the cursor back together (cursor-on-commit) —
//     nothing is enqueued, nothing is dead-lettered;
//  3. a rate-limited fetch (429 + Retry-After, ch. 14.2) closes the run
//     rate-limited — never a source fault and never a dead letter — with
//     the cursor unadvanced and nothing stored; the recovered source is
//     re-run and the same reference imports cleanly (the job stays
//     claimable/retryable, never dead-lettered).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/adapters/sources/nvd"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// errSinkFault is the deterministic failpoint error of the sink-fault
// tests.
var errSinkFault = errors.New("injected mid-stream sink failure")

// failingSink is the ARCH-002 §6 normaliser→sink fault seam: it decorates
// the real persistence sink of a pass and returns the injected error on a
// fixed call instead of forwarding it — after the earlier calls were
// forwarded, so the fault always hits mid-stream behind at least one real
// write. It lives in this test package only.
type failingSink struct {
	inner  application.NormalizeSink
	calls  int
	failOn int // the 1-based call that fails instead of forwarding
	cause  error
}

// failpoint arms one forwarded call; returns the injected error when the
// armed call is reached.
func (f *failingSink) failpoint() error {
	f.calls++
	if f.calls == f.failOn {
		return f.cause
	}
	return nil
}

func (f *failingSink) Vulnerability(ctx context.Context, v domain.Vulnerability) error {
	if err := f.failpoint(); err != nil {
		return err
	}
	return f.inner.Vulnerability(ctx, v)
}

func (f *failingSink) Evidence(ctx context.Context, e domain.Evidence) error {
	if err := f.failpoint(); err != nil {
		return err
	}
	return f.inner.Evidence(ctx, e)
}

func (f *failingSink) RecordError(ctx context.Context, e application.RecordError) error {
	if err := f.failpoint(); err != nil {
		return err
	}
	return f.inner.RecordError(ctx, e)
}

// sinkFaultNvdAdapter decorates the real NVD adapter with the failing sink
// seam: every other port method is promoted from the embedded adapter; the
// normalise half hands the real persistence sink of the pass to the inner
// adapter through the failpoint wrapper.
type sinkFaultNvdAdapter struct {
	*nvd.Adapter
	sink *failingSink
}

// Normalize implements application.SourcePort with the failpoint armed on
// the sink boundary: the inner adapter's emissions stream through the
// failing sink, so the pass aborts on the armed call after the earlier
// writes were forwarded to the real transaction.
func (a *sinkFaultNvdAdapter) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	a.sink = &failingSink{inner: sink, failOn: 2, cause: errSinkFault}
	return a.Adapter.Normalize(ctx, in, a.sink)
}

// TestFaultInjectionSinkFailureMidRunRollsBackRunWithoutCursor is the
// TR-004 proof at the source-run level: a sink failure mid-pass — after
// the first vulnerability write was forwarded — aborts the run
// transaction, so no raw record, vulnerability or evidence is committed,
// the run closes failed without a cursor, and the source re-runs cleanly
// afterwards (the retry commits the cursor).
func TestFaultInjectionSinkFailureMidRunRollsBackRunWithoutCursor(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	window := readFixture(t, "nvd-window-2026-09-09.json")
	srv := serveNvdWindow(window)
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "nvd",
		Name:     "nvd-sink-fault-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@hourly", Valid: true},
		Enabled:  true,
		Config:   []byte(twofoldNvdConfig),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)

	// Arm the seam: the pass emits the first record's vulnerability (a
	// real write inside the run transaction) and then the nvd_statement
	// evidence write fails — the fault always hits mid-stream.
	faulty := &sinkFaultNvdAdapter{Adapter: nvd.New(srv.Client().Transport)}
	_, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: faulty})
	if err == nil {
		t.Fatal("RunSource succeeded, want the injected mid-stream sink failure")
	}
	if !errors.Is(err, errSinkFault) {
		t.Fatalf("RunSource error = %v, want the injected sink failure (unwrapped)", err)
	}
	if faulty.sink == nil || faulty.sink.calls != 2 {
		t.Fatalf("sink calls = %v, want exactly 2 — one write forwarded, the armed call failed", faulty.sink)
	}

	// Complete rollback of the pass: no raw record, no vulnerability, no
	// evidence — nothing of the run transaction is observable.
	assertTableCounts(t, pool, map[string]int{
		"vulnerabilities": 0, "evidences": 0, "raw_records": 0, "outbox": 0, "quarantine": 0,
	})
	// The run closed failed with the injected cause and no cursor: the
	// cursor advances only with the commit of a successful run (ch. 6.1).
	runs := sourceRunCensus(t, pool, srcID)
	if len(runs) != 1 || runs[0].status != "failed" {
		t.Fatalf("run rows after rollback = %+v, want exactly one failed run", runs)
	}
	if got := runCursorLastModified(t, pool, sourceRunIDOf(t, pool, srcID, 0)); got != "" {
		t.Fatalf("failed run cursor_after = %q, want none — the cursor must not advance on a rolled-back run", got)
	}

	// The source is retryable: the clean re-run of the same window imports
	// the reference and commits the cursor.
	res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: nvd.New(srv.Client().Transport)})
	if err != nil {
		t.Fatalf("RunSource after rollback: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("retry status = %s, want succeeded", res.Status)
	}
	assertTableCounts(t, pool, map[string]int{
		"vulnerabilities": 2, "evidences": 4, "raw_records": 1, "outbox": 0,
	})
	if got := runCursorLastModified(t, pool, res.RunID); got != "2026-09-09T09:30:00Z" {
		t.Fatalf("retry cursor_after last_modified = %q, want the committed clock instant", got)
	}
}

// TestFaultInjectionOutboxAppendRollsBackFetchCursorOnCommit is the
// TR-004 proof on the fetch half: the terminal commit of FetchSource
// stores the raw record, completes the run with the advanced cursor and
// enqueues the source.normalize job in one transaction; a failing outbox
// append rolls all of them back — no raw record, no job (and therefore no
// dead letter), no cursor — and the healthy re-fetch commits everything.
func TestFaultInjectionOutboxAppendRollsBackFetchCursorOnCommit(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	window := readFixture(t, "nvd-window-2026-09-09.json")
	srv := serveNvdWindow(window)
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "nvd",
		Name:     "nvd-outbox-fault-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@hourly", Valid: true},
		Enabled:  true,
		Config:   []byte(twofoldNvdConfig),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)

	// The fetch half runs with the ARCH-001 §5-style failing outbox
	// decorator: every port stays real except the outbox append.
	cause := application.InfraError("outbox.append", errors.New("injected outbox append failure"))
	faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(q), cause: cause}
	faultySvc := newSourceRunServiceWithOutbox(pool, clk, faulty)

	_, err = faultySvc.FetchSource(ctx, application.FetchSourceInput{SourceID: srcID, Adapter: nvd.New(srv.Client().Transport)})
	if err == nil {
		t.Fatal("FetchSource succeeded, want the injected outbox append failure")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("FetchSource error = %v, want the injected outbox append error (unwrapped)", err)
	}
	if faulty.calls != 1 {
		t.Fatalf("outbox Append calls = %d, want 1 — the fault hit the terminal commit", faulty.calls)
	}

	// Complete rollback of the terminal commit: the raw record and the job
	// are gone (the job was never appended, so nothing is pending and
	// nothing is dead-lettered), and the run closed failed without a
	// cursor.
	assertTableCounts(t, pool, map[string]int{"raw_records": 0, "outbox": 0})
	runs := sourceRunCensus(t, pool, srcID)
	if len(runs) != 1 || runs[0].status != "failed" {
		t.Fatalf("run rows after rollback = %+v, want exactly one failed run", runs)
	}
	if got := runCursorLastModified(t, pool, sourceRunIDOf(t, pool, srcID, 0)); got != "" {
		t.Fatalf("failed run cursor_after = %q, want none — the cursor advances only after a committed run", got)
	}

	// The healthy re-fetch commits the raw record, the advanced cursor and
	// the pending source.normalize job together.
	healthySvc := newSourceRunService(pool, clk)
	res, err := healthySvc.FetchSource(ctx, application.FetchSourceInput{SourceID: srcID, Adapter: nvd.New(srv.Client().Transport)})
	if err != nil {
		t.Fatalf("FetchSource after rollback: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("retry status = %s, want succeeded", res.Status)
	}
	assertTableCounts(t, pool, map[string]int{"raw_records": 1, "outbox": 1})
	if got := runCursorLastModified(t, pool, res.RunID); got != "2026-09-09T09:30:00Z" {
		t.Fatalf("retry cursor_after last_modified = %q, want the committed clock instant", got)
	}
}

// TestRateLimitedFetchLeavesRunRetryableNotDeadLettered is the ch. 14.2
// proof on the run level: a 429 + Retry-After fetch is recorded
// rate-limited — never a source fault — with the cursor unadvanced,
// nothing stored and no outbox row (pending or dead-lettered); once the
// endpoint recovers, the same source run succeeds (the job stays
// claimable/retryable, never dead-lettered).
func TestRateLimitedFetchLeavesRunRetryableNotDeadLettered(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	window := readFixture(t, "nvd-window-2026-09-09.json")
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeNvdWindowPage(w, window, r)
	}))
	t.Cleanup(srv.Close)

	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "nvd",
		Name:     "nvd-ratelimit-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@hourly", Valid: true},
		Enabled:  true,
		Config:   []byte(twofoldNvdConfig),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)
	adapter := nvd.New(srv.Client().Transport)

	// --- the rate-limited fetch -------------------------------------------
	res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (rate limited): %v", err)
	}
	if res.Status != application.SourceRunStatusFailed || !res.Meta.RateLimited {
		t.Fatalf("rate-limited run = status %s meta %+v, want failed with Meta.RateLimited", res.Status, res.Meta)
	}
	if res.Meta.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want the header's 30s backoff", res.Meta.RetryAfter)
	}
	// The run closed rate-limited (the stable error text of ch. 14.2) with
	// the cursor unadvanced and nothing stored or enqueued — in
	// particular nothing dead-lettered.
	runs := sourceRunCensus(t, pool, srcID)
	if len(runs) != 1 || runs[0].status != "failed" {
		t.Fatalf("run rows after rate limit = %+v, want exactly one failed run", runs)
	}
	var runErr string
	if err := pool.QueryRow(ctx,
		"SELECT error FROM source_runs WHERE source_id = $1", sourceID).Scan(&runErr); err != nil {
		t.Fatalf("read rate-limited run error: %v", err)
	}
	if runErr != application.RateLimitedErrorText {
		t.Fatalf("rate-limited run error = %q, want %q (recorded rate-limited, never a source fault)", runErr, application.RateLimitedErrorText)
	}
	if got := runCursorLastModified(t, pool, sourceRunIDOf(t, pool, srcID, 0)); got != "" {
		t.Fatalf("rate-limited run cursor_after = %q, want none — the cursor must not advance", got)
	}
	assertTableCounts(t, pool, map[string]int{"raw_records": 0, "outbox": 0, "quarantine": 0})

	// --- the recovered source is retried, never dead-lettered -------------
	healthy.Store(true)
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: srcID, Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource after recovery: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Meta.RateLimited {
		t.Fatalf("recovered run = status %s meta %+v, want succeeded without rate limit", res.Status, res.Meta)
	}
	assertTableCounts(t, pool, map[string]int{
		"vulnerabilities": 2, "evidences": 4, "raw_records": 1, "outbox": 0,
	})
	if got := runCursorLastModified(t, pool, res.RunID); got != "2026-09-09T09:30:00Z" {
		t.Fatalf("recovered run cursor_after last_modified = %q, want the committed clock instant", got)
	}
	if n := countDeadLetterRows(t, pool); n != 0 {
		t.Fatalf("dead-lettered outbox rows = %d, want 0 — a rate limit never dead-letters a job", n)
	}
}

// newSourceRunServiceWithOutbox wires the source-run service with a
// decorated outbox repository (every other port real) — the composition
// of the fetch-half fault test.
func newSourceRunServiceWithOutbox(pool *pgxpool.Pool, clk clock.Clock, outbox application.OutboxRepo) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          outbox,
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		RawRecords:      repo.NewRawRecordRepo(q),
		Sources:         repo.NewSourceRepo(q),
		Quarantine:      repo.NewQuarantineRepo(q),
		Components:      repo.NewComponentRepo(q),
		Inventory:       repo.NewInventoryRepo(q),
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// sourceRunIDOf returns the id of the i-th committed run row of one source
// (oldest first) — the run census reads need the row id to read its cursor.
func sourceRunIDOf(t *testing.T, pool *pgxpool.Pool, sourceID string, i int) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var id pgtype.UUID
	if err := pool.QueryRow(ctx,
		"SELECT id FROM source_runs WHERE source_id = $1 ORDER BY started_at OFFSET $2 LIMIT 1",
		mustUUID(t, sourceID), i).Scan(&id); err != nil {
		t.Fatalf("read run row %d id: %v", i, err)
	}
	return demoUUID(id)
}

// countDeadLetterRows returns the dead-lettered outbox census.
func countDeadLetterRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE status = 'dead_letter'").Scan(&n); err != nil {
		t.Fatalf("count dead-lettered outbox rows: %v", err)
	}
	return n
}
