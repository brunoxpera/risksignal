package main

// Integration test of DEV-068 (corrective) at the scheduler composition
// root: the due-source scan (EnqueueDueSourceFetches) appends every due
// source.fetch job of one cycle on ONE transaction, so a dedupe-key
// collision must skip only its own row — a unique violation on the outbox
// UQ (dedupe_key) aborts the whole transaction and loses the other due
// fetches of the same scan.
//
// The in-memory harness masked the defect: its Append returns a catchable
// ConflictError, so the use case's conflict branch looked like a no-op. On a
// real PostgreSQL the UQ raises a unique violation that poisons the
// transaction — the pre-fix scan errored and committed nothing. This test
// seeds two due slots, keeps one already enqueued (the collision) and
// deletes the other (the absent fetch), then asserts the scan still enqueues
// the absent one without error and leaves the colliding row untouched.
//
// cmd/risksignal-worker is where the embedded migration set is wired with
// the postgres repos and the application service over postgres.WithTx — the
// scheduler's production composition — so the scan runs against the real
// schema here. Like the other integration tests it skips when no PostgreSQL
// is reachable.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// newScheduleService wires the scheduler's application service at the worker
// composition root: the real postgres repos over the pool and
// postgres.WithTx as the transaction boundary — the same composition as
// runWithContext. The injected clock pins the due schedule slot.
func newScheduleService(pool *pgxpool.Pool, clk clock.Clock) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          repo.NewOutboxRepo(q),
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

// sourceFetchPlanKeys returns the dedupe keys of the source.fetch rows in the
// outbox, ordered by key.
func sourceFetchPlanKeys(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, "SELECT dedupe_key FROM outbox WHERE type = $1 ORDER BY dedupe_key", application.EventTypeSourceFetch)
	if err != nil {
		t.Fatalf("read source.fetch dedupe keys: %v", err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("scan dedupe key: %v", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate dedupe keys: %v", err)
	}
	return keys
}

// TestEnqueueDueSourceFetchesSurvivesDedupeCollision is the DEV-068
// acceptance test: two sources are due for the same daily slot; one of the
// two jobs is already in the outbox (the collision) and the other is absent.
// One scan must skip only the colliding row and still enqueue the absent
// fetch — no error, no lost job, the pre-existing row untouched.
func TestEnqueueDueSourceFetchesSurvivesDedupeCollision(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	q := gen.New(pool)
	for _, name := range []string{"kev-dedupe-a", "kev-dedupe-b"} {
		if _, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
			Type:     string(application.SourceTypeKEV),
			Name:     name,
			Schedule: pgtype.Text{String: application.ScheduleDaily, Valid: true},
			Enabled:  true,
		}); err != nil {
			t.Fatalf("UpsertSource %s: %v", name, err)
		}
	}

	// A pinned clock fixes the daily slot both sources are due for.
	clk := clock.NewFakeClock(time.Date(2026, 9, 10, 3, 11, 0, 0, time.UTC))
	svc := newScheduleService(pool, clk)

	// First cycle: both due slots enqueue in one scan.
	res, err := svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches (seed): %v", err)
	}
	if res.Enqueued != 2 || res.AlreadyQueued != 0 {
		t.Fatalf("seed result = %+v, want 2 enqueued", res)
	}
	keys := sourceFetchPlanKeys(t, ctx, pool)
	if len(keys) != 2 {
		t.Fatalf("outbox source.fetch rows = %d, want 2", len(keys))
	}

	// Make exactly one of the two slots "already enqueued" (the collision)
	// and the other due-and-absent: keep one row, delete the other. The kept
	// key is the dedupe collision the scan must skip; the deleted key is the
	// due fetch it must still enqueue.
	kept, missing := keys[0], keys[1]
	if _, err := pool.Exec(ctx, "DELETE FROM outbox WHERE dedupe_key = $1", missing); err != nil {
		t.Fatalf("delete seed row: %v", err)
	}

	// The pre-fix scan aborts here: the kept key's INSERT raises the UQ
	// (dedupe_key) unique violation, the transaction is aborted and the
	// absent slot's job is lost. With DEV-068 the collision is a per-row
	// pre-checked no-op and the other fetch still enqueues.
	res, err = svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches survived-collision: %v", err)
	}
	if res.Enqueued != 1 || res.AlreadyQueued != 1 {
		t.Fatalf("collision result = %+v, want 1 enqueued (the absent slot) and 1 already-queued (the collision)", res)
	}
	got := sourceFetchPlanKeys(t, ctx, pool)
	if len(got) != 2 {
		t.Fatalf("outbox source.fetch rows after collision = %d (%v), want 2 — the colliding row kept and the absent slot re-enqueued", len(got), got)
	}
	if got[0] != kept || got[1] != missing {
		t.Fatalf("outbox keys after collision = %v, want [%s %s] (the collision kept, the absent slot re-enqueued)", got, kept, missing)
	}
}
