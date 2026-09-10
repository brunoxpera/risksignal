package repo

// Integration test for the I5b InventoryImportRepo postgres adapter
// (ARCH-006 §2.1, WP-5b.05 / DEV-101, the DEV-099 review follow-up (a)): it
// proves the production adapter the staged-import use cases run on persists,
// reads and commit-marks a record over the real inventory_imports table —
// insert (pending) → read-back → guarded commit-mark (counters stamped) →
// idempotent second commit (marked=false, no error, no re-stamp) → the
// operator list — plus the not-found mapping of an unknown id.
//
// It runs against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded set (the shared newI4TestPool helper of
// i4_integration_test.go, same package). When no database is reachable the
// test skips, so `go test ./...` stays green on machines without the
// environment.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

func TestInventoryImportRepoIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	imports := NewInventoryImportRepo(gen.New(pool))

	now := time.Now().UTC().Truncate(time.Microsecond)
	file := []byte("source,external_id,type,name,environment,criticality,exposure\ninv,a1,server_vm,Alpha,production,critical,internet\n")

	// 1. Insert a staged upload (pending) on a transaction — the record is
	// only visible once the transaction commits.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin insert tx: %v", err)
	}
	stored, err := imports.Insert(ctx, tx, application.InventoryImportRecord{
		Status:        application.InventoryImportPending,
		File:          file,
		Rows:          1,
		ErrorCount:    0,
		WarningCount:  1,
		ActorID:       "actor-1",
		CorrelationID: "corr-1",
		CreatedAt:     now,
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit insert tx: %v", err)
	}
	if stored.ID == "" {
		t.Fatal("insert returned an empty id")
	}
	if stored.Status != application.InventoryImportPending {
		t.Fatalf("inserted status = %q, want pending", stored.Status)
	}
	if !stored.CommittedAt.IsZero() {
		t.Fatalf("committed_at on a pending record = %v, want zero (NULL)", stored.CommittedAt)
	}

	// 2. Read it back: the bytes and the preview tallies are stored verbatim,
	// the commit-outcome counters are still 0.
	got, err := imports.Get(ctx, stored.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.File) != string(file) {
		t.Fatalf("stored file = %q, want the uploaded bytes back verbatim", got.File)
	}
	if got.Status != application.InventoryImportPending || got.Rows != 1 || got.WarningCount != 1 || got.CorrelationID != "corr-1" {
		t.Fatalf("read-back = %+v, want the stored pending record", got)
	}
	if got.AssetsCreated != 0 || got.ComponentsUpdated != 0 {
		t.Fatalf("commit-outcome counters default = %d/%d, want 0/0", got.AssetsCreated, got.ComponentsUpdated)
	}

	// 3. Commit-mark it on a transaction: pending → committed, committed_at
	// stamped, the four counters populated atomically.
	counts := application.InventoryImportCounts{AssetsCreated: 1, AssetsUpdated: 2, ComponentsCreated: 3, ComponentsUpdated: 4}
	committedAt := now.Add(10 * time.Minute)
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin mark tx: %v", err)
	}
	marked, ok, err := imports.MarkCommitted(ctx, tx2, stored.ID, counts, committedAt)
	if err != nil {
		_ = tx2.Rollback(ctx)
		t.Fatalf("mark committed: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit mark tx: %v", err)
	}
	if !ok {
		t.Fatal("MarkCommitted marked = false, want true for a pending record")
	}
	if marked.Status != application.InventoryImportCommitted {
		t.Fatalf("marked status = %q, want committed", marked.Status)
	}
	if !marked.CommittedAt.Equal(committedAt) {
		t.Fatalf("committed_at = %v, want %v", marked.CommittedAt, committedAt)
	}
	if marked.AssetsCreated != 1 || marked.AssetsUpdated != 2 || marked.ComponentsCreated != 3 || marked.ComponentsUpdated != 4 {
		t.Fatalf("stamped counters = %d/%d/%d/%d, want 1/2/3/4",
			marked.AssetsCreated, marked.AssetsUpdated, marked.ComponentsCreated, marked.ComponentsUpdated)
	}

	// The committed record reads back with the counters and committed_at.
	reread, err := imports.Get(ctx, stored.ID)
	if err != nil {
		t.Fatalf("get after commit: %v", err)
	}
	if reread.Status != application.InventoryImportCommitted || !reread.CommittedAt.Equal(committedAt) {
		t.Fatalf("read after commit = %+v, want committed at %v", reread, committedAt)
	}
	if reread.AssetsCreated != 1 || reread.ComponentsUpdated != 4 {
		t.Fatalf("read-after-commit counters = %d/%d, want 1/4", reread.AssetsCreated, reread.ComponentsUpdated)
	}

	// 4. Re-commit is a no-op: the pending guard matches zero rows, so
	// MarkCommitted reports marked=false with no error and never re-stamps.
	tx3, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second mark tx: %v", err)
	}
	_, ok, err = imports.MarkCommitted(ctx, tx3, stored.ID, application.InventoryImportCounts{}, committedAt.Add(time.Hour))
	if err != nil {
		_ = tx3.Rollback(ctx)
		t.Fatalf("second commit err = %v, want nil (the guard did not match: the no-op)", err)
	}
	if err := tx3.Commit(ctx); err != nil {
		t.Fatalf("commit second mark tx: %v", err)
	}
	if ok {
		t.Fatal("second MarkCommitted marked = true, want false (guard did not match)")
	}
	afterSecond, err := imports.Get(ctx, stored.ID)
	if err != nil {
		t.Fatalf("get after second commit: %v", err)
	}
	if !afterSecond.CommittedAt.Equal(committedAt) {
		t.Fatalf("committed_at moved on re-commit: %v → %v", committedAt, afterSecond.CommittedAt)
	}

	// 5. An unknown import id is a not-found application error.
	_, err = imports.Get(ctx, "00000000-0000-4000-8000-0000000000ff")
	if err == nil {
		t.Fatal("Get on an unknown id succeeded, want not-found")
	}
	var appErr *application.Error
	if !errors.As(err, &appErr) || appErr.Kind != application.KindNotFound {
		t.Fatalf("unknown-id error = %v, want a not-found application error", err)
	}

	// 6. The operator list returns the committed record.
	list, err := imports.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == stored.ID {
			found = true
			if r.Status != application.InventoryImportCommitted {
				t.Fatalf("listed record status = %q, want committed", r.Status)
			}
		}
	}
	if !found {
		t.Fatalf("List did not include the stored import %s", stored.ID)
	}
}
