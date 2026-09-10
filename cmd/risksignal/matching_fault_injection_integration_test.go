package main

// Integration test of the WP-3.11 fault-injection exit criterion, case (i)
// (DEV-054, ARCH-003 §8, TR-004): the rebuild-trigger transaction is atomic.
// The I3 inventory commit is one domain command / one transaction (ch. 5.1,
// ARCH-003 §1.3/§5): it writes the inventory state (assets + components, the
// state the matching engine reads) and enqueues exactly one matching.rebuild
// job on the same transaction. Injecting a failure on the outbox append —
// the ARCH-003 §5/§1.3 fault seam, after the inventory writes succeeded —
// must roll the whole transaction back: no inventory-without-job half-state
// can exist. This is the I3 form of the ARCH-001 §5 atomicity proof (the
// DEV-024 CreateSignal test is the signal-side sibling).
//
// The fault is injected exactly on the seam: a decorator wraps the real
// postgres OutboxRepo (every other port stays real) and overrides Append with
// a deterministic failpoint — an error return, no sleep, no flake. It lives
// in this test package, never in production code.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// matchingFaultInventoryCSV is the one-row inventory commit of the atomicity
// test: one asset with one component row (the canonical ARCH-003 §1.3 shape).
func matchingFaultInventoryCSV() []byte {
	const header = "source,external_id,type,name,environment,criticality,exposure,owner,vendor,product,version,cpe,purl,image,digest\n"
	return []byte(header + "cmdb,a1,server_vm,Portal,production,high,internet,,Acme,Widget,1.2.3,,,,\n")
}

// TestMatchingFaultInventoryCommitRollsBackAllWrites is the complete-rollback
// proof of the rebuild-trigger transaction (TR-004): with the outbox append
// armed to fail, CommitInventory returns the injected error and the inventory
// writes (assets, components) and the audit event roll back with it — nothing
// is observable. The positive control that follows proves the same command
// commits the inventory and exactly one matching.rebuild job when the append
// succeeds.
func TestMatchingFaultInventoryCommitRollsBackAllWrites(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := faultTestClockTime
	clk := clock.NewFakeClock(at)
	q := gen.New(pool)

	// The four tables of the command are empty before it runs.
	assertTableCounts(t, pool, map[string]int{
		"assets": 0, "components": 0, "outbox": 0, "audit_events": 0,
	})

	// Arm the fault seam: the real asset/component/audit ports stay wired;
	// only the outbox append is decorated with the deterministic failpoint.
	cause := application.InfraError("outbox.append", errors.New("injected outbox append failure"))
	faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(q), cause: cause}
	svc := newCreateSignalService(pool, faulty, clk)

	_, err := svc.CommitInventory(ctx, application.CommitInventoryInput{File: matchingFaultInventoryCSV()})
	if err == nil {
		t.Fatal("CommitInventory succeeded, want the injected outbox append error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("CommitInventory error = %v, want the injected error itself (unwrapped)", err)
	}
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindInfra {
		t.Fatalf("CommitInventory error kind = %s (ok %v), want infrastructure", kind, ok)
	}
	// The fault seam was reached exactly once: the asset and component writes
	// had succeeded inside the transaction before the outbox append failed.
	if faulty.calls != 1 {
		t.Fatalf("outbox Append calls = %d, want 1 (the fault must hit after the inventory writes)", faulty.calls)
	}

	// Complete rollback: no asset, no component, no audit event, no job is
	// observable after the failed command — the inventory state and the
	// matching.rebuild enqueue are one atomic unit (TR-004).
	assertTableCounts(t, pool, map[string]int{
		"assets": 0, "components": 0, "outbox": 0, "audit_events": 0,
	})

	// Positive control: the same command with the real outbox commits the
	// inventory and exactly one matching.rebuild job (the §5 dedupe key).
	ok := newCreateSignalService(pool, repo.NewOutboxRepo(q), clk)
	res, err := ok.CommitInventory(ctx, application.CommitInventoryInput{File: matchingFaultInventoryCSV()})
	if err != nil {
		t.Fatalf("CommitInventory (positive control): %v", err)
	}
	if !res.Changed || res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
		t.Fatalf("positive control report: changed=%v assets=%d components=%d, want 1/1", res.Changed, res.AssetsCreated, res.ComponentsCreated)
	}
	assertTableCounts(t, pool, map[string]int{
		"assets": 1, "components": 1, "outbox": 1, "audit_events": 1,
	})
	var eventType, dedupeKey string
	if err := pool.QueryRow(ctx, "SELECT type, dedupe_key FROM outbox").Scan(&eventType, &dedupeKey); err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	if eventType != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox type = %q, want %q", eventType, application.EventTypeMatchingRebuild)
	}
	if want := application.MatchingRebuildDedupeKey(res.RuleVersion, res.InventorySnapshot); dedupeKey != want {
		t.Fatalf("outbox dedupe_key = %q, want %q", dedupeKey, want)
	}
}
