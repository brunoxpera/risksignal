package main

// Integration test of the WP-1b.06 outbox relay (DEV-020) at the
// composition root: cmd/risksignal-worker is where the embedded migration
// set (db/migrations) is wired together with the postgres adapter and the
// worker relay (the architecture gate keeps db/migrations out of
// internal/adapters/** — `make lint-arch` enforces that), so the full relay
// drain lifecycle is exercised here against a real, short-lived PostgreSQL.
//
// The test drives the exit criterion of WP-1b.06 end to end through the
// real wiring of the relay: the postgres store (repo.OutboxRelay over the
// WP-1b.03 claim/ack/dead-letter statements), the worker relay with the
// signal.created sink registered on its dispatch registry, and the
// ARCH-001 §2 drain semantics:
//
//   (a) an event appended in-transaction (pending) is claimed, dispatched
//       to the sink and acked by one drain: pending -> claimed -> done with
//       exactly one done row — the event is delivered exactly once after
//       commit;
//   (b) a redelivery: a row claimed by a worker that crashes before the ack
//       (status 'claimed', lease expired) is re-claimed by the next drain
//       with attempts + 1, re-dispatched and acked — still exactly one done
//       row, and a further drain has nothing to claim (at-least-once
//       delivery, idempotent on the immutable outbox.id, ARCH-001 §2 /
//       TAT-05);
//   (c) an event type without a registered handler dead-letters with a
//       clear last_error instead of failing the drain (handler registry).
//
// Like the other integration tests it skips when no PostgreSQL is
// reachable. The relay phases are DB-clock-referential by design (ARCH-001
// §2 evaluates available_at <= now() and lease_until < now() in SQL), so
// rows written for the relay phases use now()-relative timestamps and the
// lease expiry is forced with a SQL UPDATE — the same convention as the
// WP-1b.03 tests in cmd/risksignal.

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
)

// defaultTestDBURL points at the compose db service (compose.yaml, WP-1a.03).
const defaultTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// embeddedVersions returns the version list of the embedded migration set
// (duplicated here because test helpers cannot be shared across _test
// packages; the same helper lives in cmd/risksignal).
func embeddedVersions(t *testing.T) []int64 {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	versions := make([]int64, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration file %q has no version prefix", name)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration file %q: invalid version prefix: %v", name, err)
		}
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions
}

// newTestDB creates a dedicated database for one test case and registers
// its removal. It returns the connection URL of the new database. Tests
// skip when no PostgreSQL is reachable.
func newTestDB(t *testing.T) string {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = defaultTestDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Skipf("integration database not reachable (set RISKSIGNAL_TEST_DATABASE_URL): %v", err)
	}

	name := fmt.Sprintf("risksignal_it_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		_ = admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// discardLogger keeps the relay quiet in the state assertions.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// dueNow returns a timestamptz in the recent past relative to the database
// clock, so the row is claimable immediately (available_at <= now()). The
// claim mechanics are DB-clock-referential by design (ARCH-001 §2), which
// is why the relay-phase rows cannot use a fixed test clock.
func dueNow() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
}

// outboxState is the observable state of one outbox row.
type outboxState struct {
	status    string
	attempts  int
	lastError pgtype.Text
}

// readOutbox reads the current status, attempts and last_error of one
// outbox row.
func readOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id pgtype.UUID) outboxState {
	t.Helper()
	var st outboxState
	if err := pool.QueryRow(ctx,
		"SELECT status, attempts, last_error FROM outbox WHERE id = $1", id).
		Scan(&st.status, &st.attempts, &st.lastError); err != nil {
		t.Fatalf("read outbox row %s: %v", id, err)
	}
	return st
}

// TestOutboxRelayDrainDeliversOnceAndRedeliveryIsIdempotent drives the
// WP-1b.06 exit criterion through the real composition of relay store +
// relay + sink against a fresh, fully migrated database (see the file
// comment for the phase descriptions).
func TestOutboxRelayDrainDeliversOnceAndRedeliveryIsIdempotent(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A fresh database migrates cleanly with the full embedded set — 00003
	// (audit_events + outbox) included — so the relay operates on the exact
	// ARCH-001 §1 schema.
	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	want := embeddedVersions(t)
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	if len(res.Applied) != len(want) {
		t.Fatalf("fresh migrate applied %d migration(s), want the full embedded set %v", len(res.Applied), want)
	}
	for i, v := range want {
		if res.Applied[i].Version != v {
			t.Fatalf("fresh migrate applied %+v, want versions %v in order", res.Applied, want)
		}
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := gen.New(pool)

	// The production wiring of runWithContext: the postgres relay store
	// behind the worker relay, with the signal.created sink registered on
	// its dispatch registry. The test wraps the sink in a counter so the
	// number of dispatches is observable.
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), discardLogger())
	if err != nil {
		t.Fatalf("worker.NewRelay: %v", err)
	}
	var sinkCalls atomic.Int32
	realSink := worker.SignalCreatedSink(discardLogger())
	if err := relay.Register(application.EventTypeSignalCreated, worker.Handler(func(ctx context.Context, ev worker.ClaimedEvent) error {
		sinkCalls.Add(1)
		return realSink(ctx, ev)
	})); err != nil {
		t.Fatalf("relay.Register: %v", err)
	}

	// append appends one outbox row in-transaction — exactly how the
	// CreateSignal command writes the signal.created event (ARCH-001 §2:
	// the row commits atomically with its state change; delivery happens
	// only after commit).
	appendEvent := func(t *testing.T, eventType, signalID string) gen.Outbox {
		t.Helper()
		var row gen.Outbox
		err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
			inserted, err := gen.New(pool).WithTx(tx).AppendOutbox(ctx, gen.AppendOutboxParams{
				Type:        eventType,
				Payload:     []byte(`{"type": "` + eventType + `", "signal_id": "` + signalID + `", "priority": "P1", "occurred_at": "2026-09-09T09:00:00Z", "correlation_id": "corr-020"}`),
				AvailableAt: dueNow(),
				DedupeKey:   "signal.created:" + signalID,
				CreatedAt:   pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC), Valid: true},
			})
			if err != nil {
				return err
			}
			row = inserted
			return nil
		})
		if err != nil {
			t.Fatalf("append %s event in-transaction: %v", eventType, err)
		}
		if row.Status != "pending" || row.Attempts != 0 {
			t.Fatalf("appended row = status %q attempts %d, want pending/0", row.Status, row.Attempts)
		}
		return row
	}

	// --- (a) pending -> claimed -> done through one drain -----------------
	// An event written in-transaction is delivered exactly once after
	// commit: one drain claims it (attempts 1, lease held), dispatches it
	// to the sink and acks it — the row ends terminal 'done'.
	first := appendEvent(t, application.EventTypeSignalCreated, "sig-020-1")
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if sinkCalls.Load() != 1 {
		t.Fatalf("sink dispatches after first drain = %d, want 1", sinkCalls.Load())
	}
	if st := readOutbox(t, ctx, pool, first.ID); st.status != "done" || st.attempts != 1 {
		t.Fatalf("first event after drain = status %q attempts %d, want done/1", st.status, st.attempts)
	}
	var doneCount int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE id = $1 AND status = 'done'", first.ID).Scan(&doneCount); err != nil {
		t.Fatalf("count done rows: %v", err)
	}
	if doneCount != 1 {
		t.Fatalf("done rows of the first event = %d, want exactly 1", doneCount)
	}

	// --- (b) lease-expiry redelivery is idempotent ------------------------
	// A second event is claimed by a worker that crashes before the ack:
	// the row sits in 'claimed' with a fresh lease and attempts 1. The test
	// then expires the lease (SQL-side, as time would) and runs the next
	// drain: the claim re-claims the row with attempts 2, the sink
	// dispatches it again and the guarded ack completes it — still exactly
	// one done row, no duplicate effect (at-least-once, TAT-05).
	second := appendEvent(t, application.EventTypeSignalCreated, "sig-020-2")
	claimed, err := q.ClaimOutboxBatch(ctx, 50)
	if err != nil {
		t.Fatalf("ClaimOutboxBatch (crashed worker): %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != second.ID {
		t.Fatalf("ClaimOutboxBatch = %+v, want exactly the second event %v", claimed, second.ID)
	}
	if claimed[0].Attempts != 1 {
		t.Fatalf("crash-claim attempts = %d, want 1", claimed[0].Attempts)
	}
	if st := readOutbox(t, ctx, pool, second.ID); st.status != "claimed" {
		t.Fatalf("crashed event = status %q, want claimed before the lease expires", st.status)
	}
	var leased bool
	if err := pool.QueryRow(ctx,
		"SELECT lease_until IS NOT NULL AND lease_until > now() FROM outbox WHERE id = $1", second.ID).
		Scan(&leased); err != nil {
		t.Fatalf("read crash-claim lease: %v", err)
	}
	if !leased {
		t.Fatal("crash-claim did not hold a fresh lease (status claimed, lease_until in the future)")
	}
	if _, err := pool.Exec(ctx,
		"UPDATE outbox SET lease_until = now() - interval '1 second' WHERE id = $1", second.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	if sinkCalls.Load() != 2 {
		t.Fatalf("sink dispatches after redelivery = %d, want 2 (the event was dispatched twice in total)", sinkCalls.Load())
	}
	if st := readOutbox(t, ctx, pool, second.ID); st.status != "done" || st.attempts != 2 {
		t.Fatalf("redelivered event = status %q attempts %d, want done/2", st.status, st.attempts)
	}
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE id = $1 AND status = 'done'", second.ID).Scan(&doneCount); err != nil {
		t.Fatalf("count done rows after redelivery: %v", err)
	}
	if doneCount != 1 {
		t.Fatalf("done rows of the redelivered event = %d, want exactly 1 (idempotent delivery)", doneCount)
	}

	// A further drain has nothing to claim: both events are terminal.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("idle drain: %v", err)
	}
	if sinkCalls.Load() != 2 {
		t.Fatalf("sink dispatches after idle drain = %d, want 2 (terminal rows are not redelivered)", sinkCalls.Load())
	}

	// --- (c) unregistered type dead-letters without failing the drain -----
	// A claimed event whose type has no registered handler (a future job
	// type) must not crash the drain: the row is dead-lettered with a clear
	// last_error, and the sink is not involved.
	third := appendEvent(t, "i2.unknown.job", "sig-020-3")
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("unknown-type drain returned %v, want nil (registry miss must not fail the drain)", err)
	}
	if sinkCalls.Load() != 2 {
		t.Fatalf("sink dispatches after unknown-type drain = %d, want 2", sinkCalls.Load())
	}
	st := readOutbox(t, ctx, pool, third.ID)
	if st.status != "dead_letter" || st.attempts != 1 {
		t.Fatalf("unknown-type event = status %q attempts %d, want dead_letter/1", st.status, st.attempts)
	}
	if !st.lastError.Valid || !strings.Contains(st.lastError.String, `no handler registered for outbox type "i2.unknown.job"`) {
		t.Fatalf("unknown-type last_error = %v, want a clear message naming the type", st.lastError)
	}

	// Final ledger: two events delivered (done), one dead-lettered — no row
	// left pending or claimed.
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE status IN ('pending', 'claimed')").Scan(&doneCount); err != nil {
		t.Fatalf("count unfinished outbox rows: %v", err)
	}
	if doneCount != 0 {
		t.Fatalf("outbox rows left pending or claimed = %d, want 0", doneCount)
	}
}
