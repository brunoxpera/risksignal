package main

// Integration test of the WP-1b.03 audit_events + outbox schema and sqlc
// queries (DEV-017) at the composition root. cmd/risksignal is the
// composition root that may wire the embedded migration set (db/migrations)
// together with the postgres adapter (the architecture gate keeps
// db/migrations out of internal/adapters/** — `make lint-arch` enforces
// that), so the schema and query round trip is exercised here.
//
// The test drives the exit criteria of WP-1b.03 on a real, short-lived
// PostgreSQL: a fresh database migrates cleanly with the full embedded set
// (00003 included), then the audit + outbox write path is proven end to end:
//   (a) the same-transaction append of an audit event and an outbox row via
//       WithTx commits both rows together (ch. 5.1: state change, audit and
//       outbox are one transaction);
//   (b) the claim transitions the row pending -> claimed with a fresh lease
//       and an incremented attempts counter, and the guarded ack transitions
//       it claimed -> done exactly once — a second ack is a no-op;
//   (c) a lease-expiry reclaim (a row stuck in claimed after a simulated
//       crashed worker) is returned for redelivery with attempts + 1, and
//       the ack after the redelivery still leaves exactly one done row
//       (at-least-once delivery, ARCH-001 §2, TAT-05);
//   (d) dead-letter records the error on a claimed row and the guarded ack
//       cannot touch a terminal row.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.
//
// Clock note: audit occurred_at and outbox created_at come from the fixed
// test clock (the data path never reads the wall clock, ch. 7.2). The claim,
// lease and reclaim mechanics, however, compare against the database clock
// by design — ARCH-001 §2 evaluates available_at <= now() and
// lease_until < now() in SQL — so rows written for the relay phases use
// now()-relative timestamps and the lease expiry is forced with a SQL
// UPDATE, keeping the assertions free of host/container clock skew.

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// mustUUID scans a canonical uuid string into the pgtype.UUID the generated
// queries use for uuid columns.
func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("scan uuid %q: %v", s, err)
	}
	return u
}

// dueNow returns a timestamptz in the recent past relative to the database
// clock, so the row is claimable immediately (available_at <= now()). The
// claim mechanics are DB-clock-referential by design (ARCH-001 §2), which is
// why the relay-phase rows cannot use the fixed test clock.
func dueNow() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
}

// wantOutboxPayload is the event payload the relay-phase rows carry
// (ARCH-001 §2 event shape, minus the fields that only exist once the row id
// is known); jsonb round-trips through the database, so assertions decode
// both sides instead of comparing bytes.
var wantOutboxPayload = map[string]any{
	"signal_id": "sig-017",
	"priority":  "P1",
}

func TestAuditAndOutboxAppendClaimAckAndLeaseReclaim(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A fresh database migrates cleanly with the full embedded set — 00003
	// included — so the tables exist exactly as ARCH-001 §1 declares them.
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

	// --- (a) same-transaction append of audit + outbox (ch. 5.1) -----------
	// The command runs inside WithTx and performs the audit append and the
	// outbox append on the same pgx.Tx; both commit together (ARCH-001 §2).
	occurred := mustTS(t, "2026-09-09T09:00:00Z")
	correlationID := "corr-017-1"
	var outboxID pgtype.UUID
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		qtx := gen.New(pool).WithTx(tx)
		if _, err := qtx.InsertAuditEvent(ctx, gen.InsertAuditEventParams{
			AggregateType:    "risk_signal",
			AggregateID:      mustUUID(t, "11111111-1111-1111-1111-111111111111"),
			ActorType:        "system",
			ActorID:          "demo-seed",
			ActorDisplayName: pgtype.Text{},
			Action:           "signal.created",
			OccurredAt:       occurred,
			Before:           nil,
			After:            []byte(`{"priority": "P1", "status": "new"}`),
			CorrelationID:    correlationID,
		}); err != nil {
			return err
		}
		row, err := qtx.AppendOutbox(ctx, gen.AppendOutboxParams{
			Type:        "signal.created",
			Payload:     []byte(`{"signal_id": "sig-017", "priority": "P1"}`),
			AvailableAt: dueNow(),
			DedupeKey:   "signal.created:sig-017",
			CreatedAt:   occurred,
		})
		if err != nil {
			return err
		}
		if row.Status != "pending" || row.Attempts != 0 {
			t.Fatalf("AppendOutbox returned status %q attempts %d, want pending/0", row.Status, row.Attempts)
		}
		outboxID = row.ID
		return nil
	}); err != nil {
		t.Fatalf("WithTx append audit + outbox: %v", err)
	}

	// After commit both rows are present, linked by the correlation id, and
	// the outbox row entered the queue pending with its dedupe key.
	var auditCount int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_events WHERE correlation_id = $1", correlationID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit_events: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit_events after commit = %d, want 1", auditCount)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		 WHERE id = (SELECT id FROM audit_events WHERE correlation_id = $1)
		   AND aggregate_type = 'risk_signal' AND action = 'signal.created'
		   AND actor_type = 'system' AND actor_id = 'demo-seed'
		   AND occurred_at = $2 AND after = '{"priority": "P1", "status": "new"}'::jsonb`,
		correlationID, occurred).Scan(&auditCount); err != nil {
		t.Fatalf("read audit_events row: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit_events row content mismatch (count %d), want the appended event", auditCount)
	}
	var outboxCount int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE id = $1 AND status = 'pending' AND dedupe_key = 'signal.created:sig-017'",
		outboxID).Scan(&outboxCount); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox after commit = %d, want 1 pending row with the dedupe key", outboxCount)
	}

	// --- (b) claim -> ack (pending -> claimed -> done) ---------------------
	// The ARCH-001 §2 drain claim returns the due row with attempts 1 and a
	// fresh 60s lease; the guarded ack completes the delivery exactly once.
	claimed, err := q.ClaimOutboxBatch(ctx, 50)
	if err != nil {
		t.Fatalf("ClaimOutboxBatch: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != outboxID {
		t.Fatalf("ClaimOutboxBatch = %+v, want exactly the appended row %v", claimed, outboxID)
	}
	row := claimed[0]
	if row.Type != "signal.created" || row.Attempts != 1 {
		t.Fatalf("claim returned type %q attempts %d, want signal.created/1", row.Type, row.Attempts)
	}
	var gotPayload map[string]any
	if err := json.Unmarshal(row.Payload, &gotPayload); err != nil {
		t.Fatalf("decode claimed payload: %v", err)
	}
	if !reflect.DeepEqual(gotPayload, wantOutboxPayload) {
		t.Fatalf("claimed payload = %v, want %v", gotPayload, wantOutboxPayload)
	}
	var leased bool
	if err := pool.QueryRow(ctx,
		"SELECT status = 'claimed' AND lease_until IS NOT NULL AND lease_until > now() FROM outbox WHERE id = $1",
		outboxID).Scan(&leased); err != nil {
		t.Fatalf("read claimed lease: %v", err)
	}
	if !leased {
		t.Fatal("claim did not set status=claimed with a lease_until in the future")
	}

	acked, err := q.AckOutbox(ctx, outboxID)
	if err != nil {
		t.Fatalf("AckOutbox: %v", err)
	}
	if acked != 1 {
		t.Fatalf("AckOutbox affected %d row(s), want 1", acked)
	}
	if again, err := q.AckOutbox(ctx, outboxID); err != nil || again != 0 {
		t.Fatalf("second AckOutbox = %d, %v; want 0 (double dispatch must not double-ack)", again, err)
	}
	var doneCount int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE id = $1 AND status = 'done'", outboxID).Scan(&doneCount); err != nil {
		t.Fatalf("count done outbox rows: %v", err)
	}
	if doneCount != 1 {
		t.Fatalf("done outbox rows after double ack = %d, want exactly 1", doneCount)
	}
	if leftover, err := q.ClaimOutboxBatch(ctx, 50); err != nil || len(leftover) != 0 {
		t.Fatalf("ClaimOutboxBatch after ack = %+v, %v; want no due rows", leftover, err)
	}

	// --- (c) lease-expiry reclaim (crash recovery, TAT-05) -----------------
	// A second event is claimed and then lost to a simulated crash: the row
	// stays claimed with an expired lease. The reclaim returns it for
	// redelivery with attempts + 1 and a fresh lease; the ack after the
	// redelivery still leaves exactly one done row.
	var lostID pgtype.UUID
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		row, err := gen.New(pool).WithTx(tx).AppendOutbox(ctx, gen.AppendOutboxParams{
			Type:        "signal.created",
			Payload:     []byte(`{"signal_id": "sig-017", "priority": "P1"}`),
			AvailableAt: dueNow(),
			DedupeKey:   "signal.created:sig-017-2",
			CreatedAt:   occurred,
		})
		if err != nil {
			return err
		}
		lostID = row.ID
		return nil
	}); err != nil {
		t.Fatalf("WithTx append second outbox row: %v", err)
	}
	first, err := q.ClaimOutboxBatch(ctx, 50)
	if err != nil || len(first) != 1 || first[0].ID != lostID {
		t.Fatalf("ClaimOutboxBatch (second row) = %+v, %v; want exactly %v", first, err, lostID)
	}
	if first[0].Attempts != 1 {
		t.Fatalf("first claim attempts = %d, want 1", first[0].Attempts)
	}
	// The worker dies before the ack: force the lease into the past exactly
	// as time would (SQL-side, so no host/container clock skew enters the
	// assertion).
	if _, err := pool.Exec(ctx,
		"UPDATE outbox SET lease_until = now() - interval '1 second' WHERE id = $1", lostID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	reclaimed, err := q.ReclaimExpiredOutboxLeases(ctx, 50)
	if err != nil {
		t.Fatalf("ReclaimExpiredOutboxLeases: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].ID != lostID {
		t.Fatalf("ReclaimExpiredOutboxLeases = %+v, want the lost row %v back for redelivery", reclaimed, lostID)
	}
	if reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaim attempts = %d, want 2 (the lease expiry counts as a delivery attempt)", reclaimed[0].Attempts)
	}
	if renewed, err := pool.Query(ctx,
		"SELECT lease_until > now() FROM outbox WHERE id = $1 AND status = 'claimed'", lostID); err != nil {
		t.Fatalf("read renewed lease: %v", err)
	} else {
		var ok bool
		if renewed.Next() {
			if err := renewed.Scan(&ok); err != nil {
				t.Fatalf("scan renewed lease: %v", err)
			}
		}
		renewed.Close()
		if !ok {
			t.Fatal("reclaim did not renew the lease (status=claimed, lease_until in the future)")
		}
	}

	if acked, err := q.AckOutbox(ctx, lostID); err != nil || acked != 1 {
		t.Fatalf("AckOutbox after reclaim = %d, %v; want 1", acked, err)
	}
	if again, err := q.AckOutbox(ctx, lostID); err != nil || again != 0 {
		t.Fatalf("second AckOutbox after reclaim = %d, %v; want 0", again, err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE id = $1 AND status = 'done'", lostID).Scan(&doneCount); err != nil {
		t.Fatalf("count done after redelivery: %v", err)
	}
	if doneCount != 1 {
		t.Fatalf("done outbox rows after redelivery + double ack = %d, want exactly 1", doneCount)
	}
	if leftover, err := q.ReclaimExpiredOutboxLeases(ctx, 50); err != nil || len(leftover) != 0 {
		t.Fatalf("ReclaimExpiredOutboxLeases after ack = %+v, %v; want no expired leases", leftover, err)
	}

	// --- (d) dead-letter (ch. 14.2 groundwork) -----------------------------
	// A claimed row that fails permanently is marked dead_letter with the
	// recorded error; the ack guard then refuses to touch the terminal row.
	var deadID pgtype.UUID
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		row, err := gen.New(pool).WithTx(tx).AppendOutbox(ctx, gen.AppendOutboxParams{
			Type:        "signal.created",
			Payload:     []byte(`{"signal_id": "sig-017", "priority": "P1"}`),
			AvailableAt: dueNow(),
			DedupeKey:   "signal.created:sig-017-3",
			CreatedAt:   occurred,
		})
		if err != nil {
			return err
		}
		deadID = row.ID
		return nil
	}); err != nil {
		t.Fatalf("WithTx append third outbox row: %v", err)
	}
	if claimed, err := q.ClaimOutboxBatch(ctx, 50); err != nil || len(claimed) != 1 || claimed[0].ID != deadID {
		t.Fatalf("ClaimOutboxBatch (third row) = %+v, %v; want exactly %v", claimed, err, deadID)
	}
	marked, err := q.DeadLetterOutbox(ctx, gen.DeadLetterOutboxParams{
		ID:        deadID,
		LastError: pgtype.Text{String: "delivery failed: 500", Valid: true},
	})
	if err != nil {
		t.Fatalf("DeadLetterOutbox: %v", err)
	}
	if marked != 1 {
		t.Fatalf("DeadLetterOutbox affected %d row(s), want 1", marked)
	}
	var status, lastError string
	if err := pool.QueryRow(ctx,
		"SELECT status, last_error FROM outbox WHERE id = $1", deadID).Scan(&status, &lastError); err != nil {
		t.Fatalf("read dead-letter row: %v", err)
	}
	if status != "dead_letter" || lastError != "delivery failed: 500" {
		t.Fatalf("dead-letter row = %s/%q, want dead_letter with the recorded error", status, lastError)
	}
	if acked, err := q.AckOutbox(ctx, deadID); err != nil || acked != 0 {
		t.Fatalf("AckOutbox on dead_letter row = %d, %v; want 0 (guarded, terminal rows stay terminal)", acked, err)
	}
}
