package repo

// Integration tests for the WP-6.10 audit-integrity controls (ARCH-007 §7
// control 3, DEV-123): the optional hash chain (AuditRepo.Append stamps
// prev_hash/row_hash; VerifyChain passes untampered and fails after an
// injected edit) and the append-only DB role (risksignal_app is denied
// UPDATE/DELETE on audit_events). They run against a real short-lived
// PostgreSQL database created per test case and migrated with the embedded
// set (migration 00013 creates the roles), and skip when no database is
// reachable — so `go test ./...` stays green without the environment.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// TestAuditHashChainStampsAndVerifies proves the chain: with the chain
// enabled every appended row carries prev_hash/row_hash, VerifyChain passes on
// the untampered trail and fails — naming the row — after an injected edit.
func TestAuditHashChainStampsAndVerifies(t *testing.T) {
	pool := newI4TestPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	repo := NewAuditRepoWithHashChain(q, true)
	appendOne := func(i int) {
		ev := application.AuditEvent{
			AggregateType:    "risk_signal",
			AggregateID:      fmt.Sprintf("00000000-0000-0000-0000-0000000000%02d", i),
			ActorType:        "user",
			ActorID:          "subject-1",
			ActorDisplayName: "Ada Lovelace",
			Action:           fmt.Sprintf("signal.action_%02d", i),
			OccurredAt:       base.Add(time.Duration(i) * time.Minute),
			Before:           json.RawMessage(`{"status":"open","version":1}`),
			After:            json.RawMessage(`{"status":"closed","version":2}`),
			CorrelationID:    fmt.Sprintf("corr-%02d", i),
		}
		if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error { return repo.Append(ctx, tx, ev) }); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		appendOne(i)
	}

	// Every row is stamped with a row_hash; only the first chained row links
	// to NULL (the chain head).
	var unstamped, nullPrev int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE row_hash IS NULL`).Scan(&unstamped); err != nil {
		t.Fatalf("count unstamped: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE prev_hash IS NULL`).Scan(&nullPrev); err != nil {
		t.Fatalf("count null prev: %v", err)
	}
	if unstamped != 0 {
		t.Fatalf("%d rows without a row_hash, want 0", unstamped)
	}
	if nullPrev != 1 {
		t.Fatalf("%d rows with a NULL prev_hash, want exactly 1 (the chain head)", nullPrev)
	}

	st, err := repo.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain on an intact chain: %v", err)
	}
	if st.Rows != 5 || st.Chained != 5 || st.Unchained != 0 {
		t.Fatalf("chain status = %+v, want 5 rows / 5 chained / 0 unchained", st)
	}

	// Inject an edit into the middle row, as the migration superuser (the
	// application role cannot — see the role test), and expect the verify to
	// fail and name that row.
	var id string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM audit_events WHERE action = 'signal.action_02'`).Scan(&id); err != nil {
		t.Fatalf("locate row: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action = 'tampered' WHERE id = $1`, id); err != nil {
		t.Fatalf("inject edit: %v", err)
	}
	_, err = repo.VerifyChain(ctx)
	var mismatch *ChainMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("VerifyChain after an injected edit = %v, want *ChainMismatchError", err)
	}
	if mismatch.RowID != id {
		t.Errorf("mismatch names row %s, want %s", mismatch.RowID, id)
	}
}

// TestAuditHashChainDisabledLeavesRowsUnchained proves the config gate: with
// the chain off the append path is unchanged (no prev_hash/row_hash) and the
// verifier reports an all-unchained, intact trail.
func TestAuditHashChainDisabledLeavesRowsUnchained(t *testing.T) {
	pool := newI4TestPool(t)
	ctx := context.Background()
	repo := NewAuditRepo(gen.New(pool))

	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repo.Append(ctx, tx, application.AuditEvent{
			AggregateType: "risk_signal",
			AggregateID:   "00000000-0000-0000-0000-000000000001",
			ActorType:     "system",
			ActorID:       "seed",
			Action:        "seed.created",
			OccurredAt:    time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
			CorrelationID: "corr",
		})
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	st, err := repo.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if st.Rows != 1 || st.Chained != 0 || st.Unchained != 1 {
		t.Fatalf("chain status = %+v, want 1 row / 0 chained / 1 unchained", st)
	}
}

// TestAuditAppendOnlyRoleDeniesUpdateDelete proves §7 control 3a: as the
// application role (risksignal_app) SELECT and INSERT on audit_events are
// allowed, while UPDATE and DELETE are denied with insufficient_privilege.
func TestAuditAppendOnlyRoleDeniesUpdateDelete(t *testing.T) {
	pool := newI4TestPool(t)
	ctx := context.Background()

	// Seed one audit row as the migration superuser so UPDATE/DELETE have a
	// target.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, action, occurred_at, correlation_id)
		VALUES ('risk_signal', '00000000-0000-0000-0000-000000000001', 'system', 'seed', 'seed.created', now(), 'corr')`); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SET ROLE risksignal_app"); err != nil {
		// The migration creates the role; a non-superuser test login cannot
		// SET ROLE to it and cannot exercise the control.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42501" {
			t.Skipf("cannot SET ROLE risksignal_app (insufficient privilege): %v", err)
		}
		t.Fatalf("set role: %v", err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), "RESET ROLE"); err != nil {
			t.Errorf("reset role: %v", err)
		}
	}()

	// SELECT and INSERT are allowed for the application role.
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatalf("app role SELECT denied: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, action, occurred_at, correlation_id)
		VALUES ('risk_signal', '00000000-0000-0000-0000-000000000002', 'system', 'app', 'app.created', now(), 'corr')`); err != nil {
		t.Fatalf("app role INSERT denied: %v", err)
	}

	// UPDATE and DELETE are denied.
	for _, stmt := range []string{
		`UPDATE audit_events SET action = 'x' WHERE actor_id = 'seed'`,
		`DELETE FROM audit_events WHERE actor_id = 'seed'`,
		`TRUNCATE audit_events`,
	} {
		if _, err := conn.Exec(ctx, stmt); err == nil {
			t.Errorf("app role allowed %q, want insufficient_privilege", stmt)
		} else {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("app role %q error = %v, want SQLSTATE 42501", stmt, err)
			}
		}
	}
}
