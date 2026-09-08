package postgres_test

// Integration tests for the pgx pool, the sqlc-generated anchor query and the
// transaction helper (WP-1a.05, ADR-009). They run against a real,
// short-lived PostgreSQL database created per test case and dropped
// afterwards.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the connecting
// user needs CREATEDB. When no database is reachable the tests skip, so
// `go test ./...` stays green on machines without the environment. The
// scratch-database pattern is the one introduced by the migrate integration
// tests (WP-1a.04); it is duplicated here because test helpers cannot be
// shared across _test packages.
//
// The scratch database is used as a plain PostgreSQL target: the production
// migrations are exercised by the migrate integration tests (WP-1a.04), and
// the embedded migration files under db/migrations are wired in only by the
// composition roots (cmd) — the arch gate whitelists exactly that, and this
// test package must not import db/migrations. The transaction tests create a
// table of their own on the short-lived database.
//
// These tests exercise the whole data-access path of this work package:
// OpenPool connects and pings, the generated HealthCheck query runs through
// the sqlc-generated code, and WithTx commits and rolls back against the real
// database. Access is pgx/v5 throughout — no database/sql anywhere in this
// package (ADR-009).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
)

// defaultTestDBURL points at the compose db service (compose.yaml, WP-1a.03).
const defaultTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// newTestPool creates a dedicated database for one test case, opens the pool
// under test on it and registers both for cleanup (the pool is closed before
// the database is dropped). Tests skip when no PostgreSQL is reachable.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = defaultTestDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("integration database not reachable (set RISKSIGNAL_TEST_DATABASE_URL): %v", err)
	}

	name := fmt.Sprintf("risksignal_it_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	u.Path = "/" + name

	pool, err := postgres.OpenPool(ctx, u.String())
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestOpenPoolPingsAndRunsGeneratedHealthCheck(t *testing.T) {
	// Exit criterion WP-1a.05: the pool opens against a real database, the
	// startup ping succeeds, and the sqlc-generated anchor query runs
	// through the generated code.
	pool := newTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping: %v", err)
	}

	got, err := gen.New(pool).HealthCheck(ctx)
	if err != nil {
		t.Fatalf("generated HealthCheck query: %v", err)
	}
	if got != 1 {
		t.Fatalf("HealthCheck returned %d, want 1", got)
	}
}

// probeTable is a scratch table for the transaction tests, created directly
// on the test pool (this package never ships DDL; the test database is
// short-lived and contains nothing else).
const probeTable = "CREATE TABLE tx_probe (id INTEGER PRIMARY KEY, note TEXT NOT NULL)"

func countProbeRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM tx_probe").Scan(&n); err != nil {
		t.Fatalf("count tx_probe rows: %v", err)
	}
	return n
}

func TestWithTxCommitsOnSuccess(t *testing.T) {
	pool := newTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, probeTable); err != nil {
		t.Fatalf("create tx_probe: %v", err)
	}

	err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO tx_probe (id, note) VALUES ($1, $2)", 1, "committed")
		return err
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if n := countProbeRows(t, ctx, pool); n != 1 {
		t.Fatalf("rows after committed transaction = %d, want 1", n)
	}
}

func TestWithTxRollsBackOnError(t *testing.T) {
	// A failing domain command must leave no trace: the state change of a
	// command is atomic (concept ch. 5.1), and the caller must be able to
	// classify the original error (concept ch. 5.2).
	pool := newTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, probeTable); err != nil {
		t.Fatalf("create tx_probe: %v", err)
	}

	domainErr := errors.New("domain command rejected the change")
	err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO tx_probe (id, note) VALUES ($1, $2)", 1, "rolled back"); err != nil {
			return err
		}
		return domainErr
	})
	if !errors.Is(err, domainErr) {
		t.Fatalf("WithTx returned %v, want the original domain error (errors.Is)", err)
	}
	if n := countProbeRows(t, ctx, pool); n != 0 {
		t.Fatalf("rows after rolled-back transaction = %d, want 0", n)
	}
}
