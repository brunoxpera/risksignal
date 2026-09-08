package main

// Integration tests of the migration wiring at the composition root
// (WP-1a.04): cmd/risksignal is the only place that imports both the embedded
// migration set (db/migrations) and the runner (internal/adapters/postgres/
// migrate); these tests prove the real, embedded migration files migrate an
// empty PostgreSQL database cleanly, that a second run is a no-op and that a
// dry run writes nothing.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the connecting
// user needs CREATEDB. When no database is reachable the tests skip, so
// `go test ./...` stays green on machines without the environment.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// defaultTestDBURL points at the compose db service (compose.yaml, WP-1a.03).
const defaultTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// newTestDB creates a dedicated database for one test case and registers its
// removal. It returns the connection URL of the new database. Tests skip when
// no PostgreSQL is reachable.
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

func TestEmbeddedMigrationsMigrateEmptyDatabaseAndNoopRerun(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()

	// An empty database migrates cleanly (exit criterion WP-1a.04) with the
	// real embedded migration set.
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	if res.DryRun || res.Verified != 0 || len(res.Applied) != 1 || res.Applied[0].Version != 1 {
		t.Fatalf("fresh migrate result = %+v, want exactly one applied migration (version 1)", res)
	}

	// The checksum log holds the version, the file hash and a duration.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var version int64
	var fileHash string
	var appliedAt time.Time
	var duration any
	if err := db.QueryRowContext(ctx2,
		"SELECT version, file_hash, applied_at, duration_ms FROM schema_migration_log").Scan(&version, &fileHash, &appliedAt, &duration); err != nil {
		t.Fatalf("read checksum log: %v", err)
	}
	if version != 1 {
		t.Fatalf("log version = %d, want 1", version)
	}
	embedded, err := fs.ReadFile(migrations.FS, "00001_schema_migration_log.sql")
	if err != nil {
		t.Fatalf("read embedded migration: %v", err)
	}
	sum := sha256.Sum256(embedded)
	if want := hex.EncodeToString(sum[:]); fileHash != want {
		t.Fatalf("log file_hash = %q, want sha256 of the embedded file (%q)", fileHash, want)
	}
	if appliedAt.IsZero() {
		t.Fatal("log applied_at is zero")
	}

	// A second run is a no-op (exit criterion WP-1a.04).
	res, err = runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("rerun migrate: %v", err)
	}
	if len(res.Applied) != 0 || len(res.Recovered) != 0 || res.Verified != 1 {
		t.Fatalf("rerun result = %+v, want no applied/recovered migrations and 1 verified", res)
	}
	var n int
	if err := db.QueryRowContext(ctx2, "SELECT count(*) FROM schema_migration_log").Scan(&n); err != nil {
		t.Fatalf("count schema_migration_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("checksum log rows after rerun = %d, want 1", n)
	}
}

func TestEmbeddedMigrationsDryRunIsReadOnly(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()

	// On an empty database a dry run reports the pending migration and
	// writes nothing — not even goose's own version table.
	res, err := runner.Migrate(ctx, true)
	if err != nil {
		t.Fatalf("dry run on empty database: %v", err)
	}
	if !res.DryRun || len(res.Pending) != 1 || res.Pending[0].Version != 1 || len(res.Applied) != 0 {
		t.Fatalf("dry run result = %+v, want exactly one pending migration (version 1)", res)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var reg *string
	for _, table := range []string{"schema_migration_log", "goose_db_version"} {
		if err := db.QueryRowContext(ctx2, "SELECT to_regclass($1)", table).Scan(&reg); err != nil {
			t.Fatalf("to_regclass(%s): %v", table, err)
		}
		if reg != nil {
			t.Fatalf("dry run created %s", table)
		}
	}

	// The real run applies; the following dry run has nothing left to do.
	if _, err := runner.Migrate(ctx, false); err != nil {
		t.Fatalf("real migrate: %v", err)
	}
	res, err = runner.Migrate(ctx, true)
	if err != nil {
		t.Fatalf("dry run after migrate: %v", err)
	}
	if len(res.Pending) != 0 || res.Verified != 1 {
		t.Fatalf("dry run after migrate = %+v, want no pending and 1 verified", res)
	}
	var n int
	if err := db.QueryRowContext(ctx2, "SELECT count(*) FROM schema_migration_log").Scan(&n); err != nil {
		t.Fatalf("count schema_migration_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("checksum log rows = %d, want 1 (dry run must not write)", n)
	}
}
