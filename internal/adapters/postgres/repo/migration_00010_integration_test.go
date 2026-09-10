package repo

// Integration test for migration 00010 — the I5b inventory_imports staging
// table (ARCH-006 §2.1/§7, WP-5b.02 / DEV-098). It proves the acceptance
// criteria: a fresh database migrates through 00010 cleanly, the checksum
// log records version 10, and re-running the runner on the already-migrated
// database is a clean no-op (ADR-010 forward-only / idempotent). The
// generic "an altered applied migration aborts the next run" behaviour is
// proven by the migrate package's TestAlteredAppliedMigrationAborts; this
// test pins that 00010 is applied and logged like every earlier migration.
//
// It uses the shared newI4TestPool helper (i4_integration_test.go, same
// package), which migrates the whole embedded set into a fresh database; it
// skips when no PostgreSQL is reachable.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
)

func TestMigration00010Integration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The fresh migrate applied the whole embedded set: the checksum log
	// records version 10 with a non-empty file hash.
	var hash string
	if err := pool.QueryRow(ctx,
		`SELECT file_hash FROM schema_migration_log WHERE version = 10`).Scan(&hash); err != nil {
		t.Fatalf("checksum log row for version 10: %v", err)
	}
	if hash == "" {
		t.Fatal("checksum log hash for version 10 is empty")
	}

	// The staging table and its lifecycle index exist.
	var tableExists, indexExists bool
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('inventory_imports') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatalf("to_regclass(inventory_imports): %v", err)
	}
	if !tableExists {
		t.Fatal("inventory_imports relation is missing after migration 00010")
	}
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('inventory_imports_status_created_at_idx') IS NOT NULL`).Scan(&indexExists); err != nil {
		t.Fatalf("to_regclass(index): %v", err)
	}
	if !indexExists {
		t.Fatal("inventory_imports_status_created_at_idx is missing after migration 00010")
	}

	// Re-running on the already-migrated database is a clean no-op: nothing
	// pending, nothing applied, the checksum log stays intact (ADR-010).
	dbURL := pool.Config().ConnConfig.ConnString()
	runner, err := migrate.Open(ctx, dbURL, os.DirFS(i4MigrationDir))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer func() { _ = runner.Close() }()

	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("re-migrate an already-migrated database: %v", err)
	}
	if len(res.Applied) != 0 {
		t.Fatalf("re-migrate applied %v, want none", res.Applied)
	}
	if res.Verified < 10 {
		t.Fatalf("re-migrate verified %d migrations, want at least 10", res.Verified)
	}
}
