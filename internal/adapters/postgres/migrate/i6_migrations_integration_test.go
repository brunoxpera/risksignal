package migrate_test

// Integration test for the I6 migrations applied on an *existing* database
// (ARCH-007 §11, WP-6.02 / DEV-112): a database already migrated through the
// I5b head (00010) must take exactly the two new I6 migrations (00011/00012)
// on the next run, record them in the checksum log, and leave the run
// forward-only. The fresh-database path (all migrations in one run, checksum
// log 00011/00012) is covered by the postgres/repo I6 integration test.
//
// Unlike the synthetic MapFS cases in integration_test.go this test reads the
// real migration files from db/migrations (as the repo integration tests do,
// via a path relative to the package directory — the adapters layer must not
// import db/migrations), applies the subset through 00010 first, then applies
// the full set and asserts only 00011/00012 remain. It skips without a
// reachable database, so `go test ./...` stays green on a bare machine.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// i6MigrationDir is the real migration set, located relative to this package
// directory (go test runs the binary with cwd = the package dir).
const i6MigrationDir = "../../../../db/migrations"

// realMigrationFS reads the real *.sql migrations up to and including maxVersion
// into a MapFS (the runner takes an fs.FS). Filenames are NNNNN_name.sql.
func realMigrationFS(t *testing.T, maxVersion int64) fstest.MapFS {
	t.Helper()
	entries, err := os.ReadDir(i6MigrationDir)
	if err != nil {
		t.Fatalf("read migration dir: %v", err)
	}
	m := fstest.MapFS{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		ver, err := strconv.ParseInt(strings.SplitN(name, "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatalf("parse migration version from %q: %v", name, err)
		}
		if ver > maxVersion {
			continue
		}
		// #nosec G304 — name is an entry of the fixed db/migrations directory
		// read above (os.ReadDir), never caller-controlled; the read mirrors
		// the embedded set the runner ships.
		data, err := os.ReadFile(filepath.Join(i6MigrationDir, name))
		if err != nil {
			t.Fatalf("read migration %q: %v", name, err)
		}
		m[name] = &fstest.MapFile{Data: data}
	}
	return m
}

func TestI6IncrementalMigrationOnExistingDatabase(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 1. Migrate an existing database through the I5b head (00010).
	head := openRunner(t, ctx, dbURL, realMigrationFS(t, 10))
	res, err := head.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("migrate through 00010: %v", err)
	}
	if len(res.Applied) != 10 {
		t.Fatalf("applied through 00010 = %d, want 10", len(res.Applied))
	}

	// 2. Apply the full set on the *existing* database: only 00011/00012 are new.
	full := openRunner(t, ctx, dbURL, realMigrationFS(t, 12))
	res2, err := full.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("migrate 00011/00012 on existing database: %v", err)
	}
	if len(res2.Applied) != 2 || res2.Applied[0].Version != 11 || res2.Applied[1].Version != 12 {
		t.Fatalf("incremental applied = %+v, want exactly versions 11 and 12", res2.Applied)
	}

	// 3. The checksum log records both new versions, and a third run is a no-op.
	assertLoggedVersions(t, dbURL, 11, 12)
	res3, err := full.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("third migrate run: %v", err)
	}
	if len(res3.Applied) != 0 {
		t.Fatalf("third run applied = %+v, want none (idempotent)", res3.Applied)
	}

	// 4. The I6 tables exist on the migrated database.
	for _, table := range []string{"legal_holds", "retention_runs", "exports"} {
		if !tableExists(t, dbURL, table) {
			t.Fatalf("I6 table %q missing after migration", table)
		}
	}
}

// assertLoggedVersions asserts the checksum log records every given version.
func assertLoggedVersions(t *testing.T, dbURL string, versions ...int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db := openSQL(t, dbURL)
	defer db.Close()
	for _, v := range versions {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migration_log WHERE version = $1", v).Scan(&n); err != nil {
			t.Fatalf("count checksum log for version %d: %v", v, err)
		}
		if n != 1 {
			t.Fatalf("checksum log rows for version %d = %d, want 1", v, n)
		}
	}
}

// tableExists reports whether a public table is present.
func tableExists(t *testing.T, dbURL, table string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db := openSQL(t, dbURL)
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1", table).Scan(&n); err != nil {
		t.Fatalf("table exists check %q: %v", table, err)
	}
	return n == 1
}

// openSQL opens a database/sql handle for the checksum/table assertions.
func openSQL(t *testing.T, dbURL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open %s: %v", dbURL, err)
	}
	return db
}
