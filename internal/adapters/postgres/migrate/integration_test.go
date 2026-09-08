package migrate_test

// Integration tests for the checksum-guarded migration runner (WP-1a.04,
// ADR-010). They run against a real, short-lived PostgreSQL database created
// per test case and dropped afterwards.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the connecting
// user needs CREATEDB. When no database is reachable the tests skip, so
// `go test ./...` stays green on machines without the environment.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

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

// openRunner connects a runner to dbURL.
func openRunner(t *testing.T, ctx context.Context, dbURL string, fsys fs.FS) *migrate.Runner {
	t.Helper()
	runner, err := migrate.Open(ctx, dbURL, fsys)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	t.Cleanup(func() { _ = runner.Close() })
	return runner
}

// testMigrations returns a base set of two migrations that mirrors the
// production shape: the first migration creates the checksum-log table
// (schema_migration_log) exactly like db/migrations/00001 does; tests mutate
// the map to simulate altered or broken files.
func testMigrations() fstest.MapFS {
	return fstest.MapFS{
		"00001_first.sql": {Data: []byte(`-- +goose Up
CREATE TABLE schema_migration_log (
    version     BIGINT      NOT NULL,
    file_hash   TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms BIGINT,
    CONSTRAINT schema_migration_log_version_key UNIQUE (version)
);
CREATE TABLE first_table (id BIGINT NOT NULL);
`)},
		"00002_second.sql": {Data: []byte(`-- +goose Up
CREATE TABLE second_table (id BIGINT NOT NULL);
`)},
	}
}

// countLogRows returns the number of checksum-log rows for the database.
func countLogRows(t *testing.T, dbURL string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migration_log").Scan(&n); err != nil {
		t.Fatalf("count schema_migration_log: %v", err)
	}
	return n
}

func TestAlteredAppliedMigrationAborts(t *testing.T) {
	// Negative test, exit criterion WP-1a.04: retroactively altering an
	// already-applied migration prevents the next run.
	fsys := testMigrations()
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := openRunner(t, ctx, dbURL, fsys)

	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 2 {
		t.Fatalf("apply two migrations: res=%+v err=%v", res, err)
	}

	// Tamper with the second, already-applied migration file.
	original := fsys["00002_second.sql"].Data
	fsys["00002_second.sql"] = &fstest.MapFile{Data: append(original, []byte("-- retroactive edit\n")...)}

	_, err := runner.Migrate(ctx, false)
	var cerr *migrate.ChecksumError
	if !errors.As(err, &cerr) {
		t.Fatalf("migrate with altered migration: err = %v, want *migrate.ChecksumError", err)
	}
	if cerr.Version != 2 || cerr.Path != "00002_second.sql" {
		t.Fatalf("ChecksumError = %+v, want version 2 / 00002_second.sql", cerr)
	}
	if !strings.Contains(err.Error(), "modified after it was applied") {
		t.Fatalf("error message = %q, want the immutable-migration wording", err)
	}
	// Nothing changed in the database: the abort happened before goose ran.
	if n := countLogRows(t, dbURL); n != 2 {
		t.Fatalf("checksum log rows after abort = %d, want 2", n)
	}

	// A dry run refuses exactly the same way.
	if _, err := runner.Migrate(ctx, true); err == nil {
		t.Fatal("dry run with altered migration: expected checksum error")
	}

	// Restoring the file heals; deleting the applied file is detected next.
	fsys["00002_second.sql"] = &fstest.MapFile{Data: original}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 0 {
		t.Fatalf("migrate after restore: res=%+v err=%v", res, err)
	}
	delete(fsys, "00002_second.sql")
	_, err = runner.Migrate(ctx, false)
	var merr *migrate.MigrationMissingError
	if !errors.As(err, &merr) || merr.Version != 2 {
		t.Fatalf("migrate with deleted applied migration: err = %v, want *migrate.MigrationMissingError for version 2", err)
	}
}

func TestConcurrentRunsSerialize(t *testing.T) {
	// Exit criterion WP-1a.04: concurrent runs block each other via the
	// PostgreSQL advisory lock goose takes while migrating.
	sleep := testMigrations()
	// Make the first migration slow enough that both runners provably
	// overlap while the lock is held. The bootstrap of the checksum-log
	// table stays part of the first migration, as in production.
	sleep["00001_first.sql"] = &fstest.MapFile{Data: []byte(`-- +goose Up
CREATE TABLE schema_migration_log (
    version     BIGINT      NOT NULL,
    file_hash   TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms BIGINT,
    CONSTRAINT schema_migration_log_version_key UNIQUE (version)
);
SELECT pg_sleep(1.5);
CREATE TABLE first_table (id BIGINT NOT NULL);
`)}

	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	runnerA := openRunner(t, ctx, dbURL, sleep)
	runnerB := openRunner(t, ctx, dbURL, sleep)

	type outcome struct {
		res *migrate.Result
		err error
	}
	run := func(r *migrate.Runner) outcome {
		res, err := r.Migrate(ctx, false)
		return outcome{res, err}
	}

	start := time.Now()
	chA := make(chan outcome, 1)
	chB := make(chan outcome, 1)
	go func() { chA <- run(runnerA) }()
	go func() { chB <- run(runnerB) }()
	oa, ob := <-chA, <-chB
	elapsed := time.Since(start)
	t.Logf("two concurrent runs finished after %s (single slow migration sleeps 1.5s)", elapsed.Round(time.Millisecond))

	if oa.err != nil {
		t.Fatalf("runner A: %v", oa.err)
	}
	if ob.err != nil {
		t.Fatalf("runner B: %v", ob.err)
	}
	// Exactly one runner applies; the other finds nothing left and becomes a
	// no-op. Without the advisory lock both would collide (second CREATE
	// TABLE fails) or one would double-apply.
	appliedA, appliedB := len(oa.res.Applied), len(ob.res.Applied)
	if (appliedA != 2 || appliedB != 0) && (appliedA != 0 || appliedB != 2) {
		t.Fatalf("applied counts = %d and %d, want exactly one runner applying both migrations", appliedA, appliedB)
	}
	// The blocked runner waits for the lock (goose re-probes every 5s), so
	// the concurrent pair takes measurably longer than a single run.
	if elapsed < 4*time.Second {
		t.Fatalf("concurrent runs finished after %s — the second run did not wait for the advisory lock", elapsed.Round(time.Millisecond))
	}

	// The database shows exactly one application of each migration.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var gooseRows, logRows, appliedVersions int
	if err := db.QueryRowContext(ctx2, "SELECT count(*) FROM goose_db_version WHERE version_id > 0").Scan(&gooseRows); err != nil {
		t.Fatalf("count goose_db_version: %v", err)
	}
	if err := db.QueryRowContext(ctx2, "SELECT count(*) FROM schema_migration_log").Scan(&logRows); err != nil {
		t.Fatalf("count schema_migration_log: %v", err)
	}
	if err := db.QueryRowContext(ctx2, "SELECT count(DISTINCT version_id) FROM goose_db_version WHERE version_id > 0").Scan(&appliedVersions); err != nil {
		t.Fatalf("count distinct goose versions: %v", err)
	}
	if gooseRows != 2 || appliedVersions != 2 || logRows != 2 {
		t.Fatalf("after concurrent runs: goose rows=%d distinct=%d log rows=%d, want 2/2/2", gooseRows, appliedVersions, logRows)
	}
}

func TestRecoversUnloggedAppliedMigration(t *testing.T) {
	fsys := testMigrations()
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := openRunner(t, ctx, dbURL, fsys)

	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 2 {
		t.Fatalf("apply two migrations: res=%+v err=%v", res, err)
	}

	// Simulate a crash between goose's commit of version 2 and the log
	// insert: the log row is lost, goose's bookkeeping still has it.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.ExecContext(ctx2, "DELETE FROM schema_migration_log WHERE version = 2"); err != nil {
		t.Fatalf("simulate lost log row: %v", err)
	}
	_ = db.Close()

	// The next run heals: version 2 is re-recorded from goose's
	// bookkeeping, and only then is its checksum protected again.
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("migrate after lost log row: %v", err)
	}
	if len(res.Recovered) != 1 || res.Recovered[0].Version != 2 {
		t.Fatalf("recovered = %+v, want exactly version 2", res.Recovered)
	}
	if len(res.Applied) != 0 {
		t.Fatalf("applied = %+v, want none (migration was already applied)", res.Applied)
	}
	if n := countLogRows(t, dbURL); n != 2 {
		t.Fatalf("checksum log rows after recovery = %d, want 2", n)
	}

	// Protection is restored: altering the recovered migration aborts now.
	fsys["00002_second.sql"] = &fstest.MapFile{Data: append(fsys["00002_second.sql"].Data, []byte("-- edit\n")...)}
	_, err = runner.Migrate(ctx, false)
	var cerr *migrate.ChecksumError
	if !errors.As(err, &cerr) || cerr.Version != 2 {
		t.Fatalf("migrate after recovery + alteration: err = %v, want *ChecksumError for version 2", err)
	}
}

func TestFailingMigrationStillRecordsAppliedOnes(t *testing.T) {
	fsys := testMigrations()
	// Version 2 is broken SQL; version 1 is fine.
	fsys["00002_second.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE TABLE broken (id);\n")}

	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := openRunner(t, ctx, dbURL, fsys)

	_, err := runner.Migrate(ctx, false)
	if err == nil {
		t.Fatal("migrate with broken migration: expected error")
	}

	// Version 1 committed before the failure and must be in the checksum
	// log; version 2 must not.
	db, dberr := sql.Open("pgx", dbURL)
	if dberr != nil {
		t.Fatalf("open: %v", dberr)
	}
	defer db.Close()
	var logged, applied int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migration_log").Scan(&logged); err != nil {
		t.Fatalf("count schema_migration_log: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM goose_db_version WHERE version_id > 0").Scan(&applied); err != nil {
		t.Fatalf("count goose_db_version: %v", err)
	}
	if logged != 1 || applied != 1 {
		t.Fatalf("after failed run: log rows=%d goose applied=%d, want 1/1 (version 1 recorded, version 2 not)", logged, applied)
	}

	// Fixing the broken migration lets the run complete.
	fsys["00002_second.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE TABLE second_table (id BIGINT NOT NULL);\n")}
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("migrate after fixing version 2: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 2 {
		t.Fatalf("applied = %+v, want exactly version 2", res.Applied)
	}
	if n := countLogRows(t, dbURL); n != 2 {
		t.Fatalf("checksum log rows = %d, want 2", n)
	}
}
