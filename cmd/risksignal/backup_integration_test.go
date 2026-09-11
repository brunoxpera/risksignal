package main

// Integration test of the WP-6.09 / DEV-122 restore test (AT-015): backup a
// reference instance, restore it into a throwaway empty database, run the
// checksum-guarded migration runner and assert schema/objects/sample-hashes/
// open-signals/audit-chain, then record the backup.restored audit event.
//
// The pg_dump/pg_restore clients must match the server major version; the test
// drives them through the scripts/pg-client compose shim (so the client runs
// inside the postgres:16 db container). Without a reachable database, docker
// or the shim it skips cleanly, like every other integration test.

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestRestoreTestReproducesSchemaObjectsAndAudit(t *testing.T) {
	dbURL := newTestDB(t)

	shimDir := filepath.Join("..", "..", "scripts", "pg-client")
	if _, err := os.Stat(filepath.Join(shimDir, "pg_dump")); err != nil {
		t.Skipf("pg-client shim unavailable: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker unavailable for the pg-client shim: %v", err)
	}
	// A bare pg_dump on PATH must resolve to an absolute path (Go refuses to
	// run executables found relative to the current directory), so make the
	// shim directory absolute before prepending it.
	shimDir, err := filepath.Abs(shimDir)
	if err != nil {
		t.Fatalf("resolve shim dir: %v", err)
	}
	// #nosec G204 -- the pg-client shim is a fixed, repository-owned script,
	// not tainted input.
	probe := exec.Command(filepath.Join(shimDir, "pg_dump"), "--version")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("pg-client shim not usable: %v (%s)", err, out)
	}
	pathEnv := shimDir + string(os.PathListSeparator) + os.Getenv("PATH")

	seedRestoreFixture(t, dbURL)

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	backupDir := t.TempDir()
	env := map[string]string{
		"RISKSIGNAL_DATABASE_URL":              dbURL,
		"RISKSIGNAL_OIDC_ISSUER":               "http://127.0.0.1:9000/oidc",
		"RISKSIGNAL_BACKUP_DIR":                backupDir,
		"RISKSIGNAL_BACKUP_ENCRYPTION_KEY_REF": "RISKSIGNAL_BACKUP_TEST_IDENTITY",
		"RISKSIGNAL_BACKUP_TEST_IDENTITY":      identity.String(),
		"PATH":                                 pathEnv,
	}

	// 1. The encrypted off-host backup is written.
	code, stdout, stderr := runCLI(t, env, "diagnose", "backup", "--output", "json")
	if code != exitOK {
		t.Fatalf("diagnose backup exit = %d, want 0 (stdout: %s stderr: %s)", code, stdout, stderr)
	}
	var art backupArtifactView
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &art)
	if _, err := os.Stat(art.Path); err != nil {
		t.Fatalf("backup artifact missing: %v", err)
	}
	if len(art.SHA256) != 64 || art.SizeBytes == 0 {
		t.Fatalf("backup artifact = %+v, want a non-empty sha256 and size", art)
	}

	// 2. The restore test reproduces the source in a throwaway instance.
	code, stdout, stderr = runCLI(t, env, "diagnose", "restore-test", "--output", "json")
	if code != exitOK {
		t.Fatalf("diagnose restore-test exit = %d, want 0 (stdout: %s stderr: %s)", code, stdout, stderr)
	}
	var view restoreTestView
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &view)
	if !view.Integrity.Matched {
		t.Fatalf("integrity not matched: %+v", view.Integrity.Mismatches)
	}
	if !view.Throwaway || !view.Audited {
		t.Fatalf("restore view = %+v, want a throwaway target and an audit event", view)
	}
	if view.MigrationsVerified == 0 {
		t.Fatalf("no migration checksums verified: %+v", view)
	}
	if view.Integrity.Tables == 0 || view.Integrity.AuditRows < 2 {
		t.Fatalf("integrity report = %+v, want tables and the seeded audit rows", view.Integrity)
	}
	assertBackupRestoredAudit(t, dbURL)

	// 3. Drift in the source is caught: an extra row makes the restored
	//    instance diverge from the (now changed) source, so the assertion
	//    fails with the conflict exit code and records no new audit event.
	src, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	if _, err := src.Exec(`INSERT INTO sources (type, name, enabled) VALUES ('kev', 'restore-drift', true)`); err != nil {
		t.Fatalf("insert drift row: %v", err)
	}
	_ = src.Close()
	code, stdout, stderr = runCLI(t, env, "diagnose", "restore-test", "--output", "json")
	if code != exitConflict {
		t.Fatalf("drifted restore-test exit = %d, want %d (stdout: %s stderr: %s)", code, exitConflict, stdout, stderr)
	}
}

// seedRestoreFixture migrates the throwaway source database and seeds a small,
// deterministic fixture (two sources and two audit rows) so the object counts
// and sample-row hashes are non-trivial.
func seedRestoreFixture(t *testing.T, dbURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = runner.Close()

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sources (type, name, enabled) VALUES ('synthetic', 'restore-fixture', true), ('nvd', 'restore-fixture-nvd', false)`); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, action, occurred_at, correlation_id)
		 VALUES ('risk_signal', gen_random_uuid(), 'system', 'fixture', 'signal.created', now(), 'fixture-1'),
		        ('risk_signal', gen_random_uuid(), 'system', 'fixture', 'signal.triaged', now(), 'fixture-2')`); err != nil {
		t.Fatalf("seed audit rows: %v", err)
	}
}

// assertBackupRestoredAudit asserts the backup.restored audit event was
// recorded on the source database.
func assertBackupRestoredAudit(t *testing.T, dbURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'backup.restored'`).Scan(&n); err != nil {
		t.Fatalf("count backup.restored: %v", err)
	}
	if n < 1 {
		t.Fatalf("backup.restored audit event not recorded (%d)", n)
	}
}
