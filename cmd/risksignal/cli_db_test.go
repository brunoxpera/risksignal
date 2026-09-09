package main

// Integration tests of the WP-1a.09 exit-code contract against a real
// PostgreSQL: a fresh database migrates through the CLI with exit 0, a
// rerun is a no-op, a dry run reports without writing, and an altered
// applied migration (ADR-010) makes `maintenance migrate` fail with the
// conflict exit code 5. Like the WP-1a.04 tests in main_test.go these tests
// skip when no PostgreSQL is reachable, so `go test ./...` stays green on
// machines without the compose environment.

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// cliDBEnv builds the CLI environment pointing at the given database URL.
func cliDBEnv(dbURL string) map[string]string {
	return map[string]string{
		"RISKSIGNAL_DATABASE_URL": dbURL,
		"RISKSIGNAL_OIDC_ISSUER":  "http://127.0.0.1:9000/oidc",
	}
}

// TestCLIMigrateExitCodesAgainstRealDatabase drives the whole WP-1a.04
// lifecycle through the CLI and asserts the exit codes per outcome class.
func TestCLIMigrateExitCodesAgainstRealDatabase(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)

	// A fresh database migrates cleanly: exit 0 with every embedded migration
	// applied, in version order (the applied set is derived from the embedded
	// migration files, not hard-coded — see embeddedVersions in main_test.go).
	want := embeddedVersions(t)
	code, stdout, stderr := runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitOK {
		t.Fatalf("fresh migrate exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Error != nil {
		t.Fatalf("envelope = %+v, want ok", envJSON)
	}
	var res migrateResult
	decodeJSONStrict(t, string(envJSON.Result), &res)
	if res.DryRun || res.Verified != 0 || len(res.Applied) != len(want) ||
		len(res.Pending) != 0 || len(res.Recovered) != 0 {
		t.Fatalf("fresh migrate result = %+v, want exactly %d applied migrations", res, len(want))
	}
	for i, v := range want {
		if res.Applied[i].Version != v {
			t.Fatalf("fresh migrate applied %+v, want versions %v in order", res.Applied, want)
		}
	}
	if res.Applied[0].DurationMS < 0 || res.Applied[0].Path == "" {
		t.Fatalf("applied migration %+v, want path and non-negative duration", res.Applied[0])
	}

	// A rerun is a no-op: exit 0, every checksum verified, nothing applied.
	code, stdout, stderr = runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitOK {
		t.Fatalf("rerun exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	res = migrateResult{}
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &res)
	if res.Verified != len(want) || len(res.Applied) != 0 || len(res.Pending) != 0 {
		t.Fatalf("rerun result = %+v, want %d verified checksums and nothing to do", res, len(want))
	}

	// A dry run on the migrated database verifies and writes nothing.
	code, stdout, stderr = runCLI(t, env, "maintenance", "migrate", "--dry-run", "--output", "json")
	if code != exitOK {
		t.Fatalf("dry run exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	res = migrateResult{}
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &res)
	if !res.DryRun || res.Verified != len(want) || len(res.Applied) != 0 || len(res.Pending) != 0 {
		t.Fatalf("dry run result = %+v, want read-only verification of %d checksums", res, len(want))
	}

	// The text form of the same command stays human-readable.
	code, stdout, _ = runCLI(t, env, "maintenance", "migrate", "--dry-run")
	if code != exitOK {
		t.Fatalf("text dry run exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, fmt.Sprintf("verified checksums of %d applied migration(s); nothing to do", len(want))) {
		t.Fatalf("text dry run stdout = %q", stdout)
	}

	// Tamper with the recorded checksum: an altered applied migration is a
	// conflict with the embedded migration set (ADR-010) and must abort with
	// exit code 5 — the conflict class, not a generic or infrastructure
	// failure.
	tamperChecksum(t, dbURL, 1)

	code, stdout, stderr = runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitConflict {
		t.Fatalf("tampered migrate exit code = %d, want %d (stderr: %s)", code, exitConflict, stderr)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.ExitCode != exitConflict || envJSON.Status != "error" ||
		envJSON.Error == nil || envJSON.Error.Class != classConflict || string(envJSON.Result) != "null" {
		t.Fatalf("envelope = %+v, want a conflict error", envJSON)
	}
	if !strings.Contains(envJSON.Error.Message, "refusing to migrate") {
		t.Errorf("conflict message %q does not name the refusal", envJSON.Error.Message)
	}

	// The text form reports the same conflict on stderr.
	code, stdout, stderr = runCLI(t, env, "maintenance", "migrate")
	if code != exitConflict {
		t.Fatalf("text tampered migrate exit code = %d, want %d", code, exitConflict)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
	if !strings.Contains(stderr, "was modified after it was applied") {
		t.Errorf("stderr %q does not name the modified migration", stderr)
	}
}

// tamperChecksum rewrites the recorded file hash of one applied migration so
// the next run sees a divergence between the database and the embedded file.
func tamperChecksum(t *testing.T, dbURL string, version int64) {
	t.Helper()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	// The hash column is a fixed-width hex SHA-256; any deterministic value
	// other than the real hash triggers the ADR-010 refusal.
	const fakeHash = "deadbeef"
	if _, err := db.Exec("UPDATE schema_migration_log SET file_hash = $1 WHERE version = $2", fakeHash, version); err != nil {
		t.Fatalf("tamper with checksum log: %v", err)
	}
}
