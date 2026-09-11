package main

// CLI integration test for the audit chain verifier (ARCH-007 §7 control 3b,
// WP-6.10 / DEV-123): `risksignal diagnose audit-chain` reports an intact trail
// with exit 0 and fails with the conflict exit code (5) after an injected row
// whose row_hash does not match its content. It runs against a real
// PostgreSQL database migrated through the CLI and skips without one.

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestCLIDiagnoseAuditChain(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)

	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit code = %d, want 0 (stderr: %s)", code, stderr)
	}

	// An empty trail verifies as intact.
	code, stdout, stderr := runCLI(t, env, "diagnose", "audit-chain", "--output", "json")
	if code != exitOK {
		t.Fatalf("audit-chain on empty trail exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	var view auditChainView
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &view)
	if !view.Verified || view.Rows != 0 || view.Chained != 0 {
		t.Fatalf("empty-trail view = %+v, want verified with 0 rows", view)
	}

	// Inject a row whose stored row_hash does not match its content (as the
	// migration superuser; the application role cannot write the hash at all)
	// and expect the verifier to fail with the conflict exit code.
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, action, occurred_at, correlation_id, prev_hash, row_hash)
		VALUES ('risk_signal', '00000000-0000-0000-0000-000000000001', 'system', 'seed', 'seed.created', now(), 'corr', NULL, 'deadbeef')`); err != nil {
		t.Fatalf("inject tampered row: %v", err)
	}

	code, _, stderr = runCLI(t, env, "diagnose", "audit-chain")
	if code != exitConflict {
		t.Fatalf("audit-chain after tamper exit code = %d, want %d (stderr: %s)", code, exitConflict, stderr)
	}
	if !strings.Contains(stderr, "audit chain verification failed") {
		t.Fatalf("stderr %q does not report a chain mismatch", stderr)
	}
}
