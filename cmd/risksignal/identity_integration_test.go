package main

// Integration test of the governed `maintenance identity-lookup` command
// (ARCH-005 §7, WP-5a.07 / DEV-094, ADR-014) against a real PostgreSQL: the
// CLI drives the same RevealAuditIdentity use case as the API endpoint, with
// the same permission gate and the same self-audit (channel parity, NFR-013).
// It skips when no PostgreSQL is reachable, like the other integration tests.

import (
	"database/sql"
	"strings"
	"testing"
)

// seededAuditorUser is the fixed id of the migration-seeded local::auditor
// user (00009), used here as the target of a reveal.
const seededAuditorUser = "e5a00000-0000-4000-8000-000000000005"

// seedAuditEventRow inserts one committed audit event (the target of a
// reveal) with an explicit id.
func seedAuditEventRow(t *testing.T, dbURL, id, actorType, actorID, display string) {
	t.Helper()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(
		`INSERT INTO audit_events
		   (id, aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, correlation_id)
		 VALUES ($1, 'risk_signal', 'e5a00000-0000-4000-8000-00000000aaaa', $2, $3, $4, 'signal.created', now(), 'seed')`,
		id, actorType, actorID, display)
	if err != nil {
		t.Fatalf("seed audit event: %v", err)
	}
}

// countRevealAudits returns the number of audit.identity_revealed rows.
func countRevealAudits(t *testing.T, dbURL string) int {
	t.Helper()
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'audit.identity_revealed'`).Scan(&n); err != nil {
		t.Fatalf("count reveal audits: %v", err)
	}
	return n
}

// TestIdentityLookupCommandAgainstRealDatabase drives the CLI reveal: a
// user-actor event resolves and self-audits under an Auditor, the
// Administrator is denied (exit 4, nothing written), a blank reason is a
// validation error, and a system actor returns its label.
func TestIdentityLookupCommandAgainstRealDatabase(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)

	// Migrate through the CLI (exercises the real composition path).
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	seedAuditEventRow(t, dbURL, "00000000-0000-4000-8000-0000000000e1", "user", seededAuditorUser, "Auditor")
	seedAuditEventRow(t, dbURL, "00000000-0000-4000-8000-0000000000e2", "system", "sla.evaluate", "")

	// Auditor: reveal succeeds and writes exactly one self-audit.
	code, stdout, stderr := runCLI(t, env, "maintenance", "identity-lookup",
		"--event", "00000000-0000-4000-8000-0000000000e1", "--reason", "subject access request",
		"--as", "local::auditor", "--output", "json")
	if code != exitOK {
		t.Fatalf("auditor reveal exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	envelope := decodeEnvelope(t, stdout)
	if envelope.Status != "ok" || envelope.Error != nil {
		t.Fatalf("envelope = %+v, want ok", envelope)
	}
	var res identityLookupResult
	decodeJSONStrict(t, string(envelope.Result), &res)
	if !res.IsUser || res.UserID != seededAuditorUser || res.SubjectID != "local::auditor" || res.Label != "Auditor" {
		t.Fatalf("result = %+v, want the resolved auditor identity", res)
	}
	if got := countRevealAudits(t, dbURL); got != 1 {
		t.Fatalf("self-audit rows = %d, want exactly 1", got)
	}

	// Administrator: denied (403), no new self-audit.
	code, stdout, stderr = runCLI(t, env, "maintenance", "identity-lookup",
		"--event", "00000000-0000-4000-8000-0000000000e1", "--reason", "curious",
		"--as", "local::administrator", "--output", "json")
	if code != exitAuthorisation {
		t.Fatalf("admin reveal exit = %d, want %d (stderr: %s)", code, exitAuthorisation, stderr)
	}
	envelope = decodeEnvelope(t, stdout)
	if envelope.Status != "error" || envelope.Error == nil || envelope.Error.Class != classAuthorisation {
		t.Fatalf("envelope = %+v, want an authorisation error", envelope)
	}
	if got := countRevealAudits(t, dbURL); got != 1 {
		t.Fatalf("denied reveal wrote a self-audit (rows = %d, want 1)", got)
	}

	// Blank reason: validation error (exit 2), nothing written.
	code, _, _ = runCLI(t, env, "maintenance", "identity-lookup",
		"--event", "00000000-0000-4000-8000-0000000000e1", "--reason", "  ", "--as", "local::auditor")
	if code != exitValidation {
		t.Fatalf("blank-reason exit = %d, want %d", code, exitValidation)
	}
	if got := countRevealAudits(t, dbURL); got != 1 {
		t.Fatalf("blank-reason reveal wrote a self-audit (rows = %d, want 1)", got)
	}

	// A system-actor event returns its label and writes nothing.
	code, stdout, stderr = runCLI(t, env, "maintenance", "identity-lookup",
		"--event", "00000000-0000-4000-8000-0000000000e2", "--reason", "check",
		"--as", "local::auditor", "--output", "json")
	if code != exitOK {
		t.Fatalf("system-actor reveal exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	res = identityLookupResult{}
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &res)
	if res.IsUser || res.Label != "sla.evaluate" || res.ActorType != "system" {
		t.Fatalf("result = %+v, want the system label sla.evaluate", res)
	}
	if got := countRevealAudits(t, dbURL); got != 1 {
		t.Fatalf("system-actor reveal wrote a self-audit (rows = %d, want 1)", got)
	}

	// Argument validation: a missing --event or --reason fails before the DB.
	if code, _, _ := runCLI(t, env, "maintenance", "identity-lookup", "--reason", "x"); code != exitValidation {
		t.Fatalf("missing --event exit = %d, want %d", code, exitValidation)
	}
	if code, _, _ := runCLI(t, env, "maintenance", "identity-lookup", "--event", "x"); code != exitValidation {
		t.Fatalf("missing --reason exit = %d, want %d", code, exitValidation)
	}

	// The text form is human-readable.
	code, stdout, _ = runCLI(t, env, "maintenance", "identity-lookup",
		"--event", "00000000-0000-4000-8000-0000000000e1", "--reason", "again", "--as", "local::auditor")
	if code != exitOK {
		t.Fatalf("text reveal exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "resolved user identity") {
		t.Fatalf("text output = %q, want the human-readable reveal line", stdout)
	}
}
