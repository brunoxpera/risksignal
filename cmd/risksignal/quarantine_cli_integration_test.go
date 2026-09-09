package main

// Integration tests of the DEV-035 quarantine CLI against a real
// PostgreSQL (ARCH-002 §4, concept ch. 8.6 / 11.3 / 13.2): `quarantine
// list`, `quarantine ack` and `quarantine reprocess` driven end to end on
// seeded isolations — the exit-criterion proof of WP-2.09. A quarantined
// row (source, raw record, position/reason/payload hash) is listed,
// reviewed (new -> acknowledged, note recorded) and reprocessed through
// the real KEV adapter over the stored raw record bytes: the clean pass
// resolves the row and links the vulnerability the pass materialised. The
// assertions cover the state transitions, the audit events written
// atomically with each state change (quarantine.acknowledged /
// quarantine.resolved, actor = the I2 system principal) and the link to
// the new domain object. Like the other database-backed CLI tests these
// skip when no PostgreSQL is reachable, so `go test ./...` stays green on
// machines without the compose environment.

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// quarantineKEVCatalogFixture is the corrected single-entry KEV catalog
// the reprocess proves: the raw record that carried the previously
// malformed entry now normalises cleanly under the current adapter, so the
// reprocess pass resolves instead of isolating again (ARCH-002 §6 exit
// criterion 2 — the fixture swap stands in for the parser fix).
const quarantineKEVCatalogFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.09.09",
  "dateReleased": "2026-09-09T18:00:00Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-3001",
      "vendorProject": "Acme",
      "product": "Portal",
      "vulnerabilityName": "Acme Portal Command Injection",
      "dateAdded": "2026-09-01",
      "shortDescription": "Acme Portal contains a command injection vulnerability.",
      "requiredAction": "Apply vendor mitigations.",
      "dueDate": "2026-10-01",
      "knownRansomwareCampaignUse": false,
      "notes": ""
    }
  ]
}`

// seedQuarantineCLIFixture migrates a fresh database and seeds one
// isolation of the kev source: the sources row, the raw record (the
// catalog bytes above, stored as the bytea payload) and the quarantine row
// in status 'new' that was isolated from it (position vulnerabilities[0],
// a missing-cve-id reason and the hash of the offending slice). It returns
// the database URL and the seeded source/quarantine ids.
func seedQuarantineCLIFixture(t *testing.T) (dbURL, sourceID, quarantineID string) {
	t.Helper()
	dbURL = newTestDB(t)
	env := cliDBEnv(dbURL)
	code, stdout, stderr := runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitOK {
		t.Fatalf("migrate exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if decodeEnvelope(t, stdout).Status != "ok" {
		t.Fatalf("migrate envelope not ok:\n%s", stdout)
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := db.QueryRow(
		`INSERT INTO sources (type, name) VALUES ('kev', 'quarantine-test-kev') RETURNING id`,
	).Scan(&sourceID); err != nil {
		t.Fatalf("insert kev source: %v", err)
	}
	var rawRecordID string
	now := time.Now().UTC()
	if err := db.QueryRow(
		`INSERT INTO raw_records (source_id, external_id, payload, content_hash, content_encoding, fetched_at)
		 VALUES ($1, 'kev-2026-09-09', $2::bytea, 'f2d8ed2ec42f9cafc4d9d6c11a5d4a4d97c5f6a0b1c2d3e4f5a6b7c8d9e0f1a2', 'json', $3)
		 RETURNING id`,
		sourceID, []byte(quarantineKEVCatalogFixture), now).Scan(&rawRecordID); err != nil {
		t.Fatalf("insert raw record: %v", err)
	}
	quarantineID = insertQuarantineRow(t, db, sourceID, rawRecordID, strings.Repeat("ab", 32))
	return dbURL, sourceID, quarantineID
}

// insertQuarantineRow seeds one additional isolation of the same raw
// record (status 'new') — the second row the text-mode reprocess run of
// the end-to-end test consumes (a resolved row is terminal, so the
// human-readable reprocess outcome is asserted on its own row).
func insertQuarantineRow(t *testing.T, db *sql.DB, sourceID, rawRecordID, payloadHash string) string {
	t.Helper()
	var id string
	now := time.Now().UTC()
	if err := db.QueryRow(
		`INSERT INTO quarantine (source_id, raw_record_id, position, reason, payload_hash, status, created_at, updated_at)
		 VALUES ($1, $2, 'vulnerabilities[0]', 'kev.normalize.missing_id: the entry carries no cveID', $3, 'new', $4, $4)
		 RETURNING id`,
		sourceID, rawRecordID, payloadHash, now).Scan(&id); err != nil {
		t.Fatalf("insert quarantine row: %v", err)
	}
	return id
}

// TestQuarantineCLIListAckReprocessEndToEnd drives the whole WP-2.09
// chain on one seeded isolation: list shows the row with the isolation
// facts, ack records the review with the note and its audit event,
// reprocess re-runs the KEV normaliser over the stored raw record and
// resolves the row with the link to the materialised vulnerability and the
// terminal audit event.
func TestQuarantineCLIListAckReprocessEndToEnd(t *testing.T) {
	dbURL, sourceID, quarantineID := seedQuarantineCLIFixture(t)
	env := cliDBEnv(dbURL)
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	// --- list -------------------------------------------------------------
	// The working list shows the isolated row: the isolation facts
	// (position, reason, payload hash), the machine state (status new) and
	// the source attribution (id, type) plus created_at.
	code, stdout, stderr := runCLI(t, env, "quarantine", "list", "--output", "json")
	if code != exitOK {
		t.Fatalf("quarantine list exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Error != nil || envJSON.Command != "quarantine list" {
		t.Fatalf("list envelope = %+v, want ok quarantine list", envJSON)
	}
	var listed quarantineListResult
	decodeJSONStrict(t, string(envJSON.Result), &listed)
	if len(listed.Quarantine) != 1 {
		t.Fatalf("quarantine list returned %d rows, want 1: %+v", len(listed.Quarantine), listed.Quarantine)
	}
	row := listed.Quarantine[0]
	if row.ID != quarantineID || row.SourceID != sourceID || row.SourceType != "kev" || row.SourceName != "quarantine-test-kev" {
		t.Fatalf("listed row attribution = %+v, want quarantine %s of source %s (kev)", row, quarantineID, sourceID)
	}
	if row.Position != "vulnerabilities[0]" || !strings.HasPrefix(row.Reason, "kev.normalize.missing_id") ||
		row.PayloadHash != strings.Repeat("ab", 32) {
		t.Fatalf("listed row isolation facts = %+v, want position/reason/payload hash", row)
	}
	if row.Status != "new" || row.Attempts != 0 || row.CreatedAt == "" {
		t.Fatalf("listed row state = %+v, want new with attempts 0 and created_at", row)
	}

	// The text form stays human-readable: one block per row with the
	// isolation facts.
	code, stdout, stderr = runCLI(t, env, "quarantine", "list")
	if code != exitOK || stderr != "" {
		t.Fatalf("text list: code %d stderr %q, want 0 with empty stderr", code, stderr)
	}
	for _, piece := range []string{
		"quarantine list: 1 row(s)", "kev / quarantine-test-kev", "): new, attempts 0, position vulnerabilities[0]",
		"reason: kev.normalize.missing_id", "payload_hash:",
	} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("text list stdout lacks %q:\n%s", piece, stdout)
		}
	}

	// The --status filter narrows the list to the open status.
	code, stdout, stderr = runCLI(t, env, "quarantine", "list", "--status", "new", "--output", "json")
	if code != exitOK {
		t.Fatalf("quarantine list --status new exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	var open quarantineListResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &open)
	if len(open.Quarantine) != 1 || open.Quarantine[0].ID != quarantineID {
		t.Fatalf("list --status new = %+v, want the seeded row", open.Quarantine)
	}
	_, stdout, _ = runCLI(t, env, "quarantine", "list", "--status", "resolved", "--output", "json")
	var none quarantineListResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &none)
	if len(none.Quarantine) != 0 {
		t.Fatalf("list --status resolved before reprocess = %+v, want no rows", none.Quarantine)
	}

	// --- ack --------------------------------------------------------------
	// The operator review: new -> acknowledged with the note, the audit
	// event written atomically with the state change.
	note := "reviewed: parser fix shipped"
	code, stdout, stderr = runCLI(t, env, "quarantine", "ack", quarantineID, "--note", note, "--output", "json")
	if code != exitOK {
		t.Fatalf("quarantine ack exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Command != "quarantine ack" {
		t.Fatalf("ack envelope = %+v, want ok quarantine ack", envJSON)
	}
	var acked quarantineView
	decodeJSONStrict(t, string(envJSON.Result), &acked)
	if acked.ID != quarantineID || acked.Status != "acknowledged" || acked.Attempts != 0 {
		t.Fatalf("ack result = %+v, want the row acknowledged", acked)
	}
	// The review records: the reviewer is the I2 system principal
	// (application.defaultQuarantineActorID) — the CLI takes no identity
	// before I5a — and the note is recorded.
	if acked.AcknowledgedBy != "operator" || acked.AcknowledgedNote != note || acked.AcknowledgedAt == "" {
		t.Fatalf("ack review records = %+v, want operator + note + acknowledged_at", acked)
	}

	// The text form of the same outcome, on a second untouched row (the
	// json run above already acknowledged the first one — a reviewed row
	// cannot be acknowledged twice, ARCH-002 §4).
	thirdID := insertQuarantineRow(t, db, sourceID, quarantineRawRecordID(t, db, quarantineID), strings.Repeat("ef", 32))
	code, stdout, stderr = runCLI(t, env, "quarantine", "ack", thirdID, "--note", note)
	if code != exitOK || stderr != "" {
		t.Fatalf("text ack: code %d stderr %q, want 0 with empty stderr", code, stderr)
	}
	for _, piece := range []string{
		"quarantine " + thirdID + " acknowledged: status acknowledged, by operator",
		"note: " + note,
	} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("text ack stdout lacks %q:\n%s", piece, stdout)
		}
	}

	// --- reprocess --------------------------------------------------------
	// The reprocess of the reviewed row re-runs the KEV normaliser over
	// the stored raw record: the clean pass resolves the row and links the
	// vulnerability it materialised.
	code, stdout, stderr = runCLI(t, env, "quarantine", "reprocess", quarantineID, "--output", "json")
	if code != exitOK {
		t.Fatalf("quarantine reprocess exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Command != "quarantine reprocess" {
		t.Fatalf("reprocess envelope = %+v, want ok quarantine reprocess", envJSON)
	}
	var reprocessed quarantineReprocessResult
	decodeJSONStrict(t, string(envJSON.Result), &reprocessed)
	if !reprocessed.Resolved || reprocessed.Errors != 0 || reprocessed.Records != 2 {
		t.Fatalf("reprocess result = %+v, want a resolved clean pass (records 2)", reprocessed)
	}
	if reprocessed.ID != quarantineID || reprocessed.Status != "resolved" || reprocessed.ResolvedAt == "" {
		t.Fatalf("reprocess committed state = %+v, want resolved with resolved_at", reprocessed)
	}
	if reprocessed.ResolvedVulnerabilityID == "" {
		t.Fatalf("reprocess result = %+v, want the materialised vulnerability linked", reprocessed)
	}

	// The text form of the reprocess outcome (on a second, untouched row:
	// a resolved row is terminal and the json run above already resolved
	// the first one) renders the resolved verdict with the pass counts and
	// the resolution link.
	secondID := insertQuarantineRow(t, db, sourceID, quarantineRawRecordID(t, db, quarantineID), strings.Repeat("cd", 32))
	code, stdout, stderr = runCLI(t, env, "quarantine", "reprocess", secondID)
	if code != exitOK || stderr != "" {
		t.Fatalf("text reprocess: code %d stderr %q, want 0 with empty stderr", code, stderr)
	}
	for _, piece := range []string{
		"quarantine " + secondID + " reprocessed: resolved (records 2, errors 0)",
		"linked vulnerability " + reprocessed.ResolvedVulnerabilityID,
	} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("text reprocess stdout lacks %q:\n%s", piece, stdout)
		}
	}

	// --- committed state + audit + domain object --------------------------
	// The first quarantine row is resolved and linked to the vulnerability
	// the reprocess upserted (cve CVE-2026-3001, the fixture entry).
	var dbStatus, resolvedVulnID string
	if err := db.QueryRow(
		`SELECT status, COALESCE(resolved_vulnerability_id::text, '') FROM quarantine WHERE id = $1`,
		quarantineID).Scan(&dbStatus, &resolvedVulnID); err != nil {
		t.Fatalf("read quarantine row: %v", err)
	}
	if dbStatus != "resolved" || resolvedVulnID != reprocessed.ResolvedVulnerabilityID {
		t.Fatalf("committed row = %s / %s, want resolved with the linked vulnerability", dbStatus, resolvedVulnID)
	}
	var cveID string
	if err := db.QueryRow(`SELECT cve_id FROM vulnerabilities WHERE id = $1`, resolvedVulnID).Scan(&cveID); err != nil {
		t.Fatalf("read linked vulnerability: %v", err)
	}
	if cveID != "CVE-2026-3001" {
		t.Fatalf("linked vulnerability cve = %s, want CVE-2026-3001", cveID)
	}
	// The kev evidence of the pass is attached to the stored raw record.
	var evidenceCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM evidences e JOIN quarantine q ON q.raw_record_id = e.raw_record_id
		 WHERE q.id = $1 AND e.type = 'kev' AND e.value->>'cve_id' = 'CVE-2026-3001'`,
		quarantineID).Scan(&evidenceCount); err != nil {
		t.Fatalf("count kev evidence: %v", err)
	}
	if evidenceCount != 1 {
		t.Fatalf("kev evidence count = %d, want 1 (the reprocess pass attached the statement to the raw record)", evidenceCount)
	}

	// The audit trail of the first row: exactly two events, one per
	// audited transition, actor = the system principal, snapshots carrying
	// the status change.
	rows, err := db.Query(
		`SELECT action, actor_type, actor_id, before, after FROM audit_events
		 WHERE aggregate_type = 'quarantine' AND aggregate_id = $1 ORDER BY occurred_at`,
		quarantineID)
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	defer rows.Close()
	type auditRow struct {
		action, actorType, actorID string
		before, after              map[string]any
	}
	var audit []auditRow
	for rows.Next() {
		var a auditRow
		var before, after []byte
		if err := rows.Scan(&a.action, &a.actorType, &a.actorID, &before, &after); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		if err := json.Unmarshal(before, &a.before); err != nil {
			t.Fatalf("decode before snapshot: %v", err)
		}
		if err := json.Unmarshal(after, &a.after); err != nil {
			t.Fatalf("decode after snapshot: %v", err)
		}
		audit = append(audit, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit rows: %v", err)
	}
	if len(audit) != 2 {
		t.Fatalf("audit events = %d, want 2 (acknowledged + resolved): %+v", len(audit), audit)
	}
	for i, want := range []struct {
		action, status string
	}{{"quarantine.acknowledged", "acknowledged"}, {"quarantine.resolved", "resolved"}} {
		a := audit[i]
		if a.action != want.action || a.actorType != "system" || a.actorID != "operator" {
			t.Fatalf("audit event %d = %s by %s/%s, want %s by the system operator", i, a.action, a.actorType, a.actorID, want.action)
		}
		if a.after["status"] != want.status {
			t.Fatalf("audit event %d after snapshot = %v, want status %s", i, a.after, want.status)
		}
	}

	// --- terminality ------------------------------------------------------
	// A resolved row is terminal: a further reprocess is rejected (exit 2,
	// validation) without a write or an audit event.
	code, stdout, stderr = runCLI(t, env, "quarantine", "reprocess", quarantineID, "--output", "json")
	if code != exitValidation || stderr != "" {
		t.Fatalf("reprocess of resolved row: code %d stderr %q, want %d with empty stderr", code, stderr, exitValidation)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.Status != "error" || envJSON.Error == nil || envJSON.Error.Class != classValidation {
		t.Fatalf("terminal reprocess envelope = %+v, want a validation error", envJSON)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE aggregate_id = $1`, quarantineID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("audit events after terminal reprocess = %d, want still 2 — no event of a transition that did not happen", auditCount)
	}

	// The list now shows the resolved row under --status resolved.
	_, stdout, _ = runCLI(t, env, "quarantine", "list", "--status", "resolved", "--output", "json")
	var settled quarantineListResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &settled)
	if len(settled.Quarantine) != 2 {
		t.Fatalf("list --status resolved = %d rows, want 2 (both rows resolved)", len(settled.Quarantine))
	}
	for _, r := range settled.Quarantine {
		if r.Status != "resolved" || r.ResolvedVulnerabilityID == "" {
			t.Fatalf("settled row = %+v, want resolved with the vulnerability link", r)
		}
	}
}

// quarantineRawRecordID reads the raw record attribution of one quarantine
// row — the fixture seeding of the second isolation needs it.
func quarantineRawRecordID(t *testing.T, db *sql.DB, quarantineID string) string {
	t.Helper()
	var rawRecordID string
	if err := db.QueryRow(`SELECT raw_record_id::text FROM quarantine WHERE id = $1`, quarantineID).Scan(&rawRecordID); err != nil {
		t.Fatalf("read raw record id: %v", err)
	}
	return rawRecordID
}

// TestQuarantineCLIReprocessUnknownIDIsGenericError drives the argument
// and identity validation of the reprocess command against the database:
// an id that resolves to no quarantine row is a generic failure naming the
// id (the convention of `source run`).
func TestQuarantineCLIReprocessUnknownIDIsGenericError(t *testing.T) {
	dbURL, _, _ := seedQuarantineCLIFixture(t)
	env := cliDBEnv(dbURL)

	code, stdout, stderr := runCLI(t, env, "quarantine", "reprocess", "00000000-0000-0000-0000-000000000000", "--output", "json")
	if code != exitGeneric || stderr != "" {
		t.Fatalf("code %d stderr %q, want %d with empty stderr", code, stderr, exitGeneric)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "error" || envJSON.Error == nil || envJSON.Error.Class != classGeneric {
		t.Fatalf("envelope = %+v, want a generic error", envJSON)
	}
	if !strings.Contains(envJSON.Error.Message, "no quarantine row with id") {
		t.Errorf("error message %q does not name the unknown id", envJSON.Error.Message)
	}
}
