package main

// Integration test proving I2 exit criterion 2 — a failure case is isolated
// and reprocessable (ARCH-002 §6.2, ch. 8.6) — against a real, short-lived
// PostgreSQL. A KEV source fetches the malformed catalog fixture under
// testdata/ (one healthy entry, one entry without a cveID at
// vulnerabilities[1]) through RunSource: the run succeeds — per-record
// failures are isolated, never fatal (ch. 8.1 step 5) — with the failure
// quarantined as a row carrying the exact position, the stable reason code
// and the SHA-256 of the offending slice, attributed to the run and the raw
// record, in the same transaction as the run counters.
//
// The resolution leg then drives the operator surface: the stored raw
// record is corrected in place (the corrected fixture stands in for the
// parser/data fix — the reprocess re-reads the stored record, it never
// refetches) and `quarantine reprocess <id>` re-runs the KEV normaliser:
// the clean single-vulnerability pass resolves the row and links the
// materialised CVE via resolved_vulnerability_id, with the terminal
// transition audited (quarantine.resolved) atomically with the state
// change. A resolved row is terminal: a further reprocess is rejected.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/sources/kev"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// TestRunSourceIsolatesMalformedRecordAndReprocessResolves drives exit
// criterion 2 end to end: the malformed reference import succeeds with the
// failure isolated (position/reason/payload hash on the quarantine row, run
// succeeded with errors 1), and the corrected record — swapped into the
// stored raw document, standing in for the parser fix — reprocesses through
// the CLI to resolved, linked to the materialised CVE.
func TestRunSourceIsolatesMalformedRecordAndReprocessResolves(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	code, stdout, stderr := runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitOK {
		t.Fatalf("migrate exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if decodeEnvelope(t, stdout).Status != "ok" {
		t.Fatalf("migrate envelope not ok:\n%s", stdout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	// The malformed catalog fixture: entry 0 healthy (CVE-2026-3001),
	// entry 1 without a cveID — the failure the run must isolate.
	malformed := readFixture(t, "kev-catalog-malformed-2026-09-09.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(malformed); err != nil {
			panic(err)
		}
	}))
	t.Cleanup(srv.Close)

	clk := clock.NewFakeClock(sourceRunClockStart)
	q := gen.New(pool)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "kev",
		Name:     "kev-isolate-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@daily", Valid: true},
		Enabled:  true,
		Config:   []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	srcID := demoUUID(sourceID)
	svc := newSourceRunService(pool, clk)

	// --- isolate: the run succeeds with the failure quarantined ----------
	res, err := svc.RunSource(ctx, application.RunSourceInput{
		SourceID: srcID, Adapter: kev.New(srv.Client().Transport),
	})
	if err != nil {
		t.Fatalf("RunSource (malformed reference): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run status = %s, want succeeded — an isolated record is counted, not fatal", res.Status)
	}
	assertSourceRunCounters(t, res.Counters, 1, 2, 1) // 1 raw record, 2 domain records of entry 0, 1 isolated entry

	// The healthy entry materialised its skeleton + kev evidence; the
	// malformed one left no row behind it.
	assertTableCounts(t, pool, map[string]int{
		"vulnerabilities": 1, "evidences": 1, "raw_records": 1,
		"quarantine": 1, "risk_signals": 0,
	})
	var summary string
	if err := pool.QueryRow(ctx,
		"SELECT summary FROM vulnerabilities WHERE cve_id = 'CVE-2026-3001'").Scan(&summary); err != nil {
		t.Fatalf("read skeleton vulnerability: %v", err)
	}
	if summary != "Acme Portal contains a command injection vulnerability." {
		t.Fatalf("skeleton summary = %q, want the fixture entry's short description", summary)
	}

	// The quarantine row carries the isolation facts: position, the stable
	// reason code, the SHA-256 of the offending slice, and the attribution
	// to the run and the raw record — status new, attempts 0, the run's
	// clock instant.
	var qrow gen.Quarantine
	if err := pool.QueryRow(ctx,
		"SELECT * FROM quarantine WHERE source_id = $1", sourceID).Scan(&qrow.ID, &qrow.SourceID, &qrow.SourceRunID, &qrow.RawRecordID, &qrow.Position, &qrow.Reason, &qrow.PayloadHash, &qrow.Status, &qrow.Attempts, &qrow.AcknowledgedAt, &qrow.AcknowledgedBy, &qrow.AcknowledgedNote, &qrow.ResolvedAt, &qrow.ResolvedVulnerabilityID, &qrow.ResolvedEvidenceID, &qrow.ResolvedNote, &qrow.CreatedAt, &qrow.UpdatedAt); err != nil {
		t.Fatalf("read quarantine row: %v", err)
	}
	if qrow.Position != "vulnerabilities[1]" {
		t.Fatalf("quarantine position = %q, want vulnerabilities[1]", qrow.Position)
	}
	if !strings.HasPrefix(qrow.Reason, "kev.normalize.missing_id") {
		t.Fatalf("quarantine reason = %q, want the stable code kev.normalize.missing_id", qrow.Reason)
	}
	if want := sha256Hex(malformedEntry(t, malformed)); qrow.PayloadHash != want {
		t.Fatalf("quarantine payload_hash = %q, want the SHA-256 of the offending slice %q", qrow.PayloadHash, want)
	}
	if qrow.Status != "new" || qrow.Attempts != 0 {
		t.Fatalf("quarantine state = %s, attempts %d, want new with attempts 0", qrow.Status, qrow.Attempts)
	}
	if !qrow.SourceRunID.Valid || demoUUID(qrow.SourceRunID) != res.RunID ||
		!qrow.RawRecordID.Valid || demoUUID(qrow.RawRecordID) != res.RawRecordID {
		t.Fatalf("quarantine attribution = run %v raw %v, want run %s raw %s",
			qrow.SourceRunID, qrow.RawRecordID, res.RunID, res.RawRecordID)
	}
	if !qrow.CreatedAt.Time.Equal(sourceRunClockStart) {
		t.Fatalf("quarantine created_at = %v, want the run's clock instant %v", qrow.CreatedAt.Time, sourceRunClockStart)
	}
	quarantineID := demoUUID(qrow.ID)

	// --- reprocess: the corrected record resolves the row ---------------
	// The raw record is corrected in place with the corrected fixture (the
	// reprocess re-reads the stored record bytes — the fixture swap stands
	// in for the parser/data fix, ARCH-002 §6.2). The corrected catalog
	// carries the single healthy entry, so the pass is clean and
	// single-vulnerability: the row resolves with the CVE linked.
	corrected := readFixture(t, "kev-catalog-corrected-2026-09-09.json")
	if _, err := pool.Exec(ctx,
		"UPDATE raw_records SET payload = $1, content_hash = $2 WHERE id = $3",
		corrected, sha256Hex(corrected), qrow.RawRecordID); err != nil {
		t.Fatalf("correct stored raw record: %v", err)
	}

	code, stdout, stderr = runCLI(t, env, "quarantine", "reprocess", quarantineID, "--output", "json")
	if code != exitOK {
		t.Fatalf("quarantine reprocess exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Command != "quarantine reprocess" {
		t.Fatalf("reprocess envelope = %+v, want ok quarantine reprocess", envJSON)
	}
	var reprocessed quarantineReprocessResult
	decodeJSONStrict(t, string(envJSON.Result), &reprocessed)
	if !reprocessed.Resolved || reprocessed.Errors != 0 || reprocessed.Records != 2 {
		t.Fatalf("reprocess outcome = %+v, want a resolved clean pass (records 2, errors 0)", reprocessed)
	}
	if reprocessed.ID != quarantineID || reprocessed.Status != "resolved" || reprocessed.ResolvedAt == "" {
		t.Fatalf("reprocess committed state = %+v, want resolved with resolved_at", reprocessed)
	}
	if reprocessed.ResolvedVulnerabilityID == "" {
		t.Fatal("reprocess linked no vulnerability, want resolved_vulnerability_id on the materialised CVE")
	}

	// The committed row: resolved, linked to the CVE-2026-3001
	// vulnerability the pass materialised.
	var dbStatus, resolvedVulnID string
	if err := pool.QueryRow(ctx,
		`SELECT status, COALESCE(resolved_vulnerability_id::text, '') FROM quarantine WHERE id = $1`,
		qrow.ID).Scan(&dbStatus, &resolvedVulnID); err != nil {
		t.Fatalf("read committed quarantine row: %v", err)
	}
	if dbStatus != "resolved" || resolvedVulnID != reprocessed.ResolvedVulnerabilityID {
		t.Fatalf("committed row = %s / %s, want resolved with the linked vulnerability", dbStatus, resolvedVulnID)
	}
	var cveID string
	if err := pool.QueryRow(ctx,
		"SELECT cve_id FROM vulnerabilities WHERE id = $1", mustUUID(t, resolvedVulnID)).Scan(&cveID); err != nil {
		t.Fatalf("read linked vulnerability: %v", err)
	}
	if cveID != "CVE-2026-3001" {
		t.Fatalf("linked vulnerability cve = %s, want CVE-2026-3001", cveID)
	}
	assertTableCounts(t, pool, map[string]int{"vulnerabilities": 1, "evidences": 1, "quarantine": 1})

	// The terminal transition is audited atomically with the state change
	// (quarantine.resolved, actor = the I2 system principal).
	var auditCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE aggregate_type = 'quarantine'
		 AND aggregate_id = $1 AND action = 'quarantine.resolved' AND actor_type = 'system' AND actor_id = 'operator'`,
		qrow.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count resolution audit events: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("quarantine.resolved audit events = %d, want exactly 1", auditCount)
	}

	// --- terminality ------------------------------------------------------
	// A resolved row is terminal: a further reprocess is a validation
	// rejection that writes nothing.
	code, stdout, stderr = runCLI(t, env, "quarantine", "reprocess", quarantineID, "--output", "json")
	if code != exitValidation || stderr != "" {
		t.Fatalf("reprocess of resolved row: code %d stderr %q, want %d with empty stderr", code, stderr, exitValidation)
	}
	if envJSON := decodeEnvelope(t, stdout); envJSON.Status != "error" || envJSON.Error == nil || envJSON.Error.Class != classValidation {
		t.Fatalf("terminal reprocess envelope = %+v, want a validation error", envJSON)
	}
}

// malformedEntry returns the raw bytes of the second (malformed)
// vulnerabilities[] element of the fixture — the exact slice the
// normaliser isolated and hashed.
func malformedEntry(t *testing.T, catalog []byte) []byte {
	t.Helper()
	var doc struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(catalog, &doc); err != nil {
		t.Fatalf("decode malformed fixture: %v", err)
	}
	if len(doc.Vulnerabilities) != 2 {
		t.Fatalf("malformed fixture carries %d entries, want 2", len(doc.Vulnerabilities))
	}
	return doc.Vulnerabilities[1]
}
