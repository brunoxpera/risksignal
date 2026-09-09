package main

// Integration tests of the WP-1b.05 demo path (DEV-019) at the composition
// root: `demo seed` (register the synthetic source, seed the demo inventory
// and run the synthetic source once), `demo run` (idempotent re-run) and
// `demo reset` (dev-only truncation of the I1b tables) against a real,
// short-lived PostgreSQL.
//
// The test proves the exit criteria of WP-1b.05 end to end:
//   (a) one seed produces the full expected chain — source, inventory,
//       document, vulnerabilities + evidences, method-led matches and the
//       reference signals C1–C4 with the expected P1/P2/P2/P3 priorities
//       and high confidence, while the malformed E1 case is counted as a
//       run error without aborting the run (C5/C6 stay unmatched);
//   (b) `demo seed` twice yields no duplicates (natural-key upserts,
//       component-seed guard and the ExistsByMatchID/UQ(match_id)
//       idempotency of DEV-018) — the second run creates no new signals;
//   (c) `demo run` is an idempotent no-op on re-run;
//   (d) `demo reset` refuses without --yes (exit 2) and truncates the I1b
//       tables with --yes, after which `demo seed` rebuilds the identical
//       demo state.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// wantSignalMatrix is the expected per-case outcome of one demo seed: the
// CVE, the derived priority, the match confidence and the match method of
// every produced signal (ordered by cve_id). C5/C6 produce no signal (no
// confirmed assignment) and E1 is counted as a run error — they are not
// rows here.
var wantSignalMatrix = []string{
	"CVE-2024-0001 P1 high canonical_product_range",
	"CVE-2024-0002 P2 high canonical_product_range",
	"CVE-2024-0003 P2 high canonical_product_range",
	"CVE-2024-0004 P3 high exact_identifier",
}

// wantDemoTableCounts is the I1b row census after one demo seed (no
// duplicates anywhere; audit/outbox hold one row per created signal).
var wantDemoTableCounts = map[string]int{
	"sources":         1,
	"assets":          2,
	"components":      2,
	"source_runs":     1,
	"raw_records":     1,
	"vulnerabilities": 6,  // C1–C6; the malformed E1 case is not ingested
	"evidences":       24, // 6 ingested cases × 4 typed statements
	"matches":         4,  // C1–C4 only
	"risk_signals":    4,
	"audit_events":    4,
	"outbox":          4,
}

// TestDemoSeedRunResetAgainstRealDatabase drives the whole demo lifecycle
// through the CLI and asserts the WP-1b.05 exit criteria on the real rows.
func TestDemoSeedRunResetAgainstRealDatabase(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// A fresh database migrates first (the demo commands expect the I1b
	// schema; migrations are the CLI's own maintenance path).
	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	_ = runner.Close()

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	// --- demo run before any seed: a generic failure with a hint ----------
	code, stdout, stderr := runCLI(t, env, "demo", "run", "--output", "json")
	if code != exitGeneric {
		t.Fatalf("demo run before seed exit code = %d, want %d (stderr: %s)", code, exitGeneric, stderr)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "error" || envJSON.Error == nil || envJSON.Error.Class != classGeneric ||
		!strings.Contains(envJSON.Error.Message, "demo seed") {
		t.Fatalf("envelope = %+v, want a generic error hinting at 'demo seed'", envJSON)
	}

	// --- (a) one demo seed: full chain with the expected matrix -----------
	code, stdout, stderr = runCLI(t, env, "demo", "seed", "--output", "json")
	if code != exitOK {
		t.Fatalf("demo seed exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Error != nil {
		t.Fatalf("demo seed envelope = %+v, want ok", envJSON)
	}
	var seed demoSeedResult
	decodeJSONStrict(t, string(envJSON.Result), &seed)
	if seed.SourceType != "synthetic" || seed.SourceName != "synthetic-source" ||
		seed.Assets != 2 || seed.Components != 2 {
		t.Fatalf("demo seed result = %+v, want source synthetic/synthetic-source with 2 assets and 2 components", seed)
	}
	// The E1 case is counted without aborting the run: terminal status
	// failed, the four reference signals created, the error recorded.
	if seed.Run.Status != "failed" {
		t.Fatalf("demo seed run status = %q, want failed (E1 counted)", seed.Run.Status)
	}
	if seed.Run.Counters.Records != 7 || seed.Run.Counters.Matched != 4 || seed.Run.Counters.Signals != 4 {
		t.Fatalf("demo seed run counters = %+v, want records 7 matched 4 signals 4", seed.Run.Counters)
	}
	if len(seed.Run.Errors) != 1 || seed.Run.Errors[0] != "case 6: missing cve_id" {
		t.Fatalf("demo seed run errors = %v, want the E1 case counted", seed.Run.Errors)
	}
	if seed.Run.RunID == "" {
		t.Fatal("demo seed run_id is empty")
	}

	// The produced signals carry the expected P1/P2/P2/P3 matrix with high
	// confidence (ADR-015 methods canonical_product_range / exact_identifier).
	assertSignalMatrix(t, pool, wantSignalMatrix)
	assertTableCounts(t, pool, wantDemoTableCounts)

	// --- (b) demo seed twice yields no duplicates --------------------------
	code, stdout, stderr = runCLI(t, env, "demo", "seed", "--output", "json")
	if code != exitOK {
		t.Fatalf("second demo seed exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	seed = demoSeedResult{}
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &seed)
	if seed.Assets != 2 || seed.Components != 0 {
		t.Fatalf("second seed inventory = %d assets %d components, want 2/0 (upserts only, no new rows)", seed.Assets, seed.Components)
	}
	if seed.Run.Counters.Records != 7 || seed.Run.Counters.Matched != 4 || seed.Run.Counters.Signals != 0 {
		t.Fatalf("second seed run counters = %+v, want records 7 matched 4 signals 0 (no new signals)", seed.Run.Counters)
	}
	counts := copyTableCounts(wantDemoTableCounts)
	counts["source_runs"] = 2 // one run row per execution is the only growth
	assertTableCounts(t, pool, counts)

	// --- (c) demo run is an idempotent no-op on re-run ---------------------
	code, stdout, stderr = runCLI(t, env, "demo", "run", "--output", "json")
	if code != exitOK {
		t.Fatalf("demo run exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	var run demoRunResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &run)
	if run.Run.Counters.Records != 7 || run.Run.Counters.Matched != 4 || run.Run.Counters.Signals != 0 {
		t.Fatalf("demo run counters = %+v, want records 7 matched 4 signals 0", run.Run.Counters)
	}
	counts = copyTableCounts(wantDemoTableCounts)
	counts["source_runs"] = 3
	assertTableCounts(t, pool, counts)

	// --- (d) demo reset: --yes gate, then truncation, then a clean rebuild --
	code, stdout, stderr = runCLI(t, env, "demo", "reset")
	if code != exitValidation {
		t.Fatalf("demo reset without --yes exit code = %d, want %d (stderr: %s)", code, exitValidation, stderr)
	}
	if stdout != "" || !strings.Contains(stderr, "--yes") {
		t.Fatalf("demo reset without --yes = stdout %q stderr %q, want the --yes refusal", stdout, stderr)
	}

	code, stdout, stderr = runCLI(t, env, "demo", "reset", "--yes", "--output", "json")
	if code != exitOK {
		t.Fatalf("demo reset --yes exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	var reset demoResetResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &reset)
	if len(reset.Tables) != len(demoResetTables) {
		t.Fatalf("demo reset tables = %v, want the %d I1b tables", reset.Tables, len(demoResetTables))
	}
	empty := map[string]int{}
	for _, table := range demoResetTables {
		empty[table] = 0
	}
	assertTableCounts(t, pool, empty)

	// Re-seeding after the reset rebuilds the identical demo state — the
	// same four reference signals with the same priorities.
	code, stdout, stderr = runCLI(t, env, "demo", "seed", "--output", "json")
	if code != exitOK {
		t.Fatalf("demo seed after reset exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	seed = demoSeedResult{}
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &seed)
	if seed.Run.Counters.Signals != 4 || seed.Run.Status != "failed" {
		t.Fatalf("demo seed after reset = %+v, want the four reference signals with the E1 error counted", seed.Run)
	}
	assertSignalMatrix(t, pool, wantSignalMatrix)

	// The text forms of the demo commands stay human-readable.
	code, stdout, stderr = runCLI(t, env, "demo", "run")
	if code != exitOK || !strings.Contains(stdout, "synthetic run") || stderr != "" {
		t.Fatalf("text demo run = code %d stdout %q stderr %q, want a human-readable run report", code, stdout, stderr)
	}
}

// copyTableCounts clones a census map so per-phase adjustments never mutate
// the shared wantDemoTableCounts baseline.
func copyTableCounts(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// assertSignalMatrix compares the produced signal rows (cve_id, priority,
// confidence, method, ordered by cve_id) with the expected matrix.
func assertSignalMatrix(t *testing.T, pool *pgxpool.Pool, want []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT v.cve_id, rs.priority, m.confidence, m.method
		 FROM risk_signals rs
		 JOIN matches m ON m.id = rs.match_id
		 JOIN vulnerabilities v ON v.id = m.vulnerability_id
		 ORDER BY v.cve_id`)
	if err != nil {
		t.Fatalf("query signal matrix: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var cve, priority, confidence, method string
		if err := rows.Scan(&cve, &priority, &confidence, &method); err != nil {
			t.Fatalf("scan signal matrix: %v", err)
		}
		got = append(got, cve+" "+priority+" "+confidence+" "+method)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("signal matrix rows: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("signal matrix = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("signal matrix = %v, want %v", got, want)
		}
	}
}

// assertTableCounts compares the row census of the I1b tables with the
// expected counts (the duplicate-freedom proof of the demo path).
func assertTableCounts(t *testing.T, pool *pgxpool.Pool, want map[string]int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for table, wantCount := range want {
		var got int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != wantCount {
			t.Errorf("%s rows = %d, want %d", table, got, wantCount)
		}
	}
}
