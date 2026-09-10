package main

// Integration tests of the demo path (WP-1b.05 / DEV-019 and the WP-4.08 /
// DEV-083 I4 extension) at the composition root: `demo seed` (register the
// synthetic source, seed the demo inventory, run the synthetic source once
// and write the deterministic P1–P4 I4 fixture), `demo run` (the accelerated
// UC-08 SLA scenario through the real use cases and worker pieces) and
// `demo reset` (dev-only truncation of the demo tables) against a real,
// short-lived PostgreSQL.
//
// The test proves:
//   (a) one seed produces the synthetic reference chain (source, inventory,
//       document, vulnerabilities + evidences, method-led matches and the
//       reference signals C1–C4 with the expected P1/P2/P2/P3 priorities,
//       the malformed E1 case counted as a run error without aborting the
//       run) *plus* the deterministic I4 fixture: eight fixed-id signals
//       covering P1–P4 and every ch. 6.3 status with their SLA clocks and
//       audit rows (ARCH-004 §8, UC-08);
//   (b) `demo seed` twice yields no duplicates and the fixture is a no-op the
//       second time — identical ids, priorities and statuses;
//   (c) `demo run` shows the full accelerated SLA lifecycle end to end
//       (create → deliver → acknowledge → action_planned → resolve, a P3→P1
//       upgrade and an unacknowledged-P1 escalation) and is re-runnable;
//   (d) `demo reset` refuses without --yes (exit 2) and truncates the demo
//       tables with --yes, after which `demo seed` rebuilds the identical
//       demo state.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// wantSignalMatrix is the expected per-case outcome of one demo seed's
// synthetic source run (scoped to the "demo" inventory source so the I4
// fixture's own "demo-i4" signals do not noise it): the CVE, the derived
// priority, the match confidence and the match method of every produced
// signal (ordered by cve_id). C5/C6 produce no signal (no confirmed
// assignment) and E1 is counted as a run error — they are not rows here.
var wantSignalMatrix = []string{
	"CVE-2024-0001 P1 high canonical_product_range",
	"CVE-2024-0002 P2 high canonical_product_range",
	"CVE-2024-0003 P2 high canonical_product_range",
	"CVE-2024-0004 P3 high exact_identifier",
}

// wantDemoTableCounts is the row census after one demo seed at the I4 stage:
// the I1b synthetic chain plus the deterministic I4 fixture (one asset, one
// component, eight vulnerabilities/matches/signals, their SLA clocks and
// their audit rows; the fixture enqueues no outbox event).
var wantDemoTableCounts = map[string]int{
	"sources":         1,
	"assets":          3, // 2 synthetic + 1 I4 fixture asset
	"components":      3, // 2 synthetic + 1 I4 fixture component
	"source_runs":     1,
	"raw_records":     1,
	"vulnerabilities": 14, // C1–C6 + the 8 fixture CVEs
	"evidences":       24, // 6 ingested cases × 4 typed statements
	"matches":         12, // C1–C4 + the 8 fixture matches
	"risk_signals":    12, // C1–C4 + the 8 fixture signals
	"sla_clocks":      36, // 14 synthetic (CreateSignal creates the ch. 9.4 clocks) + 22 fixture
	"audit_events":    25, // 4 synthetic creations + 21 fixture journey rows
	"outbox":          4,  // the 4 synthetic signal.created events
}

// TestDemoSeedRunResetAgainstRealDatabase drives the whole demo lifecycle
// through the CLI and asserts the exit criteria on the real rows.
func TestDemoSeedRunResetAgainstRealDatabase(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// A fresh database migrates first (the demo commands expect the schema;
	// migrations are the CLI's own maintenance path).
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
	// The I4 fixture census is reported and matches the fixture table.
	if seed.Fixture.Signals != 8 || seed.Fixture.Clocks != 22 || seed.Fixture.Audits != 21 || seed.Fixture.AlreadyPresent {
		t.Fatalf("demo seed fixture summary = %+v, want 8 signals / 22 clocks / 21 audits", seed.Fixture)
	}

	// The produced synthetic signals carry the expected P1/P2/P2/P3 matrix
	// with high confidence (ADR-015 methods canonical_product_range /
	// exact_identifier); the I4 fixture carries its fixed P1–P4/status set.
	assertSignalMatrix(t, pool, wantSignalMatrix)
	assertDemoFixture(t, pool)
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
	// The fixture is a no-op the second time; the derived rows are unchanged.
	if !seed.Fixture.AlreadyPresent || seed.Fixture.Signals != 0 {
		t.Fatalf("second seed fixture summary = %+v, want already_present with 0 signals", seed.Fixture)
	}
	counts := copyTableCounts(wantDemoTableCounts)
	counts["source_runs"] = 2 // one run row per execution is the only growth
	assertTableCounts(t, pool, counts)
	assertDemoFixture(t, pool)
	assertSignalMatrix(t, pool, wantSignalMatrix)

	// --- (c) demo run: the accelerated UC-08 scenario ---------------------
	scenario := runDemoScenarioCLI(t, env)
	assertDemoScenarioResult(t, scenario)
	// Re-running the scenario is idempotent (it resets its own rows).
	again := runDemoScenarioCLI(t, env)
	if again.Lifecycle.StatusHistory == nil || len(again.Lifecycle.StatusHistory) != len(scenario.Lifecycle.StatusHistory) {
		t.Fatalf("demo run re-run lifecycle = %+v, want the same shape as %+v", again.Lifecycle, scenario.Lifecycle)
	}

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
		t.Fatalf("demo reset tables = %v, want the %d demo tables", reset.Tables, len(demoResetTables))
	}
	empty := map[string]int{}
	for _, table := range demoResetTables {
		empty[table] = 0
	}
	assertTableCounts(t, pool, empty)

	// Re-seeding after the reset rebuilds the identical demo state — the
	// same synthetic reference signals and the same I4 fixture.
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
	assertDemoFixture(t, pool)

	// The text forms of the demo commands stay human-readable.
	code, stdout, stderr = runCLI(t, env, "demo", "run")
	if code != exitOK || !strings.Contains(stdout, "UC-08 accelerated SLA scenario") || stderr != "" {
		t.Fatalf("text demo run = code %d stdout %q stderr %q, want a human-readable scenario report", code, stdout, stderr)
	}
}

// runDemoScenarioCLI runs `demo run --output json` and decodes the scenario.
func runDemoScenarioCLI(t *testing.T, env map[string]string) demoScenarioResult {
	t.Helper()
	code, stdout, stderr := runCLI(t, env, "demo", "run", "--output", "json")
	if code != exitOK {
		t.Fatalf("demo run exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	var run demoRunResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &run)
	return run.Scenario
}

// assertDemoScenarioResult pins the UC-08 scenario outcome: the full P1
// lifecycle, the P3→P1 upgrade (missing clocks created, existing tightened)
// and the exactly-once escalation.
func assertDemoScenarioResult(t *testing.T, s demoScenarioResult) {
	t.Helper()
	if s.Scenario != "uc-08-accelerated-sla-lifecycle" {
		t.Fatalf("scenario name = %q, want uc-08-accelerated-sla-lifecycle", s.Scenario)
	}
	wantStatuses := []string{"new", "in_review", "action_planned", "resolved"}
	if len(s.Lifecycle.StatusHistory) != len(wantStatuses) {
		t.Fatalf("lifecycle statuses = %v, want %v", s.Lifecycle.StatusHistory, wantStatuses)
	}
	for i, want := range wantStatuses {
		if s.Lifecycle.StatusHistory[i] != want {
			t.Fatalf("lifecycle status[%d] = %q, want %q (full %v)", i, s.Lifecycle.StatusHistory[i], want, s.Lifecycle.StatusHistory)
		}
	}
	if s.Lifecycle.Priority != "P1" {
		t.Errorf("lifecycle priority = %q, want P1", s.Lifecycle.Priority)
	}
	if !s.Lifecycle.NotificationDelivered {
		t.Error("lifecycle notification was not delivered")
	}
	if s.Lifecycle.ClosedAt == nil {
		t.Error("lifecycle closed_at is nil, want set after resolve")
	}
	for _, target := range []string{"notification", "acknowledgement", "assessment", "decision"} {
		clock, ok := s.Lifecycle.Clocks[target]
		if !ok {
			t.Errorf("lifecycle has no %s clock", target)
			continue
		}
		if clock.FulfilledAt == nil {
			t.Errorf("lifecycle %s clock is open, want fulfilled", target)
		}
	}

	if s.Upgrade.FromPriority != "P3" || s.Upgrade.ToPriority != "P1" {
		t.Errorf("upgrade = %s->%s, want P3->P1", s.Upgrade.FromPriority, s.Upgrade.ToPriority)
	}
	if !contains(s.Upgrade.ClocksCreated, "notification") || !contains(s.Upgrade.ClocksCreated, "decision") {
		t.Errorf("upgrade created clocks = %v, want notification+decision", s.Upgrade.ClocksCreated)
	}
	if !tightens(s.Upgrade.ClocksTightened, "acknowledgement") || !tightens(s.Upgrade.ClocksTightened, "assessment") {
		t.Errorf("upgrade tightened clocks = %+v, want acknowledgement+assessment", s.Upgrade.ClocksTightened)
	}
	if s.Upgrade.CreatedAudits != 2 || s.Upgrade.TightenedAudits != 2 {
		t.Errorf("upgrade audits = %d created / %d tightened, want 2/2", s.Upgrade.CreatedAudits, s.Upgrade.TightenedAudits)
	}

	if s.Escalation.EscalatedAt == nil {
		t.Error("escalation instant is nil, want the unacknowledged P1 escalated")
	}
	if s.Escalation.Escalations != 1 {
		t.Errorf("escalations = %d, want exactly 1", s.Escalation.Escalations)
	}
	if s.Escalation.Reminders < 1 {
		t.Errorf("reminders = %d, want at least 1 (cadence window elapsed)", s.Escalation.Reminders)
	}
}

// contains reports whether want is in the string slice.
func contains(hay []string, want string) bool {
	for _, s := range hay {
		if s == want {
			return true
		}
	}
	return false
}

// tightens reports whether the tightened set names the target with an
// earlier new deadline.
func tightens(ts []demoTightenedClock, target string) bool {
	for _, tc := range ts {
		if tc.Target == target && tc.NewDeadline.Before(tc.OldDeadline) {
			return true
		}
	}
	return false
}

// assertDemoFixture pins the seeded I4 fixture against the same pure
// derivation the seed uses: each fixed-id signal carries the derived
// priority, status, version, closed_at and factor set; its clocks are the
// profile's targets at that priority with the derived fulfilment state and
// window; and its audit count matches the journey. The instants are the seed
// clock's (unknown here), so the instants are checked for consistency, not
// equality.
func assertDemoFixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	profile := domain.DefaultSLATimeProfile()
	for _, sig := range demoFixtureSignals() {
		priority, version, _, clocks, audits, err := demoFixturePlan(sig, time.Now())
		if err != nil {
			t.Fatalf("demoFixturePlan(%s): %v", sig.ID, err)
		}
		var gotPriority, gotStatus string
		var gotVersion int32
		var factorsJSON []byte
		var closed pgtype.Timestamptz
		if err := pool.QueryRow(ctx,
			`SELECT priority, status, version, factors, closed_at FROM risk_signals WHERE id = $1`,
			mustUUID(t, sig.ID)).Scan(&gotPriority, &gotStatus, &gotVersion, &factorsJSON, &closed); err != nil {
			t.Fatalf("read fixture signal %s: %v", sig.ID, err)
		}
		if gotPriority != string(priority) || gotStatus != string(sig.Status) || gotVersion != version {
			t.Errorf("fixture signal %s = %s/%s/v%d, want %s/%s/v%d",
				sig.ID, gotPriority, gotStatus, gotVersion, priority, sig.Status, version)
		}
		if closed.Valid != sig.Status.IsClosed() {
			t.Errorf("fixture signal %s closed_at valid = %t, want %t (%s)", sig.ID, closed.Valid, sig.Status.IsClosed(), sig.Status)
		}
		var storedFactors domain.PriorityFactors
		if err := json.Unmarshal(factorsJSON, &storedFactors); err != nil {
			t.Fatalf("decode %s factors: %v", sig.ID, err)
		}
		if storedFactors != sig.Factors {
			t.Errorf("fixture signal %s factors = %+v, want %+v", sig.ID, storedFactors, sig.Factors)
		}

		// Clocks: exactly the derived targets, with the derived fulfilment and
		// a window equal to the profile duration.
		wantClocks := map[domain.SLATarget]demoFixtureClock{}
		for _, c := range clocks {
			wantClocks[c.Target] = c
		}
		rows, err := pool.Query(ctx,
			`SELECT target, started_at, deadline_at, fulfilled_at FROM sla_clocks WHERE signal_id = $1`,
			mustUUID(t, sig.ID))
		if err != nil {
			t.Fatalf("read fixture clocks of %s: %v", sig.ID, err)
		}
		seen := 0
		for rows.Next() {
			var target string
			var started, deadline time.Time
			var fulfilled pgtype.Timestamptz
			if err := rows.Scan(&target, &started, &deadline, &fulfilled); err != nil {
				rows.Close()
				t.Fatalf("scan fixture clock of %s: %v", sig.ID, err)
			}
			want, ok := wantClocks[domain.SLATarget(target)]
			if !ok {
				t.Errorf("fixture signal %s has unexpected %s clock", sig.ID, target)
				continue
			}
			seen++
			if fulfilled.Valid != !want.FulfilledAt.IsZero() {
				t.Errorf("fixture signal %s %s fulfilled = %t, want %t", sig.ID, target, fulfilled.Valid, !want.FulfilledAt.IsZero())
			}
			if got := deadline.Sub(started); got != profile.Duration(priority, domain.SLATarget(target)) {
				t.Errorf("fixture signal %s %s window = %s, want %s", sig.ID, target, got, profile.Duration(priority, domain.SLATarget(target)))
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate fixture clocks of %s: %v", sig.ID, err)
		}
		if seen != len(wantClocks) {
			t.Errorf("fixture signal %s has %d clocks, want %d", sig.ID, seen, len(wantClocks))
		}

		// Audit rows: the journey's count and actions.
		var auditCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE aggregate_id = $1`, mustUUID(t, sig.ID)).Scan(&auditCount); err != nil {
			t.Fatalf("count fixture audits of %s: %v", sig.ID, err)
		}
		if auditCount != len(audits) {
			t.Errorf("fixture signal %s has %d audit rows, want %d", sig.ID, auditCount, len(audits))
		}
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

// assertSignalMatrix compares the produced synthetic signal rows (cve_id,
// priority, confidence, method, ordered by cve_id) with the expected matrix.
// It is scoped to the synthetic inventory source ("demo"), so the I4
// fixture's own "demo-i4" signals are asserted separately.
func assertSignalMatrix(t *testing.T, pool *pgxpool.Pool, want []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT v.cve_id, rs.priority, m.confidence, m.method
		 FROM risk_signals rs
		 JOIN matches m ON m.id = rs.match_id
		 JOIN vulnerabilities v ON v.id = m.vulnerability_id
		 JOIN components c ON c.id = m.component_id
		 JOIN assets a ON a.id = c.asset_id
		 WHERE a.source = 'demo'
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

// assertTableCounts compares the row census of the demo tables with the
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
