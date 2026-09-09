package main

// Integration tests of the DEV-043 source monitor CLI against a real
// PostgreSQL (ARCH-002 §5): `source list` and `source status` render the
// monitor projection — seeded sources with finished runs, an open
// quarantine row — and the assertions cover the data-age computation, the
// degraded (stale) detection, the counters, the rate-limit flag and the
// fixed --output json envelope. Like the other database-backed CLI tests
// these skip when no PostgreSQL is reachable, so `go test ./...` stays
// green on machines without the compose environment.

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// seedMonitorFixture migrates a fresh database and seeds the monitor rows:
// a stale hourly source (data age 3h > 2×1h, one open quarantine row), a
// fresh hourly source (data age ~20m, no quarantine) and an epss source
// whose latest run loaded a daily set (epss_rows_total). It returns the
// database URL and the seeded source ids by name.
func seedMonitorFixture(t *testing.T) (dbURL string, ids map[string]string) {
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

	ids = map[string]string{}
	now := time.Now().UTC()
	insertSource := func(typ, name, schedule string) string {
		var id string
		if err := db.QueryRow(
			`INSERT INTO sources (type, name, schedule) VALUES ($1, $2, $3) RETURNING id`,
			typ, name, schedule).Scan(&id); err != nil {
			t.Fatalf("insert source %s/%s: %v", typ, name, err)
		}
		ids[name] = id
		return id
	}
	insertRun := func(sourceID, status string, startedAt, finishedAt time.Time, counters string, errText *string) {
		t.Helper()
		if _, err := db.Exec(
			`INSERT INTO source_runs (source_id, started_at, finished_at, status, counters, error)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
			sourceID, startedAt, finishedAt, status, counters, errText); err != nil {
			t.Fatalf("insert run for %s: %v", sourceID, err)
		}
	}

	// Stale source: hourly schedule, last successful run finished 3h ago —
	// data age 3h exceeds 2× the 1h planned interval → degraded.
	staleID := insertSource("synthetic", "monitor-stale", "@hourly")
	counters := `{"records":1,"normalized":2,"errors":0,"quarantined":0,"matched":0,"signals":0}`
	insertRun(staleID, "succeeded", now.Add(-3*time.Hour-90*time.Second), now.Add(-3*time.Hour), counters, nil)
	// One open quarantine row of the stale source.
	if _, err := db.Exec(
		`INSERT INTO quarantine (source_id, position, reason, payload_hash, status, created_at, updated_at)
		 VALUES ($1, '7', 'synthetic.normalize.missing_cve: fixture', 'deadbeef', 'new', $2, $2)`,
		staleID, now); err != nil {
		t.Fatalf("insert quarantine row: %v", err)
	}

	// Fresh source: hourly schedule, last successful run finished ~20m ago.
	freshID := insertSource("synthetic", "monitor-fresh", "@hourly")
	insertRun(freshID, "succeeded", now.Add(-20*time.Minute-45*time.Second), now.Add(-20*time.Minute), counters, nil)

	// EPSS source: daily schedule, latest run loaded a daily set — the
	// normalized counter carries the copied row count (epss_rows_total).
	epssID := insertSource("epss", "monitor-epss", "@daily")
	epssCounters := `{"records":1,"normalized":201234,"errors":0,"quarantined":0,"matched":0,"signals":0}`
	insertRun(epssID, "succeeded", now.Add(-12*time.Minute-50*time.Second), now.Add(-12*time.Minute), epssCounters, nil)

	// A never-succeeded source with a failed (rate-limited) latest run: the
	// error text is the stable rate-limit code of the fetch half (ch. 14.2).
	limitedID := insertSource("nvd", "monitor-limited", "@hourly")
	rateLimitText := "fetch.rate_limited"
	insertRun(limitedID, "failed", now.Add(-25*time.Minute), now.Add(-24*time.Minute), `{}`, &rateLimitText)

	return dbURL, ids
}

// TestSourceMonitorCLIRendersProjectionJSON drives `source list` and
// `source status <id>` against the seeded fixture and asserts the data-age
// computation, the degraded detection, the counters, the rate-limit flag
// and the schema-stable JSON envelope.
func TestSourceMonitorCLIRendersProjectionJSON(t *testing.T) {
	dbURL, ids := seedMonitorFixture(t)
	env := cliDBEnv(dbURL)

	code, stdout, stderr := runCLI(t, env, "source", "list", "--output", "json")
	if code != exitOK {
		t.Fatalf("source list exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Error != nil || envJSON.Command != "source list" {
		t.Fatalf("envelope = %+v, want ok source list", envJSON)
	}
	var res sourceListResult
	decodeJSONStrict(t, string(envJSON.Result), &res)
	if len(res.Sources) != 4 {
		t.Fatalf("source list returned %d sources, want 4: %+v", len(res.Sources), res.Sources)
	}

	byName := map[string]monitorEntry{}
	for _, entry := range res.Sources {
		byName[entry.Name] = entry
	}

	// The stale source: data age ≈ 3h > 2× the 1h planned interval →
	// degraded; one open quarantine row; counters of the latest run.
	stale, ok := byName["monitor-stale"]
	if !ok {
		t.Fatalf("stale source missing from list: %+v", byName)
	}
	if stale.Schedule == nil || *stale.Schedule != "@hourly" {
		t.Fatalf("stale schedule = %+v, want @hourly", stale.Schedule)
	}
	assertAgeRange(t, stale.DataAgeSeconds, "monitor-stale", 3*3600, 30)
	if !stale.Degraded {
		t.Fatalf("monitor-stale must be degraded (age 3h > 2×1h), entry = %+v", stale)
	}
	if stale.QuarantineOpen != 1 {
		t.Fatalf("monitor-stale quarantine_open = %d, want 1", stale.QuarantineOpen)
	}
	if stale.LastRun == nil || stale.LastRun.Status != "succeeded" {
		t.Fatalf("monitor-stale last run = %+v, want succeeded", stale.LastRun)
	}
	if stale.LastRun.Counters.Records != 1 || stale.LastRun.Counters.Normalized != 2 {
		t.Fatalf("monitor-stale counters = %+v", stale.LastRun.Counters)
	}
	// The metrics block mirrors the projection (data age identical).
	if stale.Metrics.SourceDataAgeSeconds == nil || *stale.Metrics.SourceDataAgeSeconds != *stale.DataAgeSeconds {
		t.Fatalf("metrics data age %+v diverges from data age %+v", stale.Metrics.SourceDataAgeSeconds, stale.DataAgeSeconds)
	}
	if stale.Metrics.SourceRecordsTotal != 1 || stale.Metrics.SourceErrorsTotal != 0 || stale.Metrics.SourceRateLimited != 0 {
		t.Fatalf("stale metrics = %+v", stale.Metrics)
	}

	// The fresh source: data age ≈ 20m < 2×1h → not degraded.
	fresh, ok := byName["monitor-fresh"]
	if !ok {
		t.Fatalf("fresh source missing: %+v", byName)
	}
	assertAgeRange(t, fresh.DataAgeSeconds, "monitor-fresh", 20*60, 30)
	if fresh.Degraded || fresh.QuarantineOpen != 0 {
		t.Fatalf("monitor-fresh = %+v, want not degraded, no quarantine", fresh)
	}

	// The epss source reports the row count of the loaded daily set.
	epss, ok := byName["monitor-epss"]
	if !ok {
		t.Fatalf("epss source missing: %+v", byName)
	}
	if epss.Metrics.EpssRowsTotal != 201234 {
		t.Fatalf("monitor-epss epss_rows_total = %v, want 201234", epss.Metrics.EpssRowsTotal)
	}

	// The rate-limited source: latest run failed with the stable code → the
	// flag is set and the metric reports 1; no successful run ever → no data
	// age and not degraded on age.
	limited, ok := byName["monitor-limited"]
	if !ok {
		t.Fatalf("limited source missing: %+v", byName)
	}
	if limited.LastRun == nil || !limited.LastRun.RateLimited {
		t.Fatalf("monitor-limited last run = %+v, want rate-limited flag", limited.LastRun)
	}
	if limited.LastRun.Error == nil || *limited.LastRun.Error != "fetch.rate_limited" {
		t.Fatalf("monitor-limited error = %+v, want fetch.rate_limited", limited.LastRun.Error)
	}
	if limited.Metrics.SourceRateLimited != 1 {
		t.Fatalf("monitor-limited metrics rate-limited = %v, want 1", limited.Metrics.SourceRateLimited)
	}
	if limited.DataAgeSeconds != nil || limited.Degraded {
		t.Fatalf("never-succeeded monitor-limited = %+v, want no age, not degraded", limited)
	}

	// `source status <id>` renders the same monitor entry for the one named
	// source — the automation read of one source.
	code, stdout, stderr = runCLI(t, env, "source", "status", ids["monitor-stale"], "--output", "json")
	if code != exitOK {
		t.Fatalf("source status exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	envJSON = decodeEnvelope(t, stdout)
	if envJSON.Status != "ok" || envJSON.Command != "source status" {
		t.Fatalf("status envelope = %+v", envJSON)
	}
	var statusRes sourceListResult
	decodeJSONStrict(t, string(envJSON.Result), &statusRes)
	if len(statusRes.Sources) != 1 || statusRes.Sources[0].SourceID != ids["monitor-stale"] {
		t.Fatalf("status result = %+v, want the one named source", statusRes.Sources)
	}
	if !statusRes.Sources[0].Degraded || statusRes.Sources[0].QuarantineOpen != 1 {
		t.Fatalf("status entry = %+v, want degraded with one open quarantine", statusRes.Sources[0])
	}

	// The text form stays human-readable for the same command.
	code, stdout, stderr = runCLI(t, env, "source", "status", ids["monitor-stale"])
	if code != exitOK {
		t.Fatalf("text status exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	for _, piece := range []string{
		"source monitor-stale", "status succeeded", "rate limited: false",
		"data age:", "degraded: true", "quarantine open: 1",
		"source_data_age_seconds", "source_records_total",
	} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("text status stdout lacks %q:\n%s", piece, stdout)
		}
	}
	if stderr != "" {
		t.Errorf("text status stderr = %q, want empty", stderr)
	}
}

// TestSourceStatusUnknownRefIsGenericError drives the argument validation
// of `source status <ref>`: a ref that resolves to no source is a generic
// failure, reported in the envelope in json mode.
func TestSourceStatusUnknownRefIsGenericError(t *testing.T) {
	dbURL, _ := seedMonitorFixture(t)
	env := cliDBEnv(dbURL)

	code, stdout, stderr := runCLI(t, env, "source", "status", "no-such-type", "--output", "json")
	if code != exitGeneric || stderr != "" {
		t.Fatalf("code %d stderr %q, want %d with empty stderr", code, stderr, exitGeneric)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Status != "error" || envJSON.Error == nil || envJSON.Error.Class != classGeneric {
		t.Fatalf("envelope = %+v, want a generic error", envJSON)
	}
	if !strings.Contains(envJSON.Error.Message, "no source of type") {
		t.Errorf("error message %q does not name the unknown type", envJSON.Error.Message)
	}
}

// assertAgeRange asserts a data age within [want-tol, want+tol] seconds.
func assertAgeRange(t *testing.T, age *float64, source string, wantSeconds, tolerance float64) {
	t.Helper()
	if age == nil {
		t.Fatalf("%s: data age is null, want ≈ %v seconds", source, wantSeconds)
	}
	if *age < wantSeconds-tolerance || *age > wantSeconds+tolerance {
		t.Fatalf("%s: data age = %v seconds, want ≈ %v ± %v", source, *age, wantSeconds, tolerance)
	}
}
