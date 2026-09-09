package main

// Unit tests of the DEV-043 monitor computation (source_monitor.go): the
// pure functions — planned interval, data age with the cursor/finished_at
// bases, stale detection, counters decoding, rate-limit detection — and
// the per-source projection assembly (monitorEntryFor) including the JSON
// rendering of the fixed monitor shape. These tests need no PostgreSQL;
// the CLI envelope against a real database lives in
// source_monitor_db_test.go.

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

func TestPlannedInterval(t *testing.T) {
	cases := []struct {
		schedule string
		want     time.Duration
		ok       bool
	}{
		{"@hourly", time.Hour, true},
		{"@daily", 24 * time.Hour, true},
		{"@weekly", 0, false}, // not a supported schedule grammar (I2)
		{"", 0, false},        // operator-triggered source: no planned cadence
	}
	for _, tc := range cases {
		interval, ok := plannedInterval(tc.schedule)
		if interval != tc.want || ok != tc.ok {
			t.Errorf("plannedInterval(%q) = %s, %v; want %s, %v", tc.schedule, interval, ok, tc.want, tc.ok)
		}
	}
}

func TestRunDataAgeSecondsBases(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC) // 3h ago

	// Full-set / cursor-less source: the basis is the run's finished_at.
	age, ok := runDataAgeSeconds(now, finished, nil)
	if !ok || age != 3*3600 {
		t.Fatalf("finished_at basis: age = %v, ok = %v; want 10800, true", age, ok)
	}

	// An NVD run commits a last-modified cursor: the cursor time — the end
	// of the fetched window — is the data basis, even when the run finished
	// later (the cursor is written at the window's To, the run closes
	// afterwards).
	cursor := json.RawMessage(`{"last_modified":"2026-09-09T08:00:00Z"}`)
	age, ok = runDataAgeSeconds(now, finished, cursor)
	if !ok || age != 4*3600 {
		t.Fatalf("cursor basis: age = %v, ok = %v; want 14400, true", age, ok)
	}

	// A cursor without a parseable last_modified member is not a basis —
	// the monitor falls back to finished_at.
	age, ok = runDataAgeSeconds(now, finished, json.RawMessage(`{"last_modified":"not-a-time"}`))
	if !ok || age != 3*3600 {
		t.Fatalf("broken cursor falls back: age = %v, ok = %v; want 10800, true", age, ok)
	}
	age, ok = runDataAgeSeconds(now, finished, json.RawMessage(`{"other":"member"}`))
	if !ok || age != 3*3600 {
		t.Fatalf("cursor without last_modified falls back: age = %v, ok = %v; want 10800, true", age, ok)
	}
}

func TestRunDataAgeSecondsClampsAndAbsent(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

	// No successful run: no finished_at → no data age.
	if age, ok := runDataAgeSeconds(now, time.Time{}, nil); ok || age != 0 {
		t.Fatalf("absent finished_at: age = %v, ok = %v; want 0, false", age, ok)
	}

	// A basis in the future (clock skew between writer and reader) clamps
	// to zero — the data is not stale, never negative.
	future := now.Add(2 * time.Hour)
	if age, ok := runDataAgeSeconds(now, future, nil); !ok || age != 0 {
		t.Fatalf("future basis: age = %v, ok = %v; want 0, true", age, ok)
	}
}

func TestMonitorDegradedThreshold(t *testing.T) {
	const interval = time.Hour // planned interval; stale at more than 2× = 7200s

	if monitorDegraded(7200, true, interval) {
		t.Error("age exactly 2× the planned interval must not be degraded")
	}
	if !monitorDegraded(7201, true, interval) {
		t.Error("age beyond 2× the planned interval must be degraded")
	}
	if monitorDegraded(99999, false, interval) {
		t.Error("a source without a data age (never succeeded) must not degrade on age")
	}
	if monitorDegraded(99999, true, 0) {
		t.Error("a source without a planned interval must not degrade on age")
	}
}

func TestRunRateLimitedDetection(t *testing.T) {
	if !runRateLimited("failed", application.RateLimitedErrorText) {
		t.Error("failed run with the rate-limit error text must be rate-limited")
	}
	for _, tc := range []struct{ status, errText string }{
		{"succeeded", application.RateLimitedErrorText}, // impossible in practice; still not a rate-limit run
		{"failed", "upstream refused connection"},
		{"failed", ""},
		{"running", application.RateLimitedErrorText},
	} {
		if runRateLimited(tc.status, tc.errText) {
			t.Errorf("run(%s, %q) wrongly detected as rate-limited", tc.status, tc.errText)
		}
	}
}

func TestDecodeRunCounters(t *testing.T) {
	// The full I2 shape decodes member by member.
	got, err := decodeRunCounters(json.RawMessage(`{"records":1,"normalized":5,"errors":2,"quarantined":2,"matched":0,"signals":0}`))
	if err != nil {
		t.Fatalf("decode full counters: %v", err)
	}
	if got.Records != 1 || got.Normalized != 5 || got.Errors != 2 || got.Quarantined != 2 || got.Matched != 0 || got.Signals != 0 {
		t.Fatalf("decoded counters = %+v", got)
	}

	// The pre-I2 subset {records, matched, signals} decodes with the missing
	// keys at zero (I1b runs stay valid monitor input).
	got, err = decodeRunCounters(json.RawMessage(`{"records":1,"matched":2,"signals":3}`))
	if err != nil {
		t.Fatalf("decode subset counters: %v", err)
	}
	if got.Normalized != 0 || got.Errors != 0 || got.Quarantined != 0 {
		t.Fatalf("missing keys must decode zero, got %+v", got)
	}

	// A corrupt shape is an error, not a guess.
	if _, err := decodeRunCounters(json.RawMessage(`{"records":"many"}`)); err == nil {
		t.Fatal("corrupt counters must fail the decode")
	}
}

// monitorUUID builds a deterministic pgtype.UUID for the projection rows.
func monitorUUID(seed byte) pgtype.UUID {
	var u pgtype.UUID
	u.Valid = true
	for i := range u.Bytes {
		u.Bytes[i] = seed + byte(i)
	}
	return u
}

// monitorTimestamptz builds a valid pgtype.Timestamptz.
func monitorTimestamptz(at time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: at, Valid: true}
}

// TestMonitorEntryForAssembly builds one source with a successful latest
// run (a full-set source whose age sits exactly at the stale boundary) and
// asserts the projection fields, the metrics and the JSON rendering of the
// fixed shape.
func TestMonitorEntryForAssembly(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	started := now.Add(-2*time.Hour - 5*time.Minute) // run took 5 minutes
	finished := now.Add(-2 * time.Hour)              // data age 7200s = exactly 2× the hourly interval

	source := genListSourcesRow("synthetic", "synthetic-source", "@hourly", true)
	latest := genLatestRunRow(source.ID, "succeeded", started, finished, `{"records":1,"normalized":4,"errors":0,"quarantined":0,"matched":0,"signals":0}`, "", nil)
	succeeded := genLatestSucceededRow(source.ID, "succeeded", started, finished, nil)
	quarantineOpen := int64(2)

	entry, err := monitorEntryFor(source, latest, succeeded, quarantineOpen, now)
	if err != nil {
		t.Fatalf("monitorEntryFor: %v", err)
	}

	if entry.SourceID != demoUUID(source.ID) || entry.Type != "synthetic" || entry.Name != "synthetic-source" {
		t.Fatalf("source identity = %+v", entry)
	}
	if !entry.Enabled || entry.Schedule == nil || *entry.Schedule != "@hourly" {
		t.Fatalf("schedule = %+v, want enabled @hourly", entry.Schedule)
	}
	if entry.PlannedIntervalSeconds == nil || *entry.PlannedIntervalSeconds != 3600 {
		t.Fatalf("planned interval = %+v, want 3600", entry.PlannedIntervalSeconds)
	}
	if entry.QuarantineOpen != 2 {
		t.Fatalf("quarantine_open = %d, want 2", entry.QuarantineOpen)
	}

	// Data age is 2h exactly: at the stale boundary it is NOT degraded.
	if entry.DataAgeSeconds == nil || *entry.DataAgeSeconds != 7200 {
		t.Fatalf("data age = %+v, want 7200", entry.DataAgeSeconds)
	}
	if entry.Degraded {
		t.Fatal("age at exactly 2× the planned interval must not be degraded")
	}

	run := entry.LastRun
	if run == nil || run.Status != "succeeded" || run.FinishedAt == nil || !run.FinishedAt.Equal(finished) {
		t.Fatalf("last run = %+v", run)
	}
	if run.Counters.Records != 1 || run.Counters.Normalized != 4 {
		t.Fatalf("last run counters = %+v", run.Counters)
	}
	if run.RateLimited || run.Error != nil {
		t.Fatalf("last run must not be rate-limited with no error, got %+v", run)
	}

	// The metrics block derives from the projection.
	if entry.Metrics.SourceRecordsTotal != 1 || entry.Metrics.SourceErrorsTotal != 0 || entry.Metrics.SourceRateLimited != 0 {
		t.Fatalf("metrics = %+v", entry.Metrics)
	}
	if entry.Metrics.SourceDataAgeSeconds == nil || *entry.Metrics.SourceDataAgeSeconds != 7200 {
		t.Fatalf("metrics data age = %+v, want 7200", entry.Metrics.SourceDataAgeSeconds)
	}
	if entry.Metrics.SourceRunDurationSeconds == nil || *entry.Metrics.SourceRunDurationSeconds != 300 {
		t.Fatalf("metrics duration = %+v, want 300", entry.Metrics.SourceRunDurationSeconds)
	}
	if entry.Metrics.EpssRowsTotal != 0 {
		t.Fatalf("non-epss source must report epss_rows_total 0, got %v", entry.Metrics.EpssRowsTotal)
	}

	// The JSON rendering carries the fixed keys with null for absent facts,
	// and the strict decode proves the shape round-trips without drift.
	encoded, err := json.Marshal(sourceListResult{Sources: []monitorEntry{entry}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var strict sourceListResult
	decodeJSONStrict(t, string(encoded), &strict)
	if len(strict.Sources) != 1 || strict.Sources[0].SourceID != entry.SourceID {
		t.Fatalf("strict round trip = %+v", strict)
	}
	for _, key := range []string{
		`"source_id"`, `"type"`, `"name"`, `"endpoint"`, `"enabled"`, `"schedule"`,
		`"planned_interval_seconds"`, `"last_run"`, `"data_age_seconds"`, `"degraded"`,
		`"quarantine_open"`, `"metrics"`,
		`"source_run_duration_seconds"`, `"source_records_total"`, `"source_errors_total"`,
		`"source_data_age_seconds"`, `"source_rate_limited"`, `"epss_rows_total"`,
		`"run_id"`, `"status"`, `"started_at"`, `"finished_at"`, `"counters"`, `"error"`, `"rate_limited"`,
	} {
		if !bytes.Contains(encoded, []byte(key)) {
			t.Errorf("rendered JSON lacks the fixed key %s:\n%s", key, encoded)
		}
	}
}

// TestMonitorEntryForDegradedAndRateLimited covers a degraded source (age
// beyond 2× the planned interval) whose latest run was rate-limited, and a
// never-run source (no last run, no data age, never degraded).
func TestMonitorEntryForDegradedAndRateLimited(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	finished := now.Add(-3 * time.Hour) // 3h of data age

	source := genListSourcesRow("kev", "kev-catalog", "@daily", true)
	// A failed rate-limited fetch is the latest run; the last successful
	// run before it still anchors the data age.
	latest := genLatestRunRow(source.ID, "failed", finished, finished.Add(2*time.Minute),
		`{}`, application.RateLimitedErrorText, nil)
	succeeded := genLatestSucceededRow(source.ID, "succeeded", finished.Add(-30*time.Minute), finished, nil)

	entry, err := monitorEntryFor(source, latest, succeeded, 0, now)
	if err != nil {
		t.Fatalf("monitorEntryFor: %v", err)
	}
	if entry.Degraded {
		t.Fatal("3h of age with a daily (24h) schedule must not degrade")
	}

	// The same source with an hourly schedule is stale: 3h > 2×1h.
	hourly := genListSourcesRow("kev", "kev-catalog", "@hourly", true)
	entry, err = monitorEntryFor(hourly, latest, succeeded, 1, now)
	if err != nil {
		t.Fatalf("monitorEntryFor: %v", err)
	}
	if !entry.Degraded {
		t.Fatal("3h of age with an hourly schedule must be degraded")
	}
	if entry.QuarantineOpen != 1 {
		t.Fatalf("quarantine_open = %d, want 1", entry.QuarantineOpen)
	}
	if entry.LastRun == nil || !entry.LastRun.RateLimited {
		t.Fatalf("latest failed run with the rate-limit text must be flagged, got %+v", entry.LastRun)
	}
	if entry.Metrics.SourceRateLimited != 1 {
		t.Fatalf("metrics rate-limited = %v, want 1", entry.Metrics.SourceRateLimited)
	}
	if entry.LastRun.Error == nil || *entry.LastRun.Error != application.RateLimitedErrorText {
		t.Fatalf("last run error = %+v, want the stable rate-limit code", entry.LastRun.Error)
	}

	// A source that never ran: no last run, no data age, never degraded.
	never := genListSourcesRow("epss", "epss-daily", "@daily", true)
	entry, err = monitorEntryFor(never, gen.LatestSourceRunBySourceRow{}, gen.LatestSucceededSourceRunBySourceRow{}, 0, now)
	if err != nil {
		t.Fatalf("monitorEntryFor never-run source: %v", err)
	}
	if entry.LastRun != nil || entry.DataAgeSeconds != nil || entry.Degraded {
		t.Fatalf("never-run source view = %+v, want no run, no age, not degraded", entry)
	}
	if entry.Metrics.SourceRecordsTotal != 0 || entry.Metrics.SourceErrorsTotal != 0 || entry.Metrics.SourceDataAgeSeconds != nil {
		t.Fatalf("never-run source metrics = %+v", entry.Metrics)
	}

	// The epss source reports the epss_rows_total of its latest run (the
	// daily set's row count as loaded by the pass).
	epssLatest := genLatestRunRow(never.ID, "succeeded", now.Add(-1*time.Hour), now.Add(-50*time.Minute),
		`{"records":1,"normalized":201234,"errors":0,"quarantined":0,"matched":0,"signals":0}`, "", nil)
	epssSucceeded := genLatestSucceededRow(never.ID, "succeeded", now.Add(-1*time.Hour), now.Add(-50*time.Minute), nil)
	entry, err = monitorEntryFor(never, epssLatest, epssSucceeded, 0, now)
	if err != nil {
		t.Fatalf("monitorEntryFor epss source: %v", err)
	}
	if entry.Metrics.EpssRowsTotal != 201234 {
		t.Fatalf("epss_rows_total = %v, want 201234", entry.Metrics.EpssRowsTotal)
	}
	if entry.Degraded {
		t.Fatal("fresh epss source must not be degraded")
	}
}

// genListSourcesRow builds one sources row of the ListSources shape.
func genListSourcesRow(typ, name, schedule string, enabled bool) gen.ListSourcesRow {
	return gen.ListSourcesRow{
		ID:       monitorUUID(1),
		Type:     typ,
		Name:     name,
		Enabled:  enabled,
		Schedule: pgtype.Text{String: schedule, Valid: schedule != ""},
	}
}

// genLatestRunRow builds one latest-run row of the monitor shape.
func genLatestRunRow(sourceID pgtype.UUID, status string, startedAt, finishedAt time.Time, counters, errText string, cursorAfter json.RawMessage) gen.LatestSourceRunBySourceRow {
	row := gen.LatestSourceRunBySourceRow{
		SourceID:    sourceID,
		ID:          monitorUUID(2),
		Status:      status,
		StartedAt:   monitorTimestamptz(startedAt),
		FinishedAt:  monitorTimestamptz(finishedAt),
		Counters:    []byte(counters),
		CursorAfter: cursorAfter,
	}
	if errText != "" {
		row.Error = pgtype.Text{String: errText, Valid: true}
	}
	return row
}

// genLatestSucceededRow builds one latest-succeeded-run row.
func genLatestSucceededRow(sourceID pgtype.UUID, status string, startedAt, finishedAt time.Time, cursorAfter json.RawMessage) gen.LatestSucceededSourceRunBySourceRow {
	return gen.LatestSucceededSourceRunBySourceRow{
		SourceID:    sourceID,
		ID:          monitorUUID(3),
		Status:      status,
		StartedAt:   monitorTimestamptz(startedAt),
		FinishedAt:  monitorTimestamptz(finishedAt),
		Counters:    []byte(`{}`),
		CursorAfter: cursorAfter,
	}
}
