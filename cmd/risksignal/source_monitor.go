// Source monitor (WP-2.08b / DEV-043, ARCH-002 §5): `source list` and
// `source status` render the monitor projection — the read-only view of
// every source: the latest run (status, finished_at, committed counters,
// error), the rate-limit flag of the latest run, the open quarantine
// count, the data age (clock.Now() − the last successful run's basis) and
// the stale detection that surfaces a source as degraded when its data age
// exceeds twice its planned interval — visibility only, never making the
// application unready (ch. 16.3).
//
// The projection is built from three operator reads on the sqlc query set
// (the sources rows, the latest source_runs rows, the open quarantine
// counts) — a read, not a domain command, following the source.go
// resolution convention of the command root. The reads select no secret:
// sources.config (which holds the api_key_ref secret reference, ch. 3.3)
// is never part of the projection or the output.
//
// This file holds the projection types and the pure computation (data age,
// degraded detection, counters, rate-limit flag, planned interval); the
// command handlers of `source list` and `source status` live in the same
// file below and render the projection as text or as the --output json
// envelope.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// plannedInterval maps a source's schedule string onto its planned run
// interval — the cadence the stale detection compares the data age against
// (ch. 16.4: more than two planned intervals without a successful run is
// stale). The grammar is the schedule vocabulary of ARCH-002 §1
// (application.ScheduleHourly/ScheduleDaily — the schedules the I2
// adapters declare). ok=false for a schedule that is not supported or
// unset: an operator-triggered source (e.g. the I1b synthetic source with
// a NULL schedule) has no planned cadence, so no age threshold applies and
// the source can never degrade on the stale criterion.
func plannedInterval(schedule string) (time.Duration, bool) {
	switch schedule {
	case application.ScheduleHourly:
		return time.Hour, true
	case application.ScheduleDaily:
		return 24 * time.Hour, true
	}
	return 0, false
}

// runDataAgeSeconds computes the data age of a source (ARCH-002 §5): the
// elapsed time from the last successful run's data basis to now. The basis
// is the run's committed cursor_after.last_modified when the run carries a
// last-modified cursor — the NVD incremental source, whose cursor marks
// the end of the fetched data window (ch. 8.2, ARCH-002 §2.1) — and the
// run's finished_at otherwise (full-set sources KEV/EPSS, the cursor-less
// synthetic source). ok=false when the run carries no finished_at — a
// source without a successful run has no data age. The age is clamped at
// zero: a basis in the future (clock skew between the run's writer and the
// monitor's reader) means the data is not stale, never negative.
func runDataAgeSeconds(now time.Time, finishedAt time.Time, cursorAfter json.RawMessage) (age float64, ok bool) {
	if finishedAt.IsZero() {
		return 0, false
	}
	basis := finishedAt
	if t, has := cursorLastModified(cursorAfter); has {
		basis = t
	}
	if age := now.Sub(basis).Seconds(); age > 0 {
		return age, true
	}
	return 0, true
}

// cursorLastModified reads the time of a last-modified cursor — the
// {"last_modified": "<RFC3339>"} shape of the NVD cursor (ARCH-002 §1).
// A cursor without a parseable last_modified member is not a data basis.
func cursorLastModified(cursor json.RawMessage) (time.Time, bool) {
	if len(cursor) == 0 {
		return time.Time{}, false
	}
	var c struct {
		LastModified string `json:"last_modified"`
	}
	if err := json.Unmarshal(cursor, &c); err != nil || c.LastModified == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, c.LastModified)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// monitorDegraded applies the stale detection of ch. 16.3/16.4: a source
// is degraded when its data age exceeds twice its planned interval. A
// source without a data age (never succeeded) or without a planned
// interval (unsupported or unset schedule) is not degraded on this
// criterion. Degraded is a visibility flag — it never makes the
// application unready (ch. 16.3).
func monitorDegraded(age float64, hasAge bool, interval time.Duration) bool {
	return hasAge && interval > 0 && age > 2*interval.Seconds()
}

// runRateLimited reports whether a run row is the rate-limited outcome of
// a fetch (ch. 14.2, ARCH-002 §2.1/§5): the run closes failed with the
// stable rate-limit error text (application.RateLimitedErrorText) — a
// rate-limited response is recorded as rate-limited, never as a source
// technical error.
func runRateLimited(status, errText string) bool {
	return status == string(application.SourceRunStatusFailed) && errText == application.RateLimitedErrorText
}

// decodeRunCounters decodes the committed counters jsonb of one run
// ({records, normalized, errors, quarantined, matched, signals}, ARCH-002
// §1). Missing keys decode as zero — I1b runs commit the pre-I2 subset
// {records, matched, signals} and stay valid — and a corrupt shape (not an
// object of the documented numeric keys) is an error the monitor surfaces
// instead of guessing at.
func decodeRunCounters(raw []byte) (application.SourceRunCounters, error) {
	var c application.SourceRunCounters
	if len(raw) == 0 {
		return c, nil // counters is NOT NULL DEFAULT '{}'; defensive
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("decode run counters: %w", err)
	}
	return c, nil
}

// monitorLastRun is the latest run of one source as the monitor reports it
// (ARCH-002 §5): the terminal state, the finished_at, the committed
// counters, the error text of a failed run and the rate-limit flag. A run
// that is still 'running' has a null finished_at and null error — the
// monitor reports the in-flight state without guessing at its outcome.
type monitorLastRun struct {
	RunID       string                        `json:"run_id"`
	Status      string                        `json:"status"`
	StartedAt   time.Time                     `json:"started_at"`
	FinishedAt  *time.Time                    `json:"finished_at"`
	Counters    application.SourceRunCounters `json:"counters"`
	Error       *string                       `json:"error"`
	RateLimited bool                          `json:"rate_limited"`
}

// monitorMetrics carries the current value of every ch. 16.2 source metric
// for one source, as measured from the monitor projection at read time
// (the CLI renders the values; a dedicated HTTP /metrics exposition is the
// later iteration I6). The names are the Prometheus-compatible metric
// names of ch. 16.2 / ARCH-002 §5:
//
//	source_run_duration_seconds  — duration of the latest run (null while
//	                               running or when the source never ran)
//	source_records_total         — records counter of the latest run
//	source_errors_total          — errors counter of the latest run
//	source_data_age_seconds      — data age (null when never succeeded)
//	source_rate_limited          — 1 when the latest run was rate-limited
//	epss_rows_total              — EPSS rows loaded by the latest run of an
//	                               epss source (0 for other source types)
//
// The records/errors/epss values follow the counters the run committed;
// the per-process accumulation of the same series at the worker's run-loop
// completion points lives in internal/platform/metrics (wired with
// DEV-043) and is the substrate of the I6 /metrics endpoint.
type monitorMetrics struct {
	SourceRunDurationSeconds *float64 `json:"source_run_duration_seconds"`
	SourceRecordsTotal       float64  `json:"source_records_total"`
	SourceErrorsTotal        float64  `json:"source_errors_total"`
	SourceDataAgeSeconds     *float64 `json:"source_data_age_seconds"`
	SourceRateLimited        float64  `json:"source_rate_limited"`
	EpssRowsTotal            float64  `json:"epss_rows_total"`
}

// monitorEntry is the per-source monitor view (ARCH-002 §5): the source
// identity and schedule, the latest run, the data age, the degraded flag
// and the open quarantine count, plus the current metric values. The JSON
// shape is fixed: absent facts are null, never missing keys (a source
// without a run has last_run null and quarantine_open 0).
type monitorEntry struct {
	SourceID               string          `json:"source_id"`
	Type                   string          `json:"type"`
	Name                   string          `json:"name"`
	Endpoint               string          `json:"endpoint"` // the public base URL; "" when unset
	Enabled                bool            `json:"enabled"`
	Schedule               *string         `json:"schedule"` // null when the source has none (operator-triggered)
	PlannedIntervalSeconds *float64        `json:"planned_interval_seconds"`
	LastRun                *monitorLastRun `json:"last_run"`
	DataAgeSeconds         *float64        `json:"data_age_seconds"`
	Degraded               bool            `json:"degraded"`
	QuarantineOpen         int64           `json:"quarantine_open"`
	Metrics                monitorMetrics  `json:"metrics"`
}

// sourceListResult is the machine-readable payload of `source list` and
// `source status`: the ordered monitor entries of the sources the command
// covers (all of them for list and for an unfiltered status, the matching
// one for status <type|id>).
type sourceListResult struct {
	Sources []monitorEntry `json:"sources"`
}

// loadMonitor builds the monitor projection at the given clock instant
// (ARCH-002 §5): the sources rows joined with the latest source_runs row
// per source, the latest successful run per source (the data-age basis)
// and the open quarantine counts. A database failure of a read is returned
// as-is (an infrastructure failure of the caller); a corrupt stored
// counters shape is wrapped as monitorDataError so the caller can classify
// it as data corruption, not infrastructure.
func loadMonitor(ctx context.Context, q *gen.Queries, now time.Time) ([]monitorEntry, error) {
	sources, err := q.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	latest, err := q.LatestSourceRunBySource(ctx)
	if err != nil {
		return nil, err
	}
	succeeded, err := q.LatestSucceededSourceRunBySource(ctx)
	if err != nil {
		return nil, err
	}
	quarantine, err := q.CountOpenQuarantineBySource(ctx)
	if err != nil {
		return nil, err
	}

	latestRuns := make(map[string]gen.LatestSourceRunBySourceRow, len(latest))
	for _, row := range latest {
		latestRuns[demoUUID(row.SourceID)] = row
	}
	succeededRuns := make(map[string]gen.LatestSucceededSourceRunBySourceRow, len(succeeded))
	for _, row := range succeeded {
		succeededRuns[demoUUID(row.SourceID)] = row
	}
	openQuarantine := make(map[string]int64, len(quarantine))
	for _, row := range quarantine {
		openQuarantine[demoUUID(row.SourceID)] = row.OpenCount
	}

	entries := make([]monitorEntry, 0, len(sources))
	for _, source := range sources {
		id := demoUUID(source.ID)
		entry, err := monitorEntryFor(source, latestRuns[id], succeededRuns[id], openQuarantine[id], now)
		if err != nil {
			return nil, monitorDataError{err: err}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// monitorEntryFor computes the monitor view of one source row from its
// latest run, its latest successful run (zero-valued when absent) and its
// open quarantine count.
func monitorEntryFor(source gen.ListSourcesRow, latest gen.LatestSourceRunBySourceRow, succeeded gen.LatestSucceededSourceRunBySourceRow, quarantineOpen int64, now time.Time) (monitorEntry, error) {
	entry := monitorEntry{
		SourceID:       demoUUID(source.ID),
		Type:           source.Type,
		Name:           source.Name,
		Endpoint:       source.Endpoint.String,
		Enabled:        source.Enabled,
		QuarantineOpen: quarantineOpen,
	}
	if source.Schedule.Valid {
		schedule := source.Schedule.String
		entry.Schedule = &schedule
		if interval, ok := plannedInterval(schedule); ok {
			seconds := interval.Seconds()
			entry.PlannedIntervalSeconds = &seconds
		}
	}

	// The latest run (any terminal state; possibly still 'running').
	hasLatest := latest.SourceID.Valid
	if hasLatest {
		counters, err := decodeRunCounters(latest.Counters)
		if err != nil {
			return monitorEntry{}, fmt.Errorf("source %s: %w", entry.Name, err)
		}
		run := &monitorLastRun{
			RunID:       demoUUID(latest.ID),
			Status:      latest.Status,
			StartedAt:   latest.StartedAt.Time,
			Counters:    counters,
			RateLimited: runRateLimited(latest.Status, latest.Error.String),
		}
		if latest.FinishedAt.Valid {
			finished := latest.FinishedAt.Time
			run.FinishedAt = &finished
		}
		if latest.Error.Valid {
			errText := latest.Error.String
			run.Error = &errText
		}
		entry.LastRun = run
	}

	// The data age from the latest successful run (ARCH-002 §5); degraded
	// when it exceeds twice the planned interval (ch. 16.3/16.4).
	if succeeded.SourceID.Valid {
		age, ok := runDataAgeSeconds(now, succeeded.FinishedAt.Time, succeeded.CursorAfter)
		if ok {
			entry.DataAgeSeconds = &age
		}
	}
	var interval time.Duration
	if entry.PlannedIntervalSeconds != nil {
		interval = time.Duration(*entry.PlannedIntervalSeconds * float64(time.Second))
	}
	entry.Degraded = monitorDegraded(ageOf(entry), entry.DataAgeSeconds != nil, interval)

	entry.Metrics = metricsFor(entry)
	return entry, nil
}

// ageOf reads the data age seconds of an entry (0 when absent) — the
// degraded check needs the numeric value only when a data age exists.
func ageOf(entry monitorEntry) float64 {
	if entry.DataAgeSeconds == nil {
		return 0
	}
	return *entry.DataAgeSeconds
}

// metricsFor derives the current metric values of one monitor entry from
// its projection fields (see monitorMetrics for the per-metric semantics).
func metricsFor(entry monitorEntry) monitorMetrics {
	metrics := monitorMetrics{
		SourceDataAgeSeconds: entry.DataAgeSeconds,
		EpssRowsTotal:        0,
	}
	if run := entry.LastRun; run != nil {
		metrics.SourceRecordsTotal = float64(run.Counters.Records)
		metrics.SourceErrorsTotal = float64(run.Counters.Errors)
		if run.RateLimited {
			metrics.SourceRateLimited = 1
		}
		if entry.Type == string(application.SourceTypeEPSS) {
			metrics.EpssRowsTotal = float64(run.Counters.Normalized)
		}
		if run.FinishedAt != nil && run.FinishedAt.After(run.StartedAt) {
			duration := run.FinishedAt.Sub(run.StartedAt).Seconds()
			metrics.SourceRunDurationSeconds = &duration
		}
	}
	return metrics
}

// monitorDataError distinguishes a corrupt stored monitor input (a run
// whose counters jsonb is not the documented shape) from the database
// failures of the projection reads: the former is a data problem the CLI
// reports as generic, the latter as infrastructure.
type monitorDataError struct{ err error }

func (e monitorDataError) Error() string { return e.err.Error() }
func (e monitorDataError) Unwrap() error { return e.err }

// cmdSourceList renders the monitor projection of every registered source
// (ARCH-002 §5, ch. 11.3): one monitor entry per source — the latest run,
// data age, degraded flag, open quarantine count and the current metric
// values — as text lines or as the --output json envelope (result: the
// ordered sources array). The command is strictly a read.
func (e *cmdEnv) cmdSourceList(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal source list")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), sourceCommandTimeout)
	defer cancel()

	pool, _, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	entries, err := loadMonitor(ctx, gen.New(pool), clock.RealClock{}.Now())
	if err != nil {
		return e.monitorFailure(err)
	}
	if e.format == formatText {
		printSourceList(e.stdout, entries)
	}
	return e.ok(sourceListResult{Sources: entries})
}

// cmdSourceStatus renders the detailed monitor view of the named source
// (ARCH-002 §5: status renders the monitor view, --output json for
// automation). The argument is the source id or its type when exactly one
// source of that type is registered (the resolution of `source run`,
// resolveSourceRef); without an argument every source is reported, so a
// bare `source status --output json` is the full monitor snapshot.
func (e *cmdEnv) cmdSourceStatus(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal source status [<type|id>]\n"+
		"  with no argument every registered source is reported")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 1 {
		return e.fail(exitValidation, classValidation,
			"source status takes at most one argument: the source id or its type")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), sourceCommandTimeout)
	defer cancel()

	pool, _, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()
	q := gen.New(pool)

	entries, err := loadMonitor(ctx, q, clock.RealClock{}.Now())
	if err != nil {
		return e.monitorFailure(err)
	}
	if fs.NArg() == 1 {
		sourceID, err := resolveSourceRef(ctx, q, fs.Arg(0))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return e.fail(exitGeneric, classGeneric, "no source with id %q registered", fs.Arg(0))
			}
			return e.fail(exitGeneric, classGeneric, "%v", err)
		}
		filtered := make([]monitorEntry, 0, 1)
		for _, entry := range entries {
			if entry.SourceID == sourceID {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	if e.format == formatText {
		printSourceStatus(e.stdout, entries)
	}
	return e.ok(sourceListResult{Sources: entries})
}

// monitorFailure classifies a monitor read failure: a database failure of
// the projection reads is infrastructure (exit 6); a corrupt stored
// counters shape is a data problem reported as generic (exit 1).
func (e *cmdEnv) monitorFailure(err error) outcome {
	var dataErr monitorDataError
	if errors.As(err, &dataErr) {
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}
	return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
}

// scheduleText renders the schedule of a monitor entry for text output.
func scheduleText(entry monitorEntry) string {
	if entry.Schedule == nil {
		return "none (operator-triggered)"
	}
	return *entry.Schedule
}

// ageText renders the data age of a monitor entry for text output.
func ageText(entry monitorEntry) string {
	if entry.DataAgeSeconds == nil {
		return "no successful run yet"
	}
	return durationText(*entry.DataAgeSeconds)
}

// durationText renders a duration in seconds as the compact Go form
// (e.g. "3h0m0s"), rounded to whole seconds for readability.
func durationText(seconds float64) string {
	return (time.Duration(seconds * float64(time.Second))).Round(time.Second).String()
}

// intervalText renders the planned interval of a monitor entry.
func intervalText(entry monitorEntry) string {
	if entry.PlannedIntervalSeconds == nil {
		return "none"
	}
	return durationText(*entry.PlannedIntervalSeconds)
}

// lastRunText renders the latest run outcome of a monitor entry for the
// list line: the status, or "never" when the source has not run.
func lastRunText(entry monitorEntry) string {
	if entry.LastRun == nil {
		return "never"
	}
	return entry.LastRun.Status
}

// printSourceList renders the compact list form: one line per source.
func printSourceList(w io.Writer, entries []monitorEntry) {
	fmt.Fprintf(w, "source list: %d source(s)\n", len(entries))
	for _, entry := range entries {
		fmt.Fprintf(w, "%s / %s: %s, schedule %s, last run %s, data age %s, degraded %v, quarantine open %d\n",
			entry.Type, entry.Name,
			enabledText(entry), scheduleText(entry),
			lastRunText(entry), ageText(entry),
			entry.Degraded, entry.QuarantineOpen)
	}
}

// printSourceStatus renders the verbose monitor block of one source per
// entry: the full latest-run facts, counters, error, rate-limit flag,
// data age, degraded verdict and the current metric values.
func printSourceStatus(w io.Writer, entries []monitorEntry) {
	for i, entry := range entries {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "source %s (type %s, id %s): %s\n",
			entry.Name, entry.Type, entry.SourceID, enabledText(entry))
		fmt.Fprintf(w, "  endpoint %s; schedule %s; planned interval %s\n",
			endpointText(entry), scheduleText(entry), intervalText(entry))
		if run := entry.LastRun; run != nil {
			fmt.Fprintf(w, "  last run %s status %s\n", run.RunID, run.Status)
			fmt.Fprintf(w, "    started %s; finished %s\n",
				entryTimeText(run.StartedAt), optionalTimeText(run.FinishedAt))
			fmt.Fprintf(w, "    counters: {records %d, normalized %d, errors %d, quarantined %d, matched %d, signals %d}\n",
				run.Counters.Records, run.Counters.Normalized, run.Counters.Errors,
				run.Counters.Quarantined, run.Counters.Matched, run.Counters.Signals)
			fmt.Fprintf(w, "    error: %s\n", errorText(run))
			fmt.Fprintf(w, "    rate limited: %v\n", run.RateLimited)
		} else {
			fmt.Fprintln(w, "  last run: never")
		}
		fmt.Fprintf(w, "  data age: %s\n", ageText(entry))
		fmt.Fprintf(w, "  degraded: %v (stale when data age exceeds 2 x planned interval)\n", entry.Degraded)
		fmt.Fprintf(w, "  quarantine open: %d\n", entry.QuarantineOpen)
		fmt.Fprintf(w, "  metrics: source_run_duration_seconds %s, source_records_total %v, "+
			"source_errors_total %v, source_data_age_seconds %s, source_rate_limited %v, epss_rows_total %v\n",
			optionalNumberText(entry.Metrics.SourceRunDurationSeconds),
			entry.Metrics.SourceRecordsTotal,
			entry.Metrics.SourceErrorsTotal,
			optionalNumberText(entry.Metrics.SourceDataAgeSeconds),
			entry.Metrics.SourceRateLimited,
			entry.Metrics.EpssRowsTotal)
	}
}

// enabledText renders the enabled state of a source for text output.
func enabledText(entry monitorEntry) string {
	if entry.Enabled {
		return "enabled"
	}
	return "disabled"
}

// endpointText renders the endpoint of a source for text output.
func endpointText(entry monitorEntry) string {
	if entry.Endpoint == "" {
		return "none"
	}
	return entry.Endpoint
}

// errorText renders the error of the latest run for text output.
func errorText(run *monitorLastRun) string {
	if run.Error == nil {
		return "none"
	}
	return *run.Error
}

// entryTimeText renders a clock timestamp in RFC 3339.
func entryTimeText(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// optionalTimeText renders an optional timestamp, "running" when unset.
func optionalTimeText(t *time.Time) string {
	if t == nil {
		return "still running"
	}
	return entryTimeText(*t)
}

// optionalNumberText renders an optional metric value, "none" when unset.
func optionalNumberText(v *float64) string {
	if v == nil {
		return "none"
	}
	return fmt.Sprintf("%v", *v)
}
