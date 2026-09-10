package application

// This file implements the ListSourceStatus read use case of ARCH-006 §3.1
// (DEV-110): the source-monitor projection the web adapter renders on
// GET /sources — per source the last run, the data age, the error count, the
// rate-limit flag of the latest run and the open quarantine count. It is a
// pure read over the I2 sources/source_runs/quarantine tables through the
// SourceMonitorRepo read port; no domain command runs and no transaction
// opens.
//
// The gate is deny-by-default via the standard resolvePrincipal+authorize
// seam (ARCH-005 §5): the use case requires sources.manage, an
// administrator-only permission with a global (all) scope — the source
// registry is operational data without an object owner, so there is no
// object-scope filter (unlike ListSignals/ListAssets). The gate runs before
// the read; a denied read returns a ForbiddenError (403).
//
// The projection's derived fields are computed here from the raw rows and the
// injected clock (ch. 7.2 / ARCH-002 §5): the data age is clock.Now() minus
// the data basis of the latest successful run (the committed cursor's
// last_modified when the run carries an incremental cursor, finished_at
// otherwise); a source is degraded when its data age exceeds twice its
// planned interval (ch. 16.3/16.4); the rate-limit flag is the latest run's
// stable rate-limit error text (ch. 14.2). Degraded is visibility only — it
// never makes the application unready.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// errSourceMonitorNotWired is the programming error of ListSourceStatus
// invoked without the SourceMonitorRepo read port.
var errSourceMonitorNotWired = errors.New("application: source monitor repository is not wired")

// ListSourceStatusInput is the source-monitor read (ARCH-006 §3.1, DEV-110):
// the authenticated principal. sources.manage gates the read; the source
// registry has no object owner, so there is no object-scope filter.
type ListSourceStatusInput struct {
	Actor Actor
}

// SourceStatus is one source's monitor row (ARCH-006 §3.1): the source
// identity and schedule, the latest run's outcome and finish instant, the
// data age (valid when HasDataAge), the latest run's error count and
// rate-limit flag, the open quarantine count and the stale/degraded verdict.
// A source that never ran carries empty LastRunStatus/zero LastRunAt; a
// source that never succeeded carries HasDataAge=false.
type SourceStatus struct {
	ID       string
	Name     string
	Type     string
	Enabled  bool
	Schedule string // "" when unset (operator-triggered source)

	LastRunStatus string    // "" when the source never ran
	LastRunAt     time.Time // finished_at of the latest run; zero when never/while running
	DataAge       time.Duration
	HasDataAge    bool
	ErrorCount    int
	RateLimited   bool

	OpenQuarantine int
	Degraded       bool
}

// ListSourceStatusResult is the full source-monitor projection, ordered by
// type then name (the SourceMonitorRepo contract — a stable operator-facing
// order).
type ListSourceStatusResult struct {
	Sources []SourceStatus
}

// ListSourceStatus returns the monitor projection of every registered source
// (ARCH-006 §3.1, DEV-110). sources.manage gates the read per the matrix (an
// administrator-only, global grant); a role-less user (or one without
// sources.manage) is denied with a ForbiddenError (403) before the read.
func (s *Service) ListSourceStatus(ctx context.Context, in ListSourceStatusInput) (ListSourceStatusResult, error) {
	const op = "list_source_status"

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return ListSourceStatusResult{}, err
	}
	// sources.manage per the matrix: a role-less user (or one without the
	// permission) is denied. The grant is global (all) — there is no
	// object-scope half for the source registry.
	scope := principal.GrantedScope(domain.PermissionSourcesManage)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return ListSourceStatusResult{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionSourcesManage)
	}
	if s.sourceMonitor == nil {
		return ListSourceStatusResult{}, InfraError(op, errSourceMonitorNotWired)
	}

	records, err := s.sourceMonitor.ListSourceStatus(ctx)
	if err != nil {
		return ListSourceStatusResult{}, err
	}
	now := s.clock.Now()
	out := make([]SourceStatus, 0, len(records))
	for _, rec := range records {
		out = append(out, sourceStatusOf(rec, now))
	}
	return ListSourceStatusResult{Sources: out}, nil
}

// sourceStatusOf derives one monitor row from a stored record and the clock
// instant (ARCH-002 §5): the latest run's outcome/counters/rate-limit flag,
// the data age from the latest successful run and the stale verdict.
func sourceStatusOf(rec SourceStatusRecord, now time.Time) SourceStatus {
	status := SourceStatus{
		ID:             rec.ID,
		Name:           rec.Name,
		Type:           string(rec.Type),
		Enabled:        rec.Enabled,
		Schedule:       rec.Schedule,
		OpenQuarantine: rec.OpenQuarantine,
	}
	if rec.LastRun != nil {
		status.LastRunStatus = string(rec.LastRun.Status)
		status.LastRunAt = rec.LastRun.FinishedAt
		status.ErrorCount = rec.LastRun.Counters.Errors
		status.RateLimited = runRateLimited(string(rec.LastRun.Status), rec.LastRun.Error)
	}
	if rec.Succeeded != nil {
		if age, ok := dataAgeSeconds(now, rec.Succeeded.FinishedAt, rec.Succeeded.CursorAfter); ok {
			status.DataAge = age
			status.HasDataAge = true
		}
	}
	var interval time.Duration
	if d, ok := plannedInterval(rec.Schedule); ok {
		interval = d
	}
	status.Degraded = monitorDegraded(status.DataAge, status.HasDataAge, interval)
	return status
}

// plannedInterval maps a source's schedule string onto its planned run
// interval — the cadence the stale detection compares the data age against
// (ch. 16.4: more than two planned intervals without a successful run is
// stale). ok=false for an unsupported or unset schedule: an
// operator-triggered source (NULL schedule) has no planned cadence, so no age
// threshold applies and it can never degrade on the stale criterion. (The
// same derivation backs the CLI monitor projection; the application harness
// keeps its own copy so it never imports the command package.)
func plannedInterval(schedule string) (time.Duration, bool) {
	switch schedule {
	case ScheduleHourly:
		return time.Hour, true
	case ScheduleDaily:
		return 24 * time.Hour, true
	}
	return 0, false
}

// dataAgeSeconds computes the data age of a source (ARCH-002 §5): the elapsed
// time from the last successful run's data basis to now. The basis is the
// run's committed cursor_after.last_modified when the run carries a
// last-modified cursor (the incremental NVD source, whose cursor marks the
// end of the fetched data window) and the run's finished_at otherwise
// (full-set sources, the cursor-less synthetic source). ok=false when the run
// carries no finished_at — a source without a successful run has no data age.
// The age is clamped at zero: a basis in the future (clock skew between the
// run's writer and the monitor's reader) means the data is not stale, never
// negative.
func dataAgeSeconds(now time.Time, finishedAt time.Time, cursorAfter json.RawMessage) (time.Duration, bool) {
	if finishedAt.IsZero() {
		return 0, false
	}
	basis := finishedAt
	if t, has := cursorLastModified(cursorAfter); has {
		basis = t
	}
	if age := now.Sub(basis); age > 0 {
		return age, true
	}
	return 0, true
}

// cursorLastModified reads the time of a last-modified cursor — the
// {"last_modified": "<RFC3339>"} shape of the NVD cursor (ARCH-002 §1). A
// cursor without a parseable last_modified member is not a data basis.
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

// monitorDegraded applies the stale detection of ch. 16.3/16.4: a source is
// degraded when its data age exceeds twice its planned interval. A source
// without a data age (never succeeded) or without a planned interval
// (unsupported/unset schedule) is not degraded on this criterion. Degraded is
// a visibility flag — it never makes the application unready (ch. 16.3).
func monitorDegraded(age time.Duration, hasAge bool, interval time.Duration) bool {
	return hasAge && interval > 0 && age > 2*interval
}

// runRateLimited reports whether a run row is the rate-limited outcome of a
// fetch (ch. 14.2, ARCH-002 §2.1/§5): the run closed failed with the stable
// rate-limit error text — a rate-limited response is recorded as
// rate-limited, never as a source technical error.
func runRateLimited(status, errText string) bool {
	return status == string(SourceRunStatusFailed) && errText == RateLimitedErrorText
}
