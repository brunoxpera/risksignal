package repo

// SourceMonitorRepo is the postgres implementation of the DEV-110
// source-monitor read port (ARCH-006 §3.1 / ARCH-002 §5): the per-source
// operational projection the ListSourceStatus use case renders on
// GET /sources — the source identity and schedule, the latest run (any
// terminal state), the latest successful run (the data age basis) and the
// open quarantine count.
//
// It is read-only and pool-scoped (no transaction) and reuses the DEV-043
// monitor reads: ListSources (the base read), LatestSourceRunBySource (the
// last run), LatestSucceededSourceRunBySource (the data-age basis, which
// prefers the committed incremental cursor over finished_at) and
// CountOpenQuarantineBySource (the open statuses of the ch. 8.6 state
// machine). It selects no secret — sources.config (which holds the
// api_key_ref secret reference, ch. 3.3) is never part of the projection or
// the returned rows. The adapter maps rows onto the application read model
// (SourceStatusRecord/SourceRunSummary) and computes nothing: the derived
// monitor fields (data age, degraded flag, rate-limit flag) are the use
// case's job.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// SourceMonitorRepo implements application.SourceMonitorRepo over one query
// set.
type SourceMonitorRepo struct {
	q *gen.Queries
}

// NewSourceMonitorRepo binds the repository to one query set.
func NewSourceMonitorRepo(q *gen.Queries) *SourceMonitorRepo { return &SourceMonitorRepo{q: q} }

// compile-time check that the repository satisfies the read port.
var _ application.SourceMonitorRepo = (*SourceMonitorRepo)(nil)

// ListSourceStatus implements application.SourceMonitorRepo (ARCH-006 §3.1,
// DEV-110): one raw monitor record per registered source, ordered by type
// then name (the ListSources order). The latest and latest-successful runs
// are joined per source_id in Go (the generated reads return one row per
// source); a source without a run carries a nil LastRun, without a
// successful run a nil Succeeded. A corrupt stored counters shape (a run
// whose counters jsonb is not the documented object) is an infrastructure
// error, never a guessed value.
func (r *SourceMonitorRepo) ListSourceStatus(ctx context.Context) ([]application.SourceStatusRecord, error) {
	const op = "source_monitor.list_status"

	sources, err := r.q.ListSources(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	latest, err := r.q.LatestSourceRunBySource(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	succeeded, err := r.q.LatestSucceededSourceRunBySource(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	quarantine, err := r.q.CountOpenQuarantineBySource(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}

	latestBySource := make(map[string]gen.LatestSourceRunBySourceRow, len(latest))
	for _, row := range latest {
		latestBySource[uuidString(row.SourceID)] = row
	}
	succeededBySource := make(map[string]gen.LatestSucceededSourceRunBySourceRow, len(succeeded))
	for _, row := range succeeded {
		succeededBySource[uuidString(row.SourceID)] = row
	}
	openBySource := make(map[string]int, len(quarantine))
	for _, row := range quarantine {
		openBySource[uuidString(row.SourceID)] = int(row.OpenCount)
	}

	out := make([]application.SourceStatusRecord, 0, len(sources))
	for _, source := range sources {
		id := uuidString(source.ID)
		rec := application.SourceStatusRecord{
			ID:             id,
			Name:           source.Name,
			Type:           application.SourceType(source.Type),
			Enabled:        source.Enabled,
			Schedule:       textValue(source.Schedule),
			OpenQuarantine: openBySource[id],
		}
		if row, ok := latestBySource[id]; ok {
			summary, serr := sourceRunSummary(op, row.Status, row.StartedAt, row.FinishedAt, row.Counters, row.Error, row.CursorAfter)
			if serr != nil {
				return nil, serr
			}
			rec.LastRun = &summary
		}
		if row, ok := succeededBySource[id]; ok {
			summary, serr := sourceRunSummary(op, row.Status, row.StartedAt, row.FinishedAt, row.Counters, row.Error, row.CursorAfter)
			if serr != nil {
				return nil, serr
			}
			rec.Succeeded = &summary
		}
		out = append(out, rec)
	}
	return out, nil
}

// sourceRunSummary maps one stored run row onto the application run summary;
// a corrupt counters shape is an infrastructure error.
func sourceRunSummary(op, status string, startedAt, finishedAt pgtype.Timestamptz, counters []byte, errText pgtype.Text, cursorAfter []byte) (application.SourceRunSummary, error) {
	decoded, err := decodeRunCounters(op, counters)
	if err != nil {
		return application.SourceRunSummary{}, err
	}
	summary := application.SourceRunSummary{
		Status:      application.SourceRunStatus(status),
		StartedAt:   tsTime(startedAt),
		FinishedAt:  tsTime(finishedAt),
		Counters:    decoded,
		Error:       textValue(errText),
		CursorAfter: json.RawMessage(cursorAfter),
	}
	return summary, nil
}

// decodeRunCounters decodes the committed counters jsonb of one run
// ({records, normalized, errors, quarantined, matched, signals}, ARCH-002
// §1). Missing keys decode as zero — I1b runs commit the pre-I2 subset
// {records, matched, signals} and stay valid — and a corrupt shape (not an
// object of the documented numeric keys) is an infrastructure error the
// adapter surfaces instead of guessing at.
func decodeRunCounters(op string, raw []byte) (application.SourceRunCounters, error) {
	var c application.SourceRunCounters
	if len(raw) == 0 {
		return c, nil // counters is NOT NULL DEFAULT '{}'; defensive
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, application.InfraError(op, fmt.Errorf("decode run counters: %w", err))
	}
	return c, nil
}
