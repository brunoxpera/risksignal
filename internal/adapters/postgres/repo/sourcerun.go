package repo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// SourceRunRepo is the postgres implementation of application.SourceRunRepo
// (source_runs.sql): the source-run lifecycle of ARCH-001 §3 steps 1 and 6
// plus the I2 cursor bookkeeping (ARCH-002 §1/§3) — cursor_before is
// written when the run opens, cursor_after only by the success path of the
// terminal commit. The raw document of a run is stored through RawRecordRepo.
type SourceRunRepo struct {
	q *gen.Queries
}

// NewSourceRunRepo binds the repository to one query set.
func NewSourceRunRepo(q *gen.Queries) *SourceRunRepo { return &SourceRunRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.SourceRunRepo = (*SourceRunRepo)(nil)

// Open implements application.SourceRunRepo: start a run with status
// 'running', the default empty counters and the cursor_before the run opens
// from (the source cursor the fetch half read; nil for full-set sources and
// the I1b synthetic source), and return its id.
func (r *SourceRunRepo) Open(ctx context.Context, tx application.Tx, sourceID string, cursorBefore json.RawMessage, startedAt time.Time) (string, error) {
	const op = "source_run.open"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID:     srcID,
		StartedAt:    toTS(startedAt),
		CursorBefore: cursorBefore,
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(row.ID), nil
}

// Complete implements application.SourceRunRepo: close the run with its
// terminal state — status succeeded or failed, finished_at, the committed
// counters and the error text of a failed run (concept ch. 8.1 step 5).
// cursorAfter is the cursor committed with a successful run only: the
// generated statement's CASE guard writes it when the terminal status is
// 'succeeded' and forces cursor_after NULL otherwise, so a failed run can
// never advance the cursor — the next run starts again from cursor_before
// (ch. 6.1, ARCH-002 §1).
func (r *SourceRunRepo) Complete(ctx context.Context, tx application.Tx, runID string, status application.SourceRunStatus, counters application.SourceRunCounters, cursorAfter json.RawMessage, errText string, finishedAt time.Time) error {
	const op = "source_run.complete"

	id, err := toUUID(runID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	countersJSON, err := json.Marshal(counters)
	if err != nil {
		return application.InfraError(op, err)
	}
	_, err = r.q.WithTx(tx).CompleteSourceRun(ctx, gen.CompleteSourceRunParams{
		ID:          id,
		FinishedAt:  toTS(finishedAt),
		Status:      string(status),
		Counters:    countersJSON,
		Error:       toTextOpt(errText),
		CursorAfter: cursorAfter,
	})
	return mapDBError(op, err)
}
