package repo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// SourceRunRepo is the postgres implementation of application.SourceRunRepo
// (source_runs.sql + raw_records.sql): the source-run lifecycle of ARCH-001
// §3 steps 1, 2 and 6 plus the unchanged raw document of a run.
type SourceRunRepo struct {
	q *gen.Queries
}

// NewSourceRunRepo binds the repository to one query set.
func NewSourceRunRepo(q *gen.Queries) *SourceRunRepo { return &SourceRunRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.SourceRunRepo = (*SourceRunRepo)(nil)

// InsertRawRecord implements application.SourceRunRepo: store the unchanged
// document and return the row id — newly inserted, or the already existing
// one of an identical earlier ingest (ON CONFLICT DO NOTHING on the natural
// key).
func (r *SourceRunRepo) InsertRawRecord(ctx context.Context, tx application.Tx, sourceID, externalID string, payload []byte, contentHash string, fetchedAt time.Time) (string, error) {
	const op = "raw_record.insert"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	id, err := r.q.WithTx(tx).InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID:    srcID,
		ExternalID:  externalID,
		ContentHash: contentHash,
		Payload:     payload,
		FetchedAt:   toTS(fetchedAt),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(id), nil
}

// Open implements application.SourceRunRepo: start a run with status
// 'running' and the default empty counters, and return its id.
func (r *SourceRunRepo) Open(ctx context.Context, tx application.Tx, sourceID string, startedAt time.Time) (string, error) {
	const op = "source_run.open"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID:  srcID,
		StartedAt: toTS(startedAt),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(row.ID), nil
}

// Complete implements application.SourceRunRepo: close the run with its
// terminal state — status succeeded or failed, finished_at, the committed
// counters and the error text of a failed run (concept ch. 8.1 step 5).
func (r *SourceRunRepo) Complete(ctx context.Context, tx application.Tx, runID string, status application.SourceRunStatus, counters application.SourceRunCounters, errText string, finishedAt time.Time) error {
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
		ID:         id,
		FinishedAt: toTS(finishedAt),
		Status:     string(status),
		Counters:   countersJSON,
		Error:      toTextOpt(errText),
	})
	return mapDBError(op, err)
}
