package repo

import (
	"context"
	"encoding/json"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// SourceRepo is the postgres implementation of application.SourceRepo
// (sources.sql): the descriptor read the I2 run use cases and the scheduler
// resolve a source row from (ARCH-002 §1).
type SourceRepo struct {
	q *gen.Queries
}

// NewSourceRepo binds the repository to one query set.
func NewSourceRepo(q *gen.Queries) *SourceRepo { return &SourceRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.SourceRepo = (*SourceRepo)(nil)

// GetByID implements application.SourceRepo: resolve the sources row into
// the adapter descriptor. Config is decoded into the plain map the adapters
// read; the cursor is carried as its stored jsonb bytes (nil when NULL).
func (r *SourceRepo) GetByID(ctx context.Context, id string) (application.SourceDescriptor, error) {
	const op = "source.get_by_id"

	srcID, err := toUUID(id)
	if err != nil {
		return application.SourceDescriptor{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetSourceByID(ctx, srcID)
	if err != nil {
		return application.SourceDescriptor{}, mapDBError(op, err)
	}

	var config map[string]any
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &config); err != nil {
			return application.SourceDescriptor{}, application.InfraError(op, err)
		}
	}
	descriptor := application.SourceDescriptor{
		ID:       uuidString(row.ID),
		Type:     application.SourceType(row.Type),
		Endpoint: row.Endpoint.String, // NULL endpoint → ""
		Config:   config,
		Cursor:   row.Cursor, // jsonb bytes, nil when NULL
	}
	return descriptor, nil
}

// SetLastContentHash implements application.SourceRepo: merge the content
// hash of the source's last committed raw record into
// sources.config.last_content_hash on the caller's transaction (the fetch
// run's terminal commit — the hash advances only with a committed run).
func (r *SourceRepo) SetLastContentHash(ctx context.Context, tx application.Tx, sourceID, contentHash string) error {
	const op = "source.set_last_content_hash"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if err := r.q.WithTx(tx).SetSourceLastContentHash(ctx, gen.SetSourceLastContentHashParams{
		ID:          srcID,
		ContentHash: contentHash,
	}); err != nil {
		return mapDBError(op, err)
	}
	return nil
}

// SetCursor implements application.SourceRepo: promote the cursor_after
// watermark of one successful run back into sources.cursor on the caller's
// transaction (the fetch run's terminal commit — DEV-067/ARCH-003 §6: the
// source cursor advances only with a committed successful run, and the
// checkpointed windows of the NVD full import resume from it).
func (r *SourceRepo) SetCursor(ctx context.Context, tx application.Tx, sourceID string, cursor json.RawMessage) error {
	const op = "source.set_cursor"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if err := r.q.WithTx(tx).SetSourceCursor(ctx, gen.SetSourceCursorParams{
		ID:     srcID,
		Cursor: cursor,
	}); err != nil {
		return mapDBError(op, err)
	}
	return nil
}

// ListEnabledScheduled implements application.SourceRepo: the scheduler
// scan read (ARCH-002 §5) — every enabled source whose schedule is set,
// with the row identity and the schedule string the scan derives the due
// slot from.
func (r *SourceRepo) ListEnabledScheduled(ctx context.Context) ([]application.ScheduledSource, error) {
	const op = "source.list_enabled_scheduled"

	rows, err := r.q.ListEnabledScheduledSources(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	sources := make([]application.ScheduledSource, 0, len(rows))
	for _, row := range rows {
		sources = append(sources, application.ScheduledSource{
			ID:       uuidString(row.ID),
			Type:     application.SourceType(row.Type),
			Schedule: row.Schedule.String, // NULL schedule is filtered by the statement
		})
	}
	return sources, nil
}
