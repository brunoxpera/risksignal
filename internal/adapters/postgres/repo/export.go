package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
)

// ExportRepo is the postgres implementation of application.ExportRepo
// (exports.sql, ARCH-007 §1.2, WP-6.06 / DEV-118): the export CRUD insert/read
// plus the generation stamps (MarkCompleted/MarkFailed), the expiry read and
// the sweep mark (MarkExpired). Reads run on the pool-scoped query set; every
// mutating method rebinds through WithTx so the row and its export.generate
// outbox job commit or roll back together (one command, one transaction,
// ch. 5.1). Driver errors are translated to the typed application errors of
// ch. 5.2 (dbmap.go); a guarded transition that matches no row is a conflict
// (the idempotency guard), not a not-found.
type ExportRepo struct {
	q *gen.Queries
}

// NewExportRepo binds the repository to one query set (pool-scoped for the
// reads; write methods rebind per transaction).
func NewExportRepo(q *gen.Queries) *ExportRepo { return &ExportRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.ExportRepo = (*ExportRepo)(nil)

// Insert implements application.ExportRepo: store one 'pending' export row
// with the frozen filter jsonb on the caller's transaction. The id, the
// 'pending' status and the generation columns' NULLs are database-assigned.
func (r *ExportRepo) Insert(ctx context.Context, tx application.Tx, rec application.ExportRecord) (application.Export, error) {
	const op = "export.insert"

	filter, err := json.Marshal(rec.Filter)
	if err != nil {
		return application.Export{}, application.InfraError(op, err)
	}
	row, err := r.q.WithTx(tx).InsertExport(ctx, gen.InsertExportParams{
		Filter:    filter,
		Format:    string(rec.Format),
		CreatedBy: rec.CreatedBy,
		CreatedAt: toTS(rec.CreatedAt),
	})
	if err != nil {
		return application.Export{}, mapDBError(op, err)
	}
	return exportFromRow(op, row)
}

// GetByID implements application.ExportRepo: read one export by its id — the
// load step of the export.generate job and the status/download reads. A
// missing id is a not-found Error.
func (r *ExportRepo) GetByID(ctx context.Context, id string) (application.Export, error) {
	const op = "export.get_by_id"

	uid, err := toUUID(id)
	if err != nil {
		return application.Export{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetExport(ctx, uid)
	if err != nil {
		return application.Export{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return exportFromRow(op, row)
}

// MarkCompleted implements application.ExportRepo: the generation stamp
// (pending/failed -> completed). The guard makes a retry idempotent at the
// statement level; a completed/expired row matches no row → conflict.
func (r *ExportRepo) MarkCompleted(ctx context.Context, tx application.Tx, done application.ExportCompletion) (application.Export, error) {
	const op = "export.mark_completed"

	uid, err := toUUID(done.ID)
	if err != nil {
		return application.Export{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkExportCompleted(ctx, gen.MarkExportCompletedParams{
		StoragePath:   toTextOpt(done.StoragePath),
		RowCount:      pgtype.Int4{Int32: int32(done.RowCount), Valid: true},
		SizeBytes:     pgtype.Int8{Int64: done.SizeBytes, Valid: true},
		Checksum:      toTextOpt(done.Checksum),
		SchemaVersion: toTextOpt(done.SchemaVersion),
		RuleVersion:   toTextOpt(done.RuleVersion),
		ExpiresAt:     toTS(done.ExpiresAt),
		ID:            uid,
	})
	if err != nil {
		return application.Export{}, exportGuardMiss(op, err)
	}
	return exportFromRow(op, row)
}

// MarkFailed implements application.ExportRepo: record a failed generation
// (pending/failed -> failed + last_error). The guard keeps a completed/expired
// row from being overwritten; a guarded miss is a conflict.
func (r *ExportRepo) MarkFailed(ctx context.Context, tx application.Tx, id, lastError string) (application.Export, error) {
	const op = "export.mark_failed"

	uid, err := toUUID(id)
	if err != nil {
		return application.Export{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkExportFailed(ctx, gen.MarkExportFailedParams{
		LastError: toTextOpt(lastError),
		ID:        uid,
	})
	if err != nil {
		return application.Export{}, exportGuardMiss(op, err)
	}
	return exportFromRow(op, row)
}

// ListExpired implements application.ExportRepo: the completed exports whose
// TTL elapsed — the daily sweep's input. No expired export yields an empty
// slice, never an error.
func (r *ExportRepo) ListExpired(ctx context.Context, now time.Time) ([]application.Export, error) {
	const op = "export.list_expired"

	rows, err := r.q.ListExpiredExports(ctx, toTS(now))
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.Export, 0, len(rows))
	for _, row := range rows {
		e, err := exportFromRow(op, row)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// MarkExpired implements application.ExportRepo: flip a completed export to
// 'expired' after its artifact was deleted. The guard makes the mark
// idempotent; a second sweep of the same row matches no row → conflict.
func (r *ExportRepo) MarkExpired(ctx context.Context, tx application.Tx, id string) (application.Export, error) {
	const op = "export.mark_expired"

	uid, err := toUUID(id)
	if err != nil {
		return application.Export{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkExportExpired(ctx, uid)
	if err != nil {
		return application.Export{}, exportGuardMiss(op, err)
	}
	return exportFromRow(op, row)
}

// exportFromRow maps a stored exports row onto the application model, decoding
// the frozen filter jsonb.
func exportFromRow(op string, row gen.Export) (application.Export, error) {
	e := application.Export{
		ID:            uuidString(row.ID),
		Status:        application.ExportStatus(row.Status),
		Format:        export.Format(row.Format),
		StoragePath:   textValue(row.StoragePath),
		RowCount:      int(row.RowCount.Int32),
		SizeBytes:     row.SizeBytes.Int64,
		Checksum:      textValue(row.Checksum),
		SchemaVersion: textValue(row.SchemaVersion),
		RuleVersion:   textValue(row.RuleVersion),
		CreatedBy:     row.CreatedBy,
		CreatedAt:     tsTime(row.CreatedAt),
		ExpiresAt:     tsTime(row.ExpiresAt),
		LastError:     textValue(row.LastError),
	}
	if len(row.Filter) > 0 {
		var filter application.ExportFilter
		if err := json.Unmarshal(row.Filter, &filter); err != nil {
			return application.Export{}, application.InfraError(op, err)
		}
		e.Filter = filter
	}
	return e, nil
}

// exportGuardMiss maps a guarded generation-stamp statement that matched no
// row onto the lifecycle vocabulary: the guard's WHERE rejected the transition
// (the row is not in a stampable state), which is a conflict, not a not-found.
func exportGuardMiss(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ConflictError(op, err)
	}
	return mapDBError(op, err)
}
