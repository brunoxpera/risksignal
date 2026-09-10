package repo

// InventoryImportRepo is the postgres implementation of the I5b staged
// inventory-import persistence (ARCH-006 §2.1, WP-5b.02 / DEV-098; adapter
// lands in WP-5b.05 / DEV-101): the insert of a pending staging record, the
// by-id read, the guarded commit-mark and the operator list over the
// inventory_imports queries (db/queries/inventory_imports.sql).
//
// It is the production adapter of application.InventoryImportRepo (DEV-099
// review follow-up (a)): it persists the bytes, the preview tallies and the
// attribution, it never re-implements the import business logic — the commit
// arm's parse/upsert/audit/enqueue work stays the I3 CommitInventory command
// (the use case orchestrates it and stamps the four commit-outcome counters
// through MarkCommitted). The write methods run on the caller's transaction
// (INSERT and the guarded commit-mark are one transaction each); the two
// reads run on the pool-scoped query set.
//
// The guarded commit-mark maps the zero-row outcome (pgx.ErrNoRows — a
// second commit of an already-committed or failed record) onto marked=false
// with no error, the statement-level idempotency the use case relies on to
// return the stored result without re-running the command (ARCH-006 §2.1).
// The stored vocabulary (status) and the nullable correlation_id/committed_at
// are read back verbatim / as the zero value (NULL ⇒ "", zero time), the same
// nullability convention as the other read models.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// InventoryImportRepo implements application.InventoryImportRepo over one
// query set.
type InventoryImportRepo struct {
	q *gen.Queries
}

// NewInventoryImportRepo binds the repository to one query set.
func NewInventoryImportRepo(q *gen.Queries) *InventoryImportRepo {
	return &InventoryImportRepo{q: q}
}

// compile-time check that the repository satisfies the staging port.
var _ application.InventoryImportRepo = (*InventoryImportRepo)(nil)

// Insert implements application.InventoryImportRepo: it stores one staged
// upload (status pending) on the caller's transaction and returns the stored
// record with its database-assigned id. The four commit-outcome counters and
// committed_at keep their column defaults (0 / NULL) until MarkCommitted
// stamps them; a correlation id of "" stores NULL.
func (r *InventoryImportRepo) Insert(ctx context.Context, tx application.Tx, rec application.InventoryImportRecord) (application.InventoryImportRecord, error) {
	const op = "inventory_import.insert"

	row, err := r.q.WithTx(tx).InsertInventoryImport(ctx, gen.InsertInventoryImportParams{
		Status:        string(rec.Status),
		File:          rec.File,
		Rows:          int32(rec.Rows),
		ErrorCount:    int32(rec.ErrorCount),
		WarningCount:  int32(rec.WarningCount),
		ActorID:       rec.ActorID,
		CorrelationID: toTextOpt(rec.CorrelationID),
		CreatedAt:     toTS(rec.CreatedAt),
	})
	if err != nil {
		return application.InventoryImportRecord{}, mapDBError(op, err)
	}
	return inventoryImportRecordFrom(row), nil
}

// Get implements application.InventoryImportRepo: it reads one staged record
// by its opaque import id. A malformed id is a caller mistake (validation);
// a missing id is a not-found error (the caller maps it to a 404).
func (r *InventoryImportRepo) Get(ctx context.Context, id string) (application.InventoryImportRecord, error) {
	const op = "inventory_import.get"

	uid, err := toUUID(id)
	if err != nil {
		return application.InventoryImportRecord{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetInventoryImport(ctx, uid)
	if err != nil {
		return application.InventoryImportRecord{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return inventoryImportRecordFrom(row), nil
}

// MarkCommitted implements application.InventoryImportRepo: it flips a
// pending record to committed, stamps committed_at from now and populates the
// four commit-outcome counters, atomically in one guarded UPDATE (the
// `status = 'pending'` guard makes a second commit a no-op). marked reports
// whether the guard matched; the zero-row case (pgx.ErrNoRows) is the no-op
// (marked=false, no error), so the use case returns the stored result.
func (r *InventoryImportRepo) MarkCommitted(ctx context.Context, tx application.Tx, id string, counts application.InventoryImportCounts, now time.Time) (application.InventoryImportRecord, bool, error) {
	const op = "inventory_import.mark_committed"

	uid, err := toUUID(id)
	if err != nil {
		return application.InventoryImportRecord{}, false, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkInventoryImportCommitted(ctx, gen.MarkInventoryImportCommittedParams{
		Now:               toTS(now),
		AssetsCreated:     int32(counts.AssetsCreated),
		AssetsUpdated:     int32(counts.AssetsUpdated),
		ComponentsCreated: int32(counts.ComponentsCreated),
		ComponentsUpdated: int32(counts.ComponentsUpdated),
		ID:                uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The guard did not match: a concurrent (or second) commit of an
			// already-committed/failed record — the idempotent no-op.
			return application.InventoryImportRecord{}, false, nil
		}
		return application.InventoryImportRecord{}, false, mapDBError(op, err)
	}
	return inventoryImportRecordFrom(row), true, nil
}

// List implements application.InventoryImportRepo: it returns every staged
// record ordered by staging instant then id. An empty table yields an empty
// slice, never an error.
func (r *InventoryImportRepo) List(ctx context.Context) ([]application.InventoryImportRecord, error) {
	const op = "inventory_import.list"

	rows, err := r.q.ListInventoryImports(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.InventoryImportRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, inventoryImportRecordFrom(row))
	}
	return out, nil
}

// inventoryImportRecordFrom maps a stored inventory_imports row onto the
// application read model (ARCH-006 §2.1): the opaque id, the lifecycle
// status, the stored bytes, the row/error/warning and commit-outcome tallies
// and the attribution. The nullable correlation_id/committed_at render as
// "" / the zero time (NULL), the same convention as the other read models.
func inventoryImportRecordFrom(row gen.InventoryImport) application.InventoryImportRecord {
	return application.InventoryImportRecord{
		ID:                uuidString(row.ID),
		Status:            application.InventoryImportStatus(row.Status),
		File:              row.File,
		Rows:              int(row.Rows),
		ErrorCount:        int(row.ErrorCount),
		WarningCount:      int(row.WarningCount),
		AssetsCreated:     int(row.AssetsCreated),
		AssetsUpdated:     int(row.AssetsUpdated),
		ComponentsCreated: int(row.ComponentsCreated),
		ComponentsUpdated: int(row.ComponentsUpdated),
		ActorID:           row.ActorID,
		CorrelationID:     textValue(row.CorrelationID),
		CreatedAt:         tsTime(row.CreatedAt),
		CommittedAt:       tsTime(row.CommittedAt),
	}
}
