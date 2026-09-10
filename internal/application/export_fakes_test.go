package application_test

// Fakes for the I6 export use cases (ARCH-007 §1.2, WP-6.04 / DEV-115): the
// export CRUD repository, the spool artifact store and the streaming
// SignalExportSource read. They are in-memory over the fakeDB; the repo
// stages its inserts on the fake transaction so commit/rollback semantics
// hold (the atomic row+job proof), while the store and the export source are
// seeded directly by the test.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// ---------------------------------------------------------------------------
// fakeExportRepo (application.ExportRepo)

type fakeExportRepo struct {
	db *fakeDB
	// failInsert, when set, makes Insert fail after recording the write — the
	// fault seam of the CreateExport command's row write (distinct from the
	// outbox failpoint that arms the row+job atomicity proof).
	failInsert error
}

var _ application.ExportRepo = (*fakeExportRepo)(nil)

func (f *fakeExportRepo) Insert(ctx context.Context, tx application.Tx, rec application.ExportRecord) (application.Export, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.Export{}, err
	}
	ftx.record("export.insert")
	if f.failInsert != nil {
		return application.Export{}, f.failInsert
	}
	row := application.Export{
		ID:        uuid.New(),
		Status:    application.ExportStatusPending,
		Filter:    rec.Filter,
		Format:    rec.Format,
		CreatedBy: rec.CreatedBy,
		CreatedAt: rec.CreatedAt,
	}
	ftx.staged.exports = append(ftx.staged.exports, row)
	return row, nil
}

func (f *fakeExportRepo) GetByID(_ context.Context, id string) (application.Export, error) {
	for _, e := range f.db.exports {
		if e.ID == id {
			return e, nil
		}
	}
	return application.Export{}, application.NotFoundError("export.get_by_id", fmt.Errorf("export %s not found", id))
}

func (f *fakeExportRepo) MarkCompleted(_ context.Context, tx application.Tx, done application.ExportCompletion) (application.Export, error) {
	if _, err := fakeTxOf(tx); err != nil {
		return application.Export{}, err
	}
	row, ok := f.db.exportByID(done.ID)
	if !ok {
		return application.Export{}, application.NotFoundError("export.mark_completed", fmt.Errorf("export %s not found", done.ID))
	}
	if row.Status != application.ExportStatusPending && row.Status != application.ExportStatusFailed {
		return application.Export{}, application.ConflictError("export.mark_completed", fmt.Errorf("export %s is %s, not pending/failed", done.ID, row.Status))
	}
	row.Status = application.ExportStatusCompleted
	row.StoragePath = done.StoragePath
	row.RowCount = done.RowCount
	row.SizeBytes = done.SizeBytes
	row.Checksum = done.Checksum
	row.SchemaVersion = done.SchemaVersion
	row.RuleVersion = done.RuleVersion
	row.ExpiresAt = done.ExpiresAt
	row.LastError = ""
	f.db.replaceExport(row)
	return row, nil
}

func (f *fakeExportRepo) MarkFailed(_ context.Context, tx application.Tx, id, lastError string) (application.Export, error) {
	if _, err := fakeTxOf(tx); err != nil {
		return application.Export{}, err
	}
	row, ok := f.db.exportByID(id)
	if !ok {
		return application.Export{}, application.NotFoundError("export.mark_failed", fmt.Errorf("export %s not found", id))
	}
	if row.Status != application.ExportStatusPending && row.Status != application.ExportStatusFailed {
		return application.Export{}, application.ConflictError("export.mark_failed", fmt.Errorf("export %s is %s, not pending/failed", id, row.Status))
	}
	row.Status = application.ExportStatusFailed
	row.LastError = lastError
	f.db.replaceExport(row)
	return row, nil
}

func (f *fakeExportRepo) ListExpired(_ context.Context, now time.Time) ([]application.Export, error) {
	var out []application.Export
	for _, e := range f.db.exports {
		if e.Status == application.ExportStatusCompleted && !e.ExpiresAt.IsZero() && !e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeExportRepo) MarkExpired(_ context.Context, tx application.Tx, id string) (application.Export, error) {
	if _, err := fakeTxOf(tx); err != nil {
		return application.Export{}, err
	}
	row, ok := f.db.exportByID(id)
	if !ok {
		return application.Export{}, application.NotFoundError("export.mark_expired", fmt.Errorf("export %s not found", id))
	}
	if row.Status != application.ExportStatusCompleted {
		return application.Export{}, application.ConflictError("export.mark_expired", fmt.Errorf("export %s is %s, not completed", id, row.Status))
	}
	row.Status = application.ExportStatusExpired
	f.db.replaceExport(row)
	return row, nil
}

// exportByID returns the committed export row of id (the fake's read-modify-write
// helper for the generation stamps).
func (d *fakeDB) exportByID(id string) (application.Export, bool) {
	for _, e := range d.exports {
		if e.ID == id {
			return e, true
		}
	}
	return application.Export{}, false
}

// replaceExport stores the mutated export row back in the committed state.
func (d *fakeDB) replaceExport(row application.Export) {
	for i := range d.exports {
		if d.exports[i].ID == row.ID {
			d.exports[i] = row
			return
		}
	}
	d.exports = append(d.exports, row)
}

// seedExport stores one committed export row (the read/download fixtures).
func seedExport(h *harness, e application.Export) application.Export {
	if e.Status == "" {
		e.Status = application.ExportStatusPending
	}
	if e.Format == "" {
		e.Format = export.FormatCSV
	}
	if e.ID == "" {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = fixedNow
	}
	h.db.exports = append(h.db.exports, e)
	return e
}

// ---------------------------------------------------------------------------
// fakeExportStore (application.ExportArtifactStore)

type fakeExportStore struct {
	artifacts map[string][]byte
	failOpen  error
}

var _ application.ExportArtifactStore = (*fakeExportStore)(nil)

func (f *fakeExportStore) Write(_ context.Context, key string, r io.Reader) (export.Artifact, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return export.Artifact{}, err
	}
	f.artifacts[key] = data
	sum := sha256.Sum256(data)
	return export.Artifact{Path: key, SizeBytes: int64(len(data)), Checksum: hex.EncodeToString(sum[:])}, nil
}

func (f *fakeExportStore) Open(_ context.Context, path string) (io.ReadCloser, error) {
	if f.failOpen != nil {
		return nil, f.failOpen
	}
	data, ok := f.artifacts[path]
	if !ok {
		return nil, application.NotFoundError("export.open", fmt.Errorf("artifact %s not found", path))
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeExportStore) Remove(_ context.Context, path string) error {
	delete(f.artifacts, path)
	return nil
}

// ---------------------------------------------------------------------------
// fakeSignalExportSource (application.SignalExportSource)

// fakeSignalExportSource is the in-memory application.SignalExportSource: it
// applies the row-level §10.4 filters it can evaluate over the read model
// (priority, status, owner, product, cve, asset id/type, creation window and
// the free-text substring) and returns the rows ordered by the §10.4
// standard sort — priority ascending, then the next open SLA deadline (rows
// with no deadline last), then created_at, then id. It stands in for the
// DEV-112 SignalExportSource query in the unit tests; the real SQL projection
// is covered by the postgres I6 integration test.
type fakeSignalExportSource struct {
	rows []export.Row
	// fail, when set, makes Scan fail — the generation-failure path of the
	// export.generate job (the row is marked failed + last_error).
	fail error
}

var _ application.SignalExportSource = (*fakeSignalExportSource)(nil)

func priorityRankExport(p string) int {
	switch p {
	case "P1":
		return 0
	case "P2":
		return 1
	case "P3":
		return 2
	case "P4":
		return 3
	}
	return 99
}

func (f *fakeSignalExportSource) Scan(_ context.Context, filter application.ExportFilter, _ time.Time) ([]export.Row, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	var out []export.Row
	for _, r := range f.rows {
		if filter.Priority != nil && r.Priority != string(*filter.Priority) {
			continue
		}
		if filter.Status != nil && r.Status != string(*filter.Status) {
			continue
		}
		if filter.OwnerID != nil && r.Owner != *filter.OwnerID {
			continue
		}
		if filter.Product != "" && r.Product != filter.Product {
			continue
		}
		if filter.Cve != "" && r.CveID != filter.Cve {
			continue
		}
		if filter.AssetID != "" && r.AssetID != filter.AssetID {
			continue
		}
		if filter.AssetType != nil && r.AssetType != string(*filter.AssetType) {
			continue
		}
		if filter.CreatedFrom != nil && r.CreatedAt.Before(*filter.CreatedFrom) {
			continue
		}
		if filter.CreatedTo != nil && !r.CreatedAt.Before(*filter.CreatedTo) {
			continue
		}
		if filter.FreeText != "" && !rowHasText(r, filter.FreeText) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if pi, pj := priorityRankExport(out[i].Priority), priorityRankExport(out[j].Priority); pi != pj {
			return pi < pj
		}
		di, dj := out[i].DueAt, out[j].DueAt
		switch {
		case di == nil && dj != nil:
			return false
		case di != nil && dj == nil:
			return true
		case di != nil && dj != nil && !di.Equal(*dj):
			return di.Before(*dj)
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func rowHasText(r export.Row, needle string) bool {
	n := strings.ToLower(needle)
	for _, s := range []string{r.CveID, r.Summary, r.Vendor, r.Product, r.AssetName} {
		if strings.Contains(strings.ToLower(s), n) {
			return true
		}
	}
	return false
}
