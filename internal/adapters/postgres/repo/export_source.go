package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
)

// SignalExportSource is the postgres implementation of
// application.SignalExportSource (export_source.sql, ARCH-007 §1.2, WP-6.06 /
// DEV-118): the full-scan streaming read the export.generate job materialises.
// It applies the frozen §10.4 filter (the object scope is already frozen into
// OwnerID by the CreateExport command) against the injected clock instant and
// returns every matching signal ordered by the §10.4 standard sort. It is a
// pure read — no write path, no shared-table mutation.
type SignalExportSource struct {
	q *gen.Queries
}

// NewSignalExportSource binds the read to one query set (pool-scoped).
func NewSignalExportSource(q *gen.Queries) *SignalExportSource {
	return &SignalExportSource{q: q}
}

// compile-time check that the adapter satisfies its port.
var _ application.SignalExportSource = (*SignalExportSource)(nil)

// Scan implements application.SignalExportSource: every signal matching the
// frozen filter, ordered by the §10.4 standard sort, evaluated against now
// (the injected clock). An empty match yields an empty slice, never an error.
func (s *SignalExportSource) Scan(ctx context.Context, filter application.ExportFilter, now time.Time) ([]export.Row, error) {
	const op = "export_source.scan"

	params := gen.SignalExportSourceParams{
		Now:         toTS(now),
		CreatedFrom: tsPtrValue(filter.CreatedFrom),
		CreatedTo:   tsPtrValue(filter.CreatedTo),
	}
	if filter.Priority != nil {
		params.Priority = toTextOpt(string(*filter.Priority))
	}
	if filter.Status != nil {
		params.Status = toTextOpt(string(*filter.Status))
	}
	if filter.OwnerID != nil {
		params.OwnerID = toTextOpt(*filter.OwnerID)
	}
	if filter.AssetType != nil {
		params.AssetType = toTextOpt(string(*filter.AssetType))
	}
	if filter.SLAState != nil {
		params.SlaState = toTextOpt(string(*filter.SLAState))
	}
	if filter.Product != "" {
		params.Product = toTextOpt(filter.Product)
	}
	if filter.Cve != "" {
		params.Cve = toTextOpt(filter.Cve)
	}
	if filter.FreeText != "" {
		params.FreeText = toTextOpt(filter.FreeText)
	}
	if filter.AssetID != "" {
		uid, err := toUUID(filter.AssetID)
		if err != nil {
			return nil, application.ValidationError(op, err)
		}
		params.AssetID = uid
	}
	if filter.SourceID != "" {
		uid, err := toUUID(filter.SourceID)
		if err != nil {
			return nil, application.ValidationError(op, err)
		}
		params.SourceID = uid
	}

	rows, err := s.q.SignalExportSource(ctx, params)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]export.Row, 0, len(rows))
	for _, row := range rows {
		out = append(out, export.Row{
			ID:               uuidString(row.ID),
			CveID:            row.CveID,
			Priority:         row.Priority,
			Status:           row.Status,
			Confidence:       row.Confidence,
			Method:           row.Method,
			Owner:            textValue(row.Owner),
			Vendor:           row.Vendor,
			Product:          row.Product,
			ComponentVersion: row.ComponentVersion,
			AssetID:          uuidString(row.AssetID),
			AssetExternalID:  row.AssetExternalID,
			AssetName:        row.AssetName,
			AssetType:        row.AssetType,
			AssetEnvironment: row.AssetEnvironment,
			AssetCriticality: row.AssetCriticality,
			AssetExposure:    row.AssetExposure,
			Summary:          row.Summary,
			CreatedAt:        tsTime(row.CreatedAt),
			DueAt:            tsPtr(row.DueAt),
			ClosedAt:         tsPtr(row.ClosedAt),
		})
	}
	return out, nil
}

// tsPtr renders a nullable timestamptz column as a *time.Time (nil when NULL)
// — the optional-instant shape of the export row.
func tsPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// tsPtrValue maps an optional instant onto a nullable timestamptz.
func tsPtrValue(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return toTS(*t)
}
