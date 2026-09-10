package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the DownloadExport act (ARCH-007 §1.1/§1.2, WP-6.04 /
// DEV-115): the time-limited, audited stream of a materialised export
// artifact behind GET /exports/{id}/download. The expiry is checked against
// the injected clock (NFR-015), and a successful download appends one audit
// event in a transaction — a denied or expired download writes nothing.

// EventTypeExportDownloaded is the audit action of a successful export
// download (ARCH-007 §1.1/§10.4: "download … time-limited; audited").
const EventTypeExportDownloaded = "export.downloaded"

// DownloadExportInput is the DownloadExport act with the authenticated
// principal. CorrelationID links the download's audit row to the request;
// empty generates one.
type DownloadExportInput struct {
	ExportID      string
	Actor         Actor
	CorrelationID string
}

// DownloadExportResult is one downloadable artifact: the spool reader the
// caller streams and closes, the response metadata (a Content-Disposition
// attachment filename and the format's content type) and the stored
// generation stamps. The reader is owned by the caller, which must close it.
type DownloadExportResult struct {
	Reader      io.ReadCloser
	Filename    string
	ContentType string
	SizeBytes   int64
	Checksum    string
	Filter      ExportFilter
	Format      export.Format
}

// DownloadExport streams one stored export artifact (ARCH-007 §1.2): it
// authorises exports.create (object-scoped to the creator) and, before any
// artifact is opened, requires the export to be 'completed' and unexpired —
// an expired export is rejected against the injected clock (NFR-015). A
// successful stream appends one export.downloaded audit event in a
// transaction; a denied, not-ready or expired download opens no transaction
// and writes no audit row. The returned reader is the caller's to close.
func (s *Service) DownloadExport(ctx context.Context, in DownloadExportInput) (DownloadExportResult, error) {
	const op = "download_export"

	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return DownloadExportResult{}, err
	}
	if s.exports == nil {
		return DownloadExportResult{}, InfraError(op, errors.New("export repository is not wired"))
	}
	if in.ExportID == "" {
		return DownloadExportResult{}, Validationf(op, "export id must not be empty")
	}
	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return DownloadExportResult{}, err
	}
	row, err := s.exports.GetByID(ctx, in.ExportID)
	if err != nil {
		return DownloadExportResult{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionExportsCreate, domain.ScopeAssigned, row.CreatedBy); err != nil {
		return DownloadExportResult{}, err
	}
	// Time-limited download: only a completed export has an artifact, and
	// its expiry is checked against the injected clock, never the wall
	// clock (NFR-015). A pending/failed export has nothing to stream.
	if row.Status != ExportStatusCompleted {
		return DownloadExportResult{}, ConflictError(op, fmt.Errorf("export %s is %s, not completed", row.ID, row.Status))
	}
	now := s.clock.Now()
	if !row.ExpiresAt.IsZero() && !now.Before(row.ExpiresAt) {
		return DownloadExportResult{}, ConflictError(op, fmt.Errorf(
			"export %s expired at %s", row.ID, row.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	if s.exportStore == nil {
		return DownloadExportResult{}, InfraError(op, errors.New("export artifact store is not wired"))
	}
	// Open first: a missing artifact is an infrastructure failure and must
	// not be audited as a successful download. The reader is closed on the
	// audit failure path so a failed act leaks nothing.
	reader, err := s.exportStore.Open(ctx, row.StoragePath)
	if err != nil {
		return DownloadExportResult{}, err
	}

	correlationID := correlationOrNew(in.CorrelationID)
	after, err := json.Marshal(newExportSnapshot(row))
	if err != nil {
		_ = reader.Close()
		return DownloadExportResult{}, InfraError(op, err)
	}
	err = s.runTx(ctx, func(tx Tx) error {
		return s.audit.Append(ctx, tx, AuditEvent{
			AggregateType:    AuditAggregateExport,
			AggregateID:      row.ID,
			ActorType:        actor.Type,
			ActorID:          actor.ID,
			ActorDisplayName: actor.DisplayName,
			Action:           EventTypeExportDownloaded,
			OccurredAt:       now,
			Before:           nil,
			After:            after,
			CorrelationID:    correlationID,
		})
	})
	if err != nil {
		_ = reader.Close()
		return DownloadExportResult{}, err
	}

	return DownloadExportResult{
		Reader:      reader,
		Filename:    exportFilename(row),
		ContentType: exportContentType(row.Format),
		SizeBytes:   row.SizeBytes,
		Checksum:    row.Checksum,
		Filter:      row.Filter,
		Format:      row.Format,
	}, nil
}

// exportFilename is the Content-Disposition attachment name of one export
// artifact: export-<id>.<format>.
func exportFilename(e Export) string {
	return "export-" + e.ID + "." + string(e.Format)
}

// exportContentType is the response content type of one export format.
func exportContentType(f export.Format) string {
	switch f {
	case export.FormatCSV:
		return "text/csv; charset=utf-8"
	case export.FormatJSON:
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
